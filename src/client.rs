// Library for building scalable privacy-preserving microservices P2P nodes
//
// SPDX-License-Identifier: Apache-2.0
//
// Written in 2022-2025 by
//     Dr. Maxim Orlovsky <orlovsky@cyphernet.org>
//
// Copyright 2022-2025 Cyphernet Labs, InDCS, Switzerland
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! A base for client-server communications clients.
//!
//! Supports exchanging of requests and replies in asynchronous mode.
//!
//! For specific applications, please check [`super::RpcClient`], [`super::PubSubClient`] and
//! [`super::RpcPubClient`] implementing and enforcing specific client-server protocols.

use std::any::Any;
use std::collections::VecDeque;
use std::fmt::Debug;
use std::os::fd::RawFd;
use std::time::Duration;
use std::{io, mem};

use reactor::poller::popol;
use reactor::{Action, Error, Reactor, ResourceId, ResourceType, Timestamp};

use crate::{Direction, Frame, ImpossibleResource, NetSession, NetTransport, SessionEvent};

#[cfg(feature = "log")]
const NAME: &str = "net-client";

/// The commands which are sent from [`Client`] runtime on the main thread and [`ClientDelegate`]
/// from inside the reactor thread to [`ClientService`] existing in the reactor thread.
///
/// When a user of the library calls [`Client`] method the actual command is passed to the
/// [`ClientCommand`] using this array.
#[derive(Debug)]
pub enum ClientCommand<R: Frame> {
    /// Send raw data to the remote server. Second argument is an extension block which allows
    /// downstream implementations of specific client-server  to provide callbacks for RPC
    /// request-reply pairs.
    Send(R),

    /// Close connection with the remote server, stop the reactor loop and complete the reactor
    /// thread.
    Terminate,
}

/// Enum defining the client behaviour when the connection with the server gets broken (or closed by
/// the server). Returned by [`ConnectionDelegate::on_disconnect`] method.
#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug)]
pub enum OnDisconnect {
    /// Terminates the client, stopping the reactor, completing its thread and making client object
    /// unusable (calls to [`Client`] methods with result in [`io::Error`] coming from the closed
    /// communication channel with the reactor).
    Terminate,

    /// Tries to reconnect to the server using [`ConnectionDelegate::connect`] method, informing it
    /// about the current connection attempt number.
    Reconnect,
}

/// Set of callbacks for managing client-server connections, provided by the [`Client`] user to the
/// reactor.
pub trait ConnectionDelegate<A, S: NetSession>:
    Send + Iterator<Item = ClientCommand<Self::Request>>
{
    type Request: Frame + Debug;

    /// Asks the delegate to construct a connection to the remote server and return it as a form of
    /// [`NetSession`] to be registered and managed by the reactor and [`ClientService`] inside of
    /// it.
    fn connect(&mut self, remote: &A) -> S;

    /// Notifies about the successful establishment of the session with the server. The `attempt`
    /// argument specifies the number of the connection attempt which has succeeded, if a
    /// reconnection or failed connection had happened.
    fn on_established(&mut self, artifact: S::Artifact, attempt: usize);

    /// Notifies about failed connection to the server. As a response, the client business logic can
    /// ask to re-establish connection by returning [`OnDisconnect::Reconnect`]. Otherwise, the
    /// reactor will terminate.
    fn on_disconnect(&mut self, err: io::Error, attempt: usize) -> OnDisconnect;

    /// Callback for processing reactor [`Error`]s.
    fn on_io_error(&mut self, err: Error<ImpossibleResource, NetTransport<S>>);
}

/// Set of callbacks used by the client to notify the business logic about server messages.
pub trait ClientDelegate<A, S: NetSession>: ConnectionDelegate<A, S> {
    /// The reply type which must be parsable from a byte blob.
    type Reply: Frame;

    /// Callback for processing the message received from the server.
    fn on_reply(&mut self, reply: Self::Reply);

    /// Callback for processing invalid message received from the server which can't be parsed into
    /// [`Self::Reply`] type.
    fn on_reply_unparsable(&mut self, err: <Self::Reply as Frame>::Error);
}

/// Handler for the client-server connection reactor on the client side. Manages state of the server
/// connectivity and orchestrates server message processing using [`ClientDelegate`] stored in the
/// `delegate`.
///
/// The reactor always has just a single resource - an outgoing connection to the remote server.
///
/// # Generics
///
/// - `A`: network address type representing remote server;
/// - `S`: server session type, implementing [`NetSession`];
/// - `D`: client delegate which callbacks are called for managing connectivity and processing
///   incoming messages (see also `delegate` above);
/// - `E`: extension argument passed to the delegate, which can be used to provide callbacks for
///   server replies in RPC protocols and server published messages in PubSub protocols.
struct ClientService<A: Send, S: NetSession, D: ClientDelegate<A, S>> {
    /// Connection and messaging delegate providing callbacks for managing server connectivity and
    /// processing its messages.
    delegate: D,
    /// Network address of the remote server.
    remote: A,
    /// Holds reactor [`ResourceId`] assigned to the server connection.
    connection_id: Option<ResourceId>,
    /// Holds file descriptor of the server connection.
    connection_fd: Option<RawFd>,
    /// Tracks the status of the connection. Set to true when the service tries to establish the
    /// connection or has an established connection, i.e. before [`ConnectionDelegate::connect`]
    /// and before receiving [`SessionEvent::Terminated`], i.e. until
    /// [`ConnectionDelegate::disconnected`]. Used to prevent repeated calls to
    /// [`ConnectionDelegate::connect`].
    active: bool,
    /// Counts the number of connection attempts.
    attempts: usize,
    /// Stores the messages sent to the remote served before the actual connection is getting
    /// established.
    data_stack: Vec<Vec<u8>>,
    /// Buffer for the actions which has to be delivered to the reactor when it calls the
    /// [`ClientServer`] as an iterator.
    action_queue: VecDeque<Action<ImpossibleResource, NetTransport<S>>>,
}

impl<A: Send, S: NetSession, D: ClientDelegate<A, S>> ClientService<A, S, D> {
    /// Constructs new reactor handler providing delegate and remote server address. Will attempt to
    /// connect to the server automatically once the reactor thread has started.
    #[inline]
    pub fn new(delegate: D, remote: A) -> Self {
        #[cfg(feature = "log")]
        log::debug!(target: NAME, "constructing client service object and scheduling connection timer");
        Self {
            delegate,
            remote,
            connection_id: None,
            connection_fd: None,
            attempts: 0,
            active: false,
            data_stack: empty!(),
            action_queue: VecDeque::from(vec![Action::SetTimer(Duration::from_millis(0))]),
        }
    }

    /// Convenience method running scenario of establishing server connection, notifying the
    /// delegate on failed attempts and repeating attempts if instructed by the delegate to do so.
    /// When the connection is established, creates a transport instance and instructs the reactor
    /// to register the transport.
    fn connect(&mut self) {
        if self.active {
            #[cfg(feature = "log")]
            log::error!(target: NAME, "calling connect method while the server connection exists (or has been establishing)");
            return;
        }
        self.active = true;
        loop {
            #[cfg(feature = "log")]
            log::info!(target: NAME, "attempting to connect the server for the {} time", self.attempts + 1);

            let session = self.delegate.connect(&self.remote);
            match NetTransport::with_session(session, Direction::Outbound) {
                Ok(transport) => {
                    #[cfg(feature = "log")]
                    log::info!(target: NAME, "server connections successfully established, scheduling registering the transport {} with the reactor", transport.display());

                    self.action_queue
                        .push_back(Action::RegisterTransport(transport));
                    break;
                }
                Err(err) => {
                    #[cfg(feature = "log")]
                    log::error!(target: NAME, "error connecting to the server: {err}");

                    self.attempts += 1;
                    if self.delegate.on_disconnect(err, self.attempts) == OnDisconnect::Terminate {
                        #[cfg(feature = "log")]
                        log::debug!(target: NAME, "delegate signalled to terminate the reactor due to unsuccesful server connection");

                        self.terminate();
                        break;
                    }
                }
            }
        }
    }

    /// Adds terminate action to the action queue, such that on the next reactor event loop run it
    /// will receive it and close the connection to the server.
    fn terminate(&mut self) {
        #[cfg(feature = "log")]
        log::info!(target: NAME, "Scheduling to terminate the reactor and client service");

        self.action_queue.push_back(Action::Terminate);
    }
}

impl<A: Send, S: NetSession, D: ClientDelegate<A, S>> reactor::Handler for ClientService<A, S, D> {
    type Listener = ImpossibleResource;
    type Transport = NetTransport<S>;
    type Command = ClientCommand<D::Request>;

    fn tick(&mut self, time: Timestamp) {
        #[cfg(feature = "log")]
        log::trace!(target: NAME, "reactor tick at {time}");
    }

    fn handle_timer(&mut self) {
        #[cfg(feature = "log")]
        log::trace!(target: NAME, "reactor timer event");
        if !self.active {
            #[cfg(feature = "log")]
            log::debug!(target: NAME, "attempting to connect to the remote server on the timer event");
            self.connect();
        }
    }

    fn handle_listener_event(&mut self, _: RawFd, _: ResourceId, _: (), _: Timestamp) {
        unreachable!("there is no listener in client")
    }

    fn handle_transport_event(
        &mut self,
        fd: RawFd,
        id: ResourceId,
        event: SessionEvent<S>,
        time: Timestamp,
    ) {
        debug_assert_eq!(self.connection_id, Some(id));
        match event {
            SessionEvent::Established(artifact) => {
                #[cfg(feature = "log")]
                log::debug!(target: NAME, "established connection to server (fd={fd}, time={time}), notifying delegate");

                debug_assert_eq!(self.connection_fd, Some(fd));
                self.delegate.on_established(artifact, self.attempts);
            }
            SessionEvent::Data(data) => match D::Reply::unmarshall(io::Cursor::new(data)) {
                Ok(Some(reply)) => {
                    #[cfg(feature = "log")]
                    log::trace!(target: NAME, "received reply from the server at {time}");

                    self.delegate.on_reply(reply)
                }
                Ok(None) => {
                    #[cfg(feature = "log")]
                    log::trace!(target: NAME, "received partial reply data from the server at {time}");
                }
                Err(err) => {
                    #[cfg(feature = "log")]
                    log::error!(target: NAME, "unparsable reply from the server at {time}: {}", err);

                    self.delegate.on_reply_unparsable(err)
                }
            },
            SessionEvent::Terminated(err) => {
                self.active = false;
                self.connection_id = None;
                self.connection_fd = None;
                self.attempts += 1;

                #[cfg(feature = "log")]
                log::debug!(target: NAME, "disconnected from the server for the {} time", self.attempts);

                if self.delegate.on_disconnect(err, self.attempts) == OnDisconnect::Reconnect {
                    self.connect();
                } else {
                    self.terminate();
                }
            }
        }
    }

    fn handle_registered(&mut self, fd: RawFd, id: ResourceId, ty: ResourceType) {
        #[cfg(feature = "log")]
        log::trace!(target: NAME, "handled registration of connection with fd={fd}, id={id} on attempt {}", self.attempts);
        debug_assert_eq!(ty, ResourceType::Transport);

        self.connection_fd = Some(fd);
        self.connection_id = Some(id);

        #[cfg(feature = "log")]
        log::trace!(target: NAME, "scheduling sending {} buffered messages to the server", self.data_stack.len());
        let mut data_stack = vec![];
        mem::swap(&mut data_stack, &mut self.data_stack);
        self.action_queue
            .extend(data_stack.into_iter().map(|data| Action::Send(id, data)));
    }

    fn handle_command(&mut self, cmd: Self::Command) {
        match cmd {
            ClientCommand::Send(data) => {
                let mut buf = Vec::new();
                data.marshall(&mut buf).expect("failed to marshall request");

                #[cfg(feature = "log")]
                log::trace!(target: NAME, "sending data to the server ({} bytes)", buf.len());

                if let Some(id) = self.connection_id {
                    self.action_queue.push_back(Action::Send(id, buf));
                } else {
                    #[cfg(feature = "log")]
                    log::trace!(target: NAME, "buffering the data since the connection is not yet established ({} elements in the stack already)", self.data_stack.len());

                    self.data_stack.push(buf);
                }
            }
            ClientCommand::Terminate => {
                self.terminate();
            }
        }
    }

    fn handle_error(&mut self, err: Error<Self::Listener, Self::Transport>) {
        #[cfg(feature = "log")]
        log::error!(target: NAME, "I/O error in server connection: {err}");

        self.delegate.on_io_error(err)
    }

    fn handover_listener(&mut self, _: ResourceId, _: Self::Listener) {
        unreachable!("there is no listener in client")
    }

    fn handover_transport(&mut self, id: ResourceId, transport: Self::Transport) {
        #[cfg(feature = "log")]
        log::trace!(target: NAME, "transport {} has been disconnected and handed over (id={id})", transport.display());
        debug_assert!(self.connection_fd.is_some());
        debug_assert_eq!(self.connection_id, Some(id));

        self.connection_id = None;
        self.connection_fd = None;
        // TODO: Check that we do not need to do anything else
    }
}

impl<A: Send, S: NetSession, D: ClientDelegate<A, S>> Iterator for ClientService<A, S, D> {
    type Item = Action<ImpossibleResource, NetTransport<S>>;

    fn next(&mut self) -> Option<Self::Item> { self.action_queue.pop_front() }
}

/// The client runtime containing reactor thread managing connection to the remote server and the
/// use of the server APIs.
pub struct Client<R: Frame> {
    reactor: Reactor<ClientCommand<R>, popol::Poller>,
}

impl<R: Frame + Debug + 'static> Client<R> {
    /// Constructs new client for client-server protocol. Takes service callback delegate and remote
    /// server address. Will attempt to connect to the server automatically once the reactor thread
    /// has started.
    pub fn new<
        A: Send + 'static,
        S: NetSession + 'static,
        D: ClientDelegate<A, S, Request = R> + 'static,
    >(
        delegate: D,
        remote: A,
    ) -> io::Result<Self> {
        let service = ClientService::<A, S, D>::new(delegate, remote);
        let reactor = Reactor::named(service, popol::Poller::new(), s!("client"))?;
        Ok(Self { reactor })
    }

    /// Terminates the client, disconnecting from the server and stopping the reactor thread.
    pub fn terminate(self) -> Result<(), Box<dyn Any + Send>> {
        self.reactor
            .controller()
            .cmd(ClientCommand::Terminate)
            .map_err(|err| Box::new(err) as Box<dyn Any + Send>)?;
        self.join()
    }

    pub fn join(self) -> Result<(), Box<dyn Any + Send>> { self.reactor.join() }

    pub fn send(&self, req: R) -> io::Result<()> {
        self.reactor.controller().cmd(ClientCommand::Send(req))
    }
}
