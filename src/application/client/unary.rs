// Library for building scalable privacy-preserving microservices P2P nodes
//
// SPDX-License-Identifier: Apache-2.0
//
// Written in 2022-2026 by
//     Dr. Maxim Orlovsky <orlovsky@cyphernet.io>
//
// Copyright 2022-2026 Cyphernet Labs, InDCS, Switzerland
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

use std::collections::{HashMap, VecDeque};
use std::fmt::{self, Debug};
use std::os::fd::{AsRawFd, RawFd};
use std::sync::mpsc;
use std::sync::mpsc::{Receiver, Sender};
use std::thread::JoinHandle;
use std::{io, thread};

use amplify::CursorDeque;
use reactor::poller::popol;
use reactor::poller::popol::PopolWaker;
use reactor::{Action, Error, Reactor, Resource, ResourceId, ResourceType, Timestamp};

use crate::frame::{PendingRequest, Request};
use crate::{Direction, Frame, ImpossibleResource, NetSession, NetTransport, SessionEvent};

#[cfg(feature = "log")]
const NAME: &str = "client-onetime";

enum Cmd<S: NetSession, Rq: Request> {
    Send(NetTransport<S>, PendingRequest<Rq>),
    Terminate,
}

impl<S: NetSession, Rq: Request> Debug for Cmd<S, Rq> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Cmd::Send(_, pending) => f
                .debug_struct("Cmd::Send")
                .field("awaits_reply", &pending.awaits_reply)
                .finish(),
            Cmd::Terminate => f.write_str("Cmd::Terminate"),
        }
    }
}

struct Inbox<Rq: Request> {
    buf: VecDeque<u8>,
    request: Rq,
}

struct Service<S: NetSession, Rq: Request> {
    inboxes: HashMap<ResourceId, Inbox<Rq>>,
    iface: Sender<(Rq, Rq::Response)>,
    send_queue: HashMap<RawFd, PendingRequest<Rq>>,
    action_queue: VecDeque<Action<ImpossibleResource, NetTransport<S>>>,
}

impl<S: NetSession, Rq: Request> Service<S, Rq> {
    fn new(iface: Sender<(Rq, Rq::Response)>) -> Self {
        Self {
            inboxes: HashMap::new(),
            iface,
            send_queue: HashMap::new(),
            action_queue: VecDeque::new(),
        }
    }

    /// Adds terminate action to the action queue, such that on the next reactor event loop run,
    /// it will receive it and close the connection to the server.
    fn terminate(&mut self) {
        #[cfg(feature = "log")]
        log::info!(target: NAME, "Scheduling to terminate the reactor and client service");

        self.action_queue.push_back(Action::Terminate);
    }
}

impl<S: NetSession, Rq: Request> reactor::Handler for Service<S, Rq> {
    type Listener = ImpossibleResource;
    type Transport = NetTransport<S>;
    type Command = Cmd<S, Rq>;

    fn tick(&mut self, time: Timestamp) {
        #[cfg(feature = "log")]
        log::trace!(target: NAME, "reactor tick at {time}");
    }

    fn handle_timer(&mut self) {
        #[cfg(feature = "log")]
        log::trace!(target: NAME, "reactor timer event");
    }

    fn handle_listener_event(
        &mut self,
        _: RawFd,
        _: ResourceId,
        _: <Self::Listener as Resource>::Event,
        _: Timestamp,
    ) {
        unreachable!("there is no listener in client")
    }

    fn handle_transport_event(
        &mut self,
        fd: RawFd,
        id: ResourceId,
        event: <Self::Transport as Resource>::Event,
        time: Timestamp,
    ) {
        match event {
            SessionEvent::Established(_) => {}
            SessionEvent::Data(data) => {
                let Some(mut inbox) = self.inboxes.remove(&id) else {
                    #[cfg(feature = "log")]
                    log::warn!(target: NAME, "unexpected reply from the server at {time}");

                    return;
                };

                inbox.buf.extend(data);
                let mut cursor = CursorDeque::new(&mut inbox.buf);
                match Rq::Response::unmarshall(&mut cursor) {
                    Ok(Some(response)) => {
                        if !cursor.is_empty() {
                            #[cfg(feature = "log")]
                            log::error!(target: NAME, "received multiple frames from the server at {time}, ignoring all except the first one");
                        } else {
                            #[cfg(feature = "log")]
                            log::trace!(target: NAME, "received reply from the server at {time}");
                        }
                        self.action_queue.push_back(Action::UnregisterTransport(id));
                        self.iface
                            .send((inbox.request, response))
                            .expect("failed to send reply to callback");
                    }
                    Ok(None) => {
                        #[cfg(feature = "log")]
                        log::trace!(target: NAME, "received partial reply data from the server at {time}");
                    }
                    Err(err) => {
                        #[cfg(feature = "log")]
                        log::error!(target: NAME, "unparsable reply from the server at {time}: {}", err);

                        self.action_queue.push_back(Action::UnregisterTransport(id));
                    }
                }
            }
            SessionEvent::Terminated(err) => {
                if self.inboxes.contains_key(&id) {
                    #[cfg(feature = "log")]
                    log::error!(target: NAME, "server connection terminated unexpectedly while waiting for reply (code {err})");
                } else {
                    #[cfg(feature = "log")]
                    log::trace!(target: NAME, "completed connection id={id}, fd={fd} (code {err})");
                }
            }
        }
    }

    fn handle_registered(&mut self, fd: RawFd, id: ResourceId, ty: ResourceType) {
        #[cfg(feature = "log")]
        log::trace!(target: NAME, "registered new transport id={id}, fd={fd}");

        debug_assert_eq!(ty, ResourceType::Transport);

        let Some(pending) = self.send_queue.remove(&fd) else {
            panic!("Unexpected registration of a new transport id={id}, fd={fd}");
        };
        let bytes = pending.request.serialize();
        self.action_queue.push_back(Action::Send(id, bytes));
        if pending.awaits_reply {
            self.inboxes
                .insert(id, Inbox { buf: VecDeque::new(), request: pending.request });
        }
    }

    fn handle_command(&mut self, cmd: Self::Command) {
        match cmd {
            Cmd::Send(transport, pending) => {
                self.send_queue.insert(transport.as_raw_fd(), pending);
                self.action_queue
                    .push_back(Action::RegisterTransport(transport));
            }
            Cmd::Terminate => self.terminate(),
        }
    }

    fn handle_error(&mut self, err: Error<Self::Listener, Self::Transport>) {
        #[cfg(feature = "log")]
        log::error!(target: NAME, "I/O error in server connection: {err}");
    }

    fn handover_listener(&mut self, _: ResourceId, _: Self::Listener) {
        unreachable!("there is no listener in client")
    }

    fn handover_transport(&mut self, id: ResourceId, transport: Self::Transport) {
        let Ok(session) = transport.into_session() else {
            panic!("handing over transport with non-empty output buffer (id={id})");
        };
        if let Err(err) = session.disconnect() {
            #[cfg(feature = "log")]
            log::error!(target: NAME, "failed to disconnect from the server for id={id}: {err}");
        }
    }
}

impl<S: NetSession, Rq: Request> Iterator for Service<S, Rq> {
    type Item = Action<ImpossibleResource, NetTransport<S>>;

    fn next(&mut self) -> Option<Self::Item> { self.action_queue.pop_front() }
}

pub trait SessionFactory: Send + 'static {
    type Session: NetSession + 'static;

    fn connect(&self) -> Option<Self::Session>;
}

enum FactoryCmd<Rq: Request> {
    Request(PendingRequest<Rq>),
    Terminate,
}

struct Factory<C: SessionFactory, Rq: Request> {
    connector: C,
    receiver: Receiver<FactoryCmd<Rq>>,
    reactor: reactor::Controller<Cmd<C::Session, Rq>, PopolWaker>,
}

impl<C: SessionFactory, Rq: Request + 'static> Factory<C, Rq> {
    fn new(
        connector: C,
        receiver: Receiver<FactoryCmd<Rq>>,
        reactor: reactor::Controller<Cmd<C::Session, Rq>, PopolWaker>,
    ) -> Self {
        Self { connector, receiver, reactor }
    }

    // TODO: Do the thread

    fn run(self) -> JoinHandle<()> {
        thread::Builder::new()
            .name(s!("connection factory"))
            .spawn(|| self.run_internal())
            .expect("failed to spawn unified client thread")
    }

    fn run_internal(self) {
        while let Ok(cmd) = self.receiver.recv() {
            match cmd {
                FactoryCmd::Request(pending) => {
                    self.process_request(pending);
                }
                FactoryCmd::Terminate => {
                    #[cfg(feature = "log")]
                    log::info!(target: NAME, "terminating connection factory");

                    self.reactor
                        .cmd(Cmd::Terminate)
                        .expect("failed to terminate reactor");
                }
            }
        }
    }

    fn process_request(&self, pending: PendingRequest<Rq>) {
        let Some(session) = self.connector.connect() else {
            #[cfg(feature = "log")]
            log::error!(target: NAME, "failed to connect to server");
            return;
        };
        let Ok(transport) =
            NetTransport::with_session(session, Direction::Outbound).inspect_err(|err| {
                #[cfg(feature = "log")]
                log::error!(target: NAME, "error establishing session: {err}");
            })
        else {
            // TODO: Ensure this works
            return;
        };

        #[cfg(feature = "log")]
        log::info!(target: NAME, "server connections successfully established, scheduling registering the transport {} with the reactor", transport.display());

        if let Err(err) = self.reactor.cmd(Cmd::Send(transport, pending)) {
            #[cfg(feature = "log")]
            log::error!(target: NAME, "failed to send request to the server: {err}");
        }
    }
}

pub struct UnaryClient<C: SessionFactory, Rq: Request> {
    factory: JoinHandle<()>,
    sender: Sender<FactoryCmd<Rq>>,
    reactor: Reactor<Cmd<C::Session, Rq>, popol::Poller>,
}

impl<C: SessionFactory, Rq: Request> UnaryClient<C, Rq> {
    pub fn new(session_factory: C, iface: Sender<(Rq, Rq::Response)>) -> io::Result<Self>
    where Rq: 'static {
        let service = Service::new(iface);
        let reactor = Reactor::named(service, popol::Poller::new(), s!("client"))?;
        let controller = reactor.controller();
        let (sender, receiver) = mpsc::channel();
        let factory = Factory::new(session_factory, receiver, controller);
        let factory = factory.run();
        Ok(Self { factory, sender, reactor })
    }

    pub fn send_only(&self, request: Rq) {
        self.sender
            .send(FactoryCmd::Request(PendingRequest { request, awaits_reply: false }))
            .expect("failed to send request to server");
    }

    pub fn send_receive(&self, request: Rq) {
        self.sender
            .send(FactoryCmd::Request(PendingRequest { request, awaits_reply: true }))
            .expect("failed to send request to server");
    }

    pub fn join(self) -> thread::Result<()> {
        self.reactor.join()?;
        self.factory.join()?;
        Ok(())
    }

    pub fn terminate(self) {
        self.sender
            .send(FactoryCmd::Terminate)
            .expect("failed to terminate client session");
    }
}
