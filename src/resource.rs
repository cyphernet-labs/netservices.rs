// Library for building scalable privacy-preserving microservices P2P nodes
//
// SPDX-License-Identifier: Apache-2.0
//
// Written in 2022-2024 by
//     Dr. Maxim Orlovsky <orlovsky@cyphernet.org>
//
// Copyright 2022-2024 Cyphernet Labs, IDCS, Switzerland
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

//! The module provides adaptors for networking sessions (see [`NetSession`]
//! trait) to become a [`reactor`]-managed [`Resource`]es, which can be polled
//! for I/O events in a non-blocking but synchronous mode in a dedicated reactor
//! thread.
//!
//! The module  allows to solve [C10k] problem with multiple connections by
//! utilizing non-blocking `poll` sys-calls. It uses the same principle as
//! async runtimes (`tokio` and others), but provides much simpler API and can
//! run without heap of dependencies introduced by async runtimes.
//!
//! [C10k]: https://en.wikipedia.org/wiki/C10k_problem

use std::collections::VecDeque;
use std::fmt::{Debug, Display, Formatter};
use std::io::Write;
use std::marker::PhantomData;
use std::net::{TcpListener, ToSocketAddrs};
use std::os::unix::io::{AsRawFd, RawFd};
use std::time::Duration;
use std::{fmt, io, net};

use reactor::poller::IoType;
use reactor::{Io, Resource, WriteAtomic, WriteError};

use crate::{Direction, NetConnection, NetListener, NetSession, READ_BUFFER_SIZE};

// TODO: Make these parameters configurable
/// Socket read buffer size.
const HEAP_BUFFER_SIZE: usize = u16::MAX as usize;
/// Maximum time to wait when reading from a socket.
const READ_TIMEOUT: Duration = Duration::from_secs(6);
/// Maximum time to wait when writing to a socket.
const WRITE_TIMEOUT: Duration = Duration::from_secs(3);

pub enum ImpossibleResource {}

impl AsRawFd for ImpossibleResource {
    fn as_raw_fd(&self) -> RawFd { unreachable!("non-instantiable enum") }
}

impl Write for ImpossibleResource {
    fn write(&mut self, _: &[u8]) -> io::Result<usize> { unreachable!("non-instantiable enum") }

    fn flush(&mut self) -> io::Result<()> { unreachable!("non-instantiable enum") }
}

impl WriteAtomic for ImpossibleResource {
    fn is_ready_to_write(&self) -> bool { unreachable!("non-instantiable enum") }

    fn empty_write_buf(&mut self) -> io::Result<bool> { unreachable!("non-instantiable enum") }

    fn write_or_buf(&mut self, _: &[u8]) -> io::Result<()> { unreachable!("non-instantiable enum") }
}

impl Resource for ImpossibleResource {
    type Event = ();

    fn interests(&self) -> IoType { unreachable!("non-instantiable enum") }

    fn handle_io(&mut self, _: Io) -> Option<Self::Event> { unreachable!("non-instantiable enum") }
}

/// An event happening for a [`NetAccept`] network listener and delivered to a
/// [`reactor::Handler`].
#[derive(Debug)]
pub enum ListenerEvent<S: NetSession> {
    /// A new incoming connection was accepted.
    ///
    /// The connection is already upgraded to a [`NetSession`], however no I/O
    /// events was read or wrote for it yet.
    Accepted(S::Connection),

    /// Listener `accept` call has resulted in a I/O error from the OS.
    Failure(io::Error),
}

/// A reactor-manageable network listener (TCP, but not limiting to) which can
/// be aware of additional encryption, authentication and other forms of
/// transport-layer protocols which will be automatically injected into accepted
/// connections.
#[derive(Debug)]
pub struct NetAccept<S: NetSession, L: NetListener<Stream = S::Connection> = TcpListener> {
    /// The `session_context` object provides information for encryption,
    /// authentication and other protocols which are a part of the application-
    /// specific transport layer and are automatically injected into the
    /// new sessions constructed by this listener before they are inserted into
    /// the [`reactor`] and notifications are delivered to [`reactor::Handler`].
    listener: L,
    _phantom: PhantomData<S>,
}

impl<L: NetListener<Stream = S::Connection>, S: NetSession> AsRawFd for NetAccept<S, L> {
    fn as_raw_fd(&self) -> RawFd { self.listener.as_raw_fd() }
}

impl<L: NetListener<Stream = S::Connection>, S: NetSession> io::Write for NetAccept<S, L> {
    fn write(&mut self, _buf: &[u8]) -> io::Result<usize> {
        Err(io::ErrorKind::InvalidInput.into())
    }

    fn flush(&mut self) -> io::Result<()> { Err(io::ErrorKind::InvalidInput.into()) }
}

impl<L: NetListener<Stream = S::Connection>, S: NetSession> WriteAtomic for NetAccept<S, L> {
    fn is_ready_to_write(&self) -> bool { false }

    fn empty_write_buf(&mut self) -> io::Result<bool> { Ok(true) }

    fn write_or_buf(&mut self, _: &[u8]) -> io::Result<()> {
        Err(io::ErrorKind::InvalidInput.into())
    }
}

impl<L: NetListener<Stream = S::Connection>, S: NetSession> NetAccept<S, L> {
    /// Binds listener to the provided socket address(es) with a given context.
    ///
    /// The `session_context` object provides information for encryption,
    /// authentication and other protocols which are a part of the application-
    /// specific transport layer and are automatically injected into the
    /// new sessions constructed by this listener before they are inserted into
    /// the [`reactor`] and notifications are delivered to [`reactor::Handler`].
    pub fn bind(addr: &impl ToSocketAddrs) -> io::Result<Self> {
        let listener = L::bind(addr)?;
        listener.set_nonblocking(true)?;
        Ok(Self {
            listener,
            _phantom: default!(),
        })
    }

    /// Binds listener to the provided socket address(es) with a given context. Same as
    /// [`NetAccept::bind`] except that it uses `SO_REUSEADDR`/`SO_REUSEPORT` to enable more
    /// sockets to bound to the same address.
    #[cfg(feature = "nonblocking")]
    pub fn bind_reusable(addr: &impl ToSocketAddrs) -> io::Result<Self> {
        let listener = L::bind_reusable(addr)?;
        listener.set_nonblocking(true)?;
        Ok(Self {
            listener,
            _phantom: default!(),
        })
    }

    /// Returns the local [`net::SocketAddr`] on which listener accepts
    /// connections.
    pub fn local_addr(&self) -> net::SocketAddr { self.listener.local_addr() }

    fn handle_accept(&mut self) -> io::Result<S::Connection> {
        let mut connection = self.listener.accept()?;
        connection.set_read_timeout(Some(READ_TIMEOUT))?;
        connection.set_write_timeout(Some(WRITE_TIMEOUT))?;
        connection.set_nonblocking(true)?;
        Ok(connection)
    }
}

impl<L: NetListener<Stream = S::Connection>, S: NetSession> Resource for NetAccept<S, L>
where S: Send
{
    type Event = ListenerEvent<S>;

    fn interests(&self) -> IoType { IoType::read_only() }

    fn handle_io(&mut self, io: Io) -> Option<Self::Event> {
        match io {
            Io::Read => Some(match self.handle_accept() {
                Err(err) => ListenerEvent::Failure(err),
                Ok(session) => ListenerEvent::Accepted(session),
            }),
            Io::Write => None,
        }
    }
}

/// An event happening for a [`NetTransport`] network transport and delivered to
/// a [`reactor::Handler`].
pub enum SessionEvent<S: NetSession> {
    Established(S::Artifact),
    Data(Vec<u8>),
    Terminated(io::Error),
}

/// A state of [`NetTransport`] network transport.
#[derive(Clone, Copy, Ord, PartialOrd, Eq, PartialEq, Hash, Debug)]
pub enum TransportState {
    /// The transport is initiated, but the connection has not established yet.
    /// This happens only for outgoing connections due to the use of
    /// non-blocking version of a `connect` sys-call. The state is switched once
    /// we receive first notification on a `write` event on this resource from
    /// the reactor `poll`.
    Init,

    /// The connection is established, but the session handshake is still in
    /// progress. This happens while encryption handshake, authentication and
    /// other protocols injected into the session haven't completed yet.
    Handshake,

    /// The session is active; all handshakes had completed.
    Active,

    /// Session was terminated by any reason: local shutdown, remote orderly
    /// shutdown, connectivity issue, dropped connections, encryption or
    /// authentication problem etc. Reading and writing from the resource in
    /// this state will result in an error ([`io::Error`]).
    Terminated,
}

/// Net transport is an adaptor around specific [`NetSession`] (implementing
/// session management, including optional handshake, encoding etc) to be used
/// as a transport resource in a [`reactor::Reactor`].
#[derive(Debug)]
pub struct NetTransport<S: NetSession> {
    state: TransportState,
    session: S,
    link_direction: Direction,
    write_intent: bool,
    read_buffer: Box<[u8; HEAP_BUFFER_SIZE]>,
    write_buffer: VecDeque<u8>,
}

impl<S: NetSession> Display for NetTransport<S> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self.session.artifact() {
            None => write!(f, "{}", self.as_raw_fd()),
            Some(id) => Display::fmt(&id, f),
        }
    }
}

impl<S: NetSession> AsRawFd for NetTransport<S> {
    fn as_raw_fd(&self) -> RawFd { self.session.as_connection().as_raw_fd() }
}

impl<S: NetSession> NetTransport<S> {
    pub fn accept(session: S) -> io::Result<Self> {
        Self::with_state(session, TransportState::Handshake, Direction::Inbound)
    }

    /// Constructs reactor-managed resource around an existing [`NetSession`].
    ///
    /// NB: Must not be called for connections created in a non-blocking mode!
    ///
    /// # Errors
    ///
    /// If a session can be put into a non-blocking mode.
    pub fn with_session(mut session: S, link_direction: Direction) -> io::Result<Self> {
        let state = if session.is_established() {
            // If we are disconnected, we will get instantly updated from the
            // reactor and the state will change automatically
            TransportState::Active
        } else {
            TransportState::Handshake
        };
        session.as_connection_mut().set_nonblocking(true)?;
        Ok(Self {
            state,
            session,
            link_direction,
            write_intent: true,
            read_buffer: Box::new([0u8; READ_BUFFER_SIZE]),
            write_buffer: empty!(),
        })
    }

    /// Tries to unwrap the underlying [`NetSession`] object.
    ///
    /// Attempts to empty data buffered for a write operation in a non-blocking
    /// way. If the non-blocking emptying is not possible errors with
    /// [`io::ErrorKind::WouldBlock`] kind of [`io::Error`].
    ///
    /// # Errors
    ///
    /// Returns the consumed `self` as a part of an error.
    ///
    /// If the write buffer can't be emptied in a non-blocking way errors with
    /// [`io::ErrorKind::WouldBlock`] kind of [`io::Error`].
    ///
    /// If the connection is failed and the write buffer has some data, errors
    /// with the connection failure code.
    pub fn into_session(mut self) -> Result<S, (Self, io::Error)> {
        if let Err(err) = self.empty_write_buf() {
            return Err((self, err));
        }
        Ok(self.session)
    }

    fn with_state(
        mut session: S,
        state: TransportState,
        link_direction: Direction,
    ) -> io::Result<Self> {
        session.as_connection_mut().set_read_timeout(Some(READ_TIMEOUT))?;
        session.as_connection_mut().set_write_timeout(Some(WRITE_TIMEOUT))?;
        Ok(Self {
            state,
            session,
            link_direction,
            write_intent: false,
            read_buffer: Box::new([0u8; READ_BUFFER_SIZE]),
            write_buffer: empty!(),
        })
    }

    pub fn display(&self) -> impl Display { self.session.display() }

    pub fn state(&self) -> TransportState { self.state }
    pub fn is_active(&self) -> bool { self.state == TransportState::Active }

    pub fn is_inbound(&self) -> bool { self.link_direction() == Direction::Inbound }
    pub fn is_outbound(&self) -> bool { self.link_direction() == Direction::Outbound }
    pub fn link_direction(&self) -> Direction { self.link_direction }

    pub fn local_addr(&self) -> io::Result<<S::Connection as NetConnection>::Addr> {
        self.session.as_connection().local_addr()
    }

    pub fn artifact(&self) -> Option<S::Artifact> { self.session.artifact() }

    pub fn expect_peer_id(&self) -> S::Artifact {
        self.session.artifact().expect("session is expected to be established at this stage")
    }

    pub fn write_buf_len(&self) -> usize { self.write_buffer.len() }

    fn terminate(&mut self, reason: io::Error) -> SessionEvent<S> {
        #[cfg(feature = "log")]
        log::trace!(target: "transport", "Terminating session {self} due to {reason:?}");

        self.state = TransportState::Terminated;
        SessionEvent::Terminated(reason)
    }

    fn handle_writable(&mut self) -> Option<SessionEvent<S>> {
        if !self.session.is_established() {
            let _ = self.session.write(&[]);
            self.write_intent = true;
            return None;
        }
        match self.flush() {
            Ok(_) => None,
            // In this case, the write couldn't complete. Leave `needs_flush` set
            // to be notified when the socket is ready to write again.
            Err(err)
                if [
                    io::ErrorKind::WouldBlock,
                    io::ErrorKind::WriteZero,
                    io::ErrorKind::OutOfMemory,
                    io::ErrorKind::Interrupted,
                ]
                .contains(&err.kind()) =>
            {
                #[cfg(feature = "log")]
                log::warn!(target: "transport", "Resource {} was not able to consume any data even though it has announced its write readiness", self.display());
                self.write_intent = true;
                None
            }
            Err(err) => Some(self.terminate(err)),
        }
    }

    fn handle_readable(&mut self) -> Option<SessionEvent<S>> {
        // Nb. Since `poll`, which this reactor is based on, is *level-triggered*,
        // we will be notified again if there is still data to be read on the socket.
        // Hence, there is no use in putting this socket read in a loop, as the second
        // invocation would likely block.
        match self.session.read(self.read_buffer.as_mut()) {
            Ok(0) if !self.session.is_established() => None,
            Ok(0) => Some(SessionEvent::Terminated(io::ErrorKind::ConnectionReset.into())),
            Ok(len) => Some(SessionEvent::Data(self.read_buffer[..len].to_vec())),
            Err(err) if err.kind() == io::ErrorKind::WouldBlock => {
                // This shouldn't normally happen, since this function is only called
                // when there's data on the socket. We leave it here in case external
                // conditions change.
                #[cfg(feature = "log")]
                log::warn!(target: "transport",
                    "WOULD_BLOCK on resource which had read intent - probably normal thing to happen"
                );
                None
            }
            Err(err) => Some(self.terminate(err)),
        }
    }

    fn flush_buffer(&mut self) -> io::Result<()> {
        let orig_len = self.write_buffer.len();
        #[cfg(feature = "log")]
        log::trace!(target: "transport", "Resource {} is flushing its buffer of {orig_len} bytes", self.display());
        let len =
            self.session.write(self.write_buffer.make_contiguous()).or_else(|err| {
                match err.kind() {
                    io::ErrorKind::WouldBlock
                    | io::ErrorKind::OutOfMemory
                    | io::ErrorKind::WriteZero
                    | io::ErrorKind::Interrupted => {
                        #[cfg(feature = "log")]
                        log::warn!(target: "transport", "Resource {} kernel buffer is fulled (system message is '{err}')", self.display());
                        Ok(0)
                    },
                    _ => {
                        #[cfg(feature = "log")]
                        log::error!(target: "transport", "Resource {} failed write operation with message '{err}'", self.display());
                        Err(err)
                    },
                }
            })?;
        if orig_len > len {
            #[cfg(feature = "log")]
            log::debug!(target: "transport", "Resource {} was able to consume only a part of the buffered data ({len} of {orig_len} bytes)", self.display());
            self.write_intent = true;
        } else {
            #[cfg(feature = "log")]
            log::trace!(target: "transport", "Resource {} was able to consume all of the buffered data ({len} of {orig_len} bytes)", self.display());
            self.write_intent = false;
        }
        self.write_buffer.drain(..len);
        Ok(())
    }
}

impl<S: NetSession> Resource for NetTransport<S> {
    type Event = SessionEvent<S>;

    fn interests(&self) -> IoType {
        match self.state {
            TransportState::Init => IoType::write_only(),
            TransportState::Terminated => IoType::none(),
            TransportState::Active | TransportState::Handshake if self.write_intent => {
                IoType::read_write()
            }
            TransportState::Active | TransportState::Handshake => IoType::read_only(),
        }
    }

    fn handle_io(&mut self, io: Io) -> Option<Self::Event> {
        debug_assert_ne!(self.state, TransportState::Terminated, "I/O on terminated transport");

        let mut force_write_intent = false;
        if self.state == TransportState::Init {
            #[cfg(feature = "log")]
            log::debug!(target: "transport", "Transport {self} is connected, initializing handshake");

            force_write_intent = true;
            self.state = TransportState::Handshake;
        } else if self.state == TransportState::Handshake {
            debug_assert!(!self.session.is_established());
            #[cfg(feature = "log")]
            log::trace!(target: "transport", "Transport {self} got I/O while in handshake mode");
        }

        let resp = match io {
            Io::Read => self.handle_readable(),
            Io::Write => self.handle_writable(),
        };

        if force_write_intent {
            self.write_intent = true;
        } else if self.state == TransportState::Handshake {
            // During handshake, after each read we need to write and then wait
            self.write_intent = io == Io::Read;
        }

        if matches!(&resp, Some(SessionEvent::Terminated(e)) if e.kind() == io::ErrorKind::ConnectionReset)
            && self.state != TransportState::Handshake
        {
            #[cfg(feature = "log")]
            log::debug!(target: "transport", "Peer {self} has reset the connection");

            self.state = TransportState::Terminated;
            resp
        } else if self.session.is_established() && self.state == TransportState::Handshake {
            #[cfg(feature = "log")]
            log::debug!(target: "transport", "Handshake with {self} is complete");

            // We just got connected; may need to send output
            self.write_intent = true;
            self.state = TransportState::Active;
            Some(SessionEvent::Established(
                self.session.artifact().expect("session is established"),
            ))
        } else {
            resp
        }
    }
}

impl<S: NetSession> Write for NetTransport<S> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self.write_atomic(buf) {
            Ok(_) => Ok(buf.len()),
            Err(WriteError::NotReady) => Err(io::ErrorKind::NotConnected.into()),
            Err(WriteError::Io(err)) => Err(err),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        let res = self.flush_buffer();
        self.session.flush().and(res)
    }
}

impl<S: NetSession> WriteAtomic for NetTransport<S> {
    fn is_ready_to_write(&self) -> bool { self.state == TransportState::Active }

    fn empty_write_buf(&mut self) -> io::Result<bool> {
        let len = self.session.write(self.write_buffer.make_contiguous())?;
        self.write_buffer.drain(..len);
        if self.write_buf_len() > 0 {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        Ok(len > 0)
    }

    fn write_or_buf(&mut self, buf: &[u8]) -> io::Result<()> {
        if buf.is_empty() {
            // Write empty data is a non-op
            return Ok(());
        }
        self.write_buffer.extend(buf);
        self.flush_buffer()
    }
}
