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

use std::collections::VecDeque;
use std::io::{Read, Write};
use std::os::unix::io::AsRawFd;
use std::time::Duration;
use std::{io, net};

use reactor::poller::{IoFail, IoType, Poll};

use crate::{NetConnection, NetSession, READ_BUFFER_SIZE};

const NAME: &str = "tunnel";

pub struct Tunnel<S: NetSession> {
    listener: net::TcpListener,
    session: S,
}

impl<S: NetSession> Tunnel<S> {
    pub fn with(session: S, addr: impl net::ToSocketAddrs) -> Result<Self, (S, io::Error)> {
        let listener = match net::TcpListener::bind(addr) {
            Err(err) => return Err((session, err)),
            Ok(listener) => listener,
        };
        Ok(Self { listener, session })
    }

    pub fn local_addr(&self) -> io::Result<net::SocketAddr> { self.listener.local_addr() }

    /// # Returns
    ///
    /// Number of bytes which passed through the tunnel
    #[allow(unused_variables)]
    pub fn tunnel_once<P: Poll>(
        &mut self,
        mut poller: P,
        timeout: Duration,
    ) -> io::Result<(usize, usize)> {
        let listener_addr = self.listener.local_addr().expect("listener always has local addr");
        #[cfg(feature = "log")]
        log::info!(target: NAME, "Tunnel accepting a single connection will run on {listener_addr}");

        let (mut stream, socket_addr) = self.listener.accept()?;
        #[cfg(feature = "log")]
        log::debug!(target: NAME, "Incoming connection from {socket_addr} for tunnel {listener_addr}");

        stream.set_nonblocking(true)?;
        stream.set_read_timeout(Some(timeout))?;
        stream.set_write_timeout(Some(timeout))?;

        let conn = self.session.as_connection_mut();
        conn.set_nonblocking(true)?;
        conn.set_read_timeout(Some(timeout))?;
        conn.set_write_timeout(Some(timeout))?;

        let int_fd = stream.as_raw_fd();
        let ext_fd = self.session.as_connection().as_raw_fd();
        let int_id = poller.register(&int_fd, IoType::read_only());
        let ext_id = poller.register(&ext_fd, IoType::read_only());

        let mut in_buf = VecDeque::<u8>::new();
        let mut out_buf = VecDeque::<u8>::new();

        let mut in_count = 0usize;
        let mut out_count = 0usize;

        let mut buf = [0u8; READ_BUFFER_SIZE];

        macro_rules! handle {
            ($call:expr, |$var:ident| $expr:expr) => {
                match $call {
                    Ok(0) => {
                        #[cfg(feature = "log")]
                        log::info!(target: NAME,
                            "Tunnel {socket_addr} has completed its work. Total {in_count} bytes are received and {out_count} sent"
                        );
                        return Ok((in_count, out_count))
                    },
                    Ok($var) => $expr,
                    Err(err) => {
                        #[cfg(feature = "log")]
                        log::error!(target: NAME,
                            "Tunnel {socket_addr} has terminated with '{err}'"
                        );
                        return Err(err)
                    },
                }
            };
        }

        #[cfg(feature = "log")]
        log::info!(target: NAME, "Tunnel on {listener_addr} is operational for a client {socket_addr}");
        loop {
            // Blocking
            let count = poller.poll(Some(timeout))?;
            if count == 0 {
                #[cfg(feature = "log")]
                log::warn!(target: NAME, "Tunnel {listener_addr} timed out with client {socket_addr}");
                return Err(io::ErrorKind::TimedOut.into());
            }
            while let Some((id, res)) = poller.next() {
                let ev = match res {
                    Ok(ev) => ev,
                    Err(IoFail::Connectivity(code)) => {
                        #[cfg(feature = "log")]
                        log::info!(target: NAME, "Tunnel {socket_addr} has completed its work with the code {code:#b}");
                        return Ok((in_count, out_count));
                    }
                    Err(IoFail::Os(code)) => {
                        #[cfg(feature = "log")]
                        log::error!(target: NAME, "Tunnel {socket_addr} was terminated with the code {code:#b}");
                        return Err(io::ErrorKind::BrokenPipe.into());
                    }
                };
                if id == int_id {
                    if ev.write {
                        #[cfg(feature = "log")]
                        log::trace!(target: NAME, "attempting to write {} bytes received from the remote {socket_addr}", in_buf.len());

                        handle!(stream.write(in_buf.make_contiguous()), |written| {
                            stream.flush()?;
                            in_buf.drain(..written);
                            in_count += written;
                            if in_buf.is_empty() {
                                poller.set_interest(int_id, IoType::read_only());
                            }
                            #[cfg(feature = "log")]
                            log::trace!(target: NAME, "{socket_addr} received {written} bytes from local out of {} buffered", in_buf.len());
                        });
                    }
                    if ev.read {
                        #[cfg(feature = "log")]
                        log::trace!(target: NAME, "attempting to read from the {socket_addr}");

                        handle!(stream.read(&mut buf), |read| {
                            out_buf.extend(&buf[..read]);
                            poller.set_interest(ext_id, IoType::read_write());
                            #[cfg(feature = "log")]
                            log::trace!(target: NAME, "{socket_addr} read {read} bytes from local ({} total in the buffer)", out_buf.len());
                        });
                    }
                } else if id == ext_id {
                    if ev.write {
                        #[cfg(feature = "log")]
                        log::trace!(target: NAME, "attempting to write {} bytes received from {socket_addr} to remote", out_buf.len());

                        handle!(self.session.write(out_buf.make_contiguous()), |written| {
                            self.session.flush()?;
                            out_buf.drain(..written);
                            out_count += written;
                            if out_buf.is_empty() {
                                poller.set_interest(ext_id, IoType::read_only());
                            }
                            #[cfg(feature = "log")]
                            log::trace!(target: NAME, "{socket_addr} sent {written} bytes to remote out of {} buffered", out_buf.len());
                        });
                    }
                    if ev.read {
                        #[cfg(feature = "log")]
                        log::trace!(target: NAME, "attempting to read from the remote");

                        handle!(self.session.read(&mut buf), |read| {
                            in_buf.extend(&buf[..read]);
                            poller.set_interest(int_id, IoType::read_write());
                            #[cfg(feature = "log")]
                            log::trace!(target: NAME, "{socket_addr} read {read} bytes from remote ({} total in the buffer)", in_buf.len());
                        });
                    }
                }
            }
        }
    }

    pub fn into_session(self) -> S { self.session }
}
