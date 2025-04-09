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

use std::io;
use std::net::{SocketAddr, TcpListener, TcpStream, ToSocketAddrs};
use std::os::unix::io::AsRawFd;

use crate::connection::NetConnection;

pub trait NetListener: AsRawFd + Send {
    type Stream: NetConnection;

    fn bind(addr: &impl ToSocketAddrs) -> io::Result<Self>
    where Self: Sized;

    #[cfg(feature = "nonblocking")]
    fn bind_reusable(addr: &impl ToSocketAddrs) -> io::Result<Self>
    where Self: Sized;

    fn accept(&self) -> io::Result<Self::Stream>;

    fn local_addr(&self) -> SocketAddr;

    fn ttl(&self) -> io::Result<u32>;
    fn set_ttl(&self, ttl: u32) -> io::Result<()>;

    fn set_nonblocking(&self, nonblocking: bool) -> io::Result<()>;

    fn try_clone(&self) -> io::Result<Self>
    where Self: Sized;
    fn take_error(&self) -> io::Result<Option<io::Error>>;
}

impl NetListener for TcpListener {
    type Stream = TcpStream;

    fn bind(addr: &impl ToSocketAddrs) -> io::Result<Self>
    where Self: Sized {
        TcpListener::bind(addr)
    }

    #[cfg(feature = "nonblocking")]
    fn bind_reusable(addr: &impl ToSocketAddrs) -> io::Result<Self>
    where Self: Sized {
        // This is the default used by std::net::TcpListener at the time of writing. Unfortunately
        // the standard library doesn't export this value so we have to hard-code it here.
        const BACKLOG: i32 = 128;

        let socket = socket2::Socket::bind_reusable(addr)?;
        socket.listen(BACKLOG)?;
        Ok(TcpListener::from(socket))
    }

    fn accept(&self) -> io::Result<Self::Stream> { Ok(TcpListener::accept(self)?.0) }

    fn local_addr(&self) -> SocketAddr {
        TcpListener::local_addr(self).expect("TCP listener doesn't have local address")
    }

    fn ttl(&self) -> io::Result<u32> { TcpListener::ttl(self) }

    fn set_ttl(&self, ttl: u32) -> io::Result<()> { TcpListener::set_ttl(self, ttl) }

    fn set_nonblocking(&self, nonblocking: bool) -> io::Result<()> {
        TcpListener::set_nonblocking(self, nonblocking)
    }

    fn try_clone(&self) -> io::Result<Self>
    where Self: Sized {
        TcpListener::try_clone(self)
    }

    fn take_error(&self) -> io::Result<Option<io::Error>> { TcpListener::take_error(self) }
}

#[cfg(feature = "nonblocking")]
impl NetListener for socket2::Socket {
    type Stream = socket2::Socket;

    fn bind(addr: &impl ToSocketAddrs) -> io::Result<Self>
    where Self: Sized {
        let addr = addr.to_socket_addrs()?.next().ok_or(io::ErrorKind::InvalidInput)?;
        let socket =
            socket2::Socket::new(socket2::Domain::for_address(addr), socket2::Type::STREAM, None)?;
        socket2::Socket::bind(&socket, &addr.into())?;
        Ok(socket)
    }

    fn bind_reusable(addr: &impl ToSocketAddrs) -> io::Result<Self>
    where Self: Sized {
        let addr = addr.to_socket_addrs()?.next().ok_or(io::ErrorKind::InvalidInput)?;
        let socket =
            socket2::Socket::new(socket2::Domain::for_address(addr), socket2::Type::STREAM, None)?;
        socket.set_reuse_address(true)?;
        #[cfg(all(unix, not(target_os = "solaris"), not(target_os = "illumos")))]
        {
            socket.set_reuse_port(true)?;
        }
        socket2::Socket::bind(&socket, &addr.into())?;
        Ok(socket)
    }

    fn accept(&self) -> io::Result<Self::Stream> { Ok(socket2::Socket::accept(self)?.0) }

    fn local_addr(&self) -> SocketAddr {
        socket2::Socket::local_addr(self)
            .expect("TCP listener doesn't have local address")
            .as_socket()
            .expect("TCP listener doesn't has local socket")
    }

    fn ttl(&self) -> io::Result<u32> { socket2::Socket::ttl(self) }

    fn set_ttl(&self, ttl: u32) -> io::Result<()> { socket2::Socket::set_ttl(self, ttl) }

    fn set_nonblocking(&self, nonblocking: bool) -> io::Result<()> {
        socket2::Socket::set_nonblocking(self, nonblocking)
    }

    fn try_clone(&self) -> io::Result<Self>
    where Self: Sized {
        socket2::Socket::try_clone(self)
    }

    fn take_error(&self) -> io::Result<Option<io::Error>> { socket2::Socket::take_error(self) }
}
