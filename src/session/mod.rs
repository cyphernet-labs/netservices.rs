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

use std::fmt::{Debug, Display};
use std::hash::Hash;
#[cfg(feature = "eidolon")]
use std::net::TcpStream;
#[cfg(feature = "eidolon")]
use std::time::Duration;
use std::{error, io};

#[cfg(feature = "eidolon")]
use cyphernet::addr::{HostName, InetHost, NetAddr};
#[cfg(feature = "eidolon")]
use cyphernet::auth::eidolon::EidolonState;
use cyphernet::encrypt::noise::NoiseState;
#[cfg(feature = "eidolon")]
use cyphernet::encrypt::noise::{HandshakePattern, Keyset};
use cyphernet::proxy::socks5;
#[cfg(feature = "eidolon")]
use cyphernet::{Cert, Digest, EcSign, x25519};

#[cfg(feature = "eidolon")]
use crate::Direction;
use crate::{NetConnection, NetReader, NetStream, NetWriter, SplitIo, SplitIoError};

#[cfg(feature = "eidolon")]
pub type EidolonSession<I, S> = NetProtocol<EidolonRuntime<I>, S>;
pub type NoiseSession<E, D, S> = NetProtocol<NoiseState<E, D>, S>;
pub type Socks5Session<S> = NetProtocol<socks5::Socks5, S>;

#[cfg(feature = "eidolon")]
pub type CypherSession<I, D> =
    EidolonSession<I, NoiseSession<x25519::PrivateKey, D, Socks5Session<TcpStream>>>;

#[cfg(feature = "eidolon")]
pub type EidolonReader<S> = NetReader<S>;
#[cfg(feature = "eidolon")]
pub type EidolonWriter<I, S> = NetWriter<EidolonRuntime<I>, S>;
#[cfg(feature = "eidolon")]
pub type CypherReader<D> =
    EidolonReader<NoiseSession<x25519::PrivateKey, D, Socks5Session<TcpStream>>>;
#[cfg(feature = "eidolon")]
pub type CypherWriter<I, D> =
    EidolonWriter<I, NoiseSession<x25519::PrivateKey, D, Socks5Session<TcpStream>>>;

#[cfg(feature = "eidolon")]
impl<I: EcSign, D: Digest> CypherSession<I, D> {
    #[cfg(feature = "reactor")]
    pub fn connect_nonblocking<const HASHLEN: usize>(
        remote_addr: NetAddr<HostName>,
        cert: Cert<I::Sig>,
        allowed_ids: Vec<I::Pk>,
        signer: I,
        proxy_addr: NetAddr<InetHost>,
        force_proxy: bool,
        timeout: Duration,
    ) -> io::Result<Self> {
        let connection = if force_proxy {
            TcpStream::connect_nonblocking(proxy_addr, timeout)?
        } else {
            TcpStream::connect_nonblocking(remote_addr.connection_addr(proxy_addr), timeout)?
        };
        Ok(Self::with_config::<HASHLEN>(
            remote_addr,
            connection,
            Direction::Outbound,
            cert,
            allowed_ids,
            signer,
            force_proxy,
        ))
    }

    #[cfg(feature = "reactor")]
    pub fn connect_reusable_nonblocking<const HASHLEN: usize>(
        local_addr: NetAddr<InetHost>,
        remote_addr: NetAddr<HostName>,
        cert: Cert<I::Sig>,
        allowed_ids: Vec<I::Pk>,
        signer: I,
        proxy_addr: NetAddr<InetHost>,
        force_proxy: bool,
    ) -> io::Result<Self> {
        let connection = if force_proxy {
            TcpStream::connect_reusable_nonblocking(local_addr, proxy_addr)?
        } else {
            TcpStream::connect_reusable_nonblocking(
                local_addr,
                remote_addr.connection_addr(proxy_addr),
            )?
        };
        Ok(Self::with_config::<HASHLEN>(
            remote_addr,
            connection,
            Direction::Outbound,
            cert,
            allowed_ids,
            signer,
            force_proxy,
        ))
    }

    pub fn connect_blocking<const HASHLEN: usize>(
        remote_addr: NetAddr<HostName>,
        cert: Cert<I::Sig>,
        allowed_ids: Vec<I::Pk>,
        signer: I,
        proxy_addr: NetAddr<InetHost>,
        force_proxy: bool,
        timeout: Duration,
    ) -> io::Result<Self> {
        let connection = if force_proxy {
            TcpStream::connect_blocking(proxy_addr, timeout)?
        } else {
            TcpStream::connect_blocking(remote_addr.connection_addr(proxy_addr), timeout)?
        };
        let mut session = Self::with_config::<HASHLEN>(
            remote_addr,
            connection,
            Direction::Outbound,
            cert,
            allowed_ids,
            signer,
            force_proxy,
        );
        session.run_handshake()?;
        Ok(session)
    }

    pub fn accept<const HASHLEN: usize>(
        connection: TcpStream,
        cert: Cert<I::Sig>,
        allowed_ids: Vec<I::Pk>,
        signer: I,
    ) -> io::Result<Self> {
        Ok(Self::with_config::<HASHLEN>(
            connection.remote_addr()?.into(),
            connection,
            Direction::Inbound,
            cert,
            allowed_ids,
            signer,
            false,
        ))
    }

    fn with_config<const HASHLEN: usize>(
        remote_addr: NetAddr<HostName>,
        connection: TcpStream,
        direction: Direction,
        cert: Cert<I::Sig>,
        allowed_ids: Vec<I::Pk>,
        signer: I,
        force_proxy: bool,
    ) -> Self {
        let socks5 = socks5::Socks5::with(remote_addr, force_proxy);
        let proxy = Socks5Session::with(connection, socks5);

        let noise = NoiseState::initialize::<HASHLEN>(
            HandshakePattern::nn(),
            direction.is_outbound(),
            &[],
            Keyset::noise_nn(),
        );

        let encoding = NoiseSession::with(proxy, noise);
        let eidolon = match direction {
            Direction::Inbound => EidolonRuntime::responder(signer, cert, allowed_ids),
            Direction::Outbound => EidolonRuntime::initiator(signer, cert, allowed_ids),
        };
        EidolonSession::with(encoding, eidolon)
    }
}

pub trait NodeId: Copy + Eq + Ord + Hash + Send + Debug + Display {}
impl<T: Copy + Eq + Ord + Hash + Send + Debug + Display> NodeId for T {}

pub trait Artifact {
    type NodeId: NodeId;
    fn remote_id(&self) -> Option<Self::NodeId>;
}

pub trait NetSession: NetStream + SplitIo {
    /// Inner session type
    type Inner: NetSession;
    /// Underlying connection
    type Connection: NetConnection;
    type Artifact: Artifact + Display;

    fn is_established(&self) -> bool { self.artifact().is_some() }
    fn run_handshake(&mut self) -> io::Result<()>;

    fn display(&self) -> String {
        match self.artifact() {
            Some(artifact) => artifact.to_string(),
            None => s!("<no-id>"),
        }
    }
    fn artifact(&self) -> Option<Self::Artifact>;
    fn as_connection(&self) -> &Self::Connection;
    fn as_connection_mut(&mut self) -> &mut Self::Connection;
    fn disconnect(self) -> io::Result<()>;
}

#[derive(Clone, Debug, Display, Error)]
#[display("handshake has failed due to {0}")]
pub struct HandshakeError(String);

impl HandshakeError {
    fn with(err: impl error::Error) -> Self { HandshakeError(err.to_string()) }
}

pub trait NetStateMachine: Sized + Send {
    const NAME: &'static str;

    type Init: Debug;
    type Artifact: Artifact;
    type Error: error::Error;

    fn init(&mut self, init: Self::Init);
    fn next_read_len(&self) -> usize;
    fn advance(&mut self, input: &[u8]) -> Result<Vec<u8>, Self::Error>;
    fn artifact(&self) -> Option<Self::Artifact>;

    // Blocking
    #[allow(clippy::read_zero_byte_vec, unused_variables)]
    fn run_handshake(&mut self, stream: &mut impl NetStream) -> io::Result<()> {
        let mut input = vec![];
        while !self.is_complete() {
            let act = self.advance(&input).map_err(|err| {
                #[cfg(feature = "log")]
                log::error!(target: Self::NAME, "Handshake failure: {err}");

                io::Error::new(io::ErrorKind::ConnectionAborted, HandshakeError::with(err))
            })?;
            if !act.is_empty() {
                #[cfg(feature = "log")]
                log::trace!(target: Self::NAME, "Sending handshake act {act:02x?}");

                stream.write_all(&act)?;
            }
            if !self.is_complete() {
                input = vec![0u8; self.next_read_len()];
                stream.read_exact(&mut input)?;

                #[cfg(feature = "log")]
                log::trace!(target: Self::NAME, "Receiving handshake act {input:02x?}");
            }
        }
        #[cfg(feature = "log")]
        log::debug!(target: Self::NAME, "Handshake protocol {} successfully completed", Self::NAME);
        Ok(())
    }

    fn is_init(&self) -> bool;
    fn is_complete(&self) -> bool { self.artifact().is_some() }
}

pub trait IntoInit<I: Sized> {
    fn into_init(self) -> I;
}

#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub struct ZeroInit;

impl<T> IntoInit<ZeroInit> for T {
    fn into_init(self) -> ZeroInit { ZeroInit }
}

#[derive(Clone, Eq, PartialEq, Hash, Debug, Display)]
#[display("{session}")]
pub struct ProtocolArtifact<M: NetStateMachine, S: NetSession> {
    pub session: S::Artifact,
    pub state: M::Artifact,
}

impl<M: NetStateMachine, S: NetSession> Artifact for ProtocolArtifact<M, S> {
    type NodeId = <M::Artifact as Artifact>::NodeId;

    fn remote_id(&self) -> Option<Self::NodeId> { self.state.remote_id() }
}

#[derive(Copy, Clone, Eq, PartialEq)]
pub struct NetProtocol<M: NetStateMachine, S: NetSession>
where S::Artifact: IntoInit<M::Init>
{
    state: M,
    session: S,
}

impl<M: NetStateMachine, S: NetSession> NetProtocol<M, S>
where S::Artifact: IntoInit<M::Init>
{
    pub fn new(session: S) -> Self
    where M: Default {
        Self::with(session, M::default())
    }

    pub fn with(session: S, state_machine: M) -> Self { Self { state: state_machine, session } }

    fn init(&mut self) -> bool {
        if !self.state.is_init() {
            if let Some(artifact) = self.session.artifact() {
                let init_data = artifact.into_init();

                #[cfg(feature = "log")]
                log::debug!(target: M::NAME, "Initializing state with data {init_data:02x?}");

                self.state.init(init_data);

                return true;
            } else {
                #[cfg(feature = "log")]
                log::trace!(target: M::NAME, "State initialized, but no artifact present (handshake is not complete)");
            }
        } else {
            #[cfg(feature = "log")]
            log::trace!(target: M::NAME, "Init event - but already initialized");
        }
        false
    }
}

impl<M: NetStateMachine, S: NetSession> io::Read for NetProtocol<M, S>
where S::Artifact: IntoInit<M::Init>
{
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        #[cfg(feature = "log")]
        log::trace!(target: M::NAME, "Reading event");

        if self.state.is_complete() || !self.session.is_established() {
            #[cfg(feature = "log")]
            log::trace!(target: M::NAME, "Passing reading to inner not yet established session");

            return self.session.read(buf);
        }

        self.init();

        let len = self.state.next_read_len();
        let mut input = vec![0u8; len];
        self.session.read_exact(&mut input)?;

        #[cfg(feature = "log")]
        log::trace!(target: M::NAME, "Received handshake act: {input:02x?}");

        if !input.is_empty() {
            #[allow(unused_variables)]
            let output = self.state.advance(&input).map_err(|err| {
                #[cfg(feature = "log")]
                log::error!(target: M::NAME, "Handshake failure: {err}");

                io::Error::new(io::ErrorKind::ConnectionAborted, HandshakeError::with(err))
            })?;

            if !output.is_empty() {
                #[cfg(feature = "log")]
                log::trace!(target: M::NAME, "Sending handshake act on read: {output:02x?}");

                self.session.write_all(&output)?;
            }
        }

        Ok(0)
    }
}

impl<M: NetStateMachine, S: NetSession> io::Write for NetProtocol<M, S>
where S::Artifact: IntoInit<M::Init>
{
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        #[cfg(feature = "log")]
        log::trace!(target: M::NAME, "Writing event (state_complete={}, session_established={})", self.state.is_complete(), self.session.is_established());

        if self.state.is_complete() || !self.session.is_established() {
            #[cfg(feature = "log")]
            log::trace!(target: M::NAME, "Passing writing to inner session");

            return self.session.write(buf);
        }

        self.init();

        if self.state.next_read_len() == 0 {
            #[cfg(feature = "log")]
            log::trace!(target: M::NAME, "Starting handshake protocol");

            #[allow(unused_variables)]
            let act = self.state.advance(&[]).map_err(|err| {
                #[cfg(feature = "log")]
                log::error!(target: M::NAME, "Handshake failure: {err}");

                io::Error::new(io::ErrorKind::ConnectionAborted, HandshakeError::with(err))
            })?;

            if !act.is_empty() {
                #[cfg(feature = "log")]
                log::trace!(target: M::NAME, "Sending handshake act on write: {act:02x?}");

                self.session.write_all(&act)?;
            } else {
                #[cfg(feature = "log")]
                log::trace!(target: M::NAME, "Handshake complete, passing data to inner session");

                return self.session.write(buf);
            }
        }

        if buf.is_empty() { Ok(0) } else { Err(io::ErrorKind::Interrupted.into()) }
    }

    fn flush(&mut self) -> io::Result<()> { self.session.flush() }
}

impl<M: NetStateMachine, S: NetSession> NetStream for NetProtocol<M, S> where S::Artifact: IntoInit<M::Init>
{}

impl<M: NetStateMachine, S: NetSession> SplitIo for NetProtocol<M, S>
where S::Artifact: IntoInit<M::Init>
{
    type Read = NetReader<S>;
    type Write = NetWriter<M, S>;

    fn split_io(mut self) -> Result<(Self::Read, Self::Write), SplitIoError<Self>> {
        let unique_id = rand::random();

        match self.session.split_io() {
            Err(err) => {
                self.session = err.original;
                Err(SplitIoError { original: self, error: err.error })
            }
            Ok((reader, writer)) => Ok((NetReader { unique_id, reader }, NetWriter {
                unique_id,
                state: self.state,
                writer,
            })),
        }
    }

    fn from_split_io(read: Self::Read, write: Self::Write) -> Self {
        if read.unique_id != write.unique_id {
            panic!("joining into NetProtocol parts not produced by the same split_io()")
        }

        Self {
            state: write.state,
            session: S::from_split_io(read.reader, write.writer),
        }
    }
}

impl<M: NetStateMachine, S: NetSession> NetSession for NetProtocol<M, S>
where S::Artifact: IntoInit<M::Init>
{
    type Inner = S;
    type Connection = S::Connection;
    type Artifact = ProtocolArtifact<M, S>;

    fn run_handshake(&mut self) -> io::Result<()> {
        #[cfg(feature = "log")]
        log::debug!(target: M::NAME, "Starting handshake protocol {}", M::NAME);

        if !self.session.is_established() {
            self.session.run_handshake()?;
        }
        self.init();
        self.state.run_handshake(self.session.as_connection_mut())
    }

    fn artifact(&self) -> Option<Self::Artifact> {
        Some(ProtocolArtifact {
            session: self.session.artifact()?,
            state: self.state.artifact()?,
        })
    }

    fn as_connection(&self) -> &Self::Connection { self.session.as_connection() }

    fn as_connection_mut(&mut self) -> &mut Self::Connection { self.session.as_connection_mut() }

    fn disconnect(self) -> io::Result<()> { self.session.disconnect() }
}

mod imp_std {
    use std::net::{Shutdown, SocketAddr, TcpStream};

    use super::*;

    impl Artifact for SocketAddr {
        type NodeId = Self;

        fn remote_id(&self) -> Option<Self::NodeId> { Some(*self) }
    }

    impl NetSession for TcpStream {
        type Inner = Self;
        type Connection = Self;
        type Artifact = SocketAddr;

        fn run_handshake(&mut self) -> io::Result<()> { Ok(()) }

        fn artifact(&self) -> Option<Self::Artifact> { self.peer_addr().ok() }

        fn as_connection(&self) -> &Self::Connection { self }

        fn as_connection_mut(&mut self) -> &mut Self::Connection { self }

        fn disconnect(self) -> io::Result<()> { self.shutdown(Shutdown::Both) }
    }
}

#[cfg(feature = "socket2")]
mod imp_socket2 {
    use std::net::{Shutdown, SocketAddr};

    use socket2::Socket;

    use super::*;

    impl NetSession for Socket {
        type Inner = Self;
        type Connection = Self;
        type Artifact = SocketAddr;

        fn run_handshake(&mut self) -> io::Result<()> { Ok(()) }

        fn artifact(&self) -> Option<Self::Artifact> { self.peer_addr().ok()?.as_socket() }

        fn as_connection(&self) -> &Self::Connection { self }

        fn as_connection_mut(&mut self) -> &mut Self::Connection { self }

        fn disconnect(self) -> io::Result<()> { self.shutdown(Shutdown::Both) }
    }
}

#[cfg(feature = "eidolon")]
mod imp_eidolon {
    use std::fmt::{self, Display, Formatter};

    use cyphernet::auth::eidolon;
    use cyphernet::display::{Encoding, MultiDisplay};
    use cyphernet::{Cert, CertFormat, Digest, EcPk, EcSig, EcSign, Ecdh};

    use super::*;

    pub struct EidolonRuntime<S: EcSign> {
        state: EidolonState<S::Sig>,
        signer: S,
    }

    impl<S: EcSign> EidolonRuntime<S> {
        pub fn initiator(signer: S, cert: Cert<S::Sig>, allowed_ids: Vec<S::Pk>) -> Self {
            Self { state: EidolonState::initiator(cert, allowed_ids), signer }
        }

        pub fn responder(signer: S, cert: Cert<S::Sig>, allowed_ids: Vec<S::Pk>) -> Self {
            Self { state: EidolonState::responder(cert, allowed_ids), signer }
        }
    }

    impl<S: EcSign> Display for EidolonRuntime<S> {
        fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
            match self.state.remote_cert() {
                Some(cert) => {
                    f.write_str(&cert.display_fmt(&CertFormat::new(", ", Encoding::Base58)))
                }
                None => f.write_str("<unidentified>"),
            }
        }
    }

    impl<S: EcSig> Artifact for Cert<S> {
        type NodeId = <S::Pk as EcPk>::Compressed;

        fn remote_id(&self) -> Option<Self::NodeId> { Some(self.pk.to_pk_compressed()) }
    }

    impl<S: EcSign> NetStateMachine for EidolonRuntime<S> {
        const NAME: &'static str = "eidolon";
        type Init = Vec<u8>;
        type Artifact = Cert<S::Sig>;
        type Error = eidolon::Error<S::Pk>;

        fn init(&mut self, init: Self::Init) { self.state.init(init) }

        fn next_read_len(&self) -> usize { self.state.next_read_len() }

        fn advance(&mut self, input: &[u8]) -> Result<Vec<u8>, Self::Error> {
            self.state.advance(input, &self.signer)
        }

        fn artifact(&self) -> Option<Self::Artifact> { self.state.remote_cert().cloned() }

        fn is_init(&self) -> bool { self.state.is_init() }
    }

    impl<S: NetSession, E: Ecdh, D: Digest> IntoInit<Vec<u8>>
        for ProtocolArtifact<NoiseState<E, D>, S>
    {
        fn into_init(self) -> Vec<u8> { self.state.to_vec() }
    }
}
#[cfg(feature = "eidolon")]
pub use imp_eidolon::EidolonRuntime;

mod impl_noise {
    use cyphernet::encrypt::noise::NoiseState;
    use cyphernet::encrypt::noise::error::NoiseError;
    use cyphernet::{Digest, EcPk, Ecdh};

    use super::*;

    #[derive(Copy, Clone, Eq, PartialEq, Hash, Debug)]
    pub struct NoiseArtifact<E: Ecdh, D: Digest> {
        pub handshake_hash: D::Output,
        pub remote_static_key: Option<E::Pk>,
    }

    impl<E: Ecdh, D: Digest> Artifact for NoiseArtifact<E, D> {
        type NodeId = <E::Pk as EcPk>::Compressed;

        fn remote_id(&self) -> Option<Self::NodeId> {
            self.remote_static_key.as_ref().map(EcPk::to_pk_compressed)
        }
    }

    impl<E: Ecdh, D: Digest> NoiseArtifact<E, D> {
        pub fn with(handshake_hash: D::Output, remote_static_key: Option<E::Pk>) -> Self {
            NoiseArtifact { handshake_hash, remote_static_key }
        }

        pub fn to_vec(&self) -> Vec<u8> {
            let mut vec = Vec::<u8>::with_capacity(D::OUTPUT_LEN + E::Pk::COMPRESSED_LEN);
            vec.extend_from_slice(self.handshake_hash.as_ref());
            if let Some(pk) = self.remote_static_key.as_ref() {
                vec.extend_from_slice(pk.to_pk_compressed().as_ref())
            }
            vec
        }
    }

    impl<E: Ecdh, D: Digest> NetStateMachine for NoiseState<E, D> {
        const NAME: &'static str = "noise";
        type Init = ZeroInit;
        type Artifact = NoiseArtifact<E, D>;
        type Error = NoiseError;

        fn init(&mut self, _: Self::Init) {}

        fn next_read_len(&self) -> usize { self.next_read_len() }

        fn advance(&mut self, input: &[u8]) -> Result<Vec<u8>, Self::Error> { self.advance(input) }

        fn artifact(&self) -> Option<Self::Artifact> {
            self.get_handshake_hash()
                .map(|hh| NoiseArtifact::with(hh, self.get_remote_static_key()))
        }

        fn is_init(&self) -> bool { true }
    }
}

mod impl_socks5 {
    use std::convert::Infallible;

    use cyphernet::addr::Host;
    #[cfg(not(feature = "eidolon"))]
    use cyphernet::addr::{HostName, NetAddr};
    use cyphernet::proxy::socks5;
    use cyphernet::proxy::socks5::Socks5;

    use super::*;

    impl Artifact for NetAddr<HostName> {
        type NodeId = Infallible;

        fn remote_id(&self) -> Option<Self::NodeId> {
            panic!("NetAddr must not be used as a NodeId")
        }
    }

    impl NetStateMachine for Socks5 {
        const NAME: &'static str = "socks5";
        type Init = ZeroInit;
        type Artifact = NetAddr<HostName>;
        type Error = socks5::Error;

        fn init(&mut self, _: Self::Init) {}

        fn next_read_len(&self) -> usize { self.next_read_len() }

        fn advance(&mut self, input: &[u8]) -> Result<Vec<u8>, Self::Error> { self.advance(input) }

        fn artifact(&self) -> Option<Self::Artifact> {
            match self {
                Socks5::Initial(addr, false) if !addr.requires_proxy() => Some(addr.clone()),
                Socks5::Active(addr) => Some(addr.clone()),
                _ => None,
            }
        }

        fn is_init(&self) -> bool { true }
    }
}
