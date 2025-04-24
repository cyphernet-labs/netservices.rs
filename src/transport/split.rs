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
use std::net::TcpStream;

use crate::transport::AsConnection;
use crate::{NetConnection, NetSession, NetStateMachine};

#[derive(Debug, Display)]
#[display("{error}")]
pub struct SplitIoError<T: SplitIo> {
    pub original: T,
    pub error: io::Error,
}

impl<T: SplitIo + std::fmt::Debug> std::error::Error for SplitIoError<T> {}

pub trait SplitIo: Sized {
    type Read: AsConnection + io::Read + Sized;
    type Write: AsConnection + io::Write + Sized;

    /// # Panics
    ///
    /// If the split operation is not possible
    fn split_io(self) -> Result<(Self::Read, Self::Write), SplitIoError<Self>>;
    fn from_split_io(read: Self::Read, write: Self::Write) -> Self;
}

pub struct NetReader<S: NetSession> {
    pub(crate) unique_id: u64,
    pub(crate) reader: <S as SplitIo>::Read,
}

impl<S: NetSession> AsConnection for NetReader<S> {
    type Connection = <<S as SplitIo>::Read as AsConnection>::Connection;
    fn as_connection(&self) -> &Self::Connection { self.reader.as_connection() }
}

impl<S: NetSession> io::Read for NetReader<S> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> { self.reader.read(buf) }
}

pub struct NetWriter<M: NetStateMachine, S: NetSession> {
    pub(crate) unique_id: u64,
    pub(crate) state: M,
    pub(crate) writer: <S as SplitIo>::Write,
}

impl<M: NetStateMachine, S: NetSession> AsConnection for NetWriter<M, S> {
    type Connection = <<S as SplitIo>::Write as AsConnection>::Connection;
    fn as_connection(&self) -> &Self::Connection { self.writer.as_connection() }
}

impl<M: NetStateMachine, S: NetSession> io::Write for NetWriter<M, S> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> { self.writer.write(buf) }
    fn flush(&mut self) -> io::Result<()> { self.writer.flush() }
}

pub struct TcpReader<C: NetConnection> {
    unique_id: u64,
    connection: C,
}

impl<C: NetConnection> io::Read for TcpReader<C> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> { self.connection.read(buf) }
}

impl<C: NetConnection> AsConnection for TcpReader<C> {
    type Connection = C;
    fn as_connection(&self) -> &Self::Connection { &self.connection }
}

pub struct TcpWriter<C: NetConnection> {
    unique_id: u64,
    connection: C,
}

impl<C: NetConnection> io::Write for TcpWriter<C> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> { self.connection.write(buf) }

    fn flush(&mut self) -> io::Result<()> { self.connection.flush() }
}

impl<C: NetConnection> AsConnection for TcpWriter<C> {
    type Connection = C;
    fn as_connection(&self) -> &Self::Connection { &self.connection }
}

impl SplitIo for TcpStream {
    type Read = TcpReader<Self>;
    type Write = TcpWriter<Self>;

    fn split_io(self) -> Result<(Self::Read, Self::Write), SplitIoError<Self>> {
        match self.try_clone() {
            Ok(clone) => {
                let unique_id = rand::random();
                let reader = TcpReader { unique_id, connection: clone };
                let writer = TcpWriter { unique_id, connection: self };
                Ok((reader, writer))
            }
            Err(error) => Err(SplitIoError { original: self, error }),
        }
    }

    fn from_split_io(read: Self::Read, write: Self::Write) -> Self {
        if read.unique_id != write.unique_id {
            panic!("joining TcpStreams which were not produced by the same split_io()")
        }
        write.connection
    }
}

#[cfg(feature = "nonblocking")]
impl SplitIo for socket2::Socket {
    type Read = TcpReader<Self>;
    type Write = TcpWriter<Self>;

    fn split_io(self) -> Result<(Self::Read, Self::Write), SplitIoError<Self>> {
        match self.try_clone() {
            Ok(clone) => {
                let unique_id = rand::random();
                let reader = TcpReader { unique_id, connection: clone };
                let writer = TcpWriter { unique_id, connection: self };
                Ok((reader, writer))
            }
            Err(error) => Err(SplitIoError { original: self, error }),
        }
    }

    fn from_split_io(read: Self::Read, write: Self::Write) -> Self {
        if read.unique_id != write.unique_id {
            panic!("joining TcpStreams which were not produced by the same split_io()")
        }
        write.connection
    }
}
