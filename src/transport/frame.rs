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

use std::collections::VecDeque;
use std::io::{Read, Write};

use amplify::CursorDeque;

pub trait Frame: Send + Sized {
    type Error: std::error::Error + Sync + Send + 'static;

    /// Reads frame from the stream.
    ///
    /// If the stream doesn't contain the whole message, must return `Ok(None)`
    /// and DO NOT consume any data from the stream.
    fn unmarshall(reader: impl Read) -> Result<Option<Self>, Self::Error>;
    fn marshall(&self, writer: impl Write) -> Result<(), Self::Error>;

    fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        self.marshall(&mut buf).expect("in-memory write operation");
        buf
    }
}

#[derive(Clone, Debug, Default)]
pub struct Marshaller {
    read_queue: VecDeque<u8>,
    write_queue: VecDeque<u8>,
}

impl Marshaller {
    pub fn new() -> Self { Self { read_queue: VecDeque::new(), write_queue: VecDeque::new() } }

    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            read_queue: VecDeque::with_capacity(capacity),
            write_queue: VecDeque::with_capacity(capacity),
        }
    }

    pub fn marshall<F: Frame>(&mut self, frame: F) {
        frame
            .marshall(&mut self.write_queue)
            .expect("in-memory write operation");
    }

    pub fn unmarshall<F: Frame>(&mut self) -> Result<Option<F>, F::Error> {
        let mut cursor = CursorDeque::new(&mut self.read_queue);
        let frame = F::unmarshall(&mut cursor)?;
        let pos = cursor.position() as usize;
        if frame.is_some() {
            self.read_queue.drain(..pos);
        }
        Ok(frame)
    }

    pub fn extend_received(&mut self, data: impl IntoIterator<Item = u8>) {
        self.read_queue.extend(data);
    }

    pub fn extend_sendable(&mut self, data: impl IntoIterator<Item = u8>) {
        self.write_queue.extend(data);
    }

    pub fn read_queue_len(&self) -> usize { self.read_queue.len() }
    pub fn write_queue_len(&self) -> usize { self.write_queue.len() }
}
