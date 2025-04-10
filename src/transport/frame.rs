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

use std::collections::VecDeque;
use std::io::{self, Read, Write};

pub trait Frame: Send + Sized {
    type Error: std::error::Error + Sync + Send + 'static;

    /// Reads frame from the stream.
    ///
    /// If the stream doesn't contain the whole message yet must return `Ok(None)`
    fn unmarshall(reader: impl Read) -> Result<Option<Self>, Self::Error>;
    fn marshall(&self, writer: impl Write) -> Result<(), Self::Error>;
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

    pub fn push<F: Frame>(&mut self, frame: F) {
        frame
            .marshall(&mut self.write_queue)
            .expect("in-memory write operation");
    }

    pub fn pop<F: Frame>(&mut self) -> Result<Option<F>, F::Error> {
        let slice = self.read_queue.make_contiguous();
        let mut cursor = io::Cursor::new(slice);
        let frame = F::unmarshall(&mut cursor)?;
        let pos = cursor.position() as usize;
        if frame.is_some() {
            self.read_queue.drain(..pos);
        }
        Ok(frame)
    }

    pub fn read_queue_len(&self) -> usize { self.read_queue.len() }
    pub fn write_queue_len(&self) -> usize { self.write_queue.len() }

    /// # Errors
    ///
    /// If write queue is not empty (i.e. some messages were not sent) fails
    /// to drain and returns back unmodified self
    pub fn drain(mut self) -> Result<Vec<u8>, Self> {
        if self.write_queue.is_empty() {
            Ok(self.read_queue.drain(..).collect())
        } else {
            Err(self)
        }
    }
}

impl Read for Marshaller {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> { self.write_queue.read(buf) }
}

impl Write for Marshaller {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> { self.read_queue.write(buf) }

    fn flush(&mut self) -> io::Result<()> {
        // Do nothing
        Ok(())
    }
}
