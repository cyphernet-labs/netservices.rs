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

pub mod frame;

mod connection;
mod listener;
mod split;

#[cfg(feature = "reactor")]
mod resource;
#[cfg(feature = "reactor")]
pub mod remotes;

pub use connection::{Address, AsConnection, NetConnection, NetStream};
pub use frame::{Frame, Marshaller, Request};
pub use listener::NetListener;
#[cfg(feature = "reactor")]
pub use resource::{ImpossibleResource, ListenerEvent, NetAccept, NetTransport, SessionEvent};
pub use split::{NetReader, NetWriter, SplitIo, SplitIoError, TcpReader, TcpWriter};
