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

mod client;
//pub mod rpc;
//pub mod rpc_pub;

pub use client::{Client, ClientCommand, ClientDelegate, ConnectionDelegate, OnDisconnect};
//pub use rpc::{RpcClient, RpcDelegate};
//pub use rpc_pub::{RpcPubClient, RpcPubDelegate, RpcPubId, CLIENT_MSG_ID_PUB, CLIENT_MSG_ID_RPC};
