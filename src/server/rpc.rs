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


use std::any::Any;
use std::io;

use crate::NetSession;

/// The client runtime containing reactor thread managing connection to the remote server and the
/// use of the server APIs.
pub struct RpcServer<Req: Into<Vec<u8>>, Rep: TryFrom<Vec<u8>> + 'static> {
    inner: Server<Req, Rep>,
}

impl<Req: Into<Vec<u8>>, Rep: TryFrom<Vec<u8>> + 'static> RpcServer<Req, Rep> {
    /// Constructs new client for RPC protocol. Takes service callback delegate and remote
    /// server address. Will attempt to connect to the server automatically once the reactor thread
    /// has started.
    pub fn new<
        A: Send + 'static,
        S: NetSession + 'static,
        D: RpcDelegate<A, S, crate::client::rpc::Reply= Rep> + 'static,
    >(
        delegate: D,
        remote: A,
    ) -> io::Result<Self> {
        let rpc_service = crate::client::rpc::RpcService::new(delegate);
        let client = Client::<Req, RpcCb<Rep>>::new(rpc_service, remote)?;
        Ok(Self { inner: client })
    }

    /// Sends a new RPC request to the server. The second argument is a closure which will be called
    /// back upon receiving reply from the server.
    pub fn send(&mut self, req: Req, cb: impl FnOnce(Rep) + Send + 'static) -> io::Result<()> {
        self.inner.send_extra(req, Box::new(cb))
    }

    /// Terminates the client, disconnecting from the server and stopping the reactor thread.
    pub fn terminate(self) -> Result<(), Box<dyn Any + Send>> { self.inner.terminate() }
}
