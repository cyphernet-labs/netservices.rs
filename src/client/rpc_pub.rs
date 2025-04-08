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

//! Client-server RPC protocol allowing asynchronous delivery of server-client messages which are
//! not replies to any specific client request. Combines properties of classic RPC and PubSub.

use std::any::Any;
use std::io;

use super::{Client, ClientDelegate, ConnectionDelegate, OnDisconnect, RpcDelegate};
use crate::client::rpc::{RpcCb, RpcReply, RpcService};
use crate::{ImpossibleResource, NetSession, NetTransport};

/// Tag byte signifying RPC server reply.
pub const CLIENT_MSG_ID_RPC: u8 = 0x01u8;
/// Tag byte signifying Pub server message.
pub const CLIENT_MSG_ID_PUB: u8 = 0x10u8;

/// Tagged message id type, distinguishing RPC server replies from Pub server messages.
#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug)]
pub enum RpcPubId {
    /// RPC message id.
    Rpc(u64),
    /// Pub message id.
    Pub(u16),
}

/// Server message, which may be an RPC reply of Pub message.
#[derive(Clone, Eq, PartialEq, Hash, Debug)]
pub struct RpcPubMsg {
    /// Message id, representing its type and indicating related RPC request or Pub topic
    /// subscription.
    pub id: RpcPubId,
    /// Unparsed message data.
    pub payload: Vec<u8>,
}

/// Errors parsing server message [`RpcPubMsg`] from the raw bytes received from the server.
#[derive(Clone, Eq, PartialEq, Hash, Debug, Display, Error)]
#[display(doc_comments)]
pub enum ParseRpcPubError {
    /// the received message is empty and lacks RPCPub identifier.
    Empty,

    /// the received message is too short and doesn't provide RPCPub identifier.
    NoId,

    /// the received message contains invalid id tag ({_0:#04x}).
    InvalidTag(u8),
}

impl TryFrom<Vec<u8>> for RpcPubMsg {
    type Error = ParseRpcPubError;

    fn try_from(data: Vec<u8>) -> Result<Self, Self::Error> {
        let Some(tag) = data.get(0) else {
            return Err(ParseRpcPubError::Empty);
        };
        let mut data = &data[1..];
        let id = match *tag {
            CLIENT_MSG_ID_RPC if data.len() < 8 => return Err(ParseRpcPubError::NoId),
            CLIENT_MSG_ID_PUB if data.len() < 2 => return Err(ParseRpcPubError::NoId),
            CLIENT_MSG_ID_RPC => {
                let mut id = [0u8; 8];
                id.copy_from_slice(&data[0..8]);
                data = &data[8..];
                RpcPubId::Rpc(u64::from_le_bytes(id))
            }
            CLIENT_MSG_ID_PUB => {
                let mut id = [0u8; 2];
                id.copy_from_slice(&data[0..2]);
                data = &data[2..];
                RpcPubId::Pub(u16::from_le_bytes(id))
            }
            wrong => return Err(ParseRpcPubError::InvalidTag(wrong)),
        };
        let payload = data.to_vec();
        Ok(RpcPubMsg { id, payload })
    }
}

impl From<RpcPubMsg> for Vec<u8> {
    fn from(msg: RpcPubMsg) -> Self {
        let mut data = Vec::with_capacity(msg.payload.len() + 9);
        match msg.id {
            RpcPubId::Rpc(id) => {
                data.push(CLIENT_MSG_ID_RPC);
                data.extend(id.to_le_bytes());
            }
            RpcPubId::Pub(id) => {
                data.push(CLIENT_MSG_ID_PUB);
                data.extend(id.to_le_bytes());
            }
        }
        data.extend(msg.payload);
        data
    }
}

/// Error processing servr message.
#[derive(Clone, Eq, PartialEq, Hash, Debug, Display, Error)]
#[display(doc_comments)]
pub enum RpcPubError {
    /// server message can't be parsed due to {0}
    UnparsableMsg(ParseRpcPubError),
    /// server Pub message with topic {0} can't be parsed due to {1}
    UnparsablePub(u16, String),
}

/// Set of callbacks used by the RPC+Pub client to notify business logic about server messages.
pub trait RpcPubDelegate<A: Send, S: NetSession>: RpcDelegate<A, S> {
    /// Pub server message type which must be parsable from a byte blob.
    type PubMsg: TryFrom<Vec<u8>, Error: std::error::Error>;

    /// Callback on receiving RPC reply.
    fn on_msg_pub(&self, id: u16, msg: Self::PubMsg);
}

/// Service handing RPC and Pub message processing.
struct RpcPubService<A: Send, S: NetSession, D: RpcPubDelegate<A, S>> {
    inner: RpcService<A, S, D>,
}

impl<A: Send, S: NetSession, D: RpcPubDelegate<A, S>> RpcPubService<A, S, D> {
    pub fn new(delegate: D) -> Self {
        RpcPubService {
            inner: RpcService::new(delegate),
        }
    }
}

impl<A: Send, S: NetSession, D: RpcPubDelegate<A, S>> ConnectionDelegate<A, S>
    for RpcPubService<A, S, D>
{
    fn connect(&self, remote: &A) -> S { self.inner.connect(remote) }

    fn on_established(&self, artifact: S::Artifact, attempt: usize) {
        self.inner.on_established(artifact, attempt)
    }

    fn on_disconnect(&self, err: io::Error, attempt: usize) -> OnDisconnect {
        self.inner.on_disconnect(err, attempt)
    }

    fn on_io_error(&self, err: reactor::Error<ImpossibleResource, NetTransport<S>>) {
        self.inner.on_io_error(err)
    }
}

impl<A: Send, S: NetSession, D: RpcPubDelegate<A, S>> ClientDelegate<A, S, RpcCb<D::Reply>>
    for RpcPubService<A, S, D>
{
    type Reply = RpcPubMsg;

    fn before_send(&mut self, data: Vec<u8>, cb: RpcCb<D::Reply>) -> Vec<u8> {
        self.inner.before_send(data, cb)
    }

    fn on_reply(&mut self, msg: RpcPubMsg) {
        match msg.id {
            RpcPubId::Rpc(id) => self.inner.on_reply(RpcReply {
                id,
                payload: msg.payload,
            }),
            RpcPubId::Pub(id) => match D::PubMsg::try_from(msg.payload) {
                Ok(msg_pub) => {
                    #[cfg(feature = "log")]
                    log::trace!(target: "netservices-client", "received Pub message with Pub id={id}. Notifying the delegate.");

                    self.inner.delegate.on_msg_pub(id, msg_pub)
                }
                Err(e) => {
                    #[cfg(feature = "log")]
                    log::error!(target: "netservices-client", "received unparsable Pub message from the server with Pub id={id}. Parse error: {e}");

                    self.inner.delegate.on_msg_error(RpcPubError::UnparsablePub(id, e.to_string()))
                }
            },
        }
    }

    fn on_reply_unparsable(&mut self, err: ParseRpcPubError) {
        #[cfg(feature = "log")]
        log::error!(target: "netservices-client", "received unparsable server message. Parse error: {err}");

        self.inner.delegate.on_msg_error(RpcPubError::UnparsableMsg(err))
    }
}

/// The client runtime containing reactor thread managing connection to the remote server and the
/// use of the server APIs.
pub struct RpcPubClient<Req: Into<Vec<u8>>, Rep: TryFrom<Vec<u8>> + 'static> {
    inner: Client<Req, RpcCb<Rep>>,
}

impl<Req: Into<Vec<u8>>, Rep: TryFrom<Vec<u8>> + 'static> RpcPubClient<Req, Rep> {
    /// Constructs new client for RPC+Pub protocol. Takes service callback delegate and remote
    /// server address. Will attempt to connect to the server automatically once the reactor thread
    /// has started.
    pub fn new<
        A: Send + 'static,
        S: NetSession + 'static,
        D: RpcPubDelegate<A, S, Reply = Rep> + 'static,
    >(
        delegate: D,
        remote: A,
    ) -> io::Result<Self> {
        let rpc_pub_service = RpcPubService::new(delegate);
        let client = Client::<Req, RpcCb<Rep>>::new(rpc_pub_service, remote)?;
        Ok(Self { inner: client })
    }

    /// Sends a new RPC request to the server. The second argument is a closure which will be called
    /// back upon receiving reply from the server.
    pub fn send(&mut self, req: Req, cb: impl FnOnce(Rep) + Send + 'static) -> io::Result<()> {
        self.inner.send_extra(req, Box::new(cb))
    }

    /// Terminates the client, disconnecting from the server and stopping the reactor thread.
    pub fn terminate(self) -> Result<(), Box<dyn Any + Send>> { self.inner.terminate() }

    pub fn join(self) -> Result<(), Box<dyn Any + Send>> { self.inner.join() }
}
