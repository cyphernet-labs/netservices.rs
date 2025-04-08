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

// TODO: Provide mechanism for detecting and reacting on RPC reply timeouts

use std::any::Any;
use std::collections::HashMap;
use std::io;
use std::marker::PhantomData;

use super::{Client, ClientDelegate, ConnectionDelegate, OnDisconnect};
use crate::{ImpossibleResource, NetSession, NetTransport};

/// RPC callback type, which is a function closure taking single argument - sever reply message. The
/// closure must be sendable between threads and is called in the context of the reactor thread.
pub type RpcCb<Rep> = Box<dyn FnOnce(Rep) + Send>;

/// Server RPC reply.
#[derive(Clone, Eq, PartialEq, Hash, Debug)]
pub struct RpcReply {
    /// Message id, representing related RPC request.
    pub id: u64,
    /// Unparsed message data.
    pub payload: Vec<u8>,
}

/// Errors parsing server message [`RpcReply`] from the raw bytes received from the server.
#[derive(Clone, Eq, PartialEq, Hash, Debug, Display, Error)]
#[display(doc_comments)]
pub enum ParseReplyError {
    /// the received message is empty and lacks RPC identifier.
    Empty,

    /// the received message is too short and doesn't provide RPC identifier.
    NoId,
}

impl TryFrom<Vec<u8>> for RpcReply {
    type Error = ParseReplyError;

    fn try_from(data: Vec<u8>) -> Result<Self, Self::Error> {
        if data.is_empty() {
            return Err(ParseReplyError::Empty);
        };
        let mut data = &data[..];
        if data.len() < 8 {
            return Err(ParseReplyError::NoId);
        };
        let mut id = [0u8; 8];
        id.copy_from_slice(&data[0..8]);
        data = &data[8..];
        let id = u64::from_le_bytes(id);
        let payload = data.to_vec();
        Ok(RpcReply { id, payload })
    }
}

impl From<RpcReply> for Vec<u8> {
    fn from(msg: RpcReply) -> Self {
        let mut data = Vec::with_capacity(msg.payload.len() + 8);
        data.extend(msg.id.to_le_bytes());
        data.extend(msg.payload);
        data
    }
}

/// Error processing servr message.
#[derive(Clone, Eq, PartialEq, Hash, Debug, Display, Error)]
#[display(doc_comments)]
pub enum RpcReplyError {
    /// server message can't be parsed as an RPC reply due to {0}
    UnparsableMsg(ParseReplyError),
    /// server RPC reply message with id {0} can't be parsed due to {1}
    UnparsableReply(u64, String),
    /// server RPC reply with id {0} doesn't match any previous RPC request.
    MismatchingReply(u64, Vec<u8>),
}

/// Set of callbacks used by the RPC client to notify business logic about server messages.
pub trait RpcDelegate<A: Send, S: NetSession>: ConnectionDelegate<A, S> {
    /// The RPC reply type which must be parsable from a byte blob.
    type Reply: TryFrom<Vec<u8>, Error: std::error::Error>;

    /// Callback for processing invalid message received from the server which can't be parsed into
    /// [`RpcReply`] type.
    fn on_msg_error(&self, err: impl std::error::Error);

    /// Callback for processing the message received from the server.
    fn on_reply(&mut self, reply: Self::Reply);
}

/// Service handing RPC and Pub message processing.
pub(super) struct RpcService<A: Send, S: NetSession, D: RpcDelegate<A, S>> {
    pub(super) delegate: D,
    /// The first unused id for RPC request-reply pairs.
    last_id: u64,
    /// RPC reply callbacks, mapped from the RPC id used in the request message.
    callbacks: HashMap<u64, RpcCb<D::Reply>>,
    _phantom: PhantomData<(A, S)>,
}

impl<A: Send, S: NetSession, D: RpcDelegate<A, S>> RpcService<A, S, D> {
    pub fn new(delegate: D) -> Self {
        RpcService {
            delegate,
            last_id: 0,
            callbacks: empty!(),
            _phantom: PhantomData,
        }
    }
}

impl<A: Send, S: NetSession, D: RpcDelegate<A, S>> ConnectionDelegate<A, S>
    for RpcService<A, S, D>
{
    fn connect(&self, remote: &A) -> S { self.delegate.connect(remote) }

    fn on_established(&self, artifact: S::Artifact, attempt: usize) {
        self.delegate.on_established(artifact, attempt)
    }

    fn on_disconnect(&self, err: io::Error, attempt: usize) -> OnDisconnect {
        self.delegate.on_disconnect(err, attempt)
    }

    fn on_io_error(&self, err: reactor::Error<ImpossibleResource, NetTransport<S>>) {
        self.delegate.on_io_error(err)
    }
}

impl<A: Send, S: NetSession, D: RpcDelegate<A, S>> ClientDelegate<A, S, RpcCb<D::Reply>>
    for RpcService<A, S, D>
{
    type Reply = RpcReply;

    fn before_send(&mut self, data: Vec<u8>, cb: RpcCb<D::Reply>) -> Vec<u8> {
        let id = self.last_id;
        #[cfg(feature = "log")]
        log::trace!(target: "netservices-client", "sending RPC request to the server (RPC id={id})");

        let mut req = Vec::with_capacity(data.len() + 9);
        let check = self.callbacks.insert(id, cb);
        debug_assert!(check.is_none());
        req.extend(id.to_le_bytes());
        req.extend(data);
        self.last_id += 1;
        req
    }

    fn on_reply(&mut self, msg: RpcReply) {
        let id = msg.id;
        if let Some(cb) = self.callbacks.remove(&id) {
            match D::Reply::try_from(msg.payload) {
                Ok(reply) => {
                    #[cfg(feature = "log")]
                    log::trace!(target: "netservices-client", "received RPC reply for the request with RPC id={id}. Calling callback.");

                    cb(reply)
                }
                Err(e) => {
                    #[cfg(feature = "log")]
                    log::error!(target: "netservices-client", "received unparsable RPC reply for the request with RPC id={id}. Parse error: {e}");

                    self.delegate.on_msg_error(RpcReplyError::UnparsableReply(id, e.to_string()))
                }
            }
        } else {
            #[cfg(feature = "log")]
            log::error!(target: "netservices-client", "received RPC reply from the server with no matching callback (RPC id={id})");

            self.delegate.on_msg_error(RpcReplyError::MismatchingReply(id, msg.payload));
        }
    }

    fn on_reply_unparsable(&mut self, err: ParseReplyError) {
        #[cfg(feature = "log")]
        log::error!(target: "netservices-client", "received unparsable server message. Parse error: {err}");

        self.delegate.on_msg_error(RpcReplyError::UnparsableMsg(err))
    }
}

/// The client runtime containing reactor thread managing connection to the remote server and the
/// use of the server APIs.
pub struct RpcClient<Req: Into<Vec<u8>>, Rep: TryFrom<Vec<u8>> + 'static> {
    inner: Client<Req, RpcCb<Rep>>,
}

impl<Req: Into<Vec<u8>>, Rep: TryFrom<Vec<u8>> + 'static> RpcClient<Req, Rep> {
    /// Constructs new client for RPC protocol. Takes service callback delegate and remote
    /// server address. Will attempt to connect to the server automatically once the reactor thread
    /// has started.
    pub fn new<
        A: Send + 'static,
        S: NetSession + 'static,
        D: RpcDelegate<A, S, Reply = Rep> + 'static,
    >(
        delegate: D,
        remote: A,
    ) -> io::Result<Self> {
        let rpc_service = RpcService::new(delegate);
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

    pub fn join(self) -> Result<(), Box<dyn Any + Send>> { self.inner.join() }
}
