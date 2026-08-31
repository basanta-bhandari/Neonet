//! Application-layer envelopes carried inside `Message.payload`.
//!
//! The transport handshake authenticates a connection and the router relays
//! by recipient identity; those layers never look inside the payload. This
//! module defines the typed requests/responses the v1 data features (`files`,
//! `burrow`, `storage`, `core`, `rendezvous`) speak over that authenticated
//! substrate. A payload that does not decode as an `AppFrame` is treated as a
//! legacy raw text message, preserving the messaging behavior that predates
//! this module.

pub mod burrow;
pub mod core;
pub mod files;
pub mod lobby;
pub mod pair;
pub mod rendezvous;
pub mod storage;

use crate::{
    messaging::{Message, MAX_MESSAGE_SIZE},
    node::Node,
};
use serde::{Deserialize, Serialize};
use std::{io, sync::Arc};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum AppFrame {
    /// Plain-text user message (also the fallback for legacy `Vec<u8>` payloads).
    Raw(Vec<u8>),
    Files(files::FilesFrame),
    Burrow(burrow::BurrowFrame),
    Storage(storage::StorageFrame),
    Core(core::CoreFrame),
    Rendezvous(rendezvous::RendezvousFrame),
    Pair(pair::PairFrame),
    Lobby(lobby::LobbyFrame),
    Channel(lobby::ChannelFrame),
}

impl AppFrame {
    pub fn encode(&self) -> io::Result<Vec<u8>> {
        let bytes = postcard::to_allocvec(self)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
        if bytes.len() > MAX_MESSAGE_SIZE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "application frame too large",
            ));
        }
        Ok(bytes)
    }

    /// Frames are postcard-encoded. Anything that fails to decode is a legacy
    /// raw text payload and is preserved as `AppFrame::Raw`, so old messages
    /// remain printable instead of being silently dropped.
    pub fn decode(bytes: &[u8]) -> Self {
        postcard::from_bytes(bytes).unwrap_or_else(|_| AppFrame::Raw(bytes.to_vec()))
    }
}

/// Outcome of handing one inbound message to the application layer.
#[derive(Debug, Default)]
pub struct Handling {
    /// Optional text to surface to the local operator (mail, transfer
    /// completion, directory-browse notifications, and so on).
    pub notify: Option<String>,
}

impl Handling {
    fn notify(text: impl Into<String>) -> Self {
        Self {
            notify: Some(text.into()),
        }
    }
}

/// Dispatch a message addressed to this node to the owning subsystem. Legacy
/// plain-text messages round-trip through `Raw` and are surfaced to the
/// operator exactly as before this module existed.
pub async fn handle(node: &Node, message: &Message) -> io::Result<Handling> {
    match AppFrame::decode(&message.payload) {
        AppFrame::Raw(payload) => match String::from_utf8(payload) {
            Ok(text) => Ok(Handling::notify(format!(
                "message {} from {}: {}",
                hex::encode(message.id),
                message.sender.fingerprint(),
                text
            ))),
            Err(_) => Ok(Handling::notify(format!(
                "message {} from {}: non-utf8 payload ({} bytes)",
                hex::encode(message.id),
                message.sender.fingerprint(),
                message.payload.len()
            ))),
        },
        AppFrame::Files(frame) => files::handle(node, message, frame).await,
        AppFrame::Burrow(frame) => burrow::handle(node, message, frame).await,
        AppFrame::Storage(frame) => storage::handle(node, message, frame).await,
        AppFrame::Core(frame) => core::handle(node, message, frame).await,
        AppFrame::Rendezvous(frame) => rendezvous::handle(node, message, frame).await,
        AppFrame::Pair(frame) => pair::handle(node, message, frame).await,
        AppFrame::Lobby(frame) => lobby::handle_lobby(node, message, frame).await,
        AppFrame::Channel(frame) => lobby::handle_channel(node, message, frame).await,
    }
}

/// Reply to `request` routed back at `request.sender`, reusing the request's
/// message id so a client can correlate without inventing a second id space.
pub(crate) async fn reply(node: &Node, request: &Message, frame: AppFrame) -> io::Result<()> {
    let payload = frame.encode()?;
    let message = Message {
        id: request.id,
        sender: node.identity(),
        recipient: request.sender.clone(),
        payload,
    };
    node.send_raw(message).await
}

/// Request/response client used by the one-shot CLI commands and tests.
///
/// Responses are correlated by echoing the request's message id into the
/// reply's id. A pump task relives the inbox: awaited request/response pairs
/// are matched by id, anything else (an unsolicited push, a stray message) is
/// handed to the normal `handle` dispatcher and surfaced in the terminal.
pub struct Client {
    node: Arc<Node>,
    waiting: Arc<
        tokio::sync::Mutex<
            std::collections::HashMap<
                crate::messaging::MessageId,
                tokio::sync::mpsc::Sender<Message>,
            >,
        >,
    >,
    pump: tokio::task::JoinHandle<()>,
}

impl Client {
    pub async fn connect(node: Arc<Node>) -> io::Result<Self> {
        let mut inbox = node.register_local().await;
        let waiting: Arc<
            tokio::sync::Mutex<
                std::collections::HashMap<
                    crate::messaging::MessageId,
                    tokio::sync::mpsc::Sender<Message>,
                >,
            >,
        > = Arc::new(tokio::sync::Mutex::new(std::collections::HashMap::new()));
        let pump_waiting = Arc::clone(&waiting);
        let pump_node = Arc::clone(&node);
        let pump = tokio::spawn(async move {
            while let Some(message) = inbox.recv().await {
                let matched = {
                    let mut waiting = pump_waiting.lock().await;
                    waiting.remove(&message.id)
                };
                match matched {
                    Some(tx) => {
                        if tx.send(message).await.is_err() {
                            // The awaiting caller dropped its receiver; nothing
                            // to surface.
                        }
                    }
                    None => match handle(&pump_node, &message).await {
                        Ok(outcome) => {
                            if let Some(text) = outcome.notify {
                                eprintln!("[neonet] {text}");
                            }
                        }
                        Err(e) => eprintln!("[neonet] error handling inbound message: {e}"),
                    },
                }
            }
        });
        Ok(Self {
            node,
            waiting,
            pump,
        })
    }

    /// Send one request and await the uniquely-correlated response. The caller
    /// must wait for a route to `peer` before this returns without error.
    pub async fn call(
        &mut self,
        peer: &crate::identity::PublicIdentity,
        frame: AppFrame,
    ) -> io::Result<Message> {
        let frame_bytes = frame.encode()?;
        let message = Message::new(self.node.identity(), peer.clone(), frame_bytes)?;
        let request_id = message.id;
        let (tx, mut rx) = tokio::sync::mpsc::channel::<Message>(1);
        {
            let mut waiting = self.waiting.lock().await;
            waiting.insert(request_id, tx);
        }
        self.node.send_raw(message).await?;
        rx.recv().await.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::BrokenPipe,
                "peer closed the response channel",
            )
        })
    }

    pub fn node(&self) -> &Arc<Node> {
        &self.node
    }
}

impl Drop for Client {
    fn drop(&mut self) {
        self.pump.abort();
    }
}
