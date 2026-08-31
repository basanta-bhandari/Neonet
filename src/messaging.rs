//! Messaging primitives and bounded offline delivery.
//!
//! The transport handshake authenticates the peer; this module defines the
//! application message envelope and the core's bounded per-identity queue.
//! Direct delivery is preferred whenever the recipient is connected. A core
//! can use the same router abstraction for locally attached edges and later
//! forward the envelope over an authenticated core-to-core connection.

use crate::identity::PublicIdentity;
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};
use std::io;
use tokio::sync::mpsc;

/// Maximum serialized application message accepted by the messaging layer.
pub const MAX_MESSAGE_SIZE: usize = 1024 * 1024;

/// A stable identifier for one message. It is intentionally independent from
/// the transport session so a message can survive relay and offline storage.
pub type MessageId = [u8; 16];

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Message {
    pub id: MessageId,
    pub sender: PublicIdentity,
    pub recipient: PublicIdentity,
    pub payload: Vec<u8>,
}

impl Message {
    pub fn new(
        sender: PublicIdentity,
        recipient: PublicIdentity,
        payload: Vec<u8>,
    ) -> io::Result<Self> {
        let mut id = [0u8; 16];
        OsRng.fill_bytes(&mut id);
        let message = Self {
            id,
            sender,
            recipient,
            payload,
        };
        message.validate_size()?;
        Ok(message)
    }

    pub fn validate_size(&self) -> io::Result<()> {
        let encoded = postcard::to_allocvec(self)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
        if encoded.len() > MAX_MESSAGE_SIZE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "message too large",
            ));
        }
        Ok(())
    }
}

/// Wire representation used after the authenticated transport handshake.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum MessagingFrame {
    Message(Message),
}

/// Send one authenticated-transport application message. The caller is
/// responsible for completing `transport::handshake` on the stream first.
pub async fn send_message<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin>(
    stream: &mut S,
    message: Message,
) -> io::Result<()> {
    message.validate_size()?;
    let frame = MessagingFrame::Message(message).encode()?;
    crate::transport::write_frame(stream, &frame).await
}

/// Receive one application message from an already-authenticated stream.
/// The sender identity is checked against the identity authenticated by the
/// transport handshake; a peer cannot simply claim to be another device.
pub async fn receive_message<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin>(
    stream: &mut S,
    authenticated_sender: &PublicIdentity,
) -> io::Result<Message> {
    let frame = MessagingFrame::decode(&crate::transport::read_frame(stream).await?)?;
    match frame {
        MessagingFrame::Message(message) => {
            message.validate_size()?;
            if &message.sender != authenticated_sender {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "message sender does not match authenticated peer",
                ));
            }
            Ok(message)
        }
    }
}

impl MessagingFrame {
    pub fn encode(&self) -> io::Result<Vec<u8>> {
        let bytes = postcard::to_allocvec(self)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
        if bytes.len() > MAX_MESSAGE_SIZE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "message frame too large",
            ));
        }
        Ok(bytes)
    }

    pub fn decode(bytes: &[u8]) -> io::Result<Self> {
        if bytes.len() > MAX_MESSAGE_SIZE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "message frame too large",
            ));
        }
        postcard::from_bytes(bytes)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))
    }
}

/// Bounded offline queue, maintained independently for each recipient
/// identity. Dropping the oldest message makes the capacity bound explicit;
/// callers can observe the returned evicted message and surface a delivery
/// failure/metric without turning the whole service into a hard failure.
#[derive(Debug)]
pub struct OfflineQueue {
    capacity: usize,
    queues: HashMap<PublicIdentity, VecDeque<Message>>,
}

impl OfflineQueue {
    pub fn new(capacity_per_identity: usize) -> io::Result<Self> {
        if capacity_per_identity == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "queue capacity must be > 0",
            ));
        }
        Ok(Self {
            capacity: capacity_per_identity,
            queues: HashMap::new(),
        })
    }

    pub fn push(&mut self, message: Message) -> Option<Message> {
        let recipient = message.recipient.clone();
        let queue = self.queues.entry(recipient).or_default();
        queue.push_back(message);
        if queue.len() > self.capacity {
            queue.pop_front()
        } else {
            None
        }
    }

    pub fn drain(&mut self, recipient: &PublicIdentity) -> Vec<Message> {
        self.queues
            .remove(recipient)
            .map(|q| q.into_iter().collect())
            .unwrap_or_default()
    }

    pub fn len(&self, recipient: &PublicIdentity) -> usize {
        self.queues.get(recipient).map_or(0, VecDeque::len)
    }
}

/// A local delivery router. Connected recipients are delivered immediately;
/// disconnected recipients enter the bounded per-identity offline queue.
///
/// Core-to-core forwarding deliberately remains outside this type: the
/// authenticated transport supplies the next-hop connection, while this
/// router owns the recipient queue and delivery semantics.
pub struct Router {
    peers: HashMap<PublicIdentity, mpsc::Sender<Message>>,
    next_hops: HashMap<PublicIdentity, mpsc::Sender<Message>>,
    /// Cores this node dialed up as a gateway. Messages to identities with no
    /// direct next-hop are forwarded to a relay, which routes them onward.
    relays: HashSet<PublicIdentity>,
    offline: OfflineQueue,
}

impl Router {
    pub fn new(queue_capacity_per_identity: usize) -> io::Result<Self> {
        Ok(Self {
            peers: HashMap::new(),
            next_hops: HashMap::new(),
            relays: HashSet::new(),
            offline: OfflineQueue::new(queue_capacity_per_identity)?,
        })
    }

    /// Register a recipient and return its receiving end. Any queued messages
    /// are delivered first, preserving FIFO order for that recipient.
    pub fn register(&mut self, identity: PublicIdentity) -> mpsc::Receiver<Message> {
        let (tx, rx) = mpsc::channel(self.offline.capacity);
        let queued = self.offline.drain(&identity);
        for message in queued {
            // A freshly-created channel with this capacity cannot be full yet.
            let _ = tx.try_send(message);
        }
        self.peers.insert(identity, tx);
        rx
    }

    pub fn unregister(&mut self, identity: &PublicIdentity) {
        self.peers.remove(identity);
    }

    /// Configure a next-hop authenticated core connection for a destination.
    /// This is the core relay primitive: the local core does not need a direct
    /// edge-to-edge connection to the destination.
    pub fn set_next_hop(&mut self, destination: PublicIdentity, next_hop: mpsc::Sender<Message>) {
        self.next_hops.insert(destination, next_hop);
    }

    pub fn remove_next_hop(&mut self, destination: &PublicIdentity) {
        self.next_hops.remove(destination);
    }

    /// Remove the next-hop entry for `destination` only if it is still owned
    /// by `expected`. Connections are keyed by remote identity, so a later
    /// connection from a process sharing that identity (every `neonet` CLI
    /// invocation is a new process) may have replaced the entry; tearing down
    /// a dying connection must not clobber a live replacement.
    pub fn remove_next_hop_if_current(
        &mut self,
        destination: &PublicIdentity,
        expected: &mpsc::Sender<Message>,
    ) {
        if let Some(current) = self.next_hops.get(destination) {
            if current.same_channel(expected) {
                self.next_hops.remove(destination);
            }
        }
    }

    pub fn has_next_hop(&self, destination: &PublicIdentity) -> bool {
        self.next_hops.contains_key(destination)
    }

    /// Configure a core node this node dialed as a relay gateway. Messages to
    /// identities without a direct next-hop are forwarded to a relay instead
    /// of being dropped to offline storage.
    pub fn set_relay(&mut self, relay: PublicIdentity) {
        self.relays.insert(relay);
    }

    pub fn remove_relay(&mut self, relay: &PublicIdentity) {
        self.relays.remove(relay);
    }

    /// True once a message to `destination` can be delivered: either a direct
    /// next-hop exists, or a relay gateway can carry it.
    pub fn reachable(&self, destination: &PublicIdentity) -> bool {
        self.next_hops.contains_key(destination) || !self.relays.is_empty()
    }

    /// Deliver directly when possible, otherwise enqueue for bounded offline
    /// delivery. Returns an evicted message if the queue was already full.
    pub async fn send(&mut self, message: Message) -> io::Result<Option<Message>> {
        message.validate_size()?;
        if let Some(peer) = self.peers.get(&message.recipient).cloned() {
            match peer.send(message.clone()).await {
                Ok(()) => return Ok(None),
                Err(_) => {
                    self.peers.remove(&message.recipient);
                }
            }
        }

        if let Some(next_hop) = self.next_hops.get(&message.recipient).cloned() {
            match next_hop.send(message.clone()).await {
                Ok(()) => return Ok(None),
                Err(_) => {
                    self.next_hops.remove(&message.recipient);
                }
            }
        }

        // No direct route: forward to a relay gateway. The relay routes the
        // message onward; the receiver still verifies sender attribution at
        // its own ingress, so this is transit, not trust in the relay.
        for relay in &self.relays {
            if let Some(next_hop) = self.next_hops.get(relay).cloned() {
                match next_hop.send(message.clone()).await {
                    Ok(()) => return Ok(None),
                    Err(_) => {
                        self.next_hops.remove(relay);
                    }
                }
            }
        }

        Ok(self.offline.push(message))
    }

    pub fn queued(&self, recipient: &PublicIdentity) -> usize {
        self.offline.len(recipient)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identity() -> PublicIdentity {
        let dir = tempfile::tempdir().unwrap();
        crate::identity::Identity::load_or_generate(dir.path())
            .unwrap()
            .public()
    }

    #[tokio::test]
    async fn direct_delivery_prefers_connected_peer() {
        let sender = identity();
        let recipient = identity();
        let mut router = Router::new(2).unwrap();
        let mut rx = router.register(recipient.clone());
        let message = Message::new(sender.clone(), recipient.clone(), b"hello".to_vec()).unwrap();
        assert!(router.send(message.clone()).await.unwrap().is_none());
        assert_eq!(rx.recv().await.unwrap(), message);
        assert_eq!(router.queued(&recipient), 0);
    }

    #[tokio::test]
    async fn disconnected_messages_are_bounded_per_identity() {
        let sender = identity();
        let recipient = identity();
        let mut router = Router::new(2).unwrap();
        for text in [b"one".as_slice(), b"two".as_slice(), b"three".as_slice()] {
            router
                .send(Message::new(sender.clone(), recipient.clone(), text.to_vec()).unwrap())
                .await
                .unwrap();
        }
        assert_eq!(router.queued(&recipient), 2);
        let mut rx = router.register(recipient.clone());
        assert_eq!(rx.recv().await.unwrap().payload, b"two");
        assert_eq!(rx.recv().await.unwrap().payload, b"three");
    }

    #[tokio::test]
    async fn next_hop_relays_when_recipient_is_not_local() {
        let sender = identity();
        let recipient = identity();
        let mut local = Router::new(2).unwrap();
        let (next_hop_tx, mut next_hop_rx) = mpsc::channel(2);
        local.set_next_hop(recipient.clone(), next_hop_tx);

        let message = Message::new(sender, recipient.clone(), b"relay".to_vec()).unwrap();
        assert!(local.send(message.clone()).await.unwrap().is_none());
        assert_eq!(next_hop_rx.recv().await.unwrap(), message);
        assert_eq!(local.queued(&recipient), 0);
    }

    #[tokio::test]
    async fn stale_connection_cleanup_does_not_clobber_a_replacement_route() {
        let recipient = identity();
        let sender = identity();
        let mut router = Router::new(2).unwrap();

        // Two sequential connections carrying the same identity, as happens
        // when distinct `neonet` CLI processes reuse one home. The second one
        // replaces the route; the first connection's teardown must not remove
        // it, or all traffic for the identity silently queues offline.
        let (first, _first_rx) = mpsc::channel(2);
        let (second, _second_rx) = mpsc::channel(2);
        router.set_next_hop(recipient.clone(), first.clone());
        router.set_next_hop(recipient.clone(), second.clone());

        router.remove_next_hop_if_current(&recipient, &first);
        assert!(
            router.has_next_hop(&recipient),
            "replacement route must survive the stale cleanup"
        );

        router.remove_next_hop_if_current(&recipient, &second);
        assert!(
            !router.has_next_hop(&recipient),
            "owning connection may remove its route"
        );

        // The replacement route still delivers after the stale teardown ran.
        let (third, mut third_rx) = mpsc::channel(2);
        router.set_next_hop(recipient.clone(), third);
        let message = Message::new(sender, recipient.clone(), b"relay".to_vec()).unwrap();
        assert!(router.send(message.clone()).await.unwrap().is_none());
        assert_eq!(third_rx.recv().await.unwrap(), message);
    }

    #[test]
    fn message_wire_round_trip() {
        let sender = identity();
        let recipient = identity();
        let message = Message::new(sender, recipient, b"wire".to_vec()).unwrap();
        let encoded = MessagingFrame::Message(message.clone()).encode().unwrap();
        assert_eq!(
            MessagingFrame::decode(&encoded).unwrap(),
            MessagingFrame::Message(message)
        );
    }
}
