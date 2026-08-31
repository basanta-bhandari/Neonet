//! Wires the already-implemented handshake, messaging router, and bootstrap
//! trust into an actual runnable TCP node. This module is intentionally thin:
//! every real decision (auth, routing, queueing) already lives in
//! `transport`, `messaging`, and `bootstrap` — this just connects sockets to
//! them.

use crate::{
    bootstrap::BootstrapEntry,
    identity::{Identity, PublicIdentity},
    messaging::{Message, MessagingFrame, Router},
    transport,
};
use std::{io, net::SocketAddr, sync::Arc};
use tokio::{
    net::{TcpListener, TcpStream},
    sync::{mpsc, Mutex},
};

/// Which identities are allowed to complete a handshake against this node
/// when it is acting as the accepting side (a core node accepting edges, or
/// an edge accepting an inbound peer). Bootstrap pinning already answers
/// "is this the core I meant to reach" for the dialing side; this answers
/// the accepting side's mirror question, "is this a peer I accept at all."
#[derive(Clone, Debug, Default)]
pub struct AllowList(Option<Vec<PublicIdentity>>);

impl AllowList {
    /// Accept any authenticated peer. Only appropriate for a first
    /// bring-up/testing node — real deployments should pass an explicit list.
    pub fn open() -> Self {
        Self(None)
    }

    pub fn only(identities: Vec<PublicIdentity>) -> Self {
        Self(Some(identities))
    }

    fn permits(&self, identity: &PublicIdentity) -> bool {
        match &self.0 {
            None => true,
            Some(list) => list.contains(identity),
        }
    }
}

/// A running node: owns the identity, the message router, and the listening
/// socket. Both core and edge roles use the same type — the only difference
/// is whether callers use `dial` (edge → core, pinned) or `serve` (accept
/// inbound connections, allow-listed).
pub struct Node {
    identity: Identity,
    router: Arc<Mutex<Router>>,
    features: Vec<String>,
    home: std::path::PathBuf,
}

impl Node {
    pub fn new(identity: Identity, queue_capacity_per_identity: usize) -> io::Result<Self> {
        let home = identity
            .path()
            .parent()
            .unwrap_or(std::path::Path::new("."))
            .to_path_buf();
        Self::with_home(identity, queue_capacity_per_identity, home)
    }

    /// Construct a node with an explicit state directory (`home`). This is the
    /// root for the receiving-side file cache, Burrow share config, encrypted
    /// blob cache, and lobby state — everything that must survive restarts.
    pub fn with_home(
        identity: Identity,
        queue_capacity_per_identity: usize,
        home: impl AsRef<std::path::Path>,
    ) -> io::Result<Self> {
        let home = home.as_ref().to_path_buf();
        std::fs::create_dir_all(&home)?;
        Ok(Self {
            identity,
            router: Arc::new(Mutex::new(Router::new(queue_capacity_per_identity)?)),
            features: vec![
                "messaging/1".to_string(),
                "files/1".to_string(),
                "burrow/1".to_string(),
                "storage/1".to_string(),
                "core/1".to_string(),
                "rendezvous/1".to_string(),
            ],
            home,
        })
    }

    pub fn identity(&self) -> PublicIdentity {
        self.identity.public()
    }

    /// The local signing identity, for building/signing manifests and frames.
    pub fn local(&self) -> &Identity {
        &self.identity
    }

    /// State directory root for persistent receiver/daemon data.
    pub fn home(&self) -> &std::path::Path {
        &self.home
    }

    /// Queue one authenticated application message into the router exactly as
    /// the wire reader would. The router handles local delivery, next-hop
    /// relay, or bounded offline storage.
    pub async fn send_raw(&self, message: Message) -> io::Result<()> {
        let _ = self.router.lock().await.send(message).await?;
        Ok(())
    }

    /// Poll until any of `identities` is reachable — via a direct next-hop or
    /// a dialed relay core. Returns `TimedOut` if the deadline passes first.
    pub async fn await_any_next_hop(
        &self,
        identities: &[PublicIdentity],
        timeout: std::time::Duration,
    ) -> io::Result<()> {
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            {
                let router = self.router.lock().await;
                if identities.iter().any(|identity| router.reachable(identity)) {
                    return Ok(());
                }
            }
            if tokio::time::Instant::now() >= deadline {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "no configured core accepted the connection",
                ));
            }
            tokio::time::sleep(std::time::Duration::from_millis(25)).await;
        }
    }

    /// Returns whether an authenticated next-hop connection to this identity
    /// is currently installed. Useful for readiness checks before a caller
    /// sends the first network message.
    pub async fn is_connected_to(&self, identity: &PublicIdentity) -> bool {
        self.router.lock().await.has_next_hop(identity)
    }

    /// Register locally for delivery and return a channel of inbound
    /// messages (queued-while-offline messages are delivered first, per
    /// `Router::register`).
    pub async fn register_local(&self) -> mpsc::Receiver<Message> {
        self.router.lock().await.register(self.identity())
    }

    /// Accept inbound connections (core role, or an edge willing to receive
    /// direct peer connections). Runs until the listener errors or the
    /// process is killed; each accepted connection is handled independently
    /// so one bad/slow peer cannot block others.
    pub async fn serve(self: Arc<Self>, addr: SocketAddr, allow: AllowList) -> io::Result<()> {
        let listener = TcpListener::bind(addr).await?;
        self.serve_listener(listener, allow).await
    }

    /// Same as `serve`, but takes an already-bound listener. Lets a caller
    /// (or a test) learn the actual bound address before accepting begins,
    /// without the bind/drop/rebind race of binding twice to "reserve" a
    /// port.
    pub async fn serve_listener(
        self: Arc<Self>,
        listener: TcpListener,
        allow: AllowList,
    ) -> io::Result<()> {
        loop {
            let (stream, peer_addr) = listener.accept().await?;
            let node = Arc::clone(&self);
            let allow = allow.clone();
            tokio::spawn(async move {
                if let Err(e) = node.handle_inbound(stream, peer_addr, &allow).await {
                    eprintln!("neonet: connection from {peer_addr} ended: {e}");
                }
            });
        }
    }

    async fn handle_inbound(
        &self,
        mut stream: TcpStream,
        peer_addr: SocketAddr,
        allow: &AllowList,
    ) -> io::Result<()> {
        let result =
            transport::handshake(&mut stream, &self.identity, self.features.clone()).await?;
        let remote_identity = result.remote.identity.clone();

        if !allow.permits(&remote_identity) {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!(
                    "peer {peer_addr} authenticated as {} but is not on the allow list",
                    remote_identity.fingerprint()
                ),
            ));
        }

        self.pump_connection(stream, remote_identity, false).await
    }

    /// Dial out to a core node, verifying its identity against the pinned
    /// bootstrap entry for that address before accepting anything it sends.
    pub async fn dial(self: Arc<Self>, bootstrap: &[BootstrapEntry]) -> io::Result<()> {
        // handshake_tcp_with_bootstrap requires a TcpStream already connected
        // to the peer address it will match against the bootstrap list, so
        // we connect to every configured core and let pinning reject any
        // that don't match — this also means a spoofed DNS/IP cannot
        // silently substitute an unpinned host.
        let mut last_err = None;
        for entry in bootstrap {
            match TcpStream::connect(entry.address).await {
                Ok(mut stream) => {
                    match transport::handshake_tcp_with_bootstrap(
                        &mut stream,
                        &self.identity,
                        self.features.clone(),
                        bootstrap,
                    )
                    .await
                    {
                        Ok(result) => {
                            let remote_identity = result.remote.identity.clone();
                            return self.pump_connection(stream, remote_identity, true).await;
                        }
                        Err(e) => last_err = Some(e),
                    }
                }
                Err(e) => last_err = Some(e),
            }
        }
        Err(last_err.unwrap_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                "no bootstrap core nodes configured",
            )
        }))
    }

    /// After a successful handshake, register the remote as a route and pump
    /// frames in both directions until the connection closes. A connection a
    /// node dialed *out* to a core is registered as a relay gateway; a
    /// connection dialed *in* is a direct next-hop for that device. On a relay
    /// connection the remote (trusted by pin or handshake) may forward other
    /// devices' messages, so sender attribution is accepted from it; on a
    /// direct connection a message claiming any other sender is spoofed and
    /// dropped.
    async fn pump_connection(
        &self,
        stream: TcpStream,
        remote_identity: PublicIdentity,
        is_relay: bool,
    ) -> io::Result<()> {
        let (mut read_half, mut write_half) = stream.into_split();
        let (out_tx, mut out_rx) = mpsc::channel::<Message>(64);

        self.router
            .lock()
            .await
            .set_next_hop(remote_identity.clone(), out_tx.clone());
        if is_relay {
            self.router.lock().await.set_relay(remote_identity.clone());
        }

        let router = Arc::clone(&self.router);
        let remote_for_reader = remote_identity.clone();
        let reader = tokio::spawn(async move {
            loop {
                let frame = match transport::read_frame(&mut read_half).await {
                    Ok(bytes) => bytes,
                    Err(_) => break,
                };
                let decoded = match MessagingFrame::decode(&frame) {
                    Ok(MessagingFrame::Message(message)) => message,
                    Err(_) => continue,
                };
                if !is_relay && decoded.sender != remote_for_reader {
                    // The transport already authenticated this connection as
                    // remote_for_reader; a message claiming a different
                    // sender is spoofed and is dropped rather than routed.
                    continue;
                }
                let mut router = router.lock().await;
                let _ = router.send(decoded).await;
            }
        });

        let writer = tokio::spawn(async move {
            while let Some(message) = out_rx.recv().await {
                let frame = match MessagingFrame::Message(message).encode() {
                    Ok(bytes) => bytes,
                    Err(_) => continue,
                };
                if transport::write_frame(&mut write_half, &frame)
                    .await
                    .is_err()
                {
                    break;
                }
            }
        });

        let _ = tokio::join!(reader, writer);
        let mut router = self.router.lock().await;
        router.remove_next_hop_if_current(&remote_identity, &out_tx);
        if is_relay {
            router.remove_relay(&remote_identity);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bootstrap::BootstrapEntry;

    async fn node() -> (Node, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let identity = Identity::load_or_generate(dir.path()).unwrap();
        (Node::new(identity, 16).unwrap(), dir)
    }

    #[tokio::test]
    async fn edge_dials_core_and_exchanges_a_message() {
        let (core, _core_dir) = node().await;
        let core = Arc::new(core);
        let core_identity = core.identity();

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let core_addr = listener.local_addr().unwrap();

        let allow = AllowList::open();
        let serve_core = Arc::clone(&core);
        tokio::spawn(async move {
            let _ = serve_core.serve_listener(listener, allow).await;
        });

        let (edge, _edge_dir) = node().await;
        let edge = Arc::new(edge);
        let edge_identity = edge.identity();

        let bootstrap = vec![BootstrapEntry {
            address: core_addr,
            pinned_public_key: core_identity.public_key,
        }];

        let core_rx_setup = core.register_local().await;
        let mut core_rx = core_rx_setup;

        let dialing_edge = Arc::clone(&edge);
        tokio::spawn(async move {
            let _ = dialing_edge.dial(&bootstrap).await;
        });
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(2);
        while !edge.is_connected_to(&core_identity).await {
            if tokio::time::Instant::now() >= deadline {
                panic!("edge never established an authenticated route to core");
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }

        let message =
            Message::new(edge_identity, core_identity, b"hello from edge".to_vec()).unwrap();
        edge.router
            .lock()
            .await
            .send(message.clone())
            .await
            .unwrap();

        let received = tokio::time::timeout(std::time::Duration::from_secs(2), core_rx.recv())
            .await
            .expect("message did not arrive before timeout")
            .expect("router channel closed");
        assert_eq!(received.payload, b"hello from edge");
    }
}
