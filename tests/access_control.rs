//! The accepting side's `--allow-file` gate: an inbound connection completes
//! the authenticated handshake, but is refused (never promoted to a routing
//! route) unless its public key is in the allow-list. The dialing peer sees a
//! silent disconnect — it is not a member and the core never installs a route
//! for it, so nothing it sends can ever reach the mesh.

use neonet::{
    identity::{Identity, PublicIdentity},
    messaging::Message,
    node::{AllowList, Node},
};
use std::sync::Arc;

async fn registered_peer(home: &tempfile::TempDir) -> Arc<Node> {
    let identity = Identity::load_or_generate(home.path()).unwrap();
    Arc::new(Node::with_home(identity, 16, home.path()).unwrap())
}

#[tokio::test]
async fn allow_list_gates_inbound_connections_by_full_key() {
    let core_home = tempfile::tempdir().unwrap();
    let allowed_home = tempfile::tempdir().unwrap();
    let denied_home = tempfile::tempdir().unwrap();

    let core_identity = Identity::load_or_generate(core_home.path()).unwrap();
    let allowed_identity = Identity::load_or_generate(allowed_home.path())
        .unwrap()
        .public();
    let denied_identity = Identity::load_or_generate(denied_home.path())
        .unwrap()
        .public();
    assert_ne!(allowed_identity, denied_identity);

    let core = Arc::new(Node::with_home(core_identity, 64, core_home.path()).unwrap());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let serving = Arc::clone(&core);
    let allowed = allowed_identity.clone();
    tokio::spawn(async move {
        // The allow-list contains the *full* public key, exactly what
        // `neonet core --allow-file` parses.
        let _ = serving
            .serve_listener(listener, AllowList::only(vec![allowed]))
            .await;
    });

    let bootstrap = vec![neonet::bootstrap::BootstrapEntry {
        address: addr,
        pinned_public_key: core.identity().public_key,
    }];

    // The allow-listed peer is welcomed and holds a route.
    let allowed_peer = registered_peer(&allowed_home).await;
    let dialing = Arc::clone(&allowed_peer);
    let bootstrap_allowed = bootstrap.clone();
    tokio::spawn(async move {
        let _ = dialing.dial(&bootstrap_allowed).await;
    });
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(3);
    while !allowed_peer.is_connected_to(&core.identity()).await {
        if tokio::time::Instant::now() >= deadline {
            panic!("allow-listed peer never established a route");
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }

    // Exchange a message so the route is genuinely live.
    let mut core_rx = core.register_local().await;
    let message = Message::new(
        allowed_peer.identity(),
        core.identity(),
        b"hi from allowed".to_vec(),
    )
    .unwrap();
    allowed_peer.send_raw(message).await.unwrap();
    let received = tokio::time::timeout(std::time::Duration::from_secs(3), core_rx.recv()).await;
    assert!(
        matches!(received, Ok(Some(msg)) if msg.payload == b"hi from allowed"),
        "allow-listed peer's message must reach the core"
    );

    // The denied peer completes the handshake (the allow check is the core's
    // next step) but is quietly dropped: no route for it is ever installed on
    // the core, so nothing it sends can reach the mesh.
    let denied_peer = registered_peer(&denied_home).await;
    let boot_denied = bootstrap.clone();
    let dialing_denied = Arc::clone(&denied_peer);
    tokio::spawn(async move {
        let _ = dialing_denied.dial(&boot_denied).await;
    });
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    assert!(
        !core.is_connected_to(&denied_identity).await,
        "core must never install a route for a non-allow-listed peer"
    );

    // And even the denied peer's own (transient, one-directional) dial route
    // cannot reach through the core: a relayed message it sends must never be
    // delivered there. The route disappears once the core's disconnect is seen.
    let mut messages_from_denied = core.register_local().await;
    let unsolicited = Message::new(
        denied_identity.clone(),
        core.identity(),
        b"smuggle".to_vec(),
    )
    .unwrap();
    let queued = denied_peer.send_raw(unsolicited).await;
    assert!(queued.is_ok(), "denied peer may still send into the void");
    let delivered = tokio::time::timeout(
        std::time::Duration::from_millis(400),
        messages_from_denied.recv(),
    )
    .await;
    assert!(
        delivered.is_err(),
        "a refused peer's message must never be delivered to the core"
    );
    let _: PublicIdentity = denied_identity;
}
