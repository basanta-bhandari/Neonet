//! End-to-end file transfer across a real three-node topology: two edge
//! devices connected through a shared relay core. Exercises the full
//! announce/accept/chunk/complete handshake, BLAKE3 verification at the
//! receiver, reconstruction, and sender status polling.

use neonet::{
    app::{self},
    bootstrap::BootstrapEntry,
    identity::{Identity, PublicIdentity},
    node::{AllowList, Node},
};
use std::sync::Arc;

fn deterministic_bytes(size: usize) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(size);
    let mut seed = 0x1234_5678_9abc_def0u64;
    for _ in 0..size {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        bytes.push(seed as u8);
    }
    bytes
}

/// Start an edge node at `home` that dials the core described in `bootstrap`,
/// returning the node and the identity it advertises.
async fn spawn_edge(
    home: &tempfile::TempDir,
    bootstrap: Vec<BootstrapEntry>,
) -> (Arc<Node>, PublicIdentity) {
    let identity = Identity::load_or_generate(home.path()).unwrap();
    let advertised = identity.public();
    let node = Arc::new(Node::with_home(identity, 64, home.path()).unwrap());
    let dialing = Arc::clone(&node);
    tokio::spawn(async move {
        let _ = dialing.dial(&bootstrap).await;
    });
    (node, advertised)
}

#[tokio::test]
async fn file_transfer_succeeds_through_a_relay_core() {
    let core_home = tempfile::tempdir().unwrap();
    let receiver_home = tempfile::tempdir().unwrap();
    let sender_home = tempfile::tempdir().unwrap();

    let core_identity = Identity::load_or_generate(core_home.path()).unwrap();
    let core = Arc::new(Node::with_home(core_identity, 64, core_home.path()).unwrap());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let core_addr = listener.local_addr().unwrap();
    let serving = Arc::clone(&core);
    tokio::spawn(async move {
        let _ = serving.serve_listener(listener, AllowList::open()).await;
    });

    let bootstrap = vec![BootstrapEntry {
        address: core_addr,
        pinned_public_key: core.identity().public_key,
    }];

    let (receiver_node, receiver_id) = spawn_edge(&receiver_home, bootstrap.clone()).await;
    let (sender_node, _sender_id) = spawn_edge(&sender_home, bootstrap).await;

    // The receiver runs an app pump so inbound frames (announce, chunks,
    // status requests) are handled and answered. Holding the client keeps the
    // pump's node alive for the duration of the transfer.
    let _receiver_client = app::Client::connect(Arc::clone(&receiver_node))
        .await
        .unwrap();
    let mut sender_client = app::Client::connect(Arc::clone(&sender_node))
        .await
        .unwrap();

    // Wait for an actual mesh route from sender to receiver.
    sender_node
        .await_any_next_hop(&[receiver_id.clone()], std::time::Duration::from_secs(5))
        .await
        .unwrap();

    let source = sender_home.path().join("payload.bin");
    let payload = deterministic_bytes(2_600_000);
    std::fs::write(&source, &payload).unwrap();

    let started = std::time::Instant::now();
    let state = app::files::send_file_and_wait(
        &receiver_id,
        &mut sender_client,
        source.clone(),
        std::time::Duration::from_secs(60),
    )
    .await
    .expect("send_file_and_wait failed");
    assert!(
        state.complete(),
        "transfer did not complete within the deadline"
    );
    assert_eq!(state.manifest.total_size, payload.len() as u64);

    // The receiver must have reconstructed a byte-identical file on disk.
    let id = neonet::files::manifest_id_from_state(&state);
    let expected = receiver_home
        .path()
        .join("incoming")
        .join(&id)
        .join(&state.manifest.name);
    let received = std::fs::read(&expected).expect("reconstructed file missing");
    assert_eq!(
        received, payload,
        "reconstructed file does not match the original"
    );

    // The relay route made the transfer travel through the core; assert the
    // far side genuinely recorded it by asking the receiver for a status.
    let request = app::AppFrame::Files(app::files::FilesFrame::StatusRequest {
        manifest_id: id.clone(),
    });
    let reply = sender_client.call(&receiver_id, request).await.unwrap();
    match app::AppFrame::decode(&reply.payload) {
        app::AppFrame::Files(app::files::FilesFrame::Status { state: remote, .. }) => {
            assert!(remote.complete());
            assert_eq!(remote.verified_chunks.len(), state.verified_chunks.len());
        }
        other => panic!("unexpected reply: {other:?}"),
    }

    // `neonet transfers` on the receiver must list it as complete.
    let summaries = neonet::files::list_transfers(receiver_home.path()).unwrap();
    assert_eq!(summaries.len(), 1);
    assert_eq!(summaries[0].verified, summaries[0].total);
    assert!(!started.elapsed().is_zero());
}
