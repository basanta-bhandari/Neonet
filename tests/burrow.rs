//! End-to-end Burrow access across the same three-node topology as file
//! transfer: an edge client browses and reads a peer's read-only share through
//! the shared relay core, and the share is never mutated by any operation.

use neonet::{
    app::{self, burrow::BurrowFrame},
    bootstrap::BootstrapEntry,
    identity::{Identity, PublicIdentity},
    node::{AllowList, Node},
};
use std::sync::Arc;

async fn spawn_core(home: &tempfile::TempDir) -> (Arc<Node>, std::net::SocketAddr) {
    let identity = Identity::load_or_generate(home.path()).unwrap();
    let core = Arc::new(Node::with_home(identity, 64, home.path()).unwrap());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let serving = Arc::clone(&core);
    tokio::spawn(async move {
        let _ = serving.serve_listener(listener, AllowList::open()).await;
    });
    (core, addr)
}

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
async fn browse_and_fork_read_only_share_through_relay_core() {
    let core_home = tempfile::tempdir().unwrap();
    let host_home = tempfile::tempdir().unwrap();
    let client_home = tempfile::tempdir().unwrap();

    // The host's shared directory: one file, one subtree, and one symlink.
    std::fs::create_dir_all(host_home.path().join("share").join("sub")).unwrap();
    std::fs::write(
        host_home.path().join("share").join("hello.txt"),
        b"hi from the share",
    )
    .unwrap();
    std::fs::write(
        host_home.path().join("share").join("sub").join("net.txt"),
        b"nested",
    )
    .unwrap();
    std::os::unix::fs::symlink("hello.txt", host_home.path().join("share").join("link.txt"))
        .unwrap();

    let (core, core_addr) = spawn_core(&core_home).await;
    let bootstrap = vec![BootstrapEntry {
        address: core_addr,
        pinned_public_key: core.identity().public_key,
    }];

    let (host_node, host_id) = spawn_edge(&host_home, bootstrap.clone()).await;
    let (client_node, _client_id) = spawn_edge(&client_home, bootstrap).await;

    // The host runs an app pump so List/Read/Fork requests are handled.
    let _host_client = app::Client::connect(Arc::clone(&host_node)).await.unwrap();
    let mut client = app::Client::connect(Arc::clone(&client_node))
        .await
        .unwrap();
    client_node
        .await_any_next_hop(&[host_id.clone()], std::time::Duration::from_secs(5))
        .await
        .unwrap();

    // Browse the share root: every kind of entry, never any file content.
    let reply = client
        .call(
            &host_id,
            app::AppFrame::Burrow(BurrowFrame::List { path: ".".into() }),
        )
        .await
        .unwrap();
    let entries = match app::AppFrame::decode(&reply.payload) {
        app::AppFrame::Burrow(BurrowFrame::Listing { entries, .. }) => entries,
        other => panic!("unexpected reply: {other:?}"),
    };
    let hello = entries
        .iter()
        .find(|e| e.name == "hello.txt")
        .expect("hello.txt missing from listing");
    assert_eq!(hello.size, "hi from the share".len() as u64);
    let sub = entries
        .iter()
        .find(|e| e.name == "sub")
        .expect("sub missing");
    assert!(matches!(sub.kind, neonet::burrow::EntryKind::Directory));
    let link = entries
        .iter()
        .find(|e| e.name == "link.txt")
        .expect("symlink missing");
    assert!(matches!(link.kind, neonet::burrow::EntryKind::Symlink));

    // Read a file through the mesh: bytes must match on the client side.
    let reply = client
        .call(
            &host_id,
            app::AppFrame::Burrow(BurrowFrame::Read {
                path: "sub/net.txt".into(),
            }),
        )
        .await
        .unwrap();
    match app::AppFrame::decode(&reply.payload) {
        app::AppFrame::Burrow(BurrowFrame::Content { bytes, .. }) => assert_eq!(bytes, b"nested"),
        other => panic!("unexpected reply: {other:?}"),
    }

    // A symlink is visible but NOT readable (read-only means no surprises).
    let reply = client
        .call(
            &host_id,
            app::AppFrame::Burrow(BurrowFrame::Read {
                path: "link.txt".into(),
            }),
        )
        .await
        .unwrap();
    assert!(matches!(
        app::AppFrame::decode(&reply.payload),
        app::AppFrame::Burrow(BurrowFrame::Error { .. })
    ));

    // Traversal cannot escape the share root.
    let reply = client
        .call(
            &host_id,
            app::AppFrame::Burrow(BurrowFrame::Read {
                path: "../secrets.txt".into(),
            }),
        )
        .await
        .unwrap();
    assert!(matches!(
        app::AppFrame::decode(&reply.payload),
        app::AppFrame::Burrow(BurrowFrame::Error { .. })
    ));

    // Host-side fork stages a full copy into the host's own forked/ directory,
    // and the share itself is untouched by everything above.
    let reply = client
        .call(
            &host_id,
            app::AppFrame::Burrow(BurrowFrame::Fork {
                path: "hello.txt".into(),
            }),
        )
        .await
        .unwrap();
    match app::AppFrame::decode(&reply.payload) {
        app::AppFrame::Burrow(BurrowFrame::ForkResult { path, ok: true, .. }) => {
            assert_eq!(path, "hello.txt");
        }
        other => panic!("unexpected reply: {other:?}"),
    }
    let staged = std::fs::read(host_home.path().join("forked").join("hello.txt")).unwrap();
    assert_eq!(staged, b"hi from the share");
    assert_eq!(
        std::fs::read(host_home.path().join("share").join("hello.txt")).unwrap(),
        b"hi from the share"
    );
}
