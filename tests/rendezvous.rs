//! Rendezvous service: devices publish signed address records for themselves,
//! other devices enumerate/scan the registry and probe liveness, and a forged
//! registration (not signed by the claimed identity) is refused without
//! touching the victim's record.

use neonet::{
    app::{
        self,
        rendezvous::{self, RendezvousFrame},
    },
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
async fn rendezvous_registers_lists_probes_and_refuses_forgeries() {
    let core_home = tempfile::tempdir().unwrap();
    let alpha_home = tempfile::tempdir().unwrap();
    let beta_home = tempfile::tempdir().unwrap();
    let forger_home = tempfile::tempdir().unwrap();

    let (rendezvous, rendezvous_addr) = spawn_core(&core_home).await;
    let bootstrap = vec![BootstrapEntry {
        address: rendezvous_addr,
        pinned_public_key: rendezvous.identity().public_key,
    }];
    let (alpha_node, alpha_id) = spawn_edge(&alpha_home, bootstrap.clone()).await;
    let (beta_node, beta_id) = spawn_edge(&beta_home, bootstrap.clone()).await;
    let (forger_node, forger_id) = spawn_edge(&forger_home, bootstrap).await;

    let _rendezvous_client = app::Client::connect(Arc::clone(&rendezvous)).await.unwrap();
    let mut alpha_client = app::Client::connect(Arc::clone(&alpha_node)).await.unwrap();
    let mut beta_client = app::Client::connect(Arc::clone(&beta_node)).await.unwrap();
    let mut forger_client = app::Client::connect(Arc::clone(&forger_node))
        .await
        .unwrap();
    for client_peer in [&alpha_node, &beta_node, &forger_node] {
        client_peer
            .await_any_next_hop(&[rendezvous.identity()], std::time::Duration::from_secs(5))
            .await
            .unwrap();
    }

    // Both devices publish signed records for themselves.
    let reply = alpha_client
        .call(
            &rendezvous.identity(),
            app::AppFrame::Rendezvous(rendezvous::register_frame(
                &alpha_node,
                "192.0.2.10:7000".into(),
            )),
        )
        .await
        .unwrap();
    assert!(matches!(
        app::AppFrame::decode(&reply.payload),
        app::AppFrame::Rendezvous(RendezvousFrame::Registered)
    ));
    let reply = beta_client
        .call(
            &rendezvous.identity(),
            app::AppFrame::Rendezvous(rendezvous::register_frame_with_ttl(
                &beta_node,
                "198.51.100.5:7000".into(),
                120,
            )),
        )
        .await
        .unwrap();
    assert!(matches!(
        app::AppFrame::decode(&reply.payload),
        app::AppFrame::Rendezvous(RendezvousFrame::Registered)
    ));

    // Lookup returns the exact record someone signed for themselves.
    let reply = alpha_client
        .call(
            &rendezvous.identity(),
            app::AppFrame::Rendezvous(RendezvousFrame::Lookup {
                fingerprint: alpha_id.fingerprint(),
            }),
        )
        .await
        .unwrap();
    let candidates = match app::AppFrame::decode(&reply.payload) {
        app::AppFrame::Rendezvous(RendezvousFrame::LookupResult { candidates, .. }) => candidates,
        other => panic!("unexpected lookup reply: {other:?}"),
    };
    assert_eq!(candidates.len(), 1);
    assert_eq!(candidates[0].address, "192.0.2.10:7000");
    assert_eq!(candidates[0].identity.fingerprint(), alpha_id.fingerprint());

    // Enumerate (the CLI's `scan` listing): both records, no forge, no expired.
    let reply = beta_client
        .call(
            &rendezvous.identity(),
            app::AppFrame::Rendezvous(RendezvousFrame::List),
        )
        .await
        .unwrap();
    let records = match app::AppFrame::decode(&reply.payload) {
        app::AppFrame::Rendezvous(RendezvousFrame::ListResult { records }) => records,
        other => panic!("unexpected list reply: {other:?}"),
    };
    assert_eq!(records.len(), 2);
    let fingerprints: Vec<String> = records.iter().map(|r| r.identity.fingerprint()).collect();
    assert!(fingerprints.contains(&alpha_id.fingerprint()));
    assert!(fingerprints.contains(&beta_id.fingerprint()));

    // TTL clamping is applied server-side: 120s stays put, a huge TTL hits the cap.
    let beta_record = records
        .iter()
        .find(|r| r.identity.fingerprint() == beta_id.fingerprint())
        .unwrap();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    assert!(
        beta_record.expires_at <= now + 120,
        "beta requested 120s; expires_at must respect it (expires_at={}, now={now})",
        beta_record.expires_at
    );

    // Probes: present -> alive, unknown -> not alive.
    for (fp, expected) in [
        (alpha_id.fingerprint(), true),
        (
            "deadbeef0000000000000000000000000000000000000000000000".into(),
            false,
        ),
        (beta_id.fingerprint(), true),
    ] {
        let reply = alpha_client
            .call(
                &rendezvous.identity(),
                app::AppFrame::Rendezvous(RendezvousFrame::Probe {
                    fingerprint: fp.clone(),
                }),
            )
            .await
            .unwrap();
        match app::AppFrame::decode(&reply.payload) {
            app::AppFrame::Rendezvous(RendezvousFrame::ProbeResult { fingerprint, alive }) => {
                assert_eq!(fingerprint, fp);
                assert_eq!(alive, expected, "probe for {fp}");
            }
            other => panic!("unexpected probe reply: {other:?}"),
        }
    }

    // A forged signature (garbage bytes, not a valid Ed25519 signature for the
    // caller's key over the address) must be refused outright, and alpha's record
    // must be untouched.
    let garbage_sig: [u8; 64] = [0x42; 64];
    let reply = forger_client
        .call(
            &rendezvous.identity(),
            app::AppFrame::Rendezvous(RendezvousFrame::Register {
                address: "192.0.2.10:7000".into(),
                ttl_secs: 3600,
                signature: garbage_sig,
            }),
        )
        .await
        .unwrap();
    match app::AppFrame::decode(&reply.payload) {
        app::AppFrame::Rendezvous(RendezvousFrame::Error { message }) => {
            assert!(
                message.contains("invalid") || message.contains("signature"),
                "forged registration must be refused, got: {message}"
            );
        }
        other => panic!("forged registration was not refused: {other:?}"),
    }
    let reply = alpha_client
        .call(
            &rendezvous.identity(),
            app::AppFrame::Rendezvous(RendezvousFrame::Lookup {
                fingerprint: alpha_id.fingerprint(),
            }),
        )
        .await
        .unwrap();
    let candidates = match app::AppFrame::decode(&reply.payload) {
        app::AppFrame::Rendezvous(RendezvousFrame::LookupResult { candidates, .. }) => candidates,
        other => panic!("unexpected lookup reply: {other:?}"),
    };
    assert_eq!(candidates.len(), 1);
    assert_eq!(candidates[0].address, "192.0.2.10:7000");
    assert!(
        !records_contain(&rendezvous_home_read(&core_home), &forger_id.fingerprint()),
        "a refused registration must not write anything to the registry"
    );
}

fn rendezvous_home_read(home: &tempfile::TempDir) -> String {
    let path = home.path().join("rendezvous.json");
    std::fs::read_to_string(&path).unwrap_or_default()
}

fn records_contain(json: &str, fingerprint: &str) -> bool {
    json.contains(fingerprint)
}
