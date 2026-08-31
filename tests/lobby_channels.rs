//! Lobbies (host/join/group text) and channels (1:1 text to an active device).
//!
//! Lobby semantics are the ones fixed in docs/LOBBY_DESIGN.md: the host is
//! authoritative while online, admission is by the shared lobby key, posts are
//! XChaCha20-Poly1305 relayed as ciphertext, and handlers drop relays whose
//! sender is not the roster's host.

use neonet::{
    app::{self, lobby::LobbyFrame},
    bootstrap::BootstrapEntry,
    identity::{Identity, PublicIdentity},
    node::{AllowList, Node},
};
use std::{sync::Arc, time::Duration};

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

async fn wait_until<F>(mut probe: F, what: &str, timeout: Duration)
where
    F: FnMut() -> bool,
{
    let deadline = std::time::Instant::now() + timeout;
    while std::time::Instant::now() < deadline {
        if probe() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("timed out waiting for {what}");
}

#[tokio::test]
async fn channel_sends_private_text_to_an_active_device() {
    let core_home = tempfile::tempdir().unwrap();
    let alpha_home = tempfile::tempdir().unwrap();
    let beta_home = tempfile::tempdir().unwrap();

    let (core, addr) = spawn_core(&core_home).await;
    let bootstrap = vec![BootstrapEntry {
        address: addr,
        pinned_public_key: core.identity().public_key,
    }];
    let (alpha_node, _alpha_id) = spawn_edge(&alpha_home, bootstrap.clone()).await;
    let (beta_node, beta_id) = spawn_edge(&beta_home, bootstrap).await;

    let _core_client = app::Client::connect(Arc::clone(&core)).await.unwrap();
    let _beta_client = app::Client::connect(Arc::clone(&beta_node)).await.unwrap();
    let mut alpha_client = app::Client::connect(Arc::clone(&alpha_node)).await.unwrap();
    alpha_node
        .await_any_next_hop(&[beta_id.clone()], Duration::from_secs(5))
        .await
        .unwrap();

    let alpha_identity = alpha_node.local().public();
    let reply = alpha_client
        .call(
            &beta_id,
            app::AppFrame::Channel(neonet::app::lobby::ChannelFrame::Send {
                text: "the keys are under the mat".into(),
            }),
        )
        .await
        .unwrap();
    match app::AppFrame::decode(&reply.payload) {
        app::AppFrame::Channel(neonet::app::lobby::ChannelFrame::Ack { at }) => {
            assert!(at > 0);
        }
        other => panic!("unexpected reply to channel send: {other:?}"),
    }

    // Alpha's message lands in beta's channel log, attributed to alpha.
    let log = beta_home
        .path()
        .join("channel")
        .join(format!("{}.log", alpha_identity.fingerprint()));
    wait_until(
        || {
            neonet::lobby::read_channel(beta_home.path(), &alpha_identity.fingerprint())
                .iter()
                .any(|line| line.text == "the keys are under the mat")
        },
        "beta's channel log to hold alpha's message",
        Duration::from_secs(5),
    )
    .await;
    assert!(log.exists());
}

#[tokio::test]
async fn lobby_host_join_post_members_leave() {
    let core_home = tempfile::tempdir().unwrap();
    let host_home = tempfile::tempdir().unwrap();
    let ann_home = tempfile::tempdir().unwrap();
    let bob_home = tempfile::tempdir().unwrap();
    let stranger_home = tempfile::tempdir().unwrap();

    let (core, addr) = spawn_core(&core_home).await;
    let bootstrap = vec![BootstrapEntry {
        address: addr,
        pinned_public_key: core.identity().public_key,
    }];
    let (host_node, _host_id) = spawn_edge(&host_home, bootstrap.clone()).await;
    let (ann_node, _ann_id) = spawn_edge(&ann_home, bootstrap.clone()).await;
    let (bob_node, _bob_id) = spawn_edge(&bob_home, bootstrap.clone()).await;
    let (stranger_node, _stranger_id) = spawn_edge(&stranger_home, bootstrap).await;

    let _core_client = app::Client::connect(Arc::clone(&core)).await.unwrap();
    // The host needs a live pump to answer joins and relay posts.
    let _host_client = app::Client::connect(Arc::clone(&host_node)).await.unwrap();
    let mut ann_client = app::Client::connect(Arc::clone(&ann_node)).await.unwrap();
    let mut bob_client = app::Client::connect(Arc::clone(&bob_node)).await.unwrap();
    let mut stranger_client = app::Client::connect(Arc::clone(&stranger_node))
        .await
        .unwrap();

    for edge in [&ann_node, &bob_node, &stranger_node] {
        edge.await_any_next_hop(&[host_node.identity()], Duration::from_secs(5))
            .await
            .unwrap();
    }

    // `neonet host`: register the hosted lobby and its printed key.
    let key_bytes = neonet::lobby::new_key();
    let key = hex::encode(key_bytes);
    neonet::app::lobby::register_host(
        host_home.path(),
        "retreat",
        &key,
        neonet::app::lobby::LobbyOptions::default(),
    );

    // A wrong key is refused and admits nobody.
    let reply = stranger_client
        .call(
            &host_node.identity(),
            app::AppFrame::Lobby(LobbyFrame::Join {
                lobby_name: "retreat".into(),
                key: hex::encode(neonet::lobby::new_key()),
            }),
        )
        .await
        .unwrap();
    match app::AppFrame::decode(&reply.payload) {
        app::AppFrame::Lobby(LobbyFrame::Refuse { message }) => {
            assert!(message.contains("wrong"), "got: {message}");
        }
        other => panic!("wrong key must be refused, got: {other:?}"),
    }

    // Joining an unknown lobby is refused too.
    let reply = stranger_client
        .call(
            &host_node.identity(),
            app::AppFrame::Lobby(LobbyFrame::Join {
                lobby_name: "nowhere".into(),
                key: key.clone(),
            }),
        )
        .await
        .unwrap();
    match app::AppFrame::decode(&reply.payload) {
        app::AppFrame::Lobby(LobbyFrame::Refuse { message }) => {
            assert!(message.contains("no lobby"), "got: {message}");
        }
        other => panic!("unknown lobby must be refused, got: {other:?}"),
    }

    // Ann and Bob join with the correct key.
    let ann_identity = ann_node.local().public();
    let bob_identity = bob_node.local().public();
    for (client, name) in [(&mut ann_client, "ann"), (&mut bob_client, "bob")] {
        let reply = client
            .call(
                &host_node.identity(),
                app::AppFrame::Lobby(LobbyFrame::Join {
                    lobby_name: "retreat".into(),
                    key: key.clone(),
                }),
            )
            .await
            .unwrap();
        match app::AppFrame::decode(&reply.payload) {
            app::AppFrame::Lobby(LobbyFrame::Joined { .. }) => {}
            other => panic!("join as {name} must admit, got: {other:?}"),
        }
    }
    // Members only work off their own roster: this test records it like `join`.
    neonet::lobby::add_to_roster(
        ann_home.path(),
        neonet::lobby::MemberLobby {
            name: "retreat".into(),
            host_alias: "host".into(),
            host_fingerprint: host_node.identity().fingerprint(),
            key_hex: key.clone(),
            title: String::new(),
            welcome: String::new(),
        },
    )
    .unwrap();
    neonet::lobby::add_to_roster(
        bob_home.path(),
        neonet::lobby::MemberLobby {
            name: "retreat".into(),
            host_alias: "host".into(),
            host_fingerprint: host_node.identity().fingerprint(),
            key_hex: key.clone(),
            title: String::new(),
            welcome: String::new(),
        },
    )
    .unwrap();

    // The host answers "who's in": ann and bob.
    let reply = ann_client
        .call(
            &host_node.identity(),
            app::AppFrame::Lobby(LobbyFrame::Members {
                lobby_name: "retreat".into(),
            }),
        )
        .await
        .unwrap();
    match app::AppFrame::decode(&reply.payload) {
        app::AppFrame::Lobby(LobbyFrame::MemberList { fingerprints }) => {
            assert!(fingerprints.contains(&ann_identity.fingerprint()));
            assert!(fingerprints.contains(&bob_identity.fingerprint()));
        }
        other => panic!("unexpected reply to members: {other:?}"),
    }

    // Ann posts: the host relays the ciphertext to every member incl ann, who
    // decrypts it into her own log; bob gets it too.
    let (nonce, ciphertext) =
        neonet::lobby::encrypt(&key_bytes, b"fire drill at the lagoon").unwrap();
    let reply = ann_client
        .call(
            &host_node.identity(),
            app::AppFrame::Lobby(LobbyFrame::Post {
                lobby_name: "retreat".into(),
                key: key.clone(),
                nonce,
                ciphertext,
            }),
        )
        .await
        .unwrap();
    match app::AppFrame::decode(&reply.payload) {
        app::AppFrame::Lobby(LobbyFrame::Posted { relayed, .. }) => {
            assert_eq!(relayed, 2, "the post must relay to ann and bob");
        }
        other => panic!("unexpected reply to post: {other:?}"),
    }
    for (home, who) in [(&ann_home, "ann"), (&bob_home, "bob")] {
        let lines = neonet::lobby::read_lobby(home.path(), "retreat");
        assert!(
            lines
                .iter()
                .any(|line| line.text == "fire drill at the lagoon"),
            "{who} must have the decrypted post in their log"
        );
    }

    // A non-host cannot relay into the lobby: a stray push from the stranger is
    // dropped at bob, even with a valid-looking frame.
    let (nonce, ciphertext) = neonet::lobby::encrypt(&key_bytes, b"forged relay").unwrap();
    let forged = neonet::messaging::Message {
        id: *b"1234567890abcdef",
        sender: stranger_node.local().public(),
        recipient: bob_identity.clone(),
        payload: app::AppFrame::Lobby(LobbyFrame::Relay {
            lobby_name: "retreat".into(),
            nonce,
            ciphertext,
        })
        .encode()
        .unwrap(),
    };
    let _ = stranger_node.send_raw(forged).await;
    let before = neonet::lobby::read_lobby(bob_home.path(), "retreat").len();
    tokio::time::sleep(Duration::from_millis(200)).await;
    let after = neonet::lobby::read_lobby(bob_home.path(), "retreat").len();
    assert_eq!(
        before, after,
        "a relay from a non-host must not reach bob's log"
    );

    // Bob leaves; the host no longer lists him.
    let reply = bob_client
        .call(
            &host_node.identity(),
            app::AppFrame::Lobby(LobbyFrame::Leave {
                lobby_name: "retreat".into(),
            }),
        )
        .await
        .unwrap();
    match app::AppFrame::decode(&reply.payload) {
        app::AppFrame::Lobby(LobbyFrame::Left { .. }) => {}
        other => panic!("unexpected reply to leave: {other:?}"),
    }
    // Leave has no reply; give the pump a beat, then ask the host again.
    tokio::time::sleep(Duration::from_millis(200)).await;
    let reply = ann_client
        .call(
            &host_node.identity(),
            app::AppFrame::Lobby(LobbyFrame::Members {
                lobby_name: "retreat".into(),
            }),
        )
        .await
        .unwrap();
    match app::AppFrame::decode(&reply.payload) {
        app::AppFrame::Lobby(LobbyFrame::MemberList { fingerprints }) => {
            assert!(fingerprints.contains(&ann_identity.fingerprint()));
            assert!(
                !fingerprints.contains(&bob_identity.fingerprint()),
                "bob must be gone after Leave"
            );
        }
        other => panic!("unexpected reply to members: {other:?}"),
    }
}

#[tokio::test]
async fn lobby_host_customizes_title_welcome_and_member_cap() {
    let core_home = tempfile::tempdir().unwrap();
    let host_home = tempfile::tempdir().unwrap();
    let ann_home = tempfile::tempdir().unwrap();
    let bob_home = tempfile::tempdir().unwrap();

    let (core, addr) = spawn_core(&core_home).await;
    let bootstrap = vec![BootstrapEntry {
        address: addr,
        pinned_public_key: core.identity().public_key,
    }];
    let (host_node, _host_id) = spawn_edge(&host_home, bootstrap.clone()).await;
    let (ann_node, _ann_id) = spawn_edge(&ann_home, bootstrap.clone()).await;
    let (bob_node, _bob_id) = spawn_edge(&bob_home, bootstrap).await;

    let _core_client = app::Client::connect(Arc::clone(&core)).await.unwrap();
    let _host_client = app::Client::connect(Arc::clone(&host_node)).await.unwrap();
    let mut ann_client = app::Client::connect(Arc::clone(&ann_node)).await.unwrap();
    let mut bob_client = app::Client::connect(Arc::clone(&bob_node)).await.unwrap();
    for edge in [&ann_node, &bob_node] {
        edge.await_any_next_hop(&[host_node.identity()], Duration::from_secs(5))
            .await
            .unwrap();
    }

    // Host picks its customization before starting: a display title, a one-time
    // welcome, and one seat. ("no custom file format/parser — the host chooses
    // customizabilities beforehand".)
    let key = hex::encode(neonet::lobby::new_key());
    neonet::app::lobby::register_host(
        host_home.path(),
        "retreat",
        &key,
        neonet::app::lobby::LobbyOptions {
            title: "The Lagoon".into(),
            welcome: "welcome to the fire drill".into(),
            max_members: Some(1),
        },
    );

    // Ann joins and is told the title + welcome in the admission reply.
    let reply = ann_client
        .call(
            &host_node.identity(),
            app::AppFrame::Lobby(LobbyFrame::Join {
                lobby_name: "retreat".into(),
                key: key.clone(),
            }),
        )
        .await
        .unwrap();
    match app::AppFrame::decode(&reply.payload) {
        app::AppFrame::Lobby(LobbyFrame::Joined {
            lobby_name,
            title,
            welcome,
        }) => {
            assert_eq!(lobby_name, "retreat");
            assert_eq!(title, "The Lagoon");
            assert_eq!(welcome, "welcome to the fire drill");
        }
        other => panic!("join must admit the first member, got: {other:?}"),
    }

    // Ann records the lobby like `neonet join` does, so the cached title shows.
    neonet::lobby::add_to_roster(
        ann_home.path(),
        neonet::lobby::MemberLobby {
            name: "retreat".into(),
            host_alias: "host".into(),
            host_fingerprint: host_node.identity().fingerprint(),
            key_hex: key.clone(),
            title: "The Lagoon".into(),
            welcome: "welcome to the fire drill".into(),
        },
    )
    .unwrap();
    let cached = neonet::lobby::find_roster(ann_home.path(), "retreat").unwrap();
    assert_eq!(cached.display_title(), "The Lagoon");

    // The second member is refused: the cap was fixed at start, host aside.
    let reply = bob_client
        .call(
            &host_node.identity(),
            app::AppFrame::Lobby(LobbyFrame::Join {
                lobby_name: "retreat".into(),
                key: key.clone(),
            }),
        )
        .await
        .unwrap();
    match app::AppFrame::decode(&reply.payload) {
        app::AppFrame::Lobby(LobbyFrame::Refuse { message }) => {
            assert!(message.contains("cap"), "got: {message}");
        }
        other => panic!("the capped lobby must refuse bob, got: {other:?}"),
    }
}
