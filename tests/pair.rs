//! Flash pairing: a single-use token turns one fresh connection into a durable
//! ledger entry on the acceptor. Tokens die after one redemption (a lost/stolen
//! token is a dead file, never a standing key) and expire on a short clock.

use neonet::{
    app::{self, pair::PairFrame},
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

async fn redeem(client: &mut app::Client, acceptor: &Node, token: &str) -> Result<String, String> {
    let reply = client
        .call(
            &acceptor.identity(),
            app::AppFrame::Pair(PairFrame::Redeem {
                token: token.to_string(),
            }),
        )
        .await
        .unwrap();
    match app::AppFrame::decode(&reply.payload) {
        app::AppFrame::Pair(PairFrame::Redeemed { fingerprint }) => Ok(fingerprint),
        app::AppFrame::Pair(PairFrame::Error { message }) => Err(message),
        other => Err(format!("unexpected reply: {other:?}")),
    }
}

#[tokio::test]
async fn flash_pairs_once_with_a_single_use_token() {
    let acceptor_home = tempfile::tempdir().unwrap();
    let alpha_home = tempfile::tempdir().unwrap();
    let beta_home = tempfile::tempdir().unwrap();

    let (acceptor, acceptor_addr) = spawn_core(&acceptor_home).await;
    let bootstrap = vec![BootstrapEntry {
        address: acceptor_addr,
        pinned_public_key: acceptor.identity().public_key,
    }];
    let (alpha_node, alpha_id) = spawn_edge(&alpha_home, bootstrap.clone()).await;
    let (beta_node, beta_id) = spawn_edge(&beta_home, bootstrap).await;

    let _acceptor_client = app::Client::connect(Arc::clone(&acceptor)).await.unwrap();
    let mut alpha_client = app::Client::connect(Arc::clone(&alpha_node)).await.unwrap();
    let mut beta_client = app::Client::connect(Arc::clone(&beta_node)).await.unwrap();
    alpha_node
        .await_any_next_hop(&[acceptor.identity()], std::time::Duration::from_secs(5))
        .await
        .unwrap();
    beta_node
        .await_any_next_hop(&[acceptor.identity()], std::time::Duration::from_secs(5))
        .await
        .unwrap();

    // The acceptor actively publishes a token (the "plugged-in drive").
    let token = neonet::pair::issue_token(acceptor_home.path(), None).unwrap();
    assert!(!token.is_empty());

    // Alpha "inserts the drive": the token is consumed and alpha is recorded.
    let fingerprint = redeem(&mut alpha_client, &acceptor, &token).await.unwrap();
    assert_eq!(fingerprint, alpha_id.fingerprint());
    assert!(neonet::pair::is_paired(acceptor_home.path(), &alpha_id));
    assert!(
        !neonet::pair::is_paired(acceptor_home.path(), &beta_id),
        "beta must not be paired by alpha's redemption"
    );

    // The same token is now dead: beta cannot use it, and nothing changes.
    let err = redeem(&mut beta_client, &acceptor, &token)
        .await
        .unwrap_err();
    assert!(
        err.contains("used") || err.contains("expired") || err.contains("invalid"),
        "a consumed token must be refused, got: {err}"
    );
    assert_eq!(neonet::pair::paired_devices(acceptor_home.path()).len(), 1);

    // A bogus token never touches the ledger either.
    let err = redeem(&mut beta_client, &acceptor, "deadbeef")
        .await
        .unwrap_err();
    assert!(!err.is_empty());
    assert_eq!(neonet::pair::paired_devices(acceptor_home.path()).len(), 1);

    // A fresh token works once more, for whoever else is plugged in.
    let second = neonet::pair::issue_token(acceptor_home.path(), None).unwrap();
    let fp = redeem(&mut beta_client, &acceptor, &second).await.unwrap();
    assert_eq!(fp, beta_id.fingerprint());
    assert_eq!(neonet::pair::paired_devices(acceptor_home.path()).len(), 2);
    assert!(neonet::pair::is_paired(acceptor_home.path(), &beta_id));
}

#[tokio::test]
async fn tokens_expire_on_the_short_window() {
    let acceptor_home = tempfile::tempdir().unwrap();
    let alpha_home = tempfile::tempdir().unwrap();

    let (acceptor, acceptor_addr) = spawn_core(&acceptor_home).await;
    let bootstrap = vec![BootstrapEntry {
        address: acceptor_addr,
        pinned_public_key: acceptor.identity().public_key,
    }];
    let (alpha_node, alpha_id) = spawn_edge(&alpha_home, bootstrap).await;
    let _acceptor_client = app::Client::connect(Arc::clone(&acceptor)).await.unwrap();
    let mut alpha_client = app::Client::connect(Arc::clone(&alpha_node)).await.unwrap();
    alpha_node
        .await_any_next_hop(&[acceptor.identity()], std::time::Duration::from_secs(5))
        .await
        .unwrap();

    let short_lived = neonet::pair::issue_token(acceptor_home.path(), Some(1)).unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
    let err = redeem(&mut alpha_client, &acceptor, &short_lived)
        .await
        .unwrap_err();
    assert!(
        err.contains("expired") || err.contains("invalid"),
        "an expired token must be refused, got: {err}"
    );
    assert!(!neonet::pair::is_paired(acceptor_home.path(), &alpha_id));
}
