use neonet::{identity::Identity, protocol::PROTOCOL_MAJOR, transport};
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};

#[tokio::test]
async fn mutual_handshake_succeeds_over_tcp() {
    let server_dir = tempfile::tempdir().unwrap();
    let client_dir = tempfile::tempdir().unwrap();
    let server_identity = Identity::load_or_generate(server_dir.path()).unwrap();
    let client_identity = Identity::load_or_generate(client_dir.path()).unwrap();

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let server = async {
        let (mut stream, _) = listener.accept().await.unwrap();
        let remote = transport::handshake(
            &mut stream,
            &server_identity,
            vec!["messaging".into(), "foundation".into()],
        )
        .await
        .unwrap();
        assert_eq!(remote.remote.identity, client_identity.public());
        assert_eq!(remote.negotiated.features, vec!["foundation", "messaging"]);
        remote
    };

    let client = async {
        let mut stream = TcpStream::connect(addr).await.unwrap();
        let remote = transport::handshake(
            &mut stream,
            &client_identity,
            vec!["foundation".into(), "messaging".into(), "unused".into()],
        )
        .await
        .unwrap();
        assert_eq!(remote.remote.identity, server_identity.public());
        assert_eq!(remote.negotiated.features, vec!["foundation", "messaging"]);
        remote
    };

    let (_server_remote, _client_remote) = tokio::join!(server, client);
    assert_eq!(PROTOCOL_MAJOR, 1);
}

#[tokio::test]
async fn pinned_identity_rejects_wrong_peer() {
    let server_dir = tempfile::tempdir().unwrap();
    let client_dir = tempfile::tempdir().unwrap();
    let attacker_dir = tempfile::tempdir().unwrap();
    let server_identity = Identity::load_or_generate(server_dir.path()).unwrap();
    let client_identity = Identity::load_or_generate(client_dir.path()).unwrap();
    let attacker_identity = Identity::load_or_generate(attacker_dir.path()).unwrap();

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let server = async {
        let (mut stream, _) = listener.accept().await.unwrap();
        let result = transport::handshake_with_pinned_identity(
            &mut stream,
            &server_identity,
            vec!["foundation".into()],
            &client_identity.public(),
        )
        .await;
        assert!(result.is_err());
    };

    let client = async {
        let mut stream = TcpStream::connect(addr).await.unwrap();
        let _ =
            transport::handshake(&mut stream, &attacker_identity, vec!["foundation".into()]).await;
        let _ = stream.shutdown().await;
    };

    tokio::join!(server, client);
}

#[tokio::test]
async fn tcp_handshake_honors_bootstrap_address_and_pin() {
    use neonet::bootstrap::BootstrapEntry;
    use std::net::SocketAddr;

    let server_dir = tempfile::tempdir().unwrap();
    let client_dir = tempfile::tempdir().unwrap();
    let server_identity = Identity::load_or_generate(server_dir.path()).unwrap();
    let client_identity = Identity::load_or_generate(client_dir.path()).unwrap();

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let bootstrap = vec![BootstrapEntry {
        address: addr,
        pinned_public_key: server_identity.public().public_key,
    }];

    let server = async {
        let (mut stream, _) = listener.accept().await.unwrap();
        transport::handshake(&mut stream, &server_identity, vec!["foundation".into()])
            .await
            .unwrap();
    };

    let client = async {
        let mut stream = TcpStream::connect(addr).await.unwrap();
        let result = transport::handshake_tcp_with_bootstrap(
            &mut stream,
            &client_identity,
            vec!["foundation".into()],
            &bootstrap,
        )
        .await
        .unwrap();
        assert_eq!(result.remote.identity, server_identity.public());
        assert_eq!(result.negotiated.features, vec!["foundation"]);
    };

    tokio::join!(server, client);

    // The trust entry is intentionally address-bound, not address-only.
    assert_eq!(bootstrap[0].address, addr as SocketAddr);
}
