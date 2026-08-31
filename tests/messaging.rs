use neonet::{
    identity::Identity,
    messaging::{Message, MessagingFrame, Router},
};

#[tokio::test]
async fn offline_queue_is_per_identity() {
    let a_dir = tempfile::tempdir().unwrap();
    let b_dir = tempfile::tempdir().unwrap();
    let c_dir = tempfile::tempdir().unwrap();
    let a = Identity::load_or_generate(a_dir.path()).unwrap().public();
    let b = Identity::load_or_generate(b_dir.path()).unwrap().public();
    let c = Identity::load_or_generate(c_dir.path()).unwrap().public();

    let mut router = Router::new(1).unwrap();
    router
        .send(Message::new(a.clone(), b.clone(), b"b1".to_vec()).unwrap())
        .await
        .unwrap();
    router
        .send(Message::new(a.clone(), c.clone(), b"c1".to_vec()).unwrap())
        .await
        .unwrap();
    assert_eq!(router.queued(&b), 1);
    assert_eq!(router.queued(&c), 1);

    let mut b_rx = router.register(b.clone());
    let mut c_rx = router.register(c.clone());
    assert_eq!(b_rx.recv().await.unwrap().payload, b"b1");
    assert_eq!(c_rx.recv().await.unwrap().payload, b"c1");
}

#[test]
fn oversized_message_is_rejected() {
    let dir_a = tempfile::tempdir().unwrap();
    let dir_b = tempfile::tempdir().unwrap();
    let a = Identity::load_or_generate(dir_a.path()).unwrap().public();
    let b = Identity::load_or_generate(dir_b.path()).unwrap().public();
    // Message::new now validates size at construction time rather than
    // leaving it to a separate validate_size() call, so the oversized
    // payload is rejected here rather than after a successful construction.
    assert!(Message::new(a, b, vec![0u8; neonet::messaging::MAX_MESSAGE_SIZE]).is_err());
}

#[test]
fn frame_decode_rejects_oversized_payload() {
    let bytes = vec![0u8; neonet::messaging::MAX_MESSAGE_SIZE + 1];
    assert!(MessagingFrame::decode(&bytes).is_err());
}

#[tokio::test]
async fn authenticated_tcp_transport_carries_messages() {
    use neonet::messaging::{receive_message, send_message};
    use tokio::net::{TcpListener, TcpStream};

    let server_dir = tempfile::tempdir().unwrap();
    let client_dir = tempfile::tempdir().unwrap();
    let server_identity = Identity::load_or_generate(server_dir.path()).unwrap();
    let client_identity = Identity::load_or_generate(client_dir.path()).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let expected = Message::new(
        client_identity.public(),
        server_identity.public(),
        b"hello over neonet".to_vec(),
    )
    .unwrap();

    let server = async {
        let (mut stream, _) = listener.accept().await.unwrap();
        let handshake =
            neonet::transport::handshake(&mut stream, &server_identity, vec!["messaging".into()])
                .await
                .unwrap();
        receive_message(&mut stream, &handshake.remote.identity)
            .await
            .unwrap()
    };

    let client = async {
        let mut stream = TcpStream::connect(addr).await.unwrap();
        neonet::transport::handshake(&mut stream, &client_identity, vec!["messaging".into()])
            .await
            .unwrap();
        send_message(&mut stream, expected.clone()).await.unwrap();
    };

    let (received, ()) = tokio::join!(server, client);
    assert_eq!(received, expected);
}

#[tokio::test]
async fn message_sender_must_match_authenticated_peer() {
    use neonet::messaging::{receive_message, send_message};
    use tokio::net::{TcpListener, TcpStream};

    let server_dir = tempfile::tempdir().unwrap();
    let client_dir = tempfile::tempdir().unwrap();
    let spoof_dir = tempfile::tempdir().unwrap();
    let server_identity = Identity::load_or_generate(server_dir.path()).unwrap();
    let client_identity = Identity::load_or_generate(client_dir.path()).unwrap();
    let spoof_identity = Identity::load_or_generate(spoof_dir.path()).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let server = async {
        let (mut stream, _) = listener.accept().await.unwrap();
        let handshake =
            neonet::transport::handshake(&mut stream, &server_identity, vec!["messaging".into()])
                .await
                .unwrap();
        let result = receive_message(&mut stream, &handshake.remote.identity).await;
        assert!(result.is_err());
    };

    let client = async {
        let mut stream = TcpStream::connect(addr).await.unwrap();
        neonet::transport::handshake(&mut stream, &client_identity, vec!["messaging".into()])
            .await
            .unwrap();
        let spoofed = Message::new(
            spoof_identity.public(),
            server_identity.public(),
            b"forged".to_vec(),
        )
        .unwrap();
        send_message(&mut stream, spoofed).await.unwrap();
    };

    tokio::join!(server, client);
}
