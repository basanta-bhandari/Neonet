//! End-to-end encrypted storage through the relay core: the client encrypts
//! locally, the storing core never sees plaintext, pull reconstructs the exact
//! original bytes, and peers outside the file's reader ACL are refused.

use neonet::{
    app::{self, storage::StorageFrame},
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

fn stub_chunk(index: u32, size: usize) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(size);
    for i in 0..size {
        bytes.push(((index as usize).wrapping_mul(31).wrapping_add(i) & 0xff) as u8);
    }
    bytes
}

#[tokio::test]
async fn store_push_pull_round_trip_with_acls() {
    let core_home = tempfile::tempdir().unwrap();
    let owner_home = tempfile::tempdir().unwrap();
    let stranger_home = tempfile::tempdir().unwrap();

    let (core_node, core_addr) = spawn_core(&core_home).await;
    let bootstrap = vec![BootstrapEntry {
        address: core_addr,
        pinned_public_key: core_node.identity().public_key,
    }];

    let (owner_node, _owner_id) = spawn_edge(&owner_home, bootstrap.clone()).await;
    let (stranger_node, _stranger_id) = spawn_edge(&stranger_home, bootstrap).await;

    let _core_client = app::Client::connect(Arc::clone(&core_node)).await.unwrap();
    let mut owner_client = app::Client::connect(Arc::clone(&owner_node)).await.unwrap();
    let mut stranger_client = app::Client::connect(Arc::clone(&stranger_node))
        .await
        .unwrap();
    owner_node
        .await_any_next_hop(&[core_node.identity()], std::time::Duration::from_secs(5))
        .await
        .unwrap();
    stranger_node
        .await_any_next_hop(&[core_node.identity()], std::time::Duration::from_secs(5))
        .await
        .unwrap();

    // Client-side: build, sign, and encrypt like `neonet store push` does.
    let source = owner_home.path().join("secrets.bin");
    let plaintext = {
        let mut data = Vec::new();
        for index in 0..4u32 {
            data.extend_from_slice(&stub_chunk(index, 300_000));
        }
        data
    };
    std::fs::write(&source, &plaintext).unwrap();

    let owner_identity = Identity::load_or_generate(owner_home.path()).unwrap();
    let (manifest, chunks) =
        neonet::files::build_manifest(&source, &owner_identity, neonet::files::DEFAULT_CHUNK_SIZE)
            .unwrap();
    let file_id = neonet::files::manifest_id(&manifest);
    let key = neonet::storage::generate_key();
    let encrypted = chunks
        .iter()
        .map(|chunk| neonet::storage::encrypt_chunk(&key, chunk).unwrap())
        .collect::<Vec<_>>();

    neonet::app::storage::push_chunks(
        &core_node.identity(),
        &mut owner_client,
        &file_id,
        &manifest,
        &encrypted,
    )
    .await
    .expect("batched push failed");

    // The core's persisted blobs must be opaque ciphertext, never plaintext:
    // each stored blob decrypts to something that shares our data's length but
    // is not byte-identical to it (XChaCha20 ciphertext differs from the input).
    let blob_dir = core_home.path().join("blobs").join(&file_id);
    let mut blobs = 0;
    for entry in std::fs::read_dir(&blob_dir).unwrap().flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        if name == "manifest.json" || name == "acl.json" || name.ends_with(".tmp") {
            continue;
        }
        blobs += 1;
        let bytes = std::fs::read(entry.path()).unwrap();
        let ciphertext = postcard::from_bytes::<neonet::storage::EncryptedChunk>(&bytes)
            .expect("stored blob is not a serialized EncryptedChunk");
        let assumed_plain = stub_chunk(ciphertext.index, ciphertext.ciphertext.len());
        assert_ne!(
            ciphertext.ciphertext, assumed_plain,
            "stored blob for chunk {} is plaintext on the core",
            ciphertext.index
        );
    }
    assert_eq!(blobs, chunks.len());

    // The owner pulls back the same bytes, reconstructed exactly (paged).
    let (fetched_manifest, fetched) =
        neonet::app::storage::pull_chunks(&core_node.identity(), &mut owner_client, &file_id)
            .await
            .expect("paged fetch failed");
    assert_eq!(fetched_manifest, manifest);
    let decrypted = fetched
        .iter()
        .map(|encrypted| neonet::storage::decrypt_chunk(&key, encrypted).unwrap())
        .collect::<Vec<_>>();
    assert_eq!(decrypted, chunks);

    let restored = owner_home.path().join("restored.bin");
    neonet::files::reconstruct(&fetched_manifest, &decrypted, &restored).unwrap();
    assert_eq!(std::fs::read(&restored).unwrap(), plaintext);

    // A stranger (not in the file's reader ACL) is refused outright.
    let reply = stranger_client
        .call(
            &core_node.identity(),
            app::AppFrame::Storage(StorageFrame::FetchChunks {
                file_id: file_id.clone(),
                offset: 0,
            }),
        )
        .await
        .unwrap();
    match app::AppFrame::decode(&reply.payload) {
        app::AppFrame::Storage(StorageFrame::Error { message }) => {
            assert!(
                message.contains("ACL"),
                "expected an ACL refusal, got: {message}"
            );
        }
        other => panic!("stranger was not refused: {other:?}"),
    }
}
