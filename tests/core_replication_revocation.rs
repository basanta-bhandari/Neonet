//! Multi-core duties: an operator replicates a stored file from one core to
//! another (both cores never see plaintext), then broadcasts a signed
//! revocation that each core applies independently. Revocation is the
//! architecture's one strong-consistency exception, so the test checks it end
//! to end through the wire: the broadcast is applied only where the caller is
//! a configured operator, and the revoked identity is refused at the revealing
//! point (the store gates) rather than informally.
//!
//! Topology (a real deployment's reference shape): every core dials the other;
//! the operator device only dials the local core, so all cross-core messages
//! travel operator → core A → core B and replies return the same way.

use neonet::{
    app::{self, core::CoreFrame},
    bootstrap::BootstrapEntry,
    identity::{Identity, PublicIdentity},
    node::{AllowList, Node},
};
use std::{io, sync::Arc};

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

fn deterministic_bytes(index: u32, size: usize) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(size);
    for i in 0..size {
        bytes.push(((index as usize).wrapping_mul(31).wrapping_add(i) & 0xff) as u8);
    }
    bytes
}

#[tokio::test]
async fn replicate_across_cores_then_revoke_on_one() {
    // Homes: two cores that dial each other, plus the operator/owner edge and a
    // stranger edge, both of which dial only core A.
    let core_a_home = tempfile::tempdir().unwrap();
    let core_b_home = tempfile::tempdir().unwrap();
    let owner_home = tempfile::tempdir().unwrap();
    let stranger_home = tempfile::tempdir().unwrap();

    let (core_a, addr_a) = spawn_core(&core_a_home).await;
    let (core_b, _addr_b) = spawn_core(&core_b_home).await;

    // Cross-mesh the two cores so replies can route back through A.
    let core_b_to_a = vec![BootstrapEntry {
        address: addr_a,
        pinned_public_key: core_a.identity().public_key,
    }];
    let dialing_b = Arc::clone(&core_b);
    tokio::spawn(async move {
        let _ = dialing_b.dial(&core_b_to_a).await;
    });

    let bootstrap = vec![BootstrapEntry {
        address: addr_a,
        pinned_public_key: core_a.identity().public_key,
    }];
    let (owner_node, _owner_id) = spawn_edge(&owner_home, bootstrap.clone()).await;
    let (stranger_node, _stranger_id) = spawn_edge(&stranger_home, bootstrap).await;

    let _core_a_client = app::Client::connect(Arc::clone(&core_a)).await.unwrap();
    let _core_b_client = app::Client::connect(Arc::clone(&core_b)).await.unwrap();
    let mut owner_client = app::Client::connect(Arc::clone(&owner_node)).await.unwrap();
    let mut stranger_client = app::Client::connect(Arc::clone(&stranger_node))
        .await
        .unwrap();
    owner_node
        .await_any_next_hop(&[core_a.identity()], std::time::Duration::from_secs(5))
        .await
        .unwrap();
    stranger_node
        .await_any_next_hop(&[core_a.identity()], std::time::Duration::from_secs(5))
        .await
        .unwrap();
    // Owner also needs a route to core B (through the A mesh) before pushing.
    owner_node
        .await_any_next_hop(&[core_b.identity()], std::time::Duration::from_secs(5))
        .await
        .unwrap();

    // Emulate `neonet operator add`: the owner is an operator of BOTH cores.
    let owner_identity = owner_node.local().public();
    neonet::app::core::set_operator(&core_a, &owner_identity).unwrap();
    neonet::app::core::set_operator(&core_b, &owner_identity).unwrap();

    // Owner stores a file on core A; the cores then hold only ciphertext.
    let source = owner_home.path().join("secrets.bin");
    let plaintext = {
        let mut data = Vec::new();
        for index in 0..4u32 {
            data.extend_from_slice(&deterministic_bytes(index, 300_000));
        }
        data
    };
    std::fs::write(&source, &plaintext).unwrap();

    let (manifest, chunks) = neonet::files::build_manifest(
        &source,
        owner_node.local(),
        neonet::files::DEFAULT_CHUNK_SIZE,
    )
    .unwrap();
    let file_id = neonet::files::manifest_id(&manifest);
    let key = neonet::storage::generate_key();
    let encrypted = chunks
        .iter()
        .map(|chunk| neonet::storage::encrypt_chunk(&key, chunk).unwrap())
        .collect::<Vec<_>>();
    neonet::app::storage::push_chunks(
        &core_a.identity(),
        &mut owner_client,
        &file_id,
        &manifest,
        &encrypted,
    )
    .await
    .expect("store on core A failed");

    // Replicate A -> B via the operator device (pull then push; the mesh
    // routes through A). Both cores still hold only opaque ciphertext.
    neonet::app::storage::push_chunks(
        &core_b.identity(),
        &mut owner_client,
        &file_id,
        &manifest,
        &encrypted,
    )
    .await
    .expect("store on core B failed");
    let (fetched_manifest, fetched) =
        neonet::app::storage::pull_chunks(&core_b.identity(), &mut owner_client, &file_id)
            .await
            .expect("paged fetch from core B failed");
    assert_eq!(fetched_manifest, manifest);
    let decrypted = fetched
        .iter()
        .map(|encrypted| neonet::storage::decrypt_chunk(&key, encrypted).unwrap())
        .collect::<Vec<_>>();
    let restored = owner_home.path().join("restored.bin");
    neonet::files::reconstruct(&fetched_manifest, &decrypted, &restored).unwrap();
    assert_eq!(std::fs::read(&restored).unwrap(), plaintext);

    let blob_dir = core_b_home.path().join("blobs").join(&file_id);
    let mut blobs = 0;
    for entry in std::fs::read_dir(&blob_dir).unwrap().flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        if name != "manifest.json" && name != "acl.json" && !name.ends_with(".tmp") {
            blobs += 1;
        }
    }
    assert_eq!(
        blobs,
        chunks.len(),
        "core B must hold every encrypted chunk"
    );

    // Revoke the stranger on core A only: owner signs the broadcast, core A
    // must accept it as operator-signed and apply it.
    let stranger_identity = stranger_node.local().public();
    let epoch = 1u64;
    let payload = neonet::app::core::revoke_payload(epoch, &stranger_identity);
    let signature = owner_node.local().sign(&payload);
    let reply = owner_client
        .call(
            &core_a.identity(),
            app::AppFrame::Core(CoreFrame::RevokeBroadcast {
                revoked: stranger_identity.clone(),
                epoch,
                signature,
            }),
        )
        .await
        .unwrap();
    match app::AppFrame::decode(&reply.payload) {
        app::AppFrame::Core(CoreFrame::RevokeAck { epoch: acked }) => {
            assert_eq!(acked, epoch);
        }
        app::AppFrame::Core(CoreFrame::RevokeRefuse { reason, .. }) => {
            panic!("core A refused the revocation: {reason}");
        }
        other => panic!("unexpected reply to revoke: {other:?}"),
    }
    assert!(
        neonet::app::storage::revoked_set(&core_a).contains(&stranger_identity.fingerprint()),
        "core A must have applied the revocation"
    );
    assert!(
        !neonet::app::storage::revoked_set(&core_b).contains(&stranger_identity.fingerprint()),
        "the revocation must not leak to core B"
    );

    // Behavioral check: the stranger is now refused when storing on core A,
    // while the same identity can still store on core B (revoked only there).
    let stranger_source = stranger_home.path().join("notes.bin");
    std::fs::write(&stranger_source, deterministic_bytes(9, 100_000)).unwrap();
    let (stranger_manifest, stranger_chunks) = neonet::files::build_manifest(
        &stranger_source,
        stranger_node.local(),
        neonet::files::DEFAULT_CHUNK_SIZE,
    )
    .unwrap();
    let stranger_file_id = neonet::files::manifest_id(&stranger_manifest);
    let stranger_key = neonet::storage::generate_key();
    let stranger_encrypted = stranger_chunks
        .iter()
        .map(|chunk| neonet::storage::encrypt_chunk(&stranger_key, chunk).unwrap())
        .collect::<Vec<_>>();

    let refused = neonet::app::storage::push_chunks(
        &core_a.identity(),
        &mut stranger_client,
        &stranger_file_id,
        &stranger_manifest,
        &stranger_encrypted,
    )
    .await;
    match refused {
        Err(e) => {
            assert!(
                e.to_string().to_lowercase().contains("revok"),
                "core A must refuse a revoked store, got: {e}"
            );
        }
        Ok(()) => panic!("core A accepted a store from a revoked identity"),
    }

    neonet::app::storage::push_chunks(
        &core_b.identity(),
        &mut stranger_client,
        &stranger_file_id,
        &stranger_manifest,
        &stranger_encrypted,
    )
    .await
    .expect("core B should still accept the stranger (revoked only on A)");

    // A non-operator cannot revoke: core A must refuse an unsigned-by-operator
    // broadcast from the stranger even though it can store there.
    let forged_epoch = 2u64;
    let forged_payload = neonet::app::core::revoke_payload(forged_epoch, &owner_identity);
    let forged_signature = stranger_node.local().sign(&forged_payload);
    let reply = stranger_client
        .call(
            &core_a.identity(),
            app::AppFrame::Core(CoreFrame::RevokeBroadcast {
                revoked: owner_identity.clone(),
                epoch: forged_epoch,
                signature: forged_signature,
            }),
        )
        .await
        .unwrap();
    match app::AppFrame::decode(&reply.payload) {
        app::AppFrame::Core(CoreFrame::RevokeRefuse { reason, .. }) => {
            assert!(
                reason.contains("operator"),
                "refusal must cite operators, got: {reason}"
            );
        }
        app::AppFrame::Core(CoreFrame::RevokeAck { .. }) => {
            panic!("core A applied a revocation from a non-operator")
        }
        other => panic!("unexpected reply to forged revoke: {other:?}"),
    }
    assert!(
        !neonet::app::storage::revoked_set(&core_a).contains(&owner_identity.fingerprint()),
        "a non-operator broadcast must never be applied"
    );

    // The owner is unaffected and can still read its own store on core B.
    let (_, after) =
        neonet::app::storage::pull_chunks(&core_b.identity(), &mut owner_client, &file_id)
            .await
            .expect("owner must survive the revocation round");
    assert_eq!(after.len(), chunks.len());
    let _: io::Result<()> = Ok(());
}
