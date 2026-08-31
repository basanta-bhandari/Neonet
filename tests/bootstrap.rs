use neonet::{
    bootstrap::{self, BootstrapEntry},
    identity::Identity,
};
use std::net::SocketAddr;

#[test]
fn bootstrap_entry_pins_identity() {
    let dir = tempfile::tempdir().unwrap();
    let identity = Identity::load_or_generate(dir.path()).unwrap();
    let entry = BootstrapEntry {
        address: "127.0.0.1:4000".parse::<SocketAddr>().unwrap(),
        pinned_public_key: identity.public().public_key,
    };
    assert!(entry.trusts(&identity.public()));

    let path = dir.path().join("bootstrap.json");
    bootstrap::save(&path, &[entry.clone()]).unwrap();
    let loaded = bootstrap::load(&path).unwrap();
    assert_eq!(loaded, vec![entry]);
}

#[test]
fn bootstrap_key_serializes_as_hex_string() {
    let dir = tempfile::tempdir().unwrap();
    let identity = Identity::load_or_generate(dir.path()).unwrap();
    let entry = BootstrapEntry {
        address: "127.0.0.1:4000".parse::<SocketAddr>().unwrap(),
        pinned_public_key: identity.public().public_key,
    };

    let path = dir.path().join("bootstrap.json");
    bootstrap::save(&path, &[entry.clone()]).unwrap();
    let raw = std::fs::read_to_string(&path).unwrap();
    let key = entry.pinned_public_key;
    assert!(
        raw.contains(&hex::encode(key)),
        "saved bootstrap should contain the hex-encoded key, got: {raw}"
    );

    let loaded = bootstrap::load(&path).unwrap();
    assert_eq!(loaded, vec![entry]);
}

#[test]
fn bootstrap_key_rejects_wrong_length_hex() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("bootstrap.json");
    std::fs::write(
        &path,
        r#"[{"address": "127.0.0.1:4000", "pinned_public_key": "abcd"}]"#,
    )
    .unwrap();
    let err = bootstrap::load(&path).unwrap_err();
    assert!(err.to_string().contains("hex"), "unexpected error: {err}");
}
