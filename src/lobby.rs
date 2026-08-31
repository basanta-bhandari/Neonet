//! Lobby and channel persistence helpers (key management, member-side roster,
//! decrypted post / channel logs). All wire logic lives in `app::lobby`.

use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use std::{
    io,
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};

pub const NONCE_LEN: usize = 24;
pub const KEY_LEN: usize = 32;

pub fn new_key() -> [u8; KEY_LEN] {
    let mut key = [0u8; KEY_LEN];
    OsRng.fill_bytes(&mut key);
    key
}

/// Lobby/channel messages are XChaCha20-Poly1305 under a 32-byte key.
pub fn encrypt(key: &[u8; KEY_LEN], plaintext: &[u8]) -> io::Result<(Vec<u8>, Vec<u8>)> {
    let cipher = XChaCha20Poly1305::new(key.into());
    let mut nonce_bytes = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = XNonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|_| io::Error::other("lobby encryption failed"))?;
    Ok((nonce_bytes.to_vec(), ciphertext))
}

pub fn decrypt(key: &[u8; KEY_LEN], nonce: &[u8], ciphertext: &[u8]) -> io::Result<Vec<u8>> {
    if nonce.len() != NONCE_LEN {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "bad nonce length",
        ));
    }
    let cipher = XChaCha20Poly1305::new(key.into());
    let nonce = XNonce::from_slice(nonce);
    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "lobby decryption failed"))
}

/// A filesystem-safe rendering of a lobby name for roster/log file names.
pub fn slug(name: &str) -> String {
    let cleaned: String = name
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.' {
                c
            } else {
                '-'
            }
        })
        .collect();
    let trimmed = cleaned.trim_matches('-');
    if trimmed.is_empty() {
        "lobby".into()
    } else {
        trimmed.into()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct MemberLobby {
    pub name: String,
    pub host_alias: String,
    pub host_fingerprint: String,
    pub key_hex: String,
    /// Display title the host chose when starting the lobby. Empty when the
    /// host gave none (falls back to `name`), and absent in rosters written
    /// by older versions.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub title: String,
    /// Welcome message the host chose; shown at admission. Empty = none.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub welcome: String,
}

impl MemberLobby {
    pub fn display_title(&self) -> &str {
        if self.title.is_empty() {
            &self.name
        } else {
            &self.title
        }
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct Roster {
    lobbies: Vec<MemberLobby>,
}

#[derive(Clone, Debug)]
pub struct LogLine {
    pub at: u64,
    pub sender: String,
    pub text: String,
}

pub fn find_roster(root: &Path, name: &str) -> Option<MemberLobby> {
    load_roster(root)
        .lobbies
        .into_iter()
        .find(|lobby| lobby.name == name)
}

pub fn add_to_roster(root: &Path, lobby: MemberLobby) -> io::Result<()> {
    let mut roster = load_roster(root);
    if let Some(slot) = roster
        .lobbies
        .iter_mut()
        .find(|entry| entry.name == lobby.name)
    {
        *slot = lobby;
        return write_roster(root, &roster);
    }
    roster.lobbies.push(lobby);
    write_roster(root, &roster)
}

/// All lobbies this device has joined, join order preserved (most recent last).
pub fn roster_lobbies(root: &Path) -> Vec<MemberLobby> {
    load_roster(root).lobbies
}

/// The most recently joined lobby, if any — the shell's default post target.
pub fn last_roster(root: &Path) -> Option<MemberLobby> {
    roster_lobbies(root).into_iter().next_back()
}

fn write_roster(root: &Path, roster: &Roster) -> io::Result<()> {
    let bytes = serde_json::to_vec(&roster)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
    let dir = roster_dir(root);
    std::fs::create_dir_all(&dir)?;
    let path = dir.join("roster.json");
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, bytes)?;
    std::fs::rename(tmp, path)
}

/// Append one decrypted post to `lobbies/<slug>.log` (this member's own log).
pub fn append_lobby(root: &Path, name: &str, sender: &str, text: &str) -> io::Result<()> {
    append_log(
        root.join("lobbies"),
        &format!("{}.log", slug(name)),
        sender,
        text,
    )
}

/// Append one decrypted channel message to `channel/<slug>.log`.
pub fn append_channel(root: &Path, sender: &str, text: &str) -> io::Result<()> {
    append_log(
        root.join("channel"),
        &format!("{}.log", slug(sender)),
        sender,
        text,
    )
}

pub fn read_lobby(root: &Path, name: &str) -> Vec<LogLine> {
    read_log(&root.join("lobbies").join(format!("{}.log", slug(name))))
}

pub fn read_channel(root: &Path, sender: &str) -> Vec<LogLine> {
    read_log(&root.join("channel").join(format!("{}.log", slug(sender))))
}

pub fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn load_roster(root: &Path) -> Roster {
    match std::fs::read(root.join("lobbies").join("roster.json")) {
        Ok(bytes) => serde_json::from_slice(&bytes).unwrap_or_default(),
        Err(_) => Roster::default(),
    }
}

fn roster_dir(root: &Path) -> std::path::PathBuf {
    root.join("lobbies")
}

fn sanitize_text(text: &str) -> String {
    text.replace(['\r', '\n'], " ")
}

fn append_log(base: std::path::PathBuf, name: &str, sender: &str, text: &str) -> io::Result<()> {
    let dir = base;
    std::fs::create_dir_all(&dir)?;
    let path = dir.join(name);
    let line = format!("{}\t{}\t{}\n", unix_now(), sender, sanitize_text(text));
    use std::io::Write;
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)?;
    file.write_all(line.as_bytes())?;
    Ok(())
}

fn read_log(path: &std::path::Path) -> Vec<LogLine> {
    let Ok(text) = std::fs::read_to_string(path) else {
        return Vec::new();
    };
    text.lines()
        .filter_map(|line| {
            let mut parts = line.splitn(3, '\t');
            let at = parts.next()?.parse().ok()?;
            let sender = parts.next().unwrap_or("").to_string();
            let text = parts.next().unwrap_or("").to_string();
            Some(LogLine { at, sender, text })
        })
        .collect()
}
