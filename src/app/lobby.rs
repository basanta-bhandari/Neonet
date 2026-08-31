//! Wire frames for lobbies (group text, host-relayed) and channels (private
//! 1:1 text, identity-addressed, persisted in the recipient's channel log).
//!
//! Lobby semantics are fixed in docs/LOBBY_DESIGN.md: the host is
//! authoritative while it is online; a lobby pauses and dies when the host
//! disconnects; posts are XChaCha20-Poly1305 under the lobby key, so relay
//! cores see membership metadata but not content — while the host itself
//! holds the key and can read everything.

use super::{reply, AppFrame, Handling};
use crate::messaging::{Message, MessageId};
use crate::node::Node;
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io;
use std::path::PathBuf;
use std::sync::Mutex;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum LobbyFrame {
    /// member -> host: "here is the code you published."
    Join { lobby_name: String, key: String },
    /// host -> member: admitted. Carries the lobby's pre-start customization
    /// (display title and welcome message) so the joiner can show them.
    Joined {
        lobby_name: String,
        title: String,
        welcome: String,
    },
    /// host -> member: the post was accepted and relayed to N members
    /// (including the sender, whose log gets its own post).
    Posted { lobby_name: String, relayed: usize },
    /// host -> member: wrong key, or no such lobby.
    Refuse { message: String },
    /// member -> host: one encrypted post.
    Post {
        lobby_name: String,
        key: String,
        nonce: Vec<u8>,
        ciphertext: Vec<u8>,
    },
    /// host -> members: an accepted post, ciphertext untouched (relay cores
    /// cannot read it).
    Relay {
        lobby_name: String,
        nonce: Vec<u8>,
        ciphertext: Vec<u8>,
    },
    /// member -> host: leave the lobby.
    Leave { lobby_name: String },
    /// host -> member: you're out.
    Left { lobby_name: String },
    /// member -> host: who is in right now.
    Members { lobby_name: String },
    /// host -> member: the member list.
    MemberList { fingerprints: Vec<String> },
}

/// Private 1:1 text on an authenticated channel to an active device.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum ChannelFrame {
    Send { text: String },
    Ack { at: u64 },
}

/// Options the host fixes before starting a lobby: what members are told it
/// is (title/welcome) and how big it may get. No post-start mutation — a
/// host that wants different walls starts a new lobby.
#[derive(Clone, Debug, Default)]
pub struct LobbyOptions {
    /// Display title. Falls back to the lobby name when empty.
    pub title: String,
    /// Message shown to each member once, at admission.
    pub welcome: String,
    /// Hard cap on simultaneous members (the host itself does not count).
    pub max_members: Option<usize>,
}

#[derive(Clone, Default)]
struct HostState {
    key: String,
    /// PublicIdentity is `Hash`, and relays need the recipient's full key.
    members: std::collections::HashSet<crate::identity::PublicIdentity>,
    title: String,
    welcome: String,
    max_members: Option<usize>,
}

static HOSTS: std::sync::OnceLock<Mutex<HashMap<(PathBuf, String), HostState>>> =
    std::sync::OnceLock::new();

fn hosts_lock() -> std::sync::MutexGuard<'static, HashMap<(PathBuf, String), HostState>> {
    HOSTS
        .get_or_init(|| Mutex::new(HashMap::new()))
        .lock()
        .unwrap()
}

/// Register a lobby this *process* is hosting (`neonet host`). Keyed by home
/// directory so different devices can host in-process (tests) without clash.
pub fn register_host(root: &std::path::Path, name: &str, key_hex: &str, options: LobbyOptions) {
    let mut hosts = hosts_lock();
    hosts.insert(
        (root.to_path_buf(), name.to_string()),
        HostState {
            key: key_hex.to_string(),
            members: std::collections::HashSet::new(),
            title: options.title,
            welcome: options.welcome,
            max_members: options.max_members,
        },
    );
}

fn host_state(root: &std::path::Path, name: &str) -> Option<HostState> {
    hosts_lock()
        .get(&(root.to_path_buf(), name.to_string()))
        .cloned()
}

fn key_bytes(key_hex: &str) -> Option<[u8; 32]> {
    let bytes = hex::decode(key_hex).ok()?;
    bytes.try_into().ok()
}

fn new_message_id() -> MessageId {
    let mut id = [0u8; 16];
    OsRng.fill_bytes(&mut id);
    id
}

pub async fn handle_lobby(
    node: &Node,
    request: &Message,
    frame: LobbyFrame,
) -> io::Result<Handling> {
    match frame {
        LobbyFrame::Join { lobby_name, key } => {
            enum JoinDecision {
                Admitted { title: String, welcome: String },
                Full,
                WrongKey,
                Unknown,
            }
            let decision = {
                let mut hosts = hosts_lock();
                match hosts.get_mut(&(node.home().to_path_buf(), lobby_name.clone())) {
                    Some(state) if state.key == key => {
                        let at_cap = state
                            .max_members
                            .map(|cap| state.members.len() >= cap)
                            .unwrap_or(false);
                        if at_cap {
                            JoinDecision::Full
                        } else {
                            state.members.insert(request.sender.clone());
                            JoinDecision::Admitted {
                                title: state.title.clone(),
                                welcome: state.welcome.clone(),
                            }
                        }
                    }
                    Some(_) => JoinDecision::WrongKey,
                    None => JoinDecision::Unknown,
                }
            };
            match decision {
                JoinDecision::Full => {
                    let _ = reply(
                        node,
                        request,
                        AppFrame::Lobby(LobbyFrame::Refuse {
                            message: "lobby is at its member cap".into(),
                        }),
                    )
                    .await;
                    Ok(Handling::default())
                }
                JoinDecision::Admitted { title, welcome } => {
                    let _ = reply(
                        node,
                        request,
                        AppFrame::Lobby(LobbyFrame::Joined {
                            lobby_name: lobby_name.clone(),
                            title,
                            welcome,
                        }),
                    )
                    .await;
                    Ok(Handling::notify(format!(
                        "[lobby {lobby_name}] {} joined",
                        request.sender.fingerprint()
                    )))
                }
                JoinDecision::WrongKey => {
                    let _ = reply(
                        node,
                        request,
                        AppFrame::Lobby(LobbyFrame::Refuse {
                            message: "wrong lobby key".into(),
                        }),
                    )
                    .await;
                    Ok(Handling::default())
                }
                JoinDecision::Unknown => {
                    let _ = reply(
                        node,
                        request,
                        AppFrame::Lobby(LobbyFrame::Refuse {
                            message: format!("no lobby named {lobby_name:?} is hosted here"),
                        }),
                    )
                    .await;
                    Ok(Handling::default())
                }
            }
        }
        LobbyFrame::Post {
            lobby_name,
            key,
            nonce,
            ciphertext,
        } => {
            let key_ok = host_state(node.home(), &lobby_name)
                .map(|state| state.key == key)
                .unwrap_or(false);
            if !key_ok {
                let _ = reply(
                    node,
                    request,
                    AppFrame::Lobby(LobbyFrame::Refuse {
                        message: "wrong lobby key or no such lobby".into(),
                    }),
                )
                .await;
                return Ok(Handling::default());
            }
            let Some(key_bytes) = key_bytes(&key) else {
                let _ = reply(
                    node,
                    request,
                    AppFrame::Lobby(LobbyFrame::Refuse {
                        message: "malformed lobby key".into(),
                    }),
                )
                .await;
                return Ok(Handling::default());
            };
            let text = match crate::lobby::decrypt(&key_bytes, &nonce, &ciphertext) {
                Ok(text) => String::from_utf8_lossy(&text).into_owned(),
                Err(_) => {
                    let _ = reply(
                        node,
                        request,
                        AppFrame::Lobby(LobbyFrame::Refuse {
                            message: "could not decrypt post".into(),
                        }),
                    )
                    .await;
                    return Ok(Handling::default());
                }
            };
            let members = {
                let hosts = hosts_lock();
                hosts
                    .get(&(node.home().to_path_buf(), lobby_name.clone()))
                    .map(|state| state.members.clone())
                    .unwrap_or_default()
            };
            crate::lobby::append_lobby(
                node.home(),
                &lobby_name,
                &request.sender.fingerprint(),
                &text,
            )?;
            let relay = AppFrame::Lobby(LobbyFrame::Relay {
                lobby_name: lobby_name.clone(),
                nonce: nonce.clone(),
                ciphertext: ciphertext.clone(),
            });
            let payload = relay.encode()?;
            let mut relayed = 0usize;
            for member in &members {
                let pushed = Message {
                    id: new_message_id(),
                    sender: node.identity(),
                    recipient: member.clone(),
                    payload: payload.clone(),
                };
                if node.send_raw(pushed).await.is_ok() {
                    relayed += 1;
                }
            }
            let _ = reply(
                node,
                request,
                AppFrame::Lobby(LobbyFrame::Posted {
                    lobby_name: lobby_name.clone(),
                    relayed,
                }),
            )
            .await;
            Ok(Handling::notify(format!(
                "[lobby {lobby_name}] {} posts relayed to {relayed} member(s): {text}",
                request.sender.fingerprint()
            )))
        }
        LobbyFrame::Relay {
            lobby_name,
            nonce,
            ciphertext,
        } => {
            let Some(roster_entry) = crate::lobby::find_roster(node.home(), &lobby_name) else {
                return Ok(Handling::default());
            };
            if request.sender.fingerprint() != roster_entry.host_fingerprint {
                return Ok(Handling::default());
            }
            let Some(key) = key_bytes(&roster_entry.key_hex) else {
                return Ok(Handling::default());
            };
            match crate::lobby::decrypt(&key, &nonce, &ciphertext) {
                Ok(plaintext) => {
                    let text = String::from_utf8_lossy(&plaintext).into_owned();
                    crate::lobby::append_lobby(
                        node.home(),
                        &lobby_name,
                        &request.sender.fingerprint(),
                        &text,
                    )?;
                    Ok(Handling::notify(format!(
                        "[lobby {lobby_name}] {}: {text}",
                        request.sender.fingerprint()
                    )))
                }
                Err(_) => Ok(Handling::default()),
            }
        }
        LobbyFrame::Leave { lobby_name } => {
            if let Some(state) =
                hosts_lock().get_mut(&(node.home().to_path_buf(), lobby_name.clone()))
            {
                state.members.remove(&request.sender);
            }
            let _ = reply(
                node,
                request,
                AppFrame::Lobby(LobbyFrame::Left {
                    lobby_name: lobby_name.clone(),
                }),
            )
            .await;
            Ok(Handling::notify(format!(
                "[lobby {lobby_name}] {} left",
                request.sender.fingerprint()
            )))
        }
        LobbyFrame::Members { lobby_name } => {
            let fingerprints = host_state(node.home(), &lobby_name)
                .map(|state| {
                    let mut names: Vec<String> =
                        state.members.iter().map(|m| m.fingerprint()).collect();
                    names.sort();
                    names
                })
                .unwrap_or_default();
            let _ = reply(
                node,
                request,
                AppFrame::Lobby(LobbyFrame::MemberList { fingerprints }),
            )
            .await;
            Ok(Handling::default())
        }
        LobbyFrame::Joined { .. } => Ok(Handling::default()),
        LobbyFrame::Posted { .. } => Ok(Handling::default()),
        LobbyFrame::MemberList { .. } => Ok(Handling::default()),
        LobbyFrame::Left { .. } => Ok(Handling::default()),
        LobbyFrame::Refuse { message } => Ok(Handling::notify(format!("lobby refused: {message}"))),
    }
}

pub async fn handle_channel(
    node: &Node,
    request: &Message,
    frame: ChannelFrame,
) -> io::Result<Handling> {
    match frame {
        ChannelFrame::Send { text } => {
            let at = crate::lobby::unix_now();
            crate::lobby::append_channel(node.home(), &request.sender.fingerprint(), &text)?;
            let _ = reply(node, request, AppFrame::Channel(ChannelFrame::Ack { at })).await;
            Ok(Handling::notify(format!(
                "[channel] {}: {text}",
                request.sender.fingerprint()
            )))
        }
        ChannelFrame::Ack { at } => Ok(Handling::notify(format!("channel ack at {at}"))),
    }
}
