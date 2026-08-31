//! Wire frames for Burrow (lazy, read-only shared directory access).
//!
//! The server side exposes `list`/`read`/`fork` only — there is no write
//! primitive anywhere in this module, so read-only is enforced on the host
//! regardless of what the client asks for. Request/response pairing mirrors
//! the transport messaging id, exactly like every other app frame.

use super::{reply, AppFrame, Handling};
use crate::{burrow::Entry, files::FileError, messaging::Message, node::Node};
use serde::{Deserialize, Serialize};
use std::io;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum BurrowFrame {
    /// Client -> host: browse one relative path (metadata only).
    List { path: String },
    /// Host -> client: the listing (never any file content).
    Listing { path: String, entries: Vec<Entry> },
    /// Client -> host: read one file's bytes.
    Read { path: String },
    /// Host -> client: file bytes.
    Content { path: String, bytes: Vec<u8> },
    /// Client -> host: pull a full local copy (explicit, not lazy).
    Fork { path: String },
    /// Host -> client: fork result.
    ForkResult {
        path: String,
        ok: bool,
        error: Option<String>,
    },
    /// Host -> client: a request failed.
    Error {
        path: Option<String>,
        message: String,
    },
}

pub async fn handle(node: &Node, request: &Message, frame: BurrowFrame) -> io::Result<Handling> {
    let share_root = node.home().join("share");
    match frame {
        BurrowFrame::List { path } => {
            // Directory browsing is notified to the operator by default (not
            // silent) per the architecture doc.
            let notify = format!("[burrow] {} browsed {}", request.sender.fingerprint(), path);
            match share(&share_root).and_then(|share| share.list(&path)) {
                Ok(entries) => {
                    let _ = reply(
                        node,
                        request,
                        AppFrame::Burrow(BurrowFrame::Listing { path, entries }),
                    )
                    .await;
                    Ok(Handling::notify(notify))
                }
                Err(e) => {
                    let _ = reply(
                        node,
                        request,
                        AppFrame::Burrow(BurrowFrame::Error {
                            path: Some(path),
                            message: e.to_string(),
                        }),
                    )
                    .await;
                    Ok(Handling::default())
                }
            }
        }
        BurrowFrame::Read { path } => {
            match share(&share_root).and_then(|share| share.read(&path)) {
                Ok(bytes) => {
                    let _ = reply(
                        node,
                        request,
                        AppFrame::Burrow(BurrowFrame::Content { path, bytes }),
                    )
                    .await;
                    Ok(Handling::default())
                }
                Err(e) => {
                    let _ = reply(
                        node,
                        request,
                        AppFrame::Burrow(BurrowFrame::Error {
                            path: Some(path),
                            message: e.to_string(),
                        }),
                    )
                    .await;
                    Ok(Handling::default())
                }
            }
        }
        BurrowFrame::Fork { path } => {
            let destination = node.home().join("forked");
            match share(&share_root).and_then(|share| share.fork(&path, destination.join(&path))) {
                Ok(()) => {
                    let _ = reply(
                        node,
                        request,
                        AppFrame::Burrow(BurrowFrame::ForkResult {
                            path: path.clone(),
                            ok: true,
                            error: None,
                        }),
                    )
                    .await;
                    Ok(Handling::notify(format!("[burrow] forked {path}")))
                }
                Err(e) => {
                    let _ = reply(
                        node,
                        request,
                        AppFrame::Burrow(BurrowFrame::ForkResult {
                            path: path.clone(),
                            ok: false,
                            error: Some(e.to_string()),
                        }),
                    )
                    .await;
                    Ok(Handling::default())
                }
            }
        }
        BurrowFrame::Listing { path: _, entries } => {
            let lines: Vec<String> = entries
                .iter()
                .map(|entry| {
                    let kind = match entry.kind {
                        crate::burrow::EntryKind::File => "",
                        crate::burrow::EntryKind::Directory => "/",
                        crate::burrow::EntryKind::Symlink => "@",
                    };
                    format!("{}{}\t{}", entry.name, kind, entry.size)
                })
                .collect();
            let body = if lines.is_empty() {
                "(empty)".to_string()
            } else {
                lines.join("\n")
            };
            Ok(Handling::notify(format!("[burrow] listing\n{body}")))
        }
        BurrowFrame::Content { path, bytes } => Ok(Handling::notify(format!(
            "[burrow] {}: {} bytes",
            path,
            bytes.len()
        ))),
        BurrowFrame::ForkResult { path, ok, error } => match ok {
            true => Ok(Handling::notify(format!(
                "[burrow] fork of {path} succeeded"
            ))),
            false => Ok(Handling::notify(format!(
                "[burrow] fork of {path} failed: {}",
                error.unwrap_or_default()
            ))),
        },
        BurrowFrame::Error { path, message } => Ok(Handling::notify(format!(
            "[burrow] {}: {message}",
            path.unwrap_or_default()
        ))),
    }
}

fn share(root: &std::path::Path) -> Result<crate::burrow::ReadOnlyShare, FileError> {
    crate::burrow::ReadOnlyShare::open(root)
}
