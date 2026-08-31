//! Wire frames for flash pairing: the requester presents the acceptor's
//! single-use token once; redemption records the requester's key in the
//! acceptor's pairing ledger.

use super::{reply, AppFrame, Handling};
use crate::{messaging::Message, node::Node};
use serde::{Deserialize, Serialize};
use std::io;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum PairFrame {
    /// Requester -> acceptor: "here is the token you published." The token is
    /// single-use and short-lived; the acceptor's operator published it
    /// actively, so a presented token implies physical/active involvement.
    Redeem { token: String },
    /// Acceptor -> requester: this device is now in the acceptor's ledger.
    Redeemed { fingerprint: String },
    /// Acceptor -> requester: the token was already used, expired, or bogus.
    Error { message: String },
}

pub async fn handle(node: &Node, request: &Message, frame: PairFrame) -> io::Result<Handling> {
    match frame {
        PairFrame::Redeem { token } => match crate::pair::consume_token(node.home(), &token) {
            Ok(true) => {
                crate::pair::record_pairing(node.home(), &request.sender)?;
                let _ = reply(
                    node,
                    request,
                    AppFrame::Pair(PairFrame::Redeemed {
                        fingerprint: request.sender.fingerprint(),
                    }),
                )
                .await;
                Ok(Handling::notify(format!(
                    "paired {} (single-use token consumed)",
                    request.sender.fingerprint()
                )))
            }
            Ok(false) => {
                let _ = reply(
                    node,
                    request,
                    AppFrame::Pair(PairFrame::Error {
                        message: "token is invalid, expired, or already used".into(),
                    }),
                )
                .await;
                Ok(Handling::default())
            }
            Err(e) => {
                let _ = reply(
                    node,
                    request,
                    AppFrame::Pair(PairFrame::Error {
                        message: format!("could not consume token: {e}"),
                    }),
                )
                .await;
                Ok(Handling::default())
            }
        },
        PairFrame::Redeemed { .. } => Ok(Handling::default()),
        PairFrame::Error { message } => Ok(Handling::notify(format!("pairing error: {message}"))),
    }
}
