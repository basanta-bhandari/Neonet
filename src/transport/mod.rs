use crate::{
    bootstrap::BootstrapEntry,
    identity::Identity,
    protocol::{self, Challenge, Hello, SignatureMessage},
};
use std::io;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Length-prefixed binary frames. The cap prevents an unauthenticated peer from
/// forcing arbitrary allocations during the foundation handshake.
pub const MAX_FRAME: usize = 1024 * 1024;

pub async fn write_frame<W: AsyncWrite + Unpin>(writer: &mut W, payload: &[u8]) -> io::Result<()> {
    if payload.len() > MAX_FRAME {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "frame too large",
        ));
    }
    writer.write_u32(payload.len() as u32).await?;
    writer.write_all(payload).await?;
    writer.flush().await
}

pub async fn read_frame<R: AsyncRead + Unpin>(reader: &mut R) -> io::Result<Vec<u8>> {
    let len = reader.read_u32().await? as usize;
    if len > MAX_FRAME {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "frame too large",
        ));
    }
    let mut buf = vec![0u8; len];
    reader.read_exact(&mut buf).await?;
    Ok(buf)
}

/// Result of the authenticated foundation handshake.
#[derive(Clone, Debug)]
pub struct HandshakeResult {
    pub remote: Hello,
    pub negotiated: protocol::NegotiatedProtocol,
}

/// Mutual HELLO -> CHALLENGE -> SIGNATURE authentication.
///
/// Both peers send HELLO first, then each challenges the other. This avoids
/// asymmetric authentication and also makes the session identity explicit.
pub async fn handshake<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    identity: &Identity,
    features: Vec<String>,
) -> io::Result<HandshakeResult> {
    handshake_inner(stream, identity, features, None).await
}

/// Authenticated handshake with an optional pinned-identity check.
///
/// When a bootstrap entry is supplied, the remote public key must match the
/// pinned key before the handshake is accepted. The address binding is handled
/// by `handshake_tcp_with_bootstrap`, which selects the entry for the actual
/// TCP peer address.
pub async fn handshake_with_pinned_identity<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    identity: &Identity,
    features: Vec<String>,
    pinned: &crate::identity::PublicIdentity,
) -> io::Result<HandshakeResult> {
    handshake_inner(stream, identity, features, Some(pinned)).await
}

async fn handshake_inner<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    identity: &Identity,
    features: Vec<String>,
    pinned: Option<&crate::identity::PublicIdentity>,
) -> io::Result<HandshakeResult> {
    let local_hello = protocol::new_hello(identity, features);
    write_frame(
        stream,
        &postcard::to_allocvec(&local_hello).map_err(codec_err)?,
    )
    .await?;

    let remote_hello: Hello =
        postcard::from_bytes(&read_frame(stream).await?).map_err(codec_err)?;

    let local_challenge = protocol::challenge();
    write_frame(
        stream,
        &postcard::to_allocvec(&local_challenge).map_err(codec_err)?,
    )
    .await?;

    let remote_challenge: Challenge =
        postcard::from_bytes(&read_frame(stream).await?).map_err(codec_err)?;

    let local_signature = protocol::sign_challenge(identity, &remote_hello, &remote_challenge);
    write_frame(
        stream,
        &postcard::to_allocvec(&local_signature).map_err(codec_err)?,
    )
    .await?;

    let remote_signature: SignatureMessage =
        postcard::from_bytes(&read_frame(stream).await?).map_err(codec_err)?;
    // The remote peer signed *our HELLO* and *our challenge*.
    protocol::verify_challenge(
        &local_hello,
        &local_challenge,
        &remote_hello.identity,
        &remote_signature,
    )
    .map_err(|e| io::Error::new(io::ErrorKind::PermissionDenied, e))?;

    if let Some(pinned) = pinned {
        if pinned.public_key != remote_hello.identity.public_key {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "remote identity does not match pinned public key",
            ));
        }
    }

    let negotiated = protocol::negotiate(
        &local_hello.version,
        &local_hello.features,
        &remote_hello.version,
        &remote_hello.features,
    )
    .map_err(|e| io::Error::new(io::ErrorKind::Unsupported, e))?;

    Ok(HandshakeResult {
        remote: remote_hello,
        negotiated,
    })
}

fn codec_err<E: std::fmt::Display>(e: E) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, e.to_string())
}

/// Selects the bootstrap pin matching the connected TCP peer address and
/// performs the authenticated handshake.
pub async fn handshake_tcp_with_bootstrap(
    stream: &mut tokio::net::TcpStream,
    identity: &Identity,
    features: Vec<String>,
    bootstrap: &[BootstrapEntry],
) -> io::Result<HandshakeResult> {
    let peer = stream.peer_addr()?;
    let entry = bootstrap
        .iter()
        .find(|entry| entry.address == peer)
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("no bootstrap trust entry for peer {peer}"),
            )
        })?;

    let pinned = crate::identity::PublicIdentity {
        public_key: entry.pinned_public_key,
    };
    handshake_with_pinned_identity(stream, identity, features, &pinned).await
}
