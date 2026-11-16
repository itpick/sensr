//! Wire framing: `u32` big-endian length, then one CBOR-encoded [`Envelope`].
//!
//! Every frame carries the protocol version, so there is no handshake round
//! trip: a request is one write and its reply one read (the API read budget
//! is sub-millisecond, docs/research/07). Additive changes (new optional
//! fields, new `Op` variants a peer does not send) keep the version; anything
//! else bumps [`PROTOCOL_VERSION`].

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::proto::{IpcError, Request, Response};

/// The protocol version this build speaks.
pub const PROTOCOL_VERSION: u16 = 1;

/// Upper bound for one frame body. A full config document is well under a
/// megabyte; the cap stops a hostile peer from making the agent allocate.
pub const MAX_FRAME_LEN: usize = 16 << 20;

/// The unit on the wire.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Envelope<B> {
    /// Protocol version of the sender.
    pub v: u16,
    /// Request id chosen by the client; replies and stream frames echo it.
    pub id: u64,
    /// Payload.
    pub body: B,
}

impl<B> Envelope<B> {
    /// Wraps `body` with the current protocol version.
    pub fn new(id: u64, body: B) -> Self {
        Self {
            v: PROTOCOL_VERSION,
            id,
            body,
        }
    }
}

/// Client → agent payloads.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ClientBody {
    /// A request; the agent answers with a [`ServerBody::Response`].
    Request(Request),
    /// Stop the stream opened by request `id`.
    Cancel,
}

/// One item of an open stream.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum StreamItem {
    /// A config/apply event.
    Event(crate::proto::Event),
    /// A free-form progress or log line.
    Line(String),
}

/// Agent → client payloads.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ServerBody {
    /// The single reply to a request (or [`Response::StreamOpened`]).
    Response(Response),
    /// Next stream item.
    Item(StreamItem),
    /// The stream is over; `Some` when it ended in an error.
    End(Option<IpcError>),
}

/// Framing and decoding failures.
#[derive(Debug, thiserror::Error)]
pub enum FrameError {
    /// Socket I/O failed.
    #[error("ipc i/o: {0}")]
    Io(#[from] std::io::Error),
    /// The peer announced a frame above [`MAX_FRAME_LEN`].
    #[error("frame of {0} bytes exceeds the {MAX_FRAME_LEN} byte limit")]
    TooLarge(usize),
    /// Serialization failed (a bug, not a peer error).
    #[error("cbor encode: {0}")]
    Encode(String),
    /// The frame is well delimited but its content is not understood. `id`
    /// is set when the envelope itself decoded, so the error can be answered.
    #[error("cbor decode: {message}")]
    Decode {
        /// Request id, when recoverable.
        id: Option<u64>,
        /// What went wrong.
        message: String,
    },
    /// The peer speaks another protocol version.
    #[error("peer speaks ipc protocol v{theirs}, this side v{PROTOCOL_VERSION}")]
    Version {
        /// Request id.
        id: u64,
        /// Peer version.
        theirs: u16,
    },
}

/// Serializes `env` into a complete frame (length prefix included).
pub fn encode<B: Serialize>(env: &Envelope<B>) -> Result<Vec<u8>, FrameError> {
    let mut buf = vec![0u8; 4];
    ciborium::into_writer(env, &mut buf).map_err(|e| FrameError::Encode(e.to_string()))?;
    let len = buf.len() - 4;
    if len > MAX_FRAME_LEN {
        return Err(FrameError::TooLarge(len));
    }
    // Checked against MAX_FRAME_LEN above, so it fits in u32.
    buf[..4].copy_from_slice(&(len as u32).to_be_bytes());
    Ok(buf)
}

/// Decodes one frame body (without its length prefix).
pub fn decode<B: DeserializeOwned>(body: &[u8]) -> Result<Envelope<B>, FrameError> {
    // Two steps so a body we cannot understand (e.g. an `Op` from a newer
    // client) still yields its id and can be answered with an error frame.
    #[derive(Deserialize)]
    struct Raw {
        v: u16,
        id: u64,
        body: ciborium::Value,
    }
    let raw: Raw = ciborium::from_reader(body).map_err(|e| FrameError::Decode {
        id: None,
        message: e.to_string(),
    })?;
    if raw.v != PROTOCOL_VERSION {
        return Err(FrameError::Version {
            id: raw.id,
            theirs: raw.v,
        });
    }
    let body = raw.body.deserialized().map_err(|e| FrameError::Decode {
        id: Some(raw.id),
        message: e.to_string(),
    })?;
    Ok(Envelope {
        v: raw.v,
        id: raw.id,
        body,
    })
}

/// Writes one frame and flushes.
pub async fn write_frame<W, B>(w: &mut W, env: &Envelope<B>) -> Result<(), FrameError>
where
    W: AsyncWrite + Unpin,
    B: Serialize,
{
    let buf = encode(env)?;
    w.write_all(&buf).await?;
    w.flush().await?;
    Ok(())
}

/// Reads one frame body. `Ok(None)` is a clean end of stream between frames.
pub async fn read_frame_bytes<R: AsyncRead + Unpin>(
    r: &mut R,
) -> Result<Option<Vec<u8>>, FrameError> {
    let mut len = [0u8; 4];
    match r.read_exact(&mut len).await {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e.into()),
    }
    let len = u32::from_be_bytes(len) as usize;
    if len > MAX_FRAME_LEN {
        return Err(FrameError::TooLarge(len));
    }
    let mut body = vec![0u8; len];
    r.read_exact(&mut body).await?;
    Ok(Some(body))
}

/// Reads and decodes one frame.
pub async fn read_frame<R, B>(r: &mut R) -> Result<Option<Envelope<B>>, FrameError>
where
    R: AsyncRead + Unpin,
    B: DeserializeOwned,
{
    match read_frame_bytes(r).await? {
        Some(bytes) => decode(&bytes).map(Some),
        None => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::{Op, Principal};

    fn ping(id: u64) -> Envelope<ClientBody> {
        Envelope::new(
            id,
            ClientBody::Request(Request {
                principal: Principal::unix("root", 0),
                op: Op::Ping,
            }),
        )
    }

    #[test]
    fn round_trip() {
        let frame = encode(&ping(7)).unwrap();
        let len = u32::from_be_bytes(frame[..4].try_into().unwrap()) as usize;
        assert_eq!(len, frame.len() - 4);
        let back: Envelope<ClientBody> = decode(&frame[4..]).unwrap();
        assert_eq!(back, ping(7));
    }

    #[test]
    fn version_mismatch_keeps_id() {
        let mut env = ping(9);
        env.v = PROTOCOL_VERSION + 1;
        let frame = encode(&env).unwrap();
        match decode::<ClientBody>(&frame[4..]) {
            Err(FrameError::Version { id: 9, theirs }) => assert_eq!(theirs, PROTOCOL_VERSION + 1),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn unknown_body_keeps_id() {
        let env = Envelope::new(11, "SomeFutureOp");
        let frame = encode(&env).unwrap();
        match decode::<ClientBody>(&frame[4..]) {
            Err(FrameError::Decode { id: Some(11), .. }) => {}
            other => panic!("{other:?}"),
        }
    }

    #[tokio::test]
    async fn oversized_length_rejected_without_allocating() {
        let mut bytes: &[u8] = &(u32::MAX).to_be_bytes();
        assert!(matches!(
            read_frame_bytes(&mut bytes).await,
            Err(FrameError::TooLarge(_))
        ));
    }

    #[tokio::test]
    async fn clean_eof_is_none() {
        let mut bytes: &[u8] = &[];
        assert!(read_frame_bytes(&mut bytes).await.unwrap().is_none());
    }

    proptest::proptest! {
        // Shadow of the `fuzz_ipc_frame` target (docs/PLAN.md §4).
        #[test]
        fn decode_never_panics(bytes in proptest::collection::vec(proptest::num::u8::ANY, 0..512)) {
            let _ = decode::<ClientBody>(&bytes);
            let _ = decode::<ServerBody>(&bytes);
        }
    }
}
