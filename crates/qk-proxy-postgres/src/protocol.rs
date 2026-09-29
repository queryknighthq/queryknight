//! Bounded PostgreSQL startup/message framing for the Simple Query proxy.

use bytes::{Buf, Bytes, BytesMut};
use tokio::io::{AsyncRead, AsyncReadExt};

/// Largest startup packet accepted, including its length word.
pub const MAX_STARTUP_PACKET: usize = 64 * 1024;
/// Largest ordinary frontend/backend frame length field.
pub const MAX_FRAME_LENGTH: usize = 64 * 1024 * 1024;
/// Password/SASL frontend authentication frame limit.
pub const MAX_AUTH_FRAME_LENGTH: usize = 64 * 1024;
/// Largest Query SQL payload, excluding its required final NUL.
pub const MAX_QUERY_BYTES: usize = qk_sql::MAX_SQL_BYTES;
const MAX_STARTUP_PARAMETERS: usize = 64;
const MAX_ERROR_MESSAGE_BYTES: usize = 4096;

/// Errors produced by the bounded PostgreSQL frame reader.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameError {
    /// Peer closed before the next frame began.
    Eof,
    /// Peer closed in the middle of a frame.
    Truncated,
    /// Length or NUL framing is malformed.
    Invalid,
    /// Frame exceeds the configured maximum.
    TooLarge,
    /// SQL payload exceeds the analysis limit; the frame was drained.
    QueryTooLarge,
    /// I/O failure while reading a frame.
    Io,
}

/// One validated message frame, including its original bytes.
#[derive(Debug)]
pub struct Frame {
    /// Frontend/backend message tag.
    pub kind: u8,
    /// Original tag + length + payload bytes. `Bytes` allows the frontend
    /// decoder to split a frame without copying its payload.
    pub raw: Bytes,
}

impl Frame {
    /// Payload without tag and length fields.
    pub fn payload(&self) -> &[u8] {
        &self.raw[5..]
    }
}

/// Length-bounded, cancellation-safe startup/message reader.
pub struct FrameReader<R> {
    reader: R,
    buffered: BytesMut,
}

impl<R: AsyncRead + Unpin> FrameReader<R> {
    /// Wrap an async reader.
    pub fn new(reader: R) -> Self {
        Self {
            reader,
            buffered: BytesMut::with_capacity(8192),
        }
    }

    /// Read one startup packet, validating its size before buffering it.
    pub async fn startup_packet(&mut self) -> Result<Bytes, FrameError> {
        self.fill_to(4, true).await?;
        let length = u32::from_be_bytes(
            self.buffered[..4]
                .try_into()
                .map_err(|_| FrameError::Invalid)?,
        ) as usize;
        if length < 8 {
            return Err(FrameError::Invalid);
        }
        if length > MAX_STARTUP_PACKET {
            return Err(FrameError::TooLarge);
        }
        self.fill_to(length, false).await?;
        Ok(self.buffered.split_to(length).freeze())
    }

    /// Read one typed frontend/backend frame. Oversized Query frames up to the
    /// general frame cap are streamed into a fixed-size scratch buffer and
    /// drained, never allocated, then reported as `QueryTooLarge`.
    pub async fn message(&mut self) -> Result<Frame, FrameError> {
        self.fill_to(5, true).await?;
        let kind = self.buffered[0];
        let length = u32::from_be_bytes(
            self.buffered[1..5]
                .try_into()
                .map_err(|_| FrameError::Invalid)?,
        ) as usize;
        if length < 4 {
            return Err(FrameError::Invalid);
        }
        if length > MAX_FRAME_LENGTH {
            return Err(FrameError::TooLarge);
        }
        if kind == b'p' && length > MAX_AUTH_FRAME_LENGTH {
            return Err(FrameError::TooLarge);
        }
        let frame_length = length.checked_add(1).ok_or(FrameError::TooLarge)?;
        let max_query_length = MAX_QUERY_BYTES + 1 + 4;
        if kind == b'Q' && length > max_query_length {
            self.drain_after_prefix(frame_length - 5).await?;
            return Err(FrameError::QueryTooLarge);
        }
        self.fill_to(frame_length, false).await?;
        let raw = self.buffered.split_to(frame_length).freeze();
        Ok(Frame { kind, raw })
    }

    async fn fill_to(&mut self, amount: usize, allow_clean_eof: bool) -> Result<(), FrameError> {
        let mut scratch = [0u8; 8192];
        while self.buffered.len() < amount {
            let read = self
                .reader
                .read(&mut scratch)
                .await
                .map_err(|_| FrameError::Io)?;
            if read == 0 {
                if allow_clean_eof && self.buffered.is_empty() {
                    return Err(FrameError::Eof);
                }
                return Err(FrameError::Truncated);
            }
            self.buffered.extend_from_slice(&scratch[..read]);
        }
        Ok(())
    }
    async fn drain_after_prefix(&mut self, mut remaining: usize) -> Result<(), FrameError> {
        self.buffered.advance(5);
        let buffered = remaining.min(self.buffered.len());
        self.buffered.advance(buffered);
        remaining -= buffered;
        let mut scratch = [0u8; 8192];
        while remaining > 0 {
            let amount = remaining.min(scratch.len());
            let read = self
                .reader
                .read(&mut scratch[..amount])
                .await
                .map_err(|_| FrameError::Io)?;
            if read == 0 {
                return Err(FrameError::Truncated);
            }
            remaining -= read;
        }
        Ok(())
    }
}

/// Startup packet category before protocol-v3 parsing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StartupKind {
    /// PostgreSQL protocol 3 StartupMessage.
    Startup,
    /// SSLRequest (8 bytes).
    SslRequest,
    /// GSSENCRequest (8 bytes).
    GssEncryptionRequest,
    /// CancelRequest (16 bytes), never forwarded by this proxy.
    CancelRequest,
    /// Any other protocol/version request.
    Unsupported,
}

/// Classify a complete, already bounded startup packet.
pub fn startup_kind(packet: &[u8]) -> Result<StartupKind, FrameError> {
    if packet.len() < 8 || packet.len() > MAX_STARTUP_PACKET {
        return Err(FrameError::Invalid);
    }
    let declared =
        u32::from_be_bytes(packet[0..4].try_into().map_err(|_| FrameError::Invalid)?) as usize;
    if declared != packet.len() {
        return Err(FrameError::Invalid);
    }
    let code = u32::from_be_bytes(packet[4..8].try_into().map_err(|_| FrameError::Invalid)?);
    Ok(match (declared, code) {
        (8, 80_877_103) => StartupKind::SslRequest,
        (8, 80_877_104) => StartupKind::GssEncryptionRequest,
        (16, 80_877_102) => StartupKind::CancelRequest,
        (_, 196_608) => StartupKind::Startup,
        _ => StartupKind::Unsupported,
    })
}

/// Validated key/value entries in a protocol-v3 StartupMessage.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StartupParameters {
    /// UTF-8 key/value pairs in their original order.
    pub pairs: Vec<(String, String)>,
}

/// Parse key/value C strings in a protocol-v3 StartupMessage.
pub fn parse_startup(packet: &[u8]) -> Result<StartupParameters, FrameError> {
    if startup_kind(packet)? != StartupKind::Startup || packet.len() < 9 {
        return Err(FrameError::Invalid);
    }
    let mut offset = 8;
    let mut pairs = Vec::new();
    loop {
        if offset >= packet.len() {
            return Err(FrameError::Invalid);
        }
        if packet[offset] == 0 {
            if offset + 1 != packet.len() {
                return Err(FrameError::Invalid);
            }
            break;
        }
        if pairs.len() >= MAX_STARTUP_PARAMETERS {
            return Err(FrameError::TooLarge);
        }
        let (key, next) = read_cstring(packet, offset)?;
        let (value, next) = read_cstring(packet, next)?;
        if key.is_empty() {
            return Err(FrameError::Invalid);
        }
        pairs.push((key, value));
        offset = next;
    }
    Ok(StartupParameters { pairs })
}

fn read_cstring(input: &[u8], start: usize) -> Result<(String, usize), FrameError> {
    if start >= input.len() {
        return Err(FrameError::Invalid);
    }
    let relative_end = input[start..]
        .iter()
        .position(|byte| *byte == 0)
        .ok_or(FrameError::Invalid)?;
    let end = start.checked_add(relative_end).ok_or(FrameError::Invalid)?;
    let text = std::str::from_utf8(&input[start..end]).map_err(|_| FrameError::Invalid)?;
    Ok((text.to_owned(), end + 1))
}

/// Decode a Simple Query payload into the exact validated UTF-8 SQL string.
pub fn simple_query_sql(payload: &[u8]) -> Result<&str, FrameError> {
    if payload.is_empty() || payload.last() != Some(&0) {
        return Err(FrameError::Invalid);
    }
    let sql = &payload[..payload.len() - 1];
    if sql.contains(&0) {
        return Err(FrameError::Invalid);
    }
    std::str::from_utf8(sql).map_err(|_| FrameError::Invalid)
}

/// Build a protocol-v3 startup packet from ordered validated parameters.
pub fn encode_startup(parameters: &[(String, String)]) -> Result<Vec<u8>, FrameError> {
    if parameters.len() > MAX_STARTUP_PARAMETERS {
        return Err(FrameError::TooLarge);
    }
    let mut packet = Vec::new();
    packet.extend_from_slice(&[0, 0, 0, 0, 0, 3, 0, 0]);
    for (key, value) in parameters {
        if key.contains('\0') || value.contains('\0') {
            return Err(FrameError::Invalid);
        }
        packet.extend_from_slice(key.as_bytes());
        packet.push(0);
        packet.extend_from_slice(value.as_bytes());
        packet.push(0);
        if packet.len() > MAX_STARTUP_PACKET {
            return Err(FrameError::TooLarge);
        }
    }
    packet.push(0);
    if packet.len() > MAX_STARTUP_PACKET {
        return Err(FrameError::TooLarge);
    }
    let length = u32::try_from(packet.len()).map_err(|_| FrameError::TooLarge)?;
    packet[..4].copy_from_slice(&length.to_be_bytes());
    Ok(packet)
}

/// Encode one backend/frontend message frame.
pub fn encode_message(kind: u8, payload: &[u8]) -> Result<Vec<u8>, FrameError> {
    let length = payload.len().checked_add(4).ok_or(FrameError::TooLarge)?;
    if length > MAX_FRAME_LENGTH {
        return Err(FrameError::TooLarge);
    }
    let length = u32::try_from(length).map_err(|_| FrameError::TooLarge)?;
    let mut frame = Vec::with_capacity(payload.len() + 5);
    frame.push(kind);
    frame.extend_from_slice(&length.to_be_bytes());
    frame.extend_from_slice(payload);
    Ok(frame)
}

/// ReadyForQuery carrying the backend's actual transaction status.
pub fn encode_ready(status: u8) -> Result<Vec<u8>, FrameError> {
    if !matches!(status, b'I' | b'T' | b'E') {
        return Err(FrameError::Invalid);
    }
    encode_message(b'Z', &[status])
}

/// EmptyQueryResponse.
pub fn encode_empty_query() -> Result<Vec<u8>, FrameError> {
    encode_message(b'I', &[])
}

/// Structured QueryKnight ErrorResponse. Embedded NULs are replaced and the
/// message is bounded so untrusted SQL text cannot add wire fields.
pub fn encode_error(severity: &str, sqlstate: &str, message: &str) -> Result<Vec<u8>, FrameError> {
    if !matches!(severity, "ERROR" | "FATAL")
        || sqlstate.len() != 5
        || !sqlstate.bytes().all(|byte| byte.is_ascii_alphanumeric())
    {
        return Err(FrameError::Invalid);
    }
    let mut payload = Vec::new();
    push_error_field(&mut payload, b'S', severity);
    push_error_field(&mut payload, b'C', sqlstate);
    push_error_field(&mut payload, b'M', message);
    payload.push(0);
    encode_message(b'E', &payload)
}

fn push_error_field(payload: &mut Vec<u8>, tag: u8, value: &str) {
    payload.push(tag);
    for character in value.chars() {
        if payload.len() >= MAX_ERROR_MESSAGE_BYTES {
            break;
        }
        if character == '\0' {
            payload.push(b' ');
        } else {
            let mut encoded = [0u8; 4];
            let bytes = character.encode_utf8(&mut encoded).as_bytes();
            if payload.len() + bytes.len() > MAX_ERROR_MESSAGE_BYTES {
                break;
            }
            payload.extend_from_slice(bytes);
        }
    }
    payload.push(0);
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;

    #[tokio::test]
    async fn frame_reader_validates_and_preserves_query_frame() {
        let sql = b"SELECT 1";
        let payload = [sql.as_slice(), &[0]].concat();
        let frame = encode_message(b'Q', &payload).unwrap();
        let (mut writer, reader) = tokio::io::duplex(frame.len());
        writer.write_all(&frame).await.unwrap();
        drop(writer);
        let mut reader = FrameReader::new(reader);
        let decoded = reader.message().await.unwrap();
        assert_eq!(decoded.kind, b'Q');
        assert_eq!(simple_query_sql(decoded.payload()).unwrap(), "SELECT 1");
        assert_eq!(decoded.raw.as_ref(), frame);
        assert!(matches!(reader.message().await, Err(FrameError::Eof)));
    }

    #[tokio::test]
    async fn malformed_and_truncated_frames_are_rejected_without_panic() {
        for bytes in [
            vec![0],
            vec![b'Q', 0, 0, 0, 3],
            vec![b'Q', 0, 0, 0, 6, b'x'],
        ] {
            let (mut writer, reader) = tokio::io::duplex(bytes.len());
            writer.write_all(&bytes).await.unwrap();
            drop(writer);
            assert!(FrameReader::new(reader).message().await.is_err());
        }
        assert_eq!(simple_query_sql(b"SELECT 1"), Err(FrameError::Invalid));
        assert_eq!(simple_query_sql(b"SELECT 1\0x\0"), Err(FrameError::Invalid));
        assert_eq!(simple_query_sql(&[0xff, 0]), Err(FrameError::Invalid));
    }

    #[tokio::test]
    async fn oversized_query_is_drained_without_allocating_payload() {
        let payload_len = MAX_QUERY_BYTES + 2;
        let length = (payload_len + 4) as u32;
        let mut frame = Vec::with_capacity(payload_len + 5);
        frame.push(b'Q');
        frame.extend_from_slice(&length.to_be_bytes());
        frame.resize(payload_len + 5, b'x');
        let (mut writer, reader) = tokio::io::duplex(frame.len());
        writer.write_all(&frame).await.unwrap();
        drop(writer);
        let mut reader = FrameReader::new(reader);
        assert!(matches!(
            reader.message().await,
            Err(FrameError::QueryTooLarge)
        ));
        assert!(matches!(reader.message().await, Err(FrameError::Eof)));
    }

    #[test]
    fn startup_fields_and_synthetic_errors_are_structured() {
        let startup = encode_startup(&[
            ("user".to_owned(), "qk".to_owned()),
            ("database".to_owned(), "queryknight".to_owned()),
        ])
        .unwrap();
        assert_eq!(startup_kind(&startup), Ok(StartupKind::Startup));
        assert_eq!(
            parse_startup(&startup).unwrap().pairs,
            vec![
                ("user".to_owned(), "qk".to_owned()),
                ("database".to_owned(), "queryknight".to_owned())
            ]
        );
        let error = encode_error("ERROR", "42501", "malicious\0Mfield").unwrap();
        assert_eq!(&error[5..], b"SERROR\0C42501\0Mmalicious Mfield\0\0");
        assert_eq!(encode_ready(b'T').unwrap()[5], b'T');
    }
}
