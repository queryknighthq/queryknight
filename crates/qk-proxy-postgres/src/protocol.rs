//! Bounded PostgreSQL startup/message framing for the Simple Query proxy.

use bytes::{Buf, Bytes, BytesMut};
use qk_core::{
    ExecutionParam, ParamRepresentation, MAX_EXECUTION_PARAMS, MAX_EXECUTION_PARAM_BYTES,
};
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

/// A completely decoded PostgreSQL Parse message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtendedParse {
    /// Client statement name; empty denotes the unnamed statement.
    pub name: String,
    /// Exact decoded SQL bytes after required UTF-8 validation.
    pub sql: String,
    /// Declared Parse parameter OIDs; zero and absent entries are unspecified.
    pub parameter_type_hints: Vec<Option<u32>>,
}

/// A completely decoded PostgreSQL Bind message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtendedBind {
    /// Client portal name; empty denotes the unnamed portal.
    pub portal_name: String,
    /// Source prepared-statement name; empty denotes the unnamed statement.
    pub statement_name: String,
    /// Ordered protocol-neutral wire values for Exact V2 authorization.
    pub execution_params: Vec<ExecutionParam>,
    /// Effective per-parameter formats (expanded from PostgreSQL's 0/1/N rule).
    pub parameter_formats: Vec<ParamRepresentation>,
    /// Original result-column format codes, which are not part of approval identity.
    pub result_formats: Vec<i16>,
}

/// A completely decoded PostgreSQL Execute message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtendedExecute {
    /// Target portal name; empty denotes the unnamed portal.
    pub portal_name: String,
    /// Maximum result rows requested by the frontend; zero means unlimited.
    pub max_rows: u32,
}

/// Prepared statement or portal target selector.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExtendedTarget {
    /// Prepared statement (`S`).
    Statement,
    /// Portal (`P`).
    Portal,
}

/// A completely decoded PostgreSQL Describe or Close target.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtendedTargetMessage {
    /// Target kind.
    pub target: ExtendedTarget,
    /// Client statement or portal name; empty denotes unnamed.
    pub name: String,
}

struct PayloadReader<'a> {
    payload: &'a [u8],
    offset: usize,
}

impl<'a> PayloadReader<'a> {
    fn new(payload: &'a [u8]) -> Self {
        Self { payload, offset: 0 }
    }

    fn cstring(&mut self) -> Result<&'a str, FrameError> {
        let remaining = self.payload.get(self.offset..).ok_or(FrameError::Invalid)?;
        let end = remaining
            .iter()
            .position(|byte| *byte == 0)
            .ok_or(FrameError::Invalid)?;
        if end > MAX_PROTOCOL_NAME_BYTES {
            return Err(FrameError::TooLarge);
        }
        let value = std::str::from_utf8(&remaining[..end]).map_err(|_| FrameError::Invalid)?;
        self.offset = self
            .offset
            .checked_add(end + 1)
            .ok_or(FrameError::Invalid)?;
        Ok(value)
    }

    fn sql_cstring(&mut self) -> Result<&'a str, FrameError> {
        let remaining = self.payload.get(self.offset..).ok_or(FrameError::Invalid)?;
        let end = remaining
            .iter()
            .position(|byte| *byte == 0)
            .ok_or(FrameError::Invalid)?;
        if end > MAX_QUERY_BYTES {
            return Err(FrameError::TooLarge);
        }
        let value = std::str::from_utf8(&remaining[..end]).map_err(|_| FrameError::Invalid)?;
        self.offset = self
            .offset
            .checked_add(end + 1)
            .ok_or(FrameError::Invalid)?;
        Ok(value)
    }

    fn i16(&mut self) -> Result<i16, FrameError> {
        let bytes = self.take(2)?;
        Ok(i16::from_be_bytes(
            bytes.try_into().map_err(|_| FrameError::Invalid)?,
        ))
    }

    fn u32(&mut self) -> Result<u32, FrameError> {
        let bytes = self.take(4)?;
        Ok(u32::from_be_bytes(
            bytes.try_into().map_err(|_| FrameError::Invalid)?,
        ))
    }

    fn i32(&mut self) -> Result<i32, FrameError> {
        let bytes = self.take(4)?;
        Ok(i32::from_be_bytes(
            bytes.try_into().map_err(|_| FrameError::Invalid)?,
        ))
    }

    fn count(&mut self) -> Result<usize, FrameError> {
        let count = self.i16()?;
        if count < 0 {
            return Err(FrameError::Invalid);
        }
        let count = count as usize;
        if count > MAX_EXECUTION_PARAMS {
            return Err(FrameError::TooLarge);
        }
        Ok(count)
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], FrameError> {
        let end = self.offset.checked_add(length).ok_or(FrameError::Invalid)?;
        let bytes = self
            .payload
            .get(self.offset..end)
            .ok_or(FrameError::Invalid)?;
        self.offset = end;
        Ok(bytes)
    }

    fn finish(self) -> Result<(), FrameError> {
        if self.offset == self.payload.len() {
            Ok(())
        } else {
            Err(FrameError::Invalid)
        }
    }
}

/// Maximum UTF-8 length of one protocol statement/portal name.
pub const MAX_PROTOCOL_NAME_BYTES: usize = 1024;

/// Decode and validate a PostgreSQL Parse payload without authorizing SQL.
pub fn parse_extended_parse(payload: &[u8]) -> Result<ExtendedParse, FrameError> {
    let mut reader = PayloadReader::new(payload);
    let name = reader.cstring()?.to_owned();
    let sql = reader.sql_cstring()?.to_owned();
    let parameter_count = reader.count()?;
    let mut parameter_type_hints = Vec::with_capacity(parameter_count);
    for _ in 0..parameter_count {
        let oid = reader.u32()?;
        parameter_type_hints.push((oid != 0).then_some(oid));
    }
    reader.finish()?;
    Ok(ExtendedParse {
        name,
        sql,
        parameter_type_hints,
    })
}

/// Decode and validate a PostgreSQL Bind payload into Exact V2 wire identity.
pub fn parse_extended_bind(
    payload: &[u8],
    parameter_type_hints: &[Option<u32>],
) -> Result<ExtendedBind, FrameError> {
    let mut reader = PayloadReader::new(payload);
    let portal_name = reader.cstring()?.to_owned();
    let statement_name = reader.cstring()?.to_owned();
    let format_count = reader.count()?;
    let mut formats = Vec::with_capacity(format_count);
    for _ in 0..format_count {
        formats.push(parse_format_code(reader.i16()?)?);
    }
    let parameter_count = reader.count()?;
    if format_count != 0 && format_count != 1 && format_count != parameter_count {
        return Err(FrameError::Invalid);
    }
    let mut parameter_formats = Vec::with_capacity(parameter_count);
    let mut execution_params = Vec::with_capacity(parameter_count);
    let mut aggregate_bytes = 0usize;
    for index in 0..parameter_count {
        let length = reader.i32()?;
        if length == -1 {
            execution_params.push(ExecutionParam::Null);
        } else {
            if length < 0 {
                return Err(FrameError::Invalid);
            }
            let length = length as usize;
            aggregate_bytes = aggregate_bytes
                .checked_add(length)
                .ok_or(FrameError::TooLarge)?;
            if aggregate_bytes > MAX_EXECUTION_PARAM_BYTES {
                return Err(FrameError::TooLarge);
            }
            let bytes = reader.take(length)?;
            let format = if formats.is_empty() {
                ParamRepresentation::Text
            } else if formats.len() == 1 {
                formats[0]
            } else {
                formats[index]
            };
            let type_hint = parameter_type_hints.get(index).copied().flatten();
            execution_params.push(ExecutionParam::Wire {
                representation: format,
                type_hint,
                bytes: bytes.to_vec(),
            });
        }
        let format = if formats.is_empty() {
            ParamRepresentation::Text
        } else if formats.len() == 1 {
            formats[0]
        } else {
            formats[index]
        };
        parameter_formats.push(format);
    }
    let result_format_count = reader.count()?;
    let mut result_formats = Vec::with_capacity(result_format_count);
    for _ in 0..result_format_count {
        let code = reader.i16()?;
        parse_format_code(code)?;
        result_formats.push(code);
    }
    reader.finish()?;
    Ok(ExtendedBind {
        portal_name,
        statement_name,
        execution_params,
        parameter_formats,
        result_formats,
    })
}

/// Decode and validate a PostgreSQL Execute payload.
pub fn parse_extended_execute(payload: &[u8]) -> Result<ExtendedExecute, FrameError> {
    let mut reader = PayloadReader::new(payload);
    let portal_name = reader.cstring()?.to_owned();
    let max_rows = reader.i32()?;
    if max_rows < 0 {
        return Err(FrameError::Invalid);
    }
    reader.finish()?;
    Ok(ExtendedExecute {
        portal_name,
        max_rows: max_rows as u32,
    })
}

/// Decode a PostgreSQL Describe or Close target payload.
pub fn parse_extended_target(payload: &[u8]) -> Result<ExtendedTargetMessage, FrameError> {
    let (&kind, rest) = payload.split_first().ok_or(FrameError::Invalid)?;
    let target = match kind {
        b'S' => ExtendedTarget::Statement,
        b'P' => ExtendedTarget::Portal,
        _ => return Err(FrameError::Invalid),
    };
    let mut reader = PayloadReader::new(rest);
    let name = reader.cstring()?.to_owned();
    reader.finish()?;
    Ok(ExtendedTargetMessage { target, name })
}

/// Validate parameterless Sync and Flush message payloads.
pub fn validate_empty_message(payload: &[u8]) -> Result<(), FrameError> {
    if payload.is_empty() {
        Ok(())
    } else {
        Err(FrameError::Invalid)
    }
}

fn parse_format_code(code: i16) -> Result<ParamRepresentation, FrameError> {
    match code {
        0 => Ok(ParamRepresentation::Text),
        1 => Ok(ParamRepresentation::Binary),
        _ => Err(FrameError::Invalid),
    }
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

    fn cstring(payload: &mut Vec<u8>, value: &str) {
        payload.extend_from_slice(value.as_bytes());
        payload.push(0);
    }

    fn i16_bytes(payload: &mut Vec<u8>, value: i16) {
        payload.extend_from_slice(&value.to_be_bytes());
    }

    fn i32_bytes(payload: &mut Vec<u8>, value: i32) {
        payload.extend_from_slice(&value.to_be_bytes());
    }

    fn bind_payload(formats: &[i16], params: &[Option<&[u8]>], result_formats: &[i16]) -> Vec<u8> {
        let mut payload = Vec::new();
        cstring(&mut payload, "portal");
        cstring(&mut payload, "statement");
        i16_bytes(&mut payload, formats.len() as i16);
        for format in formats {
            i16_bytes(&mut payload, *format);
        }
        i16_bytes(&mut payload, params.len() as i16);
        for value in params {
            match value {
                Some(value) => {
                    i32_bytes(&mut payload, value.len() as i32);
                    payload.extend_from_slice(value);
                }
                None => i32_bytes(&mut payload, -1),
            }
        }
        i16_bytes(&mut payload, result_formats.len() as i16);
        for format in result_formats {
            i16_bytes(&mut payload, *format);
        }
        payload
    }

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

    #[test]
    fn parse_decoder_tracks_exact_sql_and_declared_oids_only() {
        let mut payload = Vec::new();
        cstring(&mut payload, "s1");
        cstring(&mut payload, "SELECT $1, $2");
        i16_bytes(&mut payload, 2);
        payload.extend_from_slice(&23u32.to_be_bytes());
        payload.extend_from_slice(&0u32.to_be_bytes());
        let parsed = parse_extended_parse(&payload).unwrap();
        assert_eq!(parsed.name, "s1");
        assert_eq!(parsed.sql, "SELECT $1, $2");
        assert_eq!(parsed.parameter_type_hints, [Some(23), None]);

        let mut missing_sql_nul = Vec::new();
        cstring(&mut missing_sql_nul, "s");
        missing_sql_nul.extend_from_slice(b"SELECT 1");
        assert_eq!(
            parse_extended_parse(&missing_sql_nul),
            Err(FrameError::Invalid)
        );

        let mut truncated_oid = Vec::new();
        cstring(&mut truncated_oid, "s");
        cstring(&mut truncated_oid, "SELECT $1");
        i16_bytes(&mut truncated_oid, 1);
        truncated_oid.extend_from_slice(&23u16.to_be_bytes());
        assert_eq!(
            parse_extended_parse(&truncated_oid),
            Err(FrameError::Invalid)
        );

        let mut excessive_oids = Vec::new();
        cstring(&mut excessive_oids, "s");
        cstring(&mut excessive_oids, "SELECT 1");
        i16_bytes(&mut excessive_oids, (MAX_EXECUTION_PARAMS + 1) as i16);
        assert_eq!(
            parse_extended_parse(&excessive_oids),
            Err(FrameError::TooLarge)
        );

        let mut invalid_utf8 = Vec::new();
        cstring(&mut invalid_utf8, "s");
        invalid_utf8.extend_from_slice(&[0xff, 0, 0, 0]);
        assert_eq!(
            parse_extended_parse(&invalid_utf8),
            Err(FrameError::Invalid)
        );
    }

    #[test]
    fn bind_decoder_applies_formats_nulls_and_declared_type_hints() {
        let text_payload = bind_payload(&[], &[Some(b"42"), None], &[1]);
        let text = parse_extended_bind(&text_payload, &[Some(23), Some(20)]).unwrap();
        assert_eq!(text.portal_name, "portal");
        assert_eq!(text.statement_name, "statement");
        assert_eq!(
            text.parameter_formats,
            [ParamRepresentation::Text, ParamRepresentation::Text]
        );
        assert_eq!(
            text.execution_params,
            [
                ExecutionParam::Wire {
                    representation: ParamRepresentation::Text,
                    type_hint: Some(23),
                    bytes: b"42".to_vec(),
                },
                ExecutionParam::Null,
            ]
        );
        assert_eq!(text.result_formats, [1]);

        let binary_payload = bind_payload(&[1], &[Some(&[0, 0, 0, 42])], &[]);
        let binary = parse_extended_bind(&binary_payload, &[Some(23)]).unwrap();
        assert_eq!(
            binary.execution_params,
            [ExecutionParam::Wire {
                representation: ParamRepresentation::Binary,
                type_hint: Some(23),
                bytes: [0, 0, 0, 42].to_vec(),
            }]
        );
        let text_digest = qk_core::exact_request_digest_v2(
            qk_sql::SqlDialect::PostgreSql,
            "SELECT $1::int4",
            &text.execution_params[..1],
        )
        .unwrap();
        let binary_digest = qk_core::exact_request_digest_v2(
            qk_sql::SqlDialect::PostgreSql,
            "SELECT $1::int4",
            &binary.execution_params,
        )
        .unwrap();
        assert_ne!(text_digest, binary_digest);

        let other_oid = parse_extended_bind(&binary_payload, &[Some(20)]).unwrap();
        assert_ne!(
            qk_core::exact_request_digest_v2(
                qk_sql::SqlDialect::PostgreSql,
                "SELECT $1::int4",
                &binary.execution_params
            ),
            qk_core::exact_request_digest_v2(
                qk_sql::SqlDialect::PostgreSql,
                "SELECT $1::int4",
                &other_oid.execution_params
            )
        );
        let unspecified_oid = parse_extended_bind(&binary_payload, &[None]).unwrap();
        assert_eq!(
            match &unspecified_oid.execution_params[0] {
                ExecutionParam::Wire { type_hint, .. } => *type_hint,
                _ => unreachable!(),
            },
            None
        );
    }

    #[test]
    fn per_parameter_formats_and_exact_sql_size_are_bounded() {
        let payload = bind_payload(&[0, 1], &[Some(b"42"), Some(&[0, 0, 0, 42])], &[]);
        let bind = parse_extended_bind(&payload, &[Some(23), Some(23)]).unwrap();
        assert_eq!(
            bind.parameter_formats,
            [ParamRepresentation::Text, ParamRepresentation::Binary]
        );
        assert_eq!(
            bind.execution_params.len(),
            2,
            "ordered values stay per-parameter"
        );

        let mut oversized_sql = Vec::new();
        cstring(&mut oversized_sql, "");
        oversized_sql.extend(std::iter::repeat_n(b'x', MAX_QUERY_BYTES + 1));
        oversized_sql.push(0);
        i16_bytes(&mut oversized_sql, 0);
        assert_eq!(
            parse_extended_parse(&oversized_sql),
            Err(FrameError::TooLarge)
        );
    }

    #[test]
    fn extended_codecs_reject_malformed_counts_lengths_and_formats() {
        assert_eq!(
            parse_extended_bind(b"portal", &[]),
            Err(FrameError::Invalid)
        );
        assert_eq!(
            parse_extended_bind(b"portal\0statement", &[]),
            Err(FrameError::Invalid)
        );

        let mismatched_formats = bind_payload(&[0, 1], &[Some(b"x")], &[]);
        assert_eq!(
            parse_extended_bind(&mismatched_formats, &[None]),
            Err(FrameError::Invalid)
        );
        let invalid_parameter_format = bind_payload(&[2], &[Some(b"x")], &[]);
        assert_eq!(
            parse_extended_bind(&invalid_parameter_format, &[None]),
            Err(FrameError::Invalid)
        );
        let invalid_result_format = bind_payload(&[], &[Some(b"x")], &[2]);
        assert_eq!(
            parse_extended_bind(&invalid_result_format, &[None]),
            Err(FrameError::Invalid)
        );
        let mut negative_format_count = Vec::new();
        cstring(&mut negative_format_count, "p");
        cstring(&mut negative_format_count, "s");
        i16_bytes(&mut negative_format_count, -1);
        assert_eq!(
            parse_extended_bind(&negative_format_count, &[]),
            Err(FrameError::Invalid)
        );

        let mut truncated_result_formats = Vec::new();
        cstring(&mut truncated_result_formats, "p");
        cstring(&mut truncated_result_formats, "s");
        i16_bytes(&mut truncated_result_formats, 0);
        i16_bytes(&mut truncated_result_formats, 0);
        i16_bytes(&mut truncated_result_formats, 1);
        assert_eq!(
            parse_extended_bind(&truncated_result_formats, &[]),
            Err(FrameError::Invalid)
        );

        let mut excessive_params = Vec::new();
        cstring(&mut excessive_params, "p");
        cstring(&mut excessive_params, "s");
        i16_bytes(&mut excessive_params, 0);
        i16_bytes(&mut excessive_params, (MAX_EXECUTION_PARAMS + 1) as i16);
        assert_eq!(
            parse_extended_bind(&excessive_params, &[]),
            Err(FrameError::TooLarge)
        );

        let mut invalid_negative_length = Vec::new();
        cstring(&mut invalid_negative_length, "p");
        cstring(&mut invalid_negative_length, "s");
        i16_bytes(&mut invalid_negative_length, 0);
        i16_bytes(&mut invalid_negative_length, 1);
        i32_bytes(&mut invalid_negative_length, -2);
        i16_bytes(&mut invalid_negative_length, 0);
        assert_eq!(
            parse_extended_bind(&invalid_negative_length, &[None]),
            Err(FrameError::Invalid)
        );

        let mut truncated_parameter = Vec::new();
        cstring(&mut truncated_parameter, "p");
        cstring(&mut truncated_parameter, "s");
        i16_bytes(&mut truncated_parameter, 0);
        i16_bytes(&mut truncated_parameter, 1);
        i32_bytes(&mut truncated_parameter, 5);
        truncated_parameter.push(b'x');
        assert_eq!(
            parse_extended_bind(&truncated_parameter, &[None]),
            Err(FrameError::Invalid)
        );

        let too_large = vec![b'x'; MAX_EXECUTION_PARAM_BYTES + 1];
        let oversized_bind = bind_payload(&[], &[Some(&too_large)], &[]);
        assert_eq!(
            parse_extended_bind(&oversized_bind, &[None]),
            Err(FrameError::TooLarge)
        );
    }

    #[test]
    fn execute_describe_close_sync_and_flush_payloads_are_strict() {
        let mut execute = Vec::new();
        cstring(&mut execute, "portal");
        i32_bytes(&mut execute, 12);
        assert_eq!(
            parse_extended_execute(&execute).unwrap(),
            ExtendedExecute {
                portal_name: "portal".to_owned(),
                max_rows: 12,
            }
        );
        let mut negative_rows = Vec::new();
        cstring(&mut negative_rows, "portal");
        i32_bytes(&mut negative_rows, -1);
        assert_eq!(
            parse_extended_execute(&negative_rows),
            Err(FrameError::Invalid)
        );
        assert_eq!(parse_extended_execute(b"portal"), Err(FrameError::Invalid));

        assert_eq!(
            parse_extended_target(b"Sname\0").unwrap(),
            ExtendedTargetMessage {
                target: ExtendedTarget::Statement,
                name: "name".to_owned(),
            }
        );
        assert_eq!(parse_extended_target(b"Xname\0"), Err(FrameError::Invalid));
        assert_eq!(
            parse_extended_target(b"Pname\0junk"),
            Err(FrameError::Invalid)
        );
        assert_eq!(validate_empty_message(&[]), Ok(()));
        assert_eq!(validate_empty_message(b"x"), Err(FrameError::Invalid));
    }
}
