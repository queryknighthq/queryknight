use std::io;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub(crate) const MAX_PHYSICAL_PAYLOAD: usize = 0xFF_FF_FF;
pub(crate) const MAX_QUERY_BYTES: usize = qk_sql::MAX_SQL_BYTES;
pub(crate) const MAX_QUERY_PAYLOAD: usize = MAX_QUERY_BYTES + 1;
pub(crate) const MAX_HANDSHAKE_PAYLOAD: usize = 64 * 1024;
pub(crate) const MAX_LOGICAL_RESPONSE: usize = 64 * 1024 * 1024;
pub(crate) const MAX_COLUMNS: u64 = 4096;
const MAX_OVERSIZED_DRAIN: usize = 2 * MAX_PHYSICAL_PAYLOAD;

pub(crate) const COM_QUIT: u8 = 0x01;
pub(crate) const COM_INIT_DB: u8 = 0x02;
pub(crate) const COM_QUERY: u8 = 0x03;
pub(crate) const COM_FIELD_LIST: u8 = 0x04;
pub(crate) const COM_SHUTDOWN: u8 = 0x08;
pub(crate) const COM_STATISTICS: u8 = 0x09;
pub(crate) const COM_PROCESS_INFO: u8 = 0x0a;
pub(crate) const COM_CONNECT: u8 = 0x0b;
pub(crate) const COM_PROCESS_KILL: u8 = 0x0c;
pub(crate) const COM_DEBUG: u8 = 0x0d;
pub(crate) const COM_PING: u8 = 0x0e;
pub(crate) const COM_REFRESH: u8 = 0x07;
pub(crate) const COM_CHANGE_USER: u8 = 0x11;
pub(crate) const COM_STMT_PREPARE: u8 = 0x16;
pub(crate) const COM_STMT_EXECUTE: u8 = 0x17;
pub(crate) const COM_STMT_SEND_LONG_DATA: u8 = 0x18;
pub(crate) const COM_STMT_CLOSE: u8 = 0x19;
pub(crate) const COM_STMT_RESET: u8 = 0x1a;
pub(crate) const COM_SET_OPTION: u8 = 0x1b;
pub(crate) const COM_STMT_FETCH: u8 = 0x1c;
pub(crate) const COM_RESET_CONNECTION: u8 = 0x1f;

pub(crate) const CLIENT_CONNECT_WITH_DB: u32 = 0x0000_0008;
pub(crate) const CLIENT_NO_SCHEMA: u32 = 0x0000_0010;
pub(crate) const CLIENT_COMPRESS: u32 = 0x0000_0020;
pub(crate) const CLIENT_ODBC: u32 = 0x0000_0040;
pub(crate) const CLIENT_LOCAL_FILES: u32 = 0x0000_0080;
pub(crate) const CLIENT_IGNORE_SPACE: u32 = 0x0000_0100;
pub(crate) const CLIENT_PROTOCOL_41: u32 = 0x0000_0200;
pub(crate) const CLIENT_SSL: u32 = 0x0000_0800;
pub(crate) const CLIENT_SECURE_CONNECTION: u32 = 0x0000_8000;
pub(crate) const CLIENT_MULTI_STATEMENTS: u32 = 0x0001_0000;
pub(crate) const CLIENT_MULTI_RESULTS: u32 = 0x0002_0000;
pub(crate) const CLIENT_PS_MULTI_RESULTS: u32 = 0x0004_0000;
pub(crate) const CLIENT_PLUGIN_AUTH: u32 = 0x0008_0000;
pub(crate) const CLIENT_CONNECT_ATTRS: u32 = 0x0010_0000;
pub(crate) const CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA: u32 = 0x0020_0000;
pub(crate) const CLIENT_CAN_HANDLE_EXPIRED_PASSWORDS: u32 = 0x0040_0000;
pub(crate) const CLIENT_SESSION_TRACK: u32 = 0x0080_0000;
pub(crate) const CLIENT_DEPRECATE_EOF: u32 = 0x0100_0000;
pub(crate) const CLIENT_OPTIONAL_RESULTSET_METADATA: u32 = 0x0200_0000;
pub(crate) const CLIENT_ZSTD_COMPRESSION_ALGORITHM: u32 = 0x0400_0000;
pub(crate) const CLIENT_QUERY_ATTRIBUTES: u32 = 0x0800_0000;
pub(crate) const CLIENT_MULTI_FACTOR_AUTHENTICATION: u32 = 0x1000_0000;
const CLIENT_SSL_VERIFY_SERVER_CERT: u32 = 0x4000_0000;
const CLIENT_REMEMBER_OPTIONS: u32 = 0x8000_0000;

const CLIENT_DISABLED: u32 = CLIENT_NO_SCHEMA
    | CLIENT_COMPRESS
    | CLIENT_ODBC
    | CLIENT_LOCAL_FILES
    | CLIENT_IGNORE_SPACE
    | CLIENT_SSL
    | CLIENT_MULTI_STATEMENTS
    | CLIENT_PS_MULTI_RESULTS
    | CLIENT_CONNECT_ATTRS
    | CLIENT_CAN_HANDLE_EXPIRED_PASSWORDS
    | CLIENT_SESSION_TRACK
    | CLIENT_DEPRECATE_EOF
    | CLIENT_OPTIONAL_RESULTSET_METADATA
    | CLIENT_ZSTD_COMPRESSION_ALGORITHM
    | CLIENT_QUERY_ATTRIBUTES
    | CLIENT_MULTI_FACTOR_AUTHENTICATION
    | CLIENT_SSL_VERIFY_SERVER_CERT
    | CLIENT_REMEMBER_OPTIONS;
const CLIENT_REQUIRED: u32 =
    CLIENT_CONNECT_WITH_DB | CLIENT_PROTOCOL_41 | CLIENT_SECURE_CONNECTION | CLIENT_PLUGIN_AUTH;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ProtocolError {
    Io,
    Truncated,
    Malformed,
    Sequence,
    Oversized,
    Unsupported,
}

impl From<io::Error> for ProtocolError {
    fn from(error: io::Error) -> Self {
        if error.kind() == io::ErrorKind::UnexpectedEof {
            Self::Truncated
        } else {
            Self::Io
        }
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct CapabilityState {
    pub server_advertised: u32,
    pub proxy_supported: u32,
    pub client_selected: u32,
}

impl CapabilityState {
    pub fn supports_multi_results(self) -> bool {
        self.server_advertised & self.proxy_supported & self.client_selected & CLIENT_MULTI_RESULTS
            != 0
    }

    pub fn supports_prepared_multi_results(self) -> bool {
        self.server_advertised
            & self.proxy_supported
            & self.client_selected
            & CLIENT_PS_MULTI_RESULTS
            != 0
    }
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Message {
    pub sequence: u8,
    pub packet_count: usize,
    pub payload: Vec<u8>,
}

impl Message {
    pub fn next_sequence(&self) -> u8 {
        self.sequence.wrapping_add(self.packet_count as u8)
    }
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum FrontendCommand {
    Message(Message),
    Oversized { response_sequence: u8 },
}

pub(crate) async fn read_message<R: AsyncRead + Unpin>(
    reader: &mut R,
    first_sequence: Option<u8>,
    max_payload: usize,
) -> Result<Message, ProtocolError> {
    let mut payload = Vec::new();
    let mut expected = first_sequence;
    let mut first = None;
    let mut packet_count = 0usize;
    loop {
        let mut header = [0u8; 4];
        read_exact(reader, &mut header).await?;
        let length = packet_length(&header);
        let next_len = payload
            .len()
            .checked_add(length)
            .ok_or(ProtocolError::Oversized)?;
        if next_len > max_payload {
            return Err(ProtocolError::Oversized);
        }
        let sequence = header[3];
        if let Some(expected) = expected {
            if sequence != expected {
                return Err(ProtocolError::Sequence);
            }
        }
        if first.is_none() {
            first = Some(sequence);
        }
        payload
            .try_reserve(length)
            .map_err(|_| ProtocolError::Oversized)?;
        let old_len = payload.len();
        payload.resize(next_len, 0);
        read_exact(reader, &mut payload[old_len..]).await?;
        packet_count = packet_count
            .checked_add(1)
            .ok_or(ProtocolError::Oversized)?;
        expected = Some(sequence.wrapping_add(1));
        if length < MAX_PHYSICAL_PAYLOAD {
            break;
        }
    }
    Ok(Message {
        sequence: first.ok_or(ProtocolError::Malformed)?,
        packet_count,
        payload,
    })
}

/// Reads one classic COM_* command. Oversized COM_QUERY is drained with a
/// fixed stack buffer so its matching local ERR can be sequenced correctly.
pub(crate) async fn read_command<R: AsyncRead + Unpin>(
    reader: &mut R,
) -> Result<FrontendCommand, ProtocolError> {
    let mut header = [0u8; 4];
    read_exact(reader, &mut header).await?;
    let length = packet_length(&header);
    if length == 0 {
        return Err(ProtocolError::Malformed);
    }
    let sequence = header[3];
    if sequence != 0 {
        return Err(ProtocolError::Sequence);
    }
    let mut command = [0u8; 1];
    read_exact(reader, &mut command).await?;
    if command[0] == COM_QUERY && length > MAX_QUERY_PAYLOAD {
        let response_sequence = discard_command_tail(reader, length, sequence).await?;
        return Ok(FrontendCommand::Oversized { response_sequence });
    }
    if length > MAX_QUERY_PAYLOAD {
        return Err(ProtocolError::Oversized);
    }
    let mut payload = Vec::new();
    payload
        .try_reserve(length)
        .map_err(|_| ProtocolError::Oversized)?;
    payload.push(command[0]);
    payload.resize(length, 0);
    read_exact(reader, &mut payload[1..]).await?;
    Ok(FrontendCommand::Message(Message {
        sequence,
        packet_count: 1,
        payload,
    }))
}

async fn discard_command_tail<R: AsyncRead + Unpin>(
    reader: &mut R,
    first_length: usize,
    first_sequence: u8,
) -> Result<u8, ProtocolError> {
    let mut scratch = [0u8; 8192];
    let mut total = first_length;
    let mut sequence = first_sequence;
    skip_bytes(reader, first_length - 1, &mut scratch).await?;
    if first_length < MAX_PHYSICAL_PAYLOAD {
        return Ok(sequence.wrapping_add(1));
    }
    loop {
        let mut header = [0u8; 4];
        read_exact(reader, &mut header).await?;
        let length = packet_length(&header);
        sequence = sequence.wrapping_add(1);
        if header[3] != sequence {
            return Err(ProtocolError::Sequence);
        }
        total = total.checked_add(length).ok_or(ProtocolError::Oversized)?;
        if total > MAX_OVERSIZED_DRAIN {
            return Err(ProtocolError::Oversized);
        }
        skip_bytes(reader, length, &mut scratch).await?;
        if length < MAX_PHYSICAL_PAYLOAD {
            return Ok(sequence.wrapping_add(1));
        }
    }
}

async fn skip_bytes<R: AsyncRead + Unpin>(
    reader: &mut R,
    mut length: usize,
    scratch: &mut [u8; 8192],
) -> Result<(), ProtocolError> {
    while length != 0 {
        let chunk = length.min(scratch.len());
        read_exact(reader, &mut scratch[..chunk]).await?;
        length -= chunk;
    }
    Ok(())
}

async fn read_exact<R: AsyncRead + Unpin>(
    reader: &mut R,
    bytes: &mut [u8],
) -> Result<(), ProtocolError> {
    reader
        .read_exact(bytes)
        .await
        .map(|_| ())
        .map_err(Into::into)
}

pub(crate) async fn write_message<W: AsyncWrite + Unpin>(
    writer: &mut W,
    sequence: u8,
    payload: &[u8],
) -> Result<u8, ProtocolError> {
    let mut offset = 0usize;
    let mut next = sequence;
    loop {
        let length = (payload.len() - offset).min(MAX_PHYSICAL_PAYLOAD);
        write_packet(writer, next, &payload[offset..offset + length]).await?;
        next = next.wrapping_add(1);
        offset += length;
        if length < MAX_PHYSICAL_PAYLOAD {
            return Ok(next);
        }
        if offset == payload.len() {
            write_packet(writer, next, &[]).await?;
            return Ok(next.wrapping_add(1));
        }
    }
}

pub(crate) async fn write_packet<W: AsyncWrite + Unpin>(
    writer: &mut W,
    sequence: u8,
    payload: &[u8],
) -> Result<(), ProtocolError> {
    if payload.len() > MAX_PHYSICAL_PAYLOAD {
        return Err(ProtocolError::Oversized);
    }
    let length = payload.len();
    let header = [
        length as u8,
        (length >> 8) as u8,
        (length >> 16) as u8,
        sequence,
    ];
    writer
        .write_all(&header)
        .await
        .map_err(|_| ProtocolError::Io)?;
    writer
        .write_all(payload)
        .await
        .map_err(|_| ProtocolError::Io)?;
    Ok(())
}

pub(crate) fn packet_length(header: &[u8; 4]) -> usize {
    usize::from(header[0]) | (usize::from(header[1]) << 8) | (usize::from(header[2]) << 16)
}

pub(crate) fn encode_err(sequence: u8, code: u16, state: &[u8; 5], message: &str) -> Vec<u8> {
    let message = message.as_bytes();
    let message = &message[..message.len().min(512)];
    let mut payload = Vec::with_capacity(9 + message.len());
    payload.push(0xff);
    payload.extend_from_slice(&code.to_le_bytes());
    payload.push(b'#');
    payload.extend_from_slice(state);
    payload.extend_from_slice(message);
    let mut packet = Vec::with_capacity(payload.len() + 4);
    let length = payload.len();
    packet.extend_from_slice(&[
        length as u8,
        (length >> 8) as u8,
        (length >> 16) as u8,
        sequence,
    ]);
    packet.extend_from_slice(&payload);
    packet
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct FilteredGreeting {
    pub payload: Vec<u8>,
    pub server_capabilities: u32,
    pub proxy_capabilities: u32,
}

pub(crate) fn filter_server_greeting(payload: &[u8]) -> Result<FilteredGreeting, ProtocolError> {
    if payload.first() != Some(&10) {
        return Err(ProtocolError::Unsupported);
    }
    let (_, mut offset) = cstring(payload, 1)?;
    checked_advance(payload, &mut offset, 4 + 8 + 1)?;
    let low_offset = offset;
    let low = read_u16(payload, offset)?;
    offset += 2;
    if payload.len() < offset + 1 + 2 + 2 + 1 + 10 {
        return Err(ProtocolError::Malformed);
    }
    let _server_charset = payload[offset];
    let high_offset = offset + 3;
    let high = read_u16(payload, high_offset)?;
    let auth_len = usize::from(payload[high_offset + 2]);
    let capabilities = u32::from(low) | (u32::from(high) << 16);
    if capabilities & CLIENT_REQUIRED != CLIENT_REQUIRED {
        return Err(ProtocolError::Unsupported);
    }
    let mut plugin_offset = high_offset + 2 + 1 + 10;
    let auth_tail_len = auth_len.saturating_sub(8).max(13);
    checked_advance(payload, &mut plugin_offset, auth_tail_len)?;
    let (plugin, _) = cstring(payload, plugin_offset)?;
    if !supported_auth_plugin(plugin) {
        return Err(ProtocolError::Unsupported);
    }
    let filtered = capabilities & !CLIENT_DISABLED;
    let mut greeting = payload.to_vec();
    greeting[low_offset..low_offset + 2].copy_from_slice(&(filtered as u16).to_le_bytes());
    greeting[high_offset..high_offset + 2]
        .copy_from_slice(&((filtered >> 16) as u16).to_le_bytes());
    Ok(FilteredGreeting {
        payload: greeting,
        server_capabilities: capabilities,
        proxy_capabilities: filtered,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct LoginInfo<'a> {
    pub capabilities: u32,
    pub charset: u8,
    pub username: &'a [u8],
    pub database: &'a [u8],
    pub auth_plugin: &'a [u8],
}

pub(crate) fn parse_login<'a>(
    payload: &'a [u8],
    server_capabilities: u32,
) -> Result<LoginInfo<'a>, ProtocolError> {
    if payload.len() < 32 {
        return Err(ProtocolError::Malformed);
    }
    let capabilities = read_u32(payload, 0)?;
    if capabilities & CLIENT_REQUIRED != CLIENT_REQUIRED
        || capabilities & CLIENT_DISABLED != 0
        || capabilities & !server_capabilities != 0
    {
        return Err(ProtocolError::Unsupported);
    }
    let charset = payload[8];
    if !supported_utf8mb4_collation(charset) {
        return Err(ProtocolError::Unsupported);
    }
    if payload[9..32].iter().any(|byte| *byte != 0) {
        return Err(ProtocolError::Malformed);
    }
    let (username, mut offset) = cstring(payload, 32)?;
    let auth_len = if capabilities & CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA != 0 {
        let (length, next) = lenenc(payload, offset)?;
        offset = next;
        usize::try_from(length).map_err(|_| ProtocolError::Malformed)?
    } else {
        let length = *payload.get(offset).ok_or(ProtocolError::Malformed)?;
        offset += 1;
        usize::from(length)
    };
    checked_advance(payload, &mut offset, auth_len)?;
    let (database, next) = cstring(payload, offset)?;
    offset = next;
    let (auth_plugin, next) = cstring(payload, offset)?;
    offset = next;
    if offset != payload.len() || !supported_auth_plugin(auth_plugin) {
        return Err(ProtocolError::Unsupported);
    }
    Ok(LoginInfo {
        capabilities,
        charset,
        username,
        database,
        auth_plugin,
    })
}

pub(crate) fn auth_switch_plugin(payload: &[u8]) -> Result<&[u8], ProtocolError> {
    if payload.first() != Some(&0xfe) {
        return Err(ProtocolError::Malformed);
    }
    let (plugin, _) = cstring(payload, 1)?;
    if supported_auth_plugin(plugin) {
        Ok(plugin)
    } else {
        Err(ProtocolError::Unsupported)
    }
}

pub(crate) fn supported_auth_plugin(plugin: &[u8]) -> bool {
    plugin == b"mysql_native_password" || plugin == b"caching_sha2_password"
}

pub(crate) fn supported_utf8mb4_collation(collation: u8) -> bool {
    matches!(collation, 45 | 46 | 224..=247 | 255)
}

pub(crate) fn lenenc(payload: &[u8], offset: usize) -> Result<(u64, usize), ProtocolError> {
    let first = *payload.get(offset).ok_or(ProtocolError::Malformed)?;
    match first {
        0x00..=0xfa => Ok((u64::from(first), offset + 1)),
        0xfc => {
            let bytes = payload
                .get(offset + 1..offset + 3)
                .ok_or(ProtocolError::Malformed)?;
            Ok((
                u64::from(u16::from_le_bytes([bytes[0], bytes[1]])),
                offset + 3,
            ))
        }
        0xfd => {
            let bytes = payload
                .get(offset + 1..offset + 4)
                .ok_or(ProtocolError::Malformed)?;
            Ok((
                u64::from(bytes[0]) | (u64::from(bytes[1]) << 8) | (u64::from(bytes[2]) << 16),
                offset + 4,
            ))
        }
        0xfe => {
            let bytes = payload
                .get(offset + 1..offset + 9)
                .ok_or(ProtocolError::Malformed)?;
            Ok((
                u64::from_le_bytes(bytes.try_into().map_err(|_| ProtocolError::Malformed)?),
                offset + 9,
            ))
        }
        _ => Err(ProtocolError::Malformed),
    }
}

pub(crate) fn is_eof(payload: &[u8]) -> bool {
    payload.first() == Some(&0xfe) && payload.len() < 9
}

pub(crate) fn is_err(payload: &[u8]) -> bool {
    payload.first() == Some(&0xff)
}

pub(crate) fn is_ok(payload: &[u8]) -> bool {
    payload.first() == Some(&0x00)
}

pub(crate) fn server_status_from_ok(payload: &[u8]) -> Result<u16, ProtocolError> {
    if !is_ok(payload) {
        return Err(ProtocolError::Malformed);
    }
    let (_, offset) = lenenc(payload, 1)?;
    let (_, offset) = lenenc(payload, offset)?;
    read_u16(payload, offset)
}

pub(crate) fn server_status_from_eof(payload: &[u8]) -> Result<u16, ProtocolError> {
    if !is_eof(payload) || payload.len() < 5 {
        return Err(ProtocolError::Malformed);
    }
    read_u16(payload, 3)
}

pub(crate) fn response_has_more_results(status: u16) -> bool {
    status & 0x0008 != 0
}

pub(crate) fn query_sql(payload: &[u8]) -> Result<&str, ProtocolError> {
    if payload.first() != Some(&COM_QUERY) || payload.len() <= 1 {
        return Err(ProtocolError::Malformed);
    }
    let sql = std::str::from_utf8(&payload[1..]).map_err(|_| ProtocolError::Unsupported)?;
    if sql.len() > MAX_QUERY_BYTES {
        return Err(ProtocolError::Oversized);
    }
    Ok(sql)
}

pub(crate) fn command_code(payload: &[u8]) -> Result<u8, ProtocolError> {
    payload.first().copied().ok_or(ProtocolError::Malformed)
}

fn cstring(payload: &[u8], offset: usize) -> Result<(&[u8], usize), ProtocolError> {
    let tail = payload.get(offset..).ok_or(ProtocolError::Malformed)?;
    let length = tail
        .iter()
        .position(|byte| *byte == 0)
        .ok_or(ProtocolError::Malformed)?;
    Ok((&tail[..length], offset + length + 1))
}

fn checked_advance(payload: &[u8], offset: &mut usize, amount: usize) -> Result<(), ProtocolError> {
    let next = offset.checked_add(amount).ok_or(ProtocolError::Malformed)?;
    if next > payload.len() {
        return Err(ProtocolError::Malformed);
    }
    *offset = next;
    Ok(())
}

pub(crate) fn read_u16(payload: &[u8], offset: usize) -> Result<u16, ProtocolError> {
    let bytes = payload
        .get(offset..offset + 2)
        .ok_or(ProtocolError::Malformed)?;
    Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
}

pub(crate) fn read_u32(payload: &[u8], offset: usize) -> Result<u32, ProtocolError> {
    let bytes = payload
        .get(offset..offset + 4)
        .ok_or(ProtocolError::Malformed)?;
    Ok(u32::from_le_bytes(
        bytes.try_into().map_err(|_| ProtocolError::Malformed)?,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{duplex, AsyncReadExt, AsyncWriteExt};

    fn greeting(plugin: &[u8], capabilities: u32) -> Vec<u8> {
        let mut payload = vec![10];
        payload.extend_from_slice(b"8.4.0\0");
        payload.extend_from_slice(&1u32.to_le_bytes());
        payload.extend_from_slice(b"12345678");
        payload.push(0);
        payload.extend_from_slice(&(capabilities as u16).to_le_bytes());
        payload.push(45);
        payload.extend_from_slice(&2u16.to_le_bytes());
        payload.extend_from_slice(&((capabilities >> 16) as u16).to_le_bytes());
        payload.push(21);
        payload.extend_from_slice(&[0; 10]);
        payload.extend_from_slice(b"abcdefghijkl\0");
        payload.extend_from_slice(plugin);
        payload.push(0);
        payload
    }

    #[tokio::test]
    async fn packet_roundtrip_checks_sequence_and_length() {
        let (mut client, mut server) = duplex(64);
        let payload = b"hello".to_vec();
        let writer = tokio::spawn(async move {
            write_message(&mut client, 7, &payload)
                .await
                .expect("write");
        });
        let message = read_message(&mut server, Some(7), 16).await.expect("read");
        writer.await.expect("writer");
        assert_eq!(message.payload, b"hello");
        assert_eq!(message.packet_count, 1);
        assert_eq!(message.next_sequence(), 8);
    }

    #[tokio::test]
    async fn truncated_header_and_payload_are_rejected() {
        let (mut writer, mut reader) = duplex(16);
        writer.write_all(&[1, 2]).await.expect("header");
        drop(writer);
        assert_eq!(
            read_message(&mut reader, None, 8).await,
            Err(ProtocolError::Truncated)
        );

        let (mut writer, mut reader) = duplex(16);
        writer
            .write_all(&[3, 0, 0, 0, b'a'])
            .await
            .expect("partial packet");
        drop(writer);
        assert_eq!(
            read_message(&mut reader, None, 8).await,
            Err(ProtocolError::Truncated)
        );
    }

    #[tokio::test]
    async fn oversized_payload_is_rejected_before_body_allocation() {
        let (mut writer, mut reader) = duplex(16);
        writer.write_all(&[9, 0, 0, 0]).await.expect("header");
        assert_eq!(
            read_message(&mut reader, None, 8).await,
            Err(ProtocolError::Oversized)
        );
    }

    #[tokio::test]
    async fn command_packet_is_consumed_as_one_logical_command() {
        let (mut writer, mut reader) = duplex(64);
        writer
            .write_all(&[4, 0, 0, 0, COM_QUERY, b'a', b'b', b'c'])
            .await
            .expect("command");
        drop(writer);
        let FrontendCommand::Message(message) = read_command(&mut reader).await.expect("message")
        else {
            panic!("not oversized");
        };
        assert_eq!(message.payload, [COM_QUERY, b'a', b'b', b'c']);
        assert_eq!(message.next_sequence(), 1);
    }

    #[test]
    fn greeting_capabilities_are_filtered_and_plugin_is_validated() {
        let capabilities = CLIENT_REQUIRED
            | CLIENT_MULTI_RESULTS
            | CLIENT_SSL
            | CLIENT_COMPRESS
            | CLIENT_MULTI_STATEMENTS
            | CLIENT_LOCAL_FILES
            | CLIENT_DEPRECATE_EOF
            | CLIENT_PS_MULTI_RESULTS;
        let filtered_greeting =
            filter_server_greeting(&greeting(b"caching_sha2_password", capabilities))
                .expect("greeting");
        assert_eq!(filtered_greeting.server_capabilities, capabilities);
        assert_eq!(filtered_greeting.proxy_capabilities & CLIENT_DISABLED, 0);
        assert!(filtered_greeting.proxy_capabilities & CLIENT_MULTI_RESULTS != 0);
        assert!(filtered_greeting.payload.len() > 20);
        assert_eq!(
            filter_server_greeting(&greeting(b"mysql_clear_password", capabilities)),
            Err(ProtocolError::Unsupported)
        );
    }
    #[test]
    fn auth_switch_support_is_explicit() {
        let mut supported = vec![0xfe];
        supported.extend_from_slice(b"mysql_native_password\0challenge");
        assert_eq!(
            auth_switch_plugin(&supported).expect("native plugin"),
            b"mysql_native_password"
        );

        let mut unsupported = vec![0xfe];
        unsupported.extend_from_slice(b"mysql_clear_password\0challenge");
        assert_eq!(
            auth_switch_plugin(&unsupported),
            Err(ProtocolError::Unsupported)
        );
    }

    #[test]
    fn login_identity_charset_and_capabilities_are_strict() {
        let caps = CLIENT_REQUIRED | CLIENT_MULTI_RESULTS;
        let mut payload = Vec::new();
        payload.extend_from_slice(&caps.to_le_bytes());
        payload.extend_from_slice(&0u32.to_le_bytes());
        payload.push(45);
        payload.extend_from_slice(&[0; 23]);
        payload.extend_from_slice(b"qk\0");
        payload.push(3);
        payload.extend_from_slice(b"abc");
        payload.extend_from_slice(b"qk\0");
        payload.extend_from_slice(b"caching_sha2_password\0");
        let login = parse_login(&payload, caps).expect("login");
        assert_eq!(login.username, b"qk");
        assert_eq!(login.database, b"qk");
        assert_eq!(login.charset, 45);
        assert_eq!(login.auth_plugin, b"caching_sha2_password");

        payload[8] = 8;
        assert_eq!(parse_login(&payload, caps), Err(ProtocolError::Unsupported));
    }

    #[test]
    fn query_decoding_is_strict_and_bounded() {
        assert_eq!(
            query_sql(&[COM_QUERY, b'S', b'E', b'L', b'E', b'C', b'T', b' ', b'1']),
            Ok("SELECT 1")
        );
        assert_eq!(
            query_sql(&[COM_QUERY, 0xff]),
            Err(ProtocolError::Unsupported)
        );
        assert_eq!(query_sql(&[COM_QUERY]), Err(ProtocolError::Malformed));
    }

    #[test]
    fn sql_limit_accepts_exact_boundary_and_rejects_next_byte() {
        let mut payload = vec![COM_QUERY];
        payload.resize(MAX_QUERY_PAYLOAD, b'a');
        assert_eq!(
            query_sql(&payload).expect("boundary").len(),
            MAX_QUERY_BYTES
        );
        payload.push(b'a');
        assert_eq!(query_sql(&payload), Err(ProtocolError::Oversized));
    }

    #[tokio::test]
    async fn malformed_sequence_and_oversized_query_fail_before_forwarding() {
        let (mut writer, mut reader) = duplex(16);
        writer
            .write_all(&[1, 0, 0, 2, 0])
            .await
            .expect("bad sequence");
        assert_eq!(
            read_message(&mut reader, Some(1), 8).await,
            Err(ProtocolError::Sequence)
        );

        let (mut writer, mut reader) = duplex(1024);
        let mut payload = vec![COM_QUERY];
        payload.resize(MAX_QUERY_PAYLOAD + 1, b'a');
        let length = payload.len();
        let mut frame = Vec::with_capacity(length + 4);
        frame.extend_from_slice(&[length as u8, (length >> 8) as u8, (length >> 16) as u8, 0]);
        frame.extend_from_slice(&payload);
        let task = tokio::spawn(async move {
            writer.write_all(&frame).await.expect("oversized command");
        });
        assert_eq!(
            read_command(&mut reader).await,
            Ok(FrontendCommand::Oversized {
                response_sequence: 1
            })
        );
        task.await.expect("writer");
    }

    #[test]
    fn local_err_is_protocol_41_and_secret_free() {
        let packet = encode_err(1, 1227, b"HY000", "QueryKnight blocked this query");
        assert_eq!(packet[3], 1);
        assert_eq!(packet[4], 0xff);
        assert_eq!(u16::from_le_bytes([packet[5], packet[6]]), 1227);
        assert_eq!(&packet[8..13], b"HY000");
        assert!(!String::from_utf8_lossy(&packet).contains("MYSQL_AUTH_SECRET_67890"));
    }

    #[test]
    fn status_parsers_use_actual_backend_flags() {
        let ok = [0x00, 0x00, 0x00, 0x02, 0x40, 0x00, 0x00];
        assert_eq!(server_status_from_ok(&ok), Ok(0x4002));
        assert_eq!(
            server_status_from_eof(&[0xfe, 0, 0, 0x02, 0x40]),
            Ok(0x4002)
        );
        assert!(response_has_more_results(0x0008));
    }

    #[tokio::test]
    async fn oversized_fragmented_command_truncation_is_rejected() {
        let (mut writer, mut reader) = duplex(16);
        writer
            .write_all(&[0xff, 0xff, 0xff, 0, COM_QUERY])
            .await
            .expect("fragment header");
        drop(writer);
        assert_eq!(
            read_command(&mut reader).await,
            Err(ProtocolError::Truncated)
        );
    }

    #[tokio::test]
    async fn write_zero_length_message_has_one_frame() {
        let (mut writer, mut reader) = duplex(16);
        let task =
            tokio::spawn(async move { write_message(&mut writer, 9, &[]).await.expect("write") });
        let mut frame = [0u8; 4];
        reader.read_exact(&mut frame).await.expect("frame");
        assert_eq!(frame, [0, 0, 0, 9]);
        assert_eq!(task.await.expect("writer"), 10);
    }
}
