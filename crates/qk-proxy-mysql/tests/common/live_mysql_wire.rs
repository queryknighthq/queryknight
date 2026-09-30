use mysql_async::Opts;
use sha1::Sha1;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use super::RunningProxy;

const CLIENT_CONNECT_WITH_DB: u32 = 0x0000_0008;
const CLIENT_PROTOCOL_41: u32 = 0x0000_0200;
const CLIENT_SECURE_CONNECTION: u32 = 0x0000_8000;
const CLIENT_MULTI_RESULTS: u32 = 0x0002_0000;
const CLIENT_PLUGIN_AUTH: u32 = 0x0008_0000;
const MAX_PACKET: usize = 0xFF_FF_FF;

pub(super) struct RawMysqlClient {
    stream: TcpStream,
}

impl RawMysqlClient {
    pub(super) async fn connect(proxy: &RunningProxy, opts: &Opts) -> Self {
        let mut stream = TcpStream::connect(proxy.addr)
            .await
            .expect("raw live client connect");
        let (sequence, greeting) = read_packet(&mut stream).await.expect("MySQL greeting");
        assert_eq!(sequence, 0);
        let (plugin, salt) = greeting_auth(&greeting);
        let user = opts.user().expect("configured MySQL user");
        let database = opts.db_name().expect("configured MySQL database");
        let password = opts.pass().unwrap_or_default();
        let capabilities = CLIENT_CONNECT_WITH_DB
            | CLIENT_PROTOCOL_41
            | CLIENT_SECURE_CONNECTION
            | CLIENT_MULTI_RESULTS
            | CLIENT_PLUGIN_AUTH;
        let mut response = Vec::new();
        response.extend_from_slice(&capabilities.to_le_bytes());
        response.extend_from_slice(&0x0100_0000u32.to_le_bytes());
        response.push(45);
        response.extend_from_slice(&[0; 23]);
        response.extend_from_slice(user.as_bytes());
        response.push(0);
        let token = scramble(plugin, password.as_bytes(), &salt);
        response.push(token.len() as u8);
        response.extend_from_slice(&token);
        response.extend_from_slice(database.as_bytes());
        response.push(0);
        response.extend_from_slice(plugin);
        response.push(0);
        write_packet(&mut stream, 1, &response)
            .await
            .expect("write raw handshake response");

        let mut expected_sequence = 2u8;
        loop {
            let (sequence, packet) = read_packet(&mut stream)
                .await
                .expect("authentication reply");
            assert_eq!(sequence, expected_sequence);
            expected_sequence = expected_sequence.wrapping_add(1);
            match packet.first() {
                Some(0x00) => break,
                Some(0x01) if packet.get(1) == Some(&0x03) => continue,
                Some(0xfe) => {
                    let plugin_end = packet[1..]
                        .iter()
                        .position(|byte| *byte == 0)
                        .map(|index| index + 1)
                        .expect("auth-switch plugin terminator");
                    let switched_plugin = &packet[1..plugin_end];
                    let mut switched_salt = packet[plugin_end + 1..].to_vec();
                    while switched_salt.last() == Some(&0) {
                        switched_salt.pop();
                    }
                    let token = scramble(switched_plugin, password.as_bytes(), &switched_salt);
                    write_packet(&mut stream, expected_sequence, &token)
                        .await
                        .expect("auth-switch response");
                    expected_sequence = expected_sequence.wrapping_add(1);
                }
                _ => panic!("unsupported MySQL authentication response"),
            }
        }
        Self { stream }
    }

    pub(super) async fn prepare(&mut self, sql: &str) -> u32 {
        let mut request = vec![0x16];
        request.extend_from_slice(sql.as_bytes());
        write_packet(&mut self.stream, 0, &request)
            .await
            .expect("send COM_STMT_PREPARE");
        let (sequence, response) = read_packet(&mut self.stream)
            .await
            .expect("prepare response");
        assert_eq!(sequence, 1);
        assert_eq!(response.first(), Some(&0x00));
        let statement_id = u32::from_le_bytes([response[1], response[2], response[3], response[4]]);
        let column_count = usize::from(u16::from_le_bytes([response[5], response[6]]));
        let parameter_count = usize::from(u16::from_le_bytes([response[7], response[8]]));
        let mut expected_sequence = 2u8;
        for count in [parameter_count, column_count] {
            for _ in 0..count {
                let (sequence, definition) = read_packet(&mut self.stream)
                    .await
                    .expect("prepared metadata");
                assert_eq!(sequence, expected_sequence);
                assert!(!definition.is_empty());
                expected_sequence = expected_sequence.wrapping_add(1);
            }
            if count != 0 {
                let (sequence, eof) = read_packet(&mut self.stream)
                    .await
                    .expect("prepared metadata EOF");
                assert_eq!(sequence, expected_sequence);
                assert_eq!(eof.first(), Some(&0xfe));
                expected_sequence = expected_sequence.wrapping_add(1);
            }
        }
        statement_id
    }

    pub(super) async fn send_long_data(
        &mut self,
        statement_id: u32,
        parameter_index: u16,
        bytes: &[u8],
    ) {
        let mut request = vec![0x18];
        request.extend_from_slice(&statement_id.to_le_bytes());
        request.extend_from_slice(&parameter_index.to_le_bytes());
        request.extend_from_slice(bytes);
        write_packet(&mut self.stream, 0, &request)
            .await
            .expect("send COM_STMT_SEND_LONG_DATA");
    }

    pub(super) async fn execute_long_string(&mut self, statement_id: u32) -> Vec<u8> {
        let mut request = vec![0x17];
        request.extend_from_slice(&statement_id.to_le_bytes());
        request.push(0);
        request.extend_from_slice(&1u32.to_le_bytes());
        request.extend_from_slice(&[0, 1, 0xfd, 0]);
        write_packet(&mut self.stream, 0, &request)
            .await
            .expect("send COM_STMT_EXECUTE");

        let (sequence, first) = read_packet(&mut self.stream).await.expect("Execute result");
        assert_eq!(sequence, 1);
        assert_ne!(first.first(), Some(&0xff));
        assert_eq!(read_lenenc(&first, 0).0, 1);
        let mut expected_sequence = 2u8;
        let (sequence, _) = read_packet(&mut self.stream)
            .await
            .expect("Execute result column");
        assert_eq!(sequence, expected_sequence);
        expected_sequence = expected_sequence.wrapping_add(1);
        let (sequence, metadata_eof) = read_packet(&mut self.stream)
            .await
            .expect("Execute metadata EOF");
        assert_eq!(sequence, expected_sequence);
        assert_eq!(metadata_eof.first(), Some(&0xfe));
        expected_sequence = expected_sequence.wrapping_add(1);
        let (sequence, row) = read_packet(&mut self.stream).await.expect("binary row");
        assert_eq!(sequence, expected_sequence);
        assert_eq!(row.first(), Some(&0x00));
        assert_eq!(row.get(1), Some(&0));
        let (length, start) = read_lenenc(&row, 2);
        let end = start + usize::try_from(length).expect("row length");
        let value = row[start..end].to_vec();
        expected_sequence = expected_sequence.wrapping_add(1);
        let (sequence, result_eof) = read_packet(&mut self.stream)
            .await
            .expect("Execute result EOF");
        assert_eq!(sequence, expected_sequence);
        assert_eq!(result_eof.first(), Some(&0xfe));
        value
    }
}

fn greeting_auth(payload: &[u8]) -> (&[u8], Vec<u8>) {
    assert_eq!(payload.first(), Some(&10));
    let version_end = payload[1..]
        .iter()
        .position(|byte| *byte == 0)
        .map(|index| index + 1)
        .expect("server version terminator");
    let mut offset = version_end + 1 + 4;
    let nonce_first = &payload[offset..offset + 8];
    offset += 9 + 2 + 1 + 2 + 2;
    let auth_length = usize::from(payload[offset]);
    offset += 1 + 10;
    let auth_tail_length = auth_length.saturating_sub(8).max(13);
    let auth_tail = &payload[offset..offset + auth_tail_length];
    let mut salt = nonce_first.to_vec();
    salt.extend_from_slice(&auth_tail[..12]);
    offset += auth_tail_length;
    let plugin_end = payload[offset..]
        .iter()
        .position(|byte| *byte == 0)
        .map(|index| index + offset)
        .expect("auth plugin terminator");
    (&payload[offset..plugin_end], salt)
}

fn scramble(plugin: &[u8], password: &[u8], salt: &[u8]) -> Vec<u8> {
    if password.is_empty() {
        return Vec::new();
    }
    if plugin == b"caching_sha2_password" {
        let first = Sha256::digest(password);
        let second = Sha256::digest(first);
        let mut challenge = Vec::with_capacity(second.len() + salt.len());
        challenge.extend_from_slice(&second);
        challenge.extend_from_slice(salt);
        let third = Sha256::digest(challenge);
        return first
            .iter()
            .zip(third.iter())
            .map(|(left, right)| left ^ right)
            .collect();
    }
    if plugin == b"mysql_native_password" {
        let first = Sha1::digest(password);
        let second = Sha1::digest(first);
        let mut challenge = Vec::with_capacity(salt.len() + second.len());
        challenge.extend_from_slice(salt);
        challenge.extend_from_slice(&second);
        let third = Sha1::digest(challenge);
        return first
            .iter()
            .zip(third.iter())
            .map(|(left, right)| left ^ right)
            .collect();
    }
    panic!("unsupported MySQL authentication plugin");
}

async fn read_packet(stream: &mut TcpStream) -> Result<(u8, Vec<u8>), std::io::Error> {
    let mut header = [0u8; 4];
    stream.read_exact(&mut header).await?;
    let length =
        usize::from(header[0]) | (usize::from(header[1]) << 8) | (usize::from(header[2]) << 16);
    let mut payload = vec![0; length];
    stream.read_exact(&mut payload).await?;
    Ok((header[3], payload))
}

async fn write_packet(
    stream: &mut TcpStream,
    sequence: u8,
    payload: &[u8],
) -> Result<(), std::io::Error> {
    assert!(payload.len() <= MAX_PACKET);
    let length = payload.len();
    let header = [
        length as u8,
        (length >> 8) as u8,
        (length >> 16) as u8,
        sequence,
    ];
    stream.write_all(&header).await?;
    stream.write_all(payload).await
}

fn read_lenenc(payload: &[u8], offset: usize) -> (u64, usize) {
    match payload[offset] {
        first @ 0x00..=0xfa => (u64::from(first), offset + 1),
        0xfc => (
            u64::from(u16::from_le_bytes([
                payload[offset + 1],
                payload[offset + 2],
            ])),
            offset + 3,
        ),
        0xfd => (
            u64::from(payload[offset + 1])
                | (u64::from(payload[offset + 2]) << 8)
                | (u64::from(payload[offset + 3]) << 16),
            offset + 4,
        ),
        0xfe => (
            u64::from_le_bytes(
                payload[offset + 1..offset + 9]
                    .try_into()
                    .expect("lenenc u64"),
            ),
            offset + 9,
        ),
        _ => panic!("invalid non-NULL length-encoded integer"),
    }
}
