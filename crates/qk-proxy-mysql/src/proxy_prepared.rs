use std::borrow::Cow;
use std::collections::HashMap;
use std::sync::Arc;

use qk_core::{
    validate_execution_params, ExecutionParam, ParamRepresentation, MAX_EXECUTION_PARAMS,
    MAX_EXECUTION_PARAM_BYTES,
};
use qk_db::AuthorizationOutcome;
use tokio::net::TcpStream;

use super::{
    authorize_request, read_response_packet, relay_response, write_history, write_policy_error,
    BackendState,
};
use crate::config::ProxyConfig;
use crate::prepared::{decode_execute, parse_prepare_ok, rewrite_execute_types, ParameterType};
use crate::protocol::{
    is_eof, is_err, is_ok, read_u16, read_u32, server_status_from_eof, server_status_from_ok,
    write_message, Message, ProtocolError, COM_STMT_CLOSE, COM_STMT_PREPARE, COM_STMT_RESET,
    COM_STMT_SEND_LONG_DATA, MAX_COLUMNS, MAX_LOGICAL_RESPONSE, MAX_QUERY_BYTES,
};

const MAX_PREPARED_STATEMENTS: usize = 256;
const MAX_PREPARED_SQL_BYTES: usize = MAX_QUERY_BYTES;
const MAX_LONG_DATA_CHUNKS: usize = 8192;

#[derive(Default)]
pub(super) struct PreparedState {
    statements: HashMap<u32, PreparedStatement>,
    sql_bytes: usize,
    long_data_bytes: usize,
    long_data_chunks: usize,
}

struct PreparedStatement {
    sql: String,
    parameter_count: usize,
    client_types: Option<Vec<ParameterType>>,
    backend_types: Option<Vec<ParameterType>>,
    long_data: Vec<PreparedLongDataChunk>,
    long_data_bytes: usize,
    pending_retry: bool,
}

struct PreparedLongDataChunk {
    parameter_index: u16,
    bytes: Vec<u8>,
}

fn prepare_sql(payload: &[u8]) -> Result<&str, ProtocolError> {
    if payload.first() != Some(&COM_STMT_PREPARE) || payload.len() <= 1 {
        return Err(ProtocolError::Malformed);
    }
    let sql = std::str::from_utf8(&payload[1..]).map_err(|_| ProtocolError::Unsupported)?;
    if sql.len() > MAX_QUERY_BYTES {
        return Err(ProtocolError::Oversized);
    }
    Ok(sql)
}

pub(super) async fn handle_prepare(
    frontend: &mut TcpStream,
    backend: &mut TcpStream,
    message: &Message,
    prepared: &mut PreparedState,
    backend_state: &mut BackendState,
) -> Result<(), ProtocolError> {
    let sql = match prepare_sql(&message.payload) {
        Ok(sql) => sql,
        Err(ProtocolError::Oversized) => {
            write_policy_error(
                frontend,
                message.next_sequence(),
                "QueryKnight prepared SQL exceeds the 1,000,000-byte SQL limit",
            )
            .await?;
            return Ok(());
        }
        Err(_) => {
            write_policy_error(
                frontend,
                message.next_sequence(),
                "invalid COM_STMT_PREPARE",
            )
            .await?;
            return Ok(());
        }
    };
    if prepared.statements.len() >= MAX_PREPARED_STATEMENTS
        || prepared
            .sql_bytes
            .checked_add(sql.len())
            .is_none_or(|bytes| bytes > MAX_PREPARED_SQL_BYTES)
    {
        write_policy_error(
            frontend,
            message.next_sequence(),
            "QueryKnight prepared-statement state limit reached",
        )
        .await?;
        return Ok(());
    }

    write_message(backend, message.sequence, &message.payload).await?;
    let mut expected_sequence = message.next_sequence();
    let first = read_response_packet(backend, expected_sequence).await?;
    expected_sequence = first.next_sequence();
    if is_err(&first.payload) {
        write_message(frontend, first.sequence, &first.payload).await?;
        return Ok(());
    }
    let metadata = parse_prepare_ok(&first.payload)?;
    let parameter_count = usize::from(metadata.parameter_count);
    let column_count = usize::from(metadata.column_count);
    if parameter_count > MAX_EXECUTION_PARAMS || u64::from(metadata.column_count) > MAX_COLUMNS {
        return Err(ProtocolError::Unsupported);
    }
    if prepared.statements.contains_key(&metadata.statement_id) {
        return Err(ProtocolError::Malformed);
    }

    let mut response = Vec::new();
    let mut response_bytes = 0usize;
    append_prepare_packet(&mut response, &mut response_bytes, first)?;
    for count in [parameter_count, column_count] {
        for _ in 0..count {
            let definition = read_response_packet(backend, expected_sequence).await?;
            expected_sequence = definition.next_sequence();
            if definition.payload.is_empty()
                || is_err(&definition.payload)
                || is_eof(&definition.payload)
            {
                return Err(ProtocolError::Malformed);
            }
            append_prepare_packet(&mut response, &mut response_bytes, definition)?;
        }
        if count != 0 {
            let terminator = read_response_packet(backend, expected_sequence).await?;
            expected_sequence = terminator.next_sequence();
            if !is_eof(&terminator.payload) {
                return Err(ProtocolError::Malformed);
            }
            backend_state.status_flags = server_status_from_eof(&terminator.payload)?;
            append_prepare_packet(&mut response, &mut response_bytes, terminator)?;
        }
    }

    prepared.sql_bytes += sql.len();
    prepared.statements.insert(
        metadata.statement_id,
        PreparedStatement {
            sql: sql.to_owned(),
            parameter_count,
            client_types: None,
            backend_types: None,
            long_data: Vec::new(),
            long_data_bytes: 0,
            pending_retry: false,
        },
    );
    for packet in response {
        write_message(frontend, packet.sequence, &packet.payload).await?;
    }
    Ok(())
}

fn append_prepare_packet(
    response: &mut Vec<Message>,
    total_bytes: &mut usize,
    packet: Message,
) -> Result<(), ProtocolError> {
    *total_bytes = total_bytes
        .checked_add(packet.payload.len())
        .ok_or(ProtocolError::Oversized)?;
    if *total_bytes > MAX_LOGICAL_RESPONSE {
        return Err(ProtocolError::Oversized);
    }
    response
        .try_reserve(1)
        .map_err(|_| ProtocolError::Oversized)?;
    response.push(packet);
    Ok(())
}

pub(super) fn buffer_long_data(
    message: &Message,
    prepared: &mut PreparedState,
) -> Result<(), ProtocolError> {
    if message.payload.len() < 7 || message.payload[0] != COM_STMT_SEND_LONG_DATA {
        return Err(ProtocolError::Malformed);
    }
    let statement_id = read_u32(&message.payload, 1)?;
    let parameter_index = read_u16(&message.payload, 5)?;
    let Some(statement) = prepared.statements.get_mut(&statement_id) else {
        return Err(ProtocolError::Malformed);
    };
    if usize::from(parameter_index) >= statement.parameter_count {
        return Err(ProtocolError::Malformed);
    }
    if statement.pending_retry {
        prepared.long_data_bytes -= statement.long_data_bytes;
        prepared.long_data_chunks -= statement.long_data.len();
        statement.long_data.clear();
        statement.long_data_bytes = 0;
        statement.pending_retry = false;
    }
    let bytes = &message.payload[7..];
    if prepared.long_data_chunks >= MAX_LONG_DATA_CHUNKS
        || prepared
            .long_data_bytes
            .checked_add(bytes.len())
            .is_none_or(|length| length > MAX_EXECUTION_PARAM_BYTES)
    {
        return Err(ProtocolError::Oversized);
    }
    statement
        .long_data
        .try_reserve(1)
        .map_err(|_| ProtocolError::Oversized)?;
    let mut chunk = Vec::new();
    chunk
        .try_reserve_exact(bytes.len())
        .map_err(|_| ProtocolError::Oversized)?;
    chunk.extend_from_slice(bytes);
    statement.long_data.push(PreparedLongDataChunk {
        parameter_index,
        bytes: chunk,
    });
    statement.long_data_bytes += bytes.len();
    prepared.long_data_bytes += bytes.len();
    prepared.long_data_chunks += 1;
    Ok(())
}

fn mark_pending_execute(prepared: &mut PreparedState, statement_id: u32) {
    if let Some(statement) = prepared.statements.get_mut(&statement_id) {
        statement.pending_retry = true;
    }
}
pub(super) async fn handle_execute(
    frontend: &mut TcpStream,
    backend: &mut TcpStream,
    message: &Message,
    config: Arc<ProxyConfig>,
    session_id: Option<&str>,
    prepared: &mut PreparedState,
    backend_state: &mut BackendState,
) -> Result<(), ProtocolError> {
    let statement_id = match read_u32(&message.payload, 1) {
        Ok(id) if message.payload.len() >= 10 => id,
        _ => {
            write_policy_error(
                frontend,
                message.next_sequence(),
                "malformed COM_STMT_EXECUTE",
            )
            .await?;
            return Ok(());
        }
    };
    let (sql, execute, params) = {
        let Some(statement) = prepared.statements.get_mut(&statement_id) else {
            write_policy_error(
                frontend,
                message.next_sequence(),
                "unknown MySQL prepared statement",
            )
            .await?;
            return Ok(());
        };
        let mut long_data_params = [false; MAX_EXECUTION_PARAMS];
        for chunk in &statement.long_data {
            long_data_params[usize::from(chunk.parameter_index)] = true;
        }
        let execute = match decode_execute(
            &message.payload,
            statement.parameter_count,
            statement.client_types.as_deref(),
            &long_data_params[..statement.parameter_count],
        ) {
            Ok(execute) if execute.statement_id == statement_id => execute,
            _ => {
                statement.pending_retry = true;
                write_policy_error(
                    frontend,
                    message.next_sequence(),
                    "invalid or unsupported MySQL prepared parameters",
                )
                .await?;
                return Ok(());
            }
        };
        if execute.supplied_types {
            statement.client_types = Some(execute.types.clone());
        }
        let mut params = Vec::with_capacity(statement.parameter_count);
        for (index, value) in execute.values.iter().enumerate() {
            let has_long_data = statement
                .long_data
                .iter()
                .any(|chunk| usize::from(chunk.parameter_index) == index);
            if value.is_null {
                if has_long_data {
                    statement.pending_retry = true;
                    write_policy_error(
                        frontend,
                        message.next_sequence(),
                        "NULL parameter cannot include MySQL long data",
                    )
                    .await?;
                    return Ok(());
                }
                params.push(ExecutionParam::Null);
                continue;
            }
            let bytes = if has_long_data {
                let length: usize = statement
                    .long_data
                    .iter()
                    .filter(|chunk| usize::from(chunk.parameter_index) == index)
                    .map(|chunk| chunk.bytes.len())
                    .sum();
                let mut bytes = Vec::with_capacity(length);
                for chunk in &statement.long_data {
                    if usize::from(chunk.parameter_index) == index {
                        bytes.extend_from_slice(&chunk.bytes);
                    }
                }
                bytes
            } else {
                message.payload[value.wire_range.clone()].to_vec()
            };
            params.push(ExecutionParam::Wire {
                representation: ParamRepresentation::Binary,
                type_hint: Some(value.parameter_type.type_hint()),
                bytes,
            });
        }
        (statement.sql.clone(), execute, params)
    };

    if validate_execution_params(&params).is_err() {
        mark_pending_execute(prepared, statement_id);
        write_policy_error(
            frontend,
            message.next_sequence(),
            "prepared parameters exceed QueryKnight's exact-identity limits",
        )
        .await?;
        return Ok(());
    }
    let outcome = match authorize_request(
        config.clone(),
        session_id.map(str::to_owned),
        sql.clone(),
        params,
    )
    .await
    {
        Some(outcome) => outcome,
        None => {
            mark_pending_execute(prepared, statement_id);
            write_policy_error(
                frontend,
                message.next_sequence(),
                "QueryKnight authorization is unavailable",
            )
            .await?;
            return Ok(());
        }
    };
    let permit = match outcome {
        AuthorizationOutcome::Permitted(permit) => permit,
        AuthorizationOutcome::Blocked(_) => {
            mark_pending_execute(prepared, statement_id);
            write_policy_error(
                frontend,
                message.next_sequence(),
                "QueryKnight blocked this query",
            )
            .await?;
            return Ok(());
        }
        AuthorizationOutcome::PendingApproval(pending) => {
            mark_pending_execute(prepared, statement_id);
            let text = format!("QueryKnight approval required ({})", pending.approval_id);
            write_policy_error(frontend, message.next_sequence(), &text).await?;
            return Ok(());
        }
        AuthorizationOutcome::Failed(_) => {
            mark_pending_execute(prepared, statement_id);
            write_policy_error(
                frontend,
                message.next_sequence(),
                "QueryKnight could not authorize this query",
            )
            .await?;
            return Ok(());
        }
    };
    if permit.dialect() != qk_sql::SqlDialect::MySql
        || permit.scope().database != config.database_key
    {
        mark_pending_execute(prepared, statement_id);
        write_policy_error(
            frontend,
            message.next_sequence(),
            "QueryKnight authorization scope mismatch",
        )
        .await?;
        return Ok(());
    }
    let _ = write_history(&config, session_id, &sql).await;

    let (execute_payload, long_data) = {
        let statement = prepared
            .statements
            .get_mut(&statement_id)
            .ok_or(ProtocolError::Malformed)?;
        let backend_needs_types = !execute.supplied_types
            && !execute.types.is_empty()
            && statement.backend_types.as_deref() != Some(execute.types.as_slice());
        let execute_payload = if backend_needs_types {
            Cow::Owned(rewrite_execute_types(&message.payload, &execute)?)
        } else {
            Cow::Borrowed(message.payload.as_slice())
        };
        let long_data = std::mem::take(&mut statement.long_data);
        prepared.long_data_bytes -= statement.long_data_bytes;
        prepared.long_data_chunks -= long_data.len();
        statement.long_data_bytes = 0;
        statement.pending_retry = false;
        (execute_payload, long_data)
    };

    // The permit is consumed immediately before any buffered parameter bytes reach MySQL.
    drop(permit);
    for chunk in &long_data {
        let mut payload = Vec::with_capacity(7 + chunk.bytes.len());
        payload.push(COM_STMT_SEND_LONG_DATA);
        payload.extend_from_slice(&statement_id.to_le_bytes());
        payload.extend_from_slice(&chunk.parameter_index.to_le_bytes());
        payload.extend_from_slice(&chunk.bytes);
        write_message(backend, 0, &payload).await?;
    }
    write_message(backend, message.sequence, &execute_payload).await?;
    relay_response(
        frontend,
        backend,
        message.next_sequence(),
        backend_state,
        true,
    )
    .await?;
    if let Some(statement) = prepared.statements.get_mut(&statement_id) {
        statement.backend_types = Some(execute.types);
    }
    Ok(())
}

pub(super) async fn handle_reset(
    frontend: &mut TcpStream,
    backend: &mut TcpStream,
    message: &Message,
    prepared: &mut PreparedState,
    backend_state: &mut BackendState,
) -> Result<(), ProtocolError> {
    if message.payload.len() != 5 || message.payload[0] != COM_STMT_RESET {
        write_policy_error(
            frontend,
            message.next_sequence(),
            "malformed COM_STMT_RESET",
        )
        .await?;
        return Ok(());
    }
    let statement_id = read_u32(&message.payload, 1)?;
    if !prepared.statements.contains_key(&statement_id) {
        write_policy_error(
            frontend,
            message.next_sequence(),
            "unknown MySQL prepared statement",
        )
        .await?;
        return Ok(());
    }
    write_message(backend, message.sequence, &message.payload).await?;
    let response = read_response_packet(backend, message.next_sequence()).await?;
    if is_err(&response.payload) {
        write_message(frontend, response.sequence, &response.payload).await?;
        return Ok(());
    }
    if !is_ok(&response.payload) {
        return Err(ProtocolError::Malformed);
    }
    backend_state.status_flags = server_status_from_ok(&response.payload)?;
    write_message(frontend, response.sequence, &response.payload).await?;
    let statement = prepared
        .statements
        .get_mut(&statement_id)
        .ok_or(ProtocolError::Malformed)?;
    prepared.long_data_bytes -= statement.long_data_bytes;
    prepared.long_data_chunks -= statement.long_data.len();
    statement.long_data.clear();
    statement.long_data_bytes = 0;
    statement.backend_types = None;
    statement.pending_retry = false;
    Ok(())
}

pub(super) async fn handle_close(
    backend: &mut TcpStream,
    message: &Message,
    prepared: &mut PreparedState,
) -> Result<(), ProtocolError> {
    if message.payload.len() != 5 || message.payload[0] != COM_STMT_CLOSE {
        return Err(ProtocolError::Malformed);
    }
    let statement_id = read_u32(&message.payload, 1)?;
    if !prepared.statements.contains_key(&statement_id) {
        return Err(ProtocolError::Malformed);
    }
    write_message(backend, message.sequence, &message.payload).await?;
    let statement = prepared
        .statements
        .remove(&statement_id)
        .ok_or(ProtocolError::Malformed)?;
    prepared.sql_bytes -= statement.sql.len();
    prepared.long_data_bytes -= statement.long_data_bytes;
    prepared.long_data_chunks -= statement.long_data.len();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prepared_sql_is_strict_and_bounded() {
        assert_eq!(
            prepare_sql(&[COM_STMT_PREPARE, b'S', b'E', b'L', b'E', b'C', b'T']),
            Ok("SELECT")
        );
        assert_eq!(
            prepare_sql(&[COM_STMT_PREPARE, 0xff]),
            Err(ProtocolError::Unsupported)
        );
        assert_eq!(
            prepare_sql(&[COM_STMT_PREPARE]),
            Err(ProtocolError::Malformed)
        );
    }
}
