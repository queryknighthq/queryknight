use std::ops::Range;

use crate::protocol::{read_u16, read_u32, ProtocolError, COM_STMT_EXECUTE};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ParameterType {
    pub(crate) code: u8,
    pub(crate) flags: u8,
}

impl ParameterType {
    pub(crate) fn type_hint(self) -> u32 {
        u32::from(self.code) | (u32::from(self.flags) << 8)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PreparedMetadata {
    pub(crate) statement_id: u32,
    pub(crate) column_count: u16,
    pub(crate) parameter_count: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DecodedValue {
    pub(crate) parameter_type: ParameterType,
    pub(crate) is_null: bool,
    pub(crate) wire_range: Range<usize>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DecodedExecute {
    pub(crate) statement_id: u32,
    pub(crate) types: Vec<ParameterType>,
    pub(crate) supplied_types: bool,
    pub(crate) type_flag_offset: Option<usize>,
    pub(crate) values: Vec<DecodedValue>,
}

pub(crate) fn parse_prepare_ok(payload: &[u8]) -> Result<PreparedMetadata, ProtocolError> {
    if payload.len() != 12 || payload[0] != 0 || payload[9] != 0 {
        return Err(ProtocolError::Malformed);
    }
    Ok(PreparedMetadata {
        statement_id: read_u32(payload, 1)?,
        column_count: read_u16(payload, 5)?,
        parameter_count: read_u16(payload, 7)?,
    })
}

pub(crate) fn decode_execute(
    payload: &[u8],
    parameter_count: usize,
    cached_types: Option<&[ParameterType]>,
    long_data_params: &[bool],
) -> Result<DecodedExecute, ProtocolError> {
    if payload.first() != Some(&COM_STMT_EXECUTE) || payload.len() < 10 {
        return Err(ProtocolError::Malformed);
    }
    if payload[5] != 0 || read_u32(payload, 6)? != 1 {
        return Err(ProtocolError::Unsupported);
    }
    if parameter_count > qk_core::MAX_EXECUTION_PARAMS || long_data_params.len() != parameter_count
    {
        return Err(ProtocolError::Unsupported);
    }
    let statement_id = read_u32(payload, 1)?;
    if parameter_count == 0 {
        if payload.len() != 10 {
            return Err(ProtocolError::Malformed);
        }
        return Ok(DecodedExecute {
            statement_id,
            types: Vec::new(),
            supplied_types: false,
            type_flag_offset: None,
            values: Vec::new(),
        });
    }

    let bitmap_len = parameter_count.div_ceil(8);
    let bitmap_start = 10usize;
    let bitmap_end = bitmap_start
        .checked_add(bitmap_len)
        .ok_or(ProtocolError::Malformed)?;
    let bitmap = payload
        .get(bitmap_start..bitmap_end)
        .ok_or(ProtocolError::Malformed)?;
    if !parameter_count.is_multiple_of(8) {
        let used_bits = parameter_count % 8;
        let unused_mask = !((1u8 << used_bits) - 1);
        if bitmap.last().is_some_and(|last| last & unused_mask != 0) {
            return Err(ProtocolError::Malformed);
        }
    }
    let type_flag_offset = bitmap_end;
    let bind_flag = *payload
        .get(type_flag_offset)
        .ok_or(ProtocolError::Malformed)?;
    if bind_flag > 1 {
        return Err(ProtocolError::Malformed);
    }
    let supplied_types = bind_flag == 1;
    let (types, mut offset) = if supplied_types {
        let descriptors_end = type_flag_offset
            .checked_add(1 + parameter_count * 2)
            .ok_or(ProtocolError::Malformed)?;
        let descriptors = payload
            .get(type_flag_offset + 1..descriptors_end)
            .ok_or(ProtocolError::Malformed)?;
        let mut types = Vec::with_capacity(parameter_count);
        for pair in descriptors.chunks_exact(2) {
            let parameter_type = ParameterType {
                code: pair[0],
                flags: pair[1],
            };
            if !supported_type(parameter_type) {
                return Err(ProtocolError::Unsupported);
            }
            types.push(parameter_type);
        }
        (types, descriptors_end)
    } else {
        let types = cached_types.ok_or(ProtocolError::Malformed)?;
        if types.len() != parameter_count || types.iter().any(|ty| !supported_type(*ty)) {
            return Err(ProtocolError::Malformed);
        }
        (types.to_vec(), type_flag_offset + 1)
    };

    let mut values = Vec::with_capacity(parameter_count);
    for (index, parameter_type) in types.iter().copied().enumerate() {
        let is_null = bitmap[index / 8] & (1 << (index % 8)) != 0 || parameter_type.code == 0x06;
        let start = offset;
        if !is_null && !long_data_params[index] {
            offset = value_end(payload, offset, parameter_type.code)?;
        }
        values.push(DecodedValue {
            parameter_type,
            is_null,
            wire_range: start..offset,
        });
    }
    if offset != payload.len() {
        return Err(ProtocolError::Malformed);
    }
    Ok(DecodedExecute {
        statement_id,
        types,
        supplied_types,
        type_flag_offset: Some(type_flag_offset),
        values,
    })
}

pub(crate) fn rewrite_execute_types(
    payload: &[u8],
    execute: &DecodedExecute,
) -> Result<Vec<u8>, ProtocolError> {
    if execute.supplied_types || execute.types.is_empty() {
        return Ok(payload.to_vec());
    }
    let flag_offset = execute.type_flag_offset.ok_or(ProtocolError::Malformed)?;
    let extra = execute
        .types
        .len()
        .checked_mul(2)
        .ok_or(ProtocolError::Oversized)?;
    let mut rewritten = Vec::with_capacity(payload.len() + extra);
    rewritten.extend_from_slice(&payload[..=flag_offset]);
    rewritten[flag_offset] = 1;
    for parameter_type in &execute.types {
        rewritten.push(parameter_type.code);
        rewritten.push(parameter_type.flags);
    }
    rewritten.extend_from_slice(&payload[flag_offset + 1..]);
    Ok(rewritten)
}

fn supported_type(parameter_type: ParameterType) -> bool {
    if parameter_type.flags & !0x80 != 0 {
        return false;
    }
    matches!(
        parameter_type.code,
        0x00..=0x14 | 0xf4..=0xff
    ) && !matches!(parameter_type.code, 0x14 | 0xf3)
}

fn value_end(payload: &[u8], offset: usize, type_code: u8) -> Result<usize, ProtocolError> {
    let width = match type_code {
        0x01 | 0xf4 => Some(1),
        0x02 | 0x0d => Some(2),
        0x03 | 0x09 => Some(4),
        0x04 => Some(4),
        0x05 | 0x08 => Some(8),
        _ => None,
    };
    if let Some(width) = width {
        let end = offset.checked_add(width).ok_or(ProtocolError::Malformed)?;
        payload.get(offset..end).ok_or(ProtocolError::Malformed)?;
        return Ok(end);
    }
    match type_code {
        0x0a | 0x0e => temporal_end(payload, offset, &[0, 4]),
        0x07 | 0x0c | 0x11 | 0x12 => temporal_end(payload, offset, &[0, 4, 7, 11]),
        0x0b | 0x13 => temporal_end(payload, offset, &[0, 8, 12]),
        0x00 | 0x0f | 0x10 | 0xf5..=0xff => length_encoded_end(payload, offset),
        0x06 => Ok(offset),
        _ => Err(ProtocolError::Unsupported),
    }
}

fn temporal_end(
    payload: &[u8],
    offset: usize,
    valid_lengths: &[u8],
) -> Result<usize, ProtocolError> {
    let length = *payload.get(offset).ok_or(ProtocolError::Malformed)?;
    if !valid_lengths.contains(&length) {
        return Err(ProtocolError::Malformed);
    }
    let end = offset
        .checked_add(1 + usize::from(length))
        .ok_or(ProtocolError::Malformed)?;
    payload.get(offset..end).ok_or(ProtocolError::Malformed)?;
    Ok(end)
}

fn length_encoded_end(payload: &[u8], offset: usize) -> Result<usize, ProtocolError> {
    let first = *payload.get(offset).ok_or(ProtocolError::Malformed)?;
    let (length, prefix) = match first {
        0x00..=0xfa => (u64::from(first), 1usize),
        0xfc => (u64::from(read_u16(payload, offset + 1)?), 3),
        0xfd => {
            let bytes = payload
                .get(offset + 1..offset + 4)
                .ok_or(ProtocolError::Malformed)?;
            (
                u64::from(bytes[0]) | (u64::from(bytes[1]) << 8) | (u64::from(bytes[2]) << 16),
                4,
            )
        }
        0xfe => (read_u64(payload, offset + 1)?, 9),
        0xfb | 0xff => return Err(ProtocolError::Malformed),
    };
    let length = usize::try_from(length).map_err(|_| ProtocolError::Oversized)?;
    let start = offset.checked_add(prefix).ok_or(ProtocolError::Malformed)?;
    let end = start.checked_add(length).ok_or(ProtocolError::Malformed)?;
    payload.get(start..end).ok_or(ProtocolError::Malformed)?;
    Ok(end)
}

fn read_u64(payload: &[u8], offset: usize) -> Result<u64, ProtocolError> {
    let bytes = payload
        .get(offset..offset + 8)
        .ok_or(ProtocolError::Malformed)?;
    Ok(u64::from_le_bytes(
        bytes.try_into().map_err(|_| ProtocolError::Malformed)?,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn execute_packet(parameter_count: usize, types: &[ParameterType], values: &[u8]) -> Vec<u8> {
        let mut packet = vec![COM_STMT_EXECUTE];
        packet.extend_from_slice(&17u32.to_le_bytes());
        packet.push(0);
        packet.extend_from_slice(&1u32.to_le_bytes());
        packet.resize(10 + parameter_count.div_ceil(8), 0);
        if parameter_count > 0 {
            packet.push(1);
            for ty in types {
                packet.push(ty.code);
                packet.push(ty.flags);
            }
        }
        packet.extend_from_slice(values);
        packet
    }

    #[test]
    fn execute_decodes_bound_values_and_null_bitmap() {
        let types = [
            ParameterType {
                code: 0x03,
                flags: 0,
            },
            ParameterType {
                code: 0xfd,
                flags: 0,
            },
            ParameterType {
                code: 0x05,
                flags: 0x80,
            },
        ];
        let mut values = 42i32.to_le_bytes().to_vec();
        values.extend_from_slice(&[3, b'a', 0, b'b']);
        values.extend_from_slice(&1.5f64.to_le_bytes());
        let packet = execute_packet(3, &types, &values);
        let decoded = decode_execute(&packet, 3, None, &[false; 3]).expect("valid Execute");
        assert!(decoded.supplied_types);
        assert_eq!(decoded.statement_id, 17);
        assert_eq!(
            &packet[decoded.values[0].wire_range.clone()],
            &42i32.to_le_bytes()
        );
        assert_eq!(decoded.types[2].type_hint(), 0x8005);

        let null_packet = execute_packet(
            1,
            &[ParameterType {
                code: 0x03,
                flags: 0,
            }],
            &[],
        );
        let mut null_packet = null_packet;
        null_packet[10] = 1;
        let decoded = decode_execute(&null_packet, 1, None, &[false]).expect("NULL parameter");
        assert!(decoded.values[0].is_null);
    }

    #[test]
    fn execute_reuses_cached_types_and_rewrites_for_backend_sync() {
        let cached = [ParameterType {
            code: 0x08,
            flags: 0x80,
        }];
        let mut packet = vec![COM_STMT_EXECUTE];
        packet.extend_from_slice(&17u32.to_le_bytes());
        packet.push(0);
        packet.extend_from_slice(&1u32.to_le_bytes());
        packet.push(0);
        packet.push(0);
        packet.extend_from_slice(&23u64.to_le_bytes());
        let decoded = decode_execute(&packet, 1, Some(&cached), &[false]).expect("cached type");
        let rewritten = rewrite_execute_types(&packet, &decoded).expect("rewrite");
        assert_eq!(rewritten[11], 1);
        assert_eq!(&rewritten[12..14], &[0x08, 0x80]);
        assert_eq!(&rewritten[14..], &23u64.to_le_bytes());
        assert_eq!(
            decode_execute(&packet, 1, None, &[false]),
            Err(ProtocolError::Malformed)
        );
    }
    #[test]
    fn long_data_execute_omits_the_parameter_value_field() {
        let ty = ParameterType {
            code: 0xfd,
            flags: 0,
        };
        let packet = execute_packet(1, &[ty], &[]);
        let decoded = decode_execute(&packet, 1, None, &[true]).expect("long-data Execute");
        assert_eq!(decoded.values[0].wire_range, 14..14);
        assert_eq!(
            decode_execute(&packet, 1, None, &[false]),
            Err(ProtocolError::Malformed)
        );
    }
    #[test]
    fn execute_decodes_decimal_blob_and_temporal_wire_slices() {
        let types = [
            ParameterType {
                code: 0x00,
                flags: 0,
            },
            ParameterType {
                code: 0xfc,
                flags: 0,
            },
            ParameterType {
                code: 0x0a,
                flags: 0,
            },
            ParameterType {
                code: 0x0b,
                flags: 0,
            },
        ];
        let mut values = vec![3, b'1', b'.', b'5', 4, 0, 1, 0x80, 0xff];
        values.extend_from_slice(&[4, 0xe8, 0x07, 9, 30]);
        values.extend_from_slice(&[8, 0, 1, 2, 3, 4, 5, 6, 7]);
        let packet = execute_packet(4, &types, &values);
        let decoded = decode_execute(&packet, 4, None, &[false; 4]).expect("encoded values");
        for value in &decoded.values {
            assert!(value.wire_range.end > value.wire_range.start);
        }
        assert_eq!(
            &packet[decoded.values[0].wire_range.clone()],
            &[3, b'1', b'.', b'5']
        );
        assert_eq!(
            &packet[decoded.values[1].wire_range.clone()],
            &[4, 0, 1, 0x80, 0xff]
        );
        assert_eq!(
            &packet[decoded.values[2].wire_range.clone()],
            &[4, 0xe8, 0x07, 9, 30]
        );
        assert_eq!(
            &packet[decoded.values[3].wire_range.clone()],
            &[8, 0, 1, 2, 3, 4, 5, 6, 7]
        );

        let invalid_date = execute_packet(
            1,
            &[ParameterType {
                code: 0x0a,
                flags: 0,
            }],
            &[7, 0, 0, 0, 0, 0, 0, 0],
        );
        assert_eq!(
            decode_execute(&invalid_date, 1, None, &[false]),
            Err(ProtocolError::Malformed)
        );
    }

    #[test]
    fn execute_rejects_bad_arity_flags_types_widths_and_trailing_bytes() {
        let int = ParameterType {
            code: 0x03,
            flags: 0,
        };
        let valid = execute_packet(1, &[int], &1i32.to_le_bytes());
        assert!(decode_execute(&valid, 2, None, &[false; 2]).is_err());
        let mut bad_flags = valid.clone();
        bad_flags[5] = 1;
        assert_eq!(
            decode_execute(&bad_flags, 1, None, &[false]),
            Err(ProtocolError::Unsupported)
        );
        let mut bad_type = valid.clone();
        bad_type[12] = 0x15;
        assert_eq!(
            decode_execute(&bad_type, 1, None, &[false]),
            Err(ProtocolError::Unsupported)
        );
        let short = execute_packet(1, &[int], &[1, 0]);
        assert_eq!(
            decode_execute(&short, 1, None, &[false]),
            Err(ProtocolError::Malformed)
        );
        let mut trailing = valid;
        trailing.push(0);
        assert_eq!(
            decode_execute(&trailing, 1, None, &[false]),
            Err(ProtocolError::Malformed)
        );
    }

    #[test]
    fn prepare_ok_requires_full_mysql_84_metadata_header() {
        let mut payload = vec![0];
        payload.extend_from_slice(&17u32.to_le_bytes());
        payload.extend_from_slice(&2u16.to_le_bytes());
        payload.extend_from_slice(&1u16.to_le_bytes());
        payload.push(0);
        payload.extend_from_slice(&3u16.to_le_bytes());
        assert_eq!(
            parse_prepare_ok(&payload),
            Ok(PreparedMetadata {
                statement_id: 17,
                column_count: 2,
                parameter_count: 1,
            })
        );
        payload[9] = 1;
        assert_eq!(parse_prepare_ok(&payload), Err(ProtocolError::Malformed));
    }
}
