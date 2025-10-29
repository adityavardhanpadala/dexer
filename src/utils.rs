use crate::types::{
    ClassDataItem,
    CodeItem,
    DecodedString,
    EncodedField,
    EncodedMethod,
    Mutf8Error,
    StringDataItem,
    proto_id_item, // Added proto_id_item
};

use log::{debug, error, info, warn};
use std::mem::size_of;

pub fn get_string_data_item(dexfile: &[u8], offset: usize) -> StringDataItem {
    let mut cursor = offset;
    let size = read_uleb128(&dexfile[cursor..]);
    cursor += uleb128_size(size);
    let data = &dexfile[cursor..cursor + size as usize];

    StringDataItem {
        size: size as u16,
        data,
    }
}

pub fn get_u32_items(dexfile: &[u8], offset: usize, count: usize) -> &[u32] {
    let start_byte = offset;
    let end_byte = offset + (count * size_of::<u32>());

    // Ensure we don't go out of bounds
    assert!(
        end_byte <= dexfile.len(),
        "Requested range is out of bounds"
    );

    unsafe {
        std::slice::from_raw_parts(dexfile[start_byte..end_byte].as_ptr() as *const u32, count)
    }
}

pub fn get_items<T>(dexfile: &[u8], offset: usize, count: usize) -> &[T] {
    let start_byte = offset;
    let end_byte = offset + (count * size_of::<T>());

    // Ensure we don't go out of bounds
    assert!(
        end_byte <= dexfile.len(),
        "Requested range is out of bounds"
    );

    unsafe { std::slice::from_raw_parts(dexfile[start_byte..end_byte].as_ptr() as *const T, count) }
}

const REPLACEMENT_CHAR: char = '\u{FFFD}'; // Unicode Replacement Character

// TODO(sfx): Fix the salvaging logic to be more robust
pub fn decode_mutf8(input: &[u8]) -> DecodedString {
    let mut result = String::new();
    let mut i = 0;

    while i < input.len() {
        if input[i] == 0 {
            break; // End of string
        } else if input[i] < 0x80 {
            // 1-byte sequence
            result.push(input[i] as char);
            i += 1;
        } else if input[i] < 0xE0 && input[i] >= 0xC0 {
            // 2-byte sequence
            if i + 1 >= input.len() {
                // Try to salvage the last byte as a single character
                result.push(REPLACEMENT_CHAR);
                return DecodedString {
                    string: result,
                    error: Some(Mutf8Error::UnexpectedEndOfInput(i)),
                };
            }
            let code_point = (((input[i] & 0x1F) as u32) << 6) | ((input[i + 1] & 0x3F) as u32);
            match char::from_u32(code_point) {
                Some(c) => result.push(c),
                None => {
                    // Try to salvage these bytes as single characters
                    result.push(input[i] as char);
                    result.push(input[i + 1] as char);
                    return DecodedString {
                        string: result,
                        error: Some(Mutf8Error::InvalidSequence(i)),
                    };
                }
            }
            i += 2;
        } else if input[i] & 0xF0 == 0xE0 {
            // 3-byte sequence
            if i + 2 >= input.len() {
                // Try to salvage the remaining bytes as single characters
                for j in i..input.len() {
                    result.push(input[j] as char);
                }
                return DecodedString {
                    string: result,
                    error: Some(Mutf8Error::UnexpectedEndOfInput(i)),
                };
            }
            let code_point = (((input[i] & 0x0F) as u32) << 12)
                | (((input[i + 1] & 0x3F) as u32) << 6)
                | ((input[i + 2] & 0x3F) as u32);
            match char::from_u32(code_point) {
                Some(c) => result.push(c),
                None => {
                    // Try to salvage these bytes as single characters
                    for j in i..i + 3 {
                        result.push(input[j] as char);
                    }
                    return DecodedString {
                        string: result,
                        error: Some(Mutf8Error::InvalidSequence(i)),
                    };
                }
            }
            i += 3;
        } else {
            // Invalid sequence, try to salvage this byte as a single character
            result.push(input[i] as char);
            i += 1;
            if i == input.len() {
                return DecodedString {
                    string: result,
                    error: Some(Mutf8Error::InvalidSequence(i - 1)),
                };
            }
        }
    }

    DecodedString {
        string: result,
        error: None,
    }
}

pub fn read_uleb128(input: &[u8]) -> u32 {
    let mut result = 0;
    let mut shift = 0;

    for &byte in input {
        result |= ((byte & 0x7f) as u32) << shift;
        if byte & 0x80 == 0 {
            break;
        }
        shift += 7;
    }

    result
}

pub fn uleb128_size(value: u32) -> usize {
    let mut size = 1;
    let mut val = value;
    while val >= 128 {
        size += 1;
        val >>= 7;
    }
    size
}

// Helper function to read a slice of u16 values
pub fn get_u16_items(dexfile: &[u8], offset: usize, count: usize) -> Vec<u16> {
    let start_byte = offset;
    let end_byte = offset + (count * size_of::<u16>());

    assert!(
        end_byte <= dexfile.len(),
        "Requested u16 range is out of bounds"
    );

    let slice_u8 = &dexfile[start_byte..end_byte];
    let mut result = Vec::with_capacity(count);
    // Assuming little-endian architecture, which is standard for DEX
    for chunk in slice_u8.chunks_exact(2) {
        result.push(u16::from_le_bytes([chunk[0], chunk[1]]));
    }
    result
}

pub fn parse_encoded_field(dexfile: &[u8], offset: usize) -> (EncodedField, usize) {
    let mut cursor = offset;

    let field_idx_diff = read_uleb128(&dexfile[cursor..]);
    cursor += uleb128_size(field_idx_diff);

    let access_flags = read_uleb128(&dexfile[cursor..]);
    cursor += uleb128_size(access_flags);

    (
        EncodedField {
            field_idx_diff,
            access_flags,
        },
        cursor - offset, // bytes read
    )
}

pub fn parse_encoded_method(dexfile: &[u8], offset: usize) -> (EncodedMethod, usize) {
    let mut cursor = offset;

    let method_idx_diff = read_uleb128(&dexfile[cursor..]);
    cursor += uleb128_size(method_idx_diff);

    let access_flags = read_uleb128(&dexfile[cursor..]);
    cursor += uleb128_size(access_flags);

    let code_off = read_uleb128(&dexfile[cursor..]);
    cursor += uleb128_size(code_off);

    (
        EncodedMethod {
            method_idx_diff,
            access_flags,
            code_off,
        },
        cursor - offset, // bytes read
    )
}

pub fn parse_class_data_item(dexfile: &[u8], offset: usize) -> (ClassDataItem, usize) {
    let mut cursor = offset;

    let static_fields_size = read_uleb128(&dexfile[cursor..]);
    cursor += uleb128_size(static_fields_size);

    let instance_fields_size = read_uleb128(&dexfile[cursor..]);
    cursor += uleb128_size(instance_fields_size);

    let direct_methods_size = read_uleb128(&dexfile[cursor..]);
    cursor += uleb128_size(direct_methods_size);

    let virtual_methods_size = read_uleb128(&dexfile[cursor..]);
    cursor += uleb128_size(virtual_methods_size);

    let mut static_fields = Vec::with_capacity(static_fields_size as usize);
    for _ in 0..static_fields_size {
        let (field, bytes_read) = parse_encoded_field(dexfile, cursor);
        static_fields.push(field);
        cursor += bytes_read;
    }

    let mut instance_fields = Vec::with_capacity(instance_fields_size as usize);
    for _ in 0..instance_fields_size {
        let (field, bytes_read) = parse_encoded_field(dexfile, cursor);
        instance_fields.push(field);
        cursor += bytes_read;
    }

    let mut direct_methods = Vec::with_capacity(direct_methods_size as usize);
    for _ in 0..direct_methods_size {
        let (method, bytes_read) = parse_encoded_method(dexfile, cursor);
        direct_methods.push(method);
        cursor += bytes_read;
    }

    let mut virtual_methods = Vec::with_capacity(virtual_methods_size as usize);
    for _ in 0..virtual_methods_size {
        let (method, bytes_read) = parse_encoded_method(dexfile, cursor);
        virtual_methods.push(method);
        cursor += bytes_read;
    }

    (
        ClassDataItem {
            static_fields_size,
            instance_fields_size,
            direct_methods_size,
            virtual_methods_size,
            static_fields,
            instance_fields,
            direct_methods,
            virtual_methods,
        },
        cursor - offset, // total bytes read
    )
}

pub fn parse_code_item(dexfile: &[u8], offset: usize) -> (CodeItem, usize) {
    let mut cursor = offset;

    // Ensure enough bytes for the fixed part of CodeItem header
    let header_size = size_of::<u16>() * 4 + size_of::<u32>() * 2;
    assert!(
        cursor + header_size <= dexfile.len(),
        "Not enough data for CodeItem header at offset {}",
        offset
    );

    let registers_size = u16::from_le_bytes([dexfile[cursor], dexfile[cursor + 1]]);
    cursor += size_of::<u16>();
    let ins_size = u16::from_le_bytes([dexfile[cursor], dexfile[cursor + 1]]);
    cursor += size_of::<u16>();
    let outs_size = u16::from_le_bytes([dexfile[cursor], dexfile[cursor + 1]]);
    cursor += size_of::<u16>();
    let tries_size = u16::from_le_bytes([dexfile[cursor], dexfile[cursor + 1]]);
    cursor += size_of::<u16>();
    let debug_info_off = u32::from_le_bytes([
        dexfile[cursor],
        dexfile[cursor + 1],
        dexfile[cursor + 2],
        dexfile[cursor + 3],
    ]);
    cursor += size_of::<u32>();
    let insns_size = u32::from_le_bytes([
        dexfile[cursor],
        dexfile[cursor + 1],
        dexfile[cursor + 2],
        dexfile[cursor + 3],
    ]);
    cursor += size_of::<u32>();

    let insns = get_u16_items(dexfile, cursor, insns_size as usize);
    let insns_bytes_size = insns_size as usize * size_of::<u16>();
    cursor += insns_bytes_size;

    // Padding if tries_size > 0 and insns_size is odd
    if tries_size > 0 && insns_size % 2 != 0 {
        cursor += size_of::<u16>(); // Skip 2 bytes padding
    }

    // TODO: Parse try_items and encoded_catch_handler_list if tries_size > 0
    // For now, we just calculate the total size including potential padding and skip them
    let code_item = CodeItem {
        registers_size,
        ins_size,
        outs_size,
        tries_size,
        debug_info_off,
        insns_size,
        insns,
    };

    // We don't parse tries/handlers yet, so the bytes read is up to the end of insns + padding
    let bytes_read = cursor - offset;

    (code_item, bytes_read)
}

/// Retrieves and formats the method signature string from a ProtoIdItem.
///
/// Args:
///     dexfile: The byte slice of the DEX file.
///     proto_item: The ProtoIdItem containing indices for the signature components.
///     string_ids: A slice containing offsets to string data items.
///     type_ids: A slice containing indices into string_ids for type descriptors.
///
/// Returns:
///     Ok(String) containing the formatted method signature (e.g., "(Ljava/lang/String;I)V")
///     Err(String) if any index is out of bounds or decoding fails.
pub fn get_method_signature(
    dexfile: &[u8],
    proto_item: &proto_id_item,
    string_ids: &[u32],
    type_ids: &[u32],
) -> Result<String, String> {
    // --- Get Return Type ---
    let return_type_string_idx = *type_ids
        .get(proto_item.return_type_idx as usize)
        .ok_or_else(|| {
            format!(
                "Return type index {} out of bounds for type_ids (len {})",
                proto_item.return_type_idx,
                type_ids.len()
            )
        })?;
    let return_type_offset = *string_ids
        .get(return_type_string_idx as usize)
        .ok_or_else(|| {
            format!(
                "Return type string index {} out of bounds for string_ids (len {})",
                return_type_string_idx,
                string_ids.len()
            )
        })?;
    let return_type_sdi = get_string_data_item(dexfile, return_type_offset as usize);
    let decoded_return_type = decode_mutf8(return_type_sdi.data);
    if let Some(err) = decoded_return_type.error {
        return Err(format!("Failed to decode return type string: {:?}", err));
    }
    let return_type_str = decoded_return_type.string;

    // --- Get Parameter Types ---
    let mut params_str = String::from("(");
    if proto_item.parameters_off != 0 {
        let params_offset = proto_item.parameters_off as usize;
        // Read the size (u32) of the type_list
        if params_offset + size_of::<u32>() > dexfile.len() {
            return Err(format!(
                "Parameter list offset {} points past end of file",
                params_offset
            ));
        }
        let size_bytes = &dexfile[params_offset..params_offset + size_of::<u32>()];
        let size = u32::from_le_bytes(size_bytes.try_into().unwrap()); // Safe unwrap due to length check

        if size > 0 {
            let list_offset = params_offset + size_of::<u32>();
            let type_indices = get_u16_items(dexfile, list_offset, size as usize);

            for (i, type_idx) in type_indices.iter().enumerate() {
                let param_type_string_idx = *type_ids.get(*type_idx as usize).ok_or_else(|| {
                    format!(
                        "Parameter type index {} out of bounds for type_ids (len {})",
                        type_idx,
                        type_ids.len()
                    )
                })?;
                let param_type_offset = *string_ids
                    .get(param_type_string_idx as usize)
                    .ok_or_else(|| {
                        format!(
                            "Parameter type string index {} out of bounds for string_ids (len {})",
                            param_type_string_idx,
                            string_ids.len()
                        )
                    })?;
                let param_sdi = get_string_data_item(dexfile, param_type_offset as usize);
                let decoded_param = decode_mutf8(param_sdi.data);
                if let Some(err) = decoded_param.error {
                    return Err(format!("Failed to decode parameter type string: {:?}", err));
                }
                params_str.push_str(&decoded_param.string);
            }
        }
    }
    params_str.push(')');

    // --- Combine and Return ---
    Ok(format!("{}{}", params_str, return_type_str))
}
