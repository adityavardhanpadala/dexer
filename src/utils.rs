use crate::types::{StringDataItem, DecodedString,Mutf8Error};

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
    assert!(end_byte <= dexfile.len(), "Requested range is out of bounds");

    unsafe {
        std::slice::from_raw_parts(
            dexfile[start_byte..end_byte].as_ptr() as *const u32,
            count
        )
    }
}

pub fn get_items<T>(dexfile: &[u8], offset: usize, count: usize) -> &[T] {
    let start_byte = offset;
    let end_byte = offset + (count * size_of::<T>());

    // Ensure we don't go out of bounds
    assert!(end_byte <= dexfile.len(), "Requested range is out of bounds");

    unsafe {
        std::slice::from_raw_parts(
            dexfile[start_byte..end_byte].as_ptr() as *const T,
            count
        )
    }
}

pub fn decode_mutf8(input: &[u8]) -> DecodedString {
    let mut result = String::new();
    let mut i = 0;

    while i < input.len() {
        if input[i] == 0 {
            break; // End of string
        } else if input[i] & 0x80 == 0 {
            // 1-byte sequence
            result.push(input[i] as char);
            i += 1;
        } else if input[i] & 0xE0 == 0xC0 {
            // 2-byte sequence
            if i + 1 >= input.len() {
                // Try to salvage the last byte as a single character
                result.push(input[i] as char);
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
                },
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
            let code_point = (((input[i] & 0x0F) as u32) << 12) | 
                             (((input[i + 1] & 0x3F) as u32) << 6) | 
                             ((input[i + 2] & 0x3F) as u32);
            match char::from_u32(code_point) {
                Some(c) => result.push(c),
                None => {
                    // Try to salvage these bytes as single characters
                    for j in i..i+3 {
                        result.push(input[j] as char);
                    }
                    return DecodedString {
                        string: result,
                        error: Some(Mutf8Error::InvalidSequence(i)),
                    };
                },
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

