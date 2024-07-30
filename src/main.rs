mod types;

use log::{debug, error, info, warn};
use memmap::MmapOptions;
use simple_logger::SimpleLogger;
use core::mem::{size_of};
use std::{
    fs::File, hash::Hash, io::{BufRead, BufReader, Read}, path::Path, usize
};

use types::StringDataItem;

use adler32;


#[derive(Debug)]
enum Mutf8Error {
    InvalidSequence(usize),
    UnexpectedEndOfInput(usize),
}

#[derive(Debug)]
struct DecodedString {
    string: String,
    error: Option<Mutf8Error>,
}

/// Dex Header Struct
/// Size : 112 bytes
#[derive(Debug, Default)]
struct Header {
    magic: [u8; 8],
    checksum: u32,
    signature: [u8; 20],
    file_size: u32,
    header_size: u32,
    endian_tag: u32,
    link_size: u32,
    link_off: u32,
    map_off: u32,
    string_ids_size: u32,
    string_ids_off: u32,
    type_ids_size: u32,
    type_ids_off: u32,
    proto_ids_size: u32,
    proto_ids_off: u32,
    field_ids_size: u32,
    field_ids_off: u32,
    method_ids_size: u32,
    method_ids_off: u32,
    class_defs_size: u32,
    class_defs_off: u32,
    data_size: u32,
    data_off: u32,
}

impl Header {
    fn new(header: &[u8]) -> &Self {
        unsafe { &*(header.as_ptr() as *const Self) }
    }
}

#[derive(Debug, Default)]
struct Dex<'a> {
    header: Header,
    string_ids: &'a [u8],
    type_ids: &'a [u8],
    proto_ids: &'a [u8],
    field_ids: &'a [u8],
    method_ids: &'a [u8],
    class_defs: &'a [u8],
    call_site_ids: &'a [u8],
    method_handles: &'a [u8],
    data: &'a [u8],
    link_data: &'a [u8],
}

impl Dex<'_> {
    /// Validate dex file and parse it into a Dex struct
    /// # Arguments
    /// * `path` - Path to dex file
    fn new(path: &String) {
        let f = match File::open(path) {
            Err(e) => panic!("Error opening file: {}", e),
            Ok(file) => file,
        };
        // Map file to memory to avoid reading the whole file into memory
        // Should help startup marginally while batch processing multiple APKs
        let dexfile = unsafe { MmapOptions::new().map(&f).unwrap() };
        
        info!("Parsing header");
        let header: &Header = Header::new(&dexfile[0..112]);

        match &header.magic {
            b"dex\n035\0" 
            | b"dex\n036\0" 
            | b"dex\n037\0" 
            | b"dex\n038\0" 
            | b"dex\n039\0" => {
                info!("Found dex file")
            }
            _ => {
                panic!("Invalid dex magic");
            }
        }

        let computed = adler32::adler32(BufReader::new(&dexfile[12..])).unwrap();

        if computed != header.checksum {
            warn!("Checksum mismatch {} != {}", computed, header.checksum);
                panic!("Invalid checksum");
        } else {
            info!("Checksum match. Valid dex found.");
        }
        
        info!("Parsing strings ids");
               
        let string_id_items = get_u32_items(&dexfile, header.string_ids_off as usize, header.string_ids_size as usize);
        
        // Create a hashmap of string ids and their corresponding strings

        let string_map = string_id_items.iter().map(|&item| {
            let str_vec = get_string_data_item(&dexfile, item as usize);
            let decoded = decode_mutf8(&str_vec.data);
            (item, decoded.string)
        }).collect::<std::collections::HashMap<u32, String>>();

        // for item in string_id_items {
        //     let str_vec = get_string_data_item(&dexfile, *item as usize);

        //     let decoded = decode_mutf8(&str_vec.data);
        //     println!("Decoded: {}", decoded.string);
        //     if let Some(error) = decoded.error {
        //         println!("Error: {:?}", error);
        //     }
        // }

        println!("{:#?}", string_map);

    }
}

fn get_string_data_item(dexfile: &[u8], offset: usize) -> StringDataItem {
    let mut cursor = offset;
    let size = read_uleb128(&dexfile[cursor..]);
    cursor += uleb128_size(size);
    let data = &dexfile[cursor..cursor + size as usize];

    StringDataItem {
        size: size as u16,
        data,
    }
}


fn get_u32_items(dexfile: &[u8], offset: usize, count: usize) -> &[u32] {
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

fn decode_mutf8(input: &[u8]) -> DecodedString {
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

fn read_uleb128(input: &[u8]) -> u32 {
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

fn uleb128_size(value: u32) -> usize {
    let mut size = 1;
    let mut val = value;
    while val >= 128 {
        size += 1;
        val >>= 7;
    }
    size
}

fn main() {
    SimpleLogger::new().init().unwrap();

    info!("Dexer v0.1.0");
    let args: Vec<String> = std::env::args().collect();
    let dex = Dex::new(&args[1]);

    print!("{:#?}", dex);
}
