pub mod disassembler;
pub mod types;
pub mod utils;

use thiserror::Error;

use crate::dexcore::types::*;
use crate::dexcore::utils::*;
use std::collections::HashMap;
use std::io::BufReader;

use log::{debug, error, info, warn};
use memmap::{Mmap, MmapOptions};

/// Dex Header Struct
/// Size : 112 bytes
#[allow(dead_code)]
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

#[derive(Error, Debug)]
pub enum DexError {
    #[error("Parsing failed: {0}")]
    ParseError(String),
    #[error("IoError")]
    IoError(#[from] std::io::Error),
}

#[allow(dead_code)]
#[derive(Debug)]
pub struct Dex<'a> {
    pub header: &'a Header,
    pub string_ids: &'a [u32],
    pub type_ids: &'a [u32],
    pub proto_ids: &'a [proto_id_item],
    pub field_ids: &'a [field_id_item],
    pub method_ids: &'a [method_id_item],
    pub class_defs: &'a [class_def_item],
    pub call_site_ids: &'a [u8],
    pub method_handles: &'a [u8],
    pub data: &'a [u8],
    pub link_data: &'a [u8],

    pub string_map: HashMap<u32, String>,
    pub type_map: Vec<String>,
}

impl Dex<'_> {
    /// Validate dex file and parse it into a Dex struct and associated maps
    /// # Arguments
    /// * `dexfile` - Memory mapped dex file
    /// Returns the Dex struct, string map, and type map
    pub fn new(dexfile: &Mmap) -> Result<Dex<'_>, DexError> {
        info!("Parsing header");
        let header: &Header = Header::new(&dexfile[0..112]);

        match &header.magic {
            b"dex\n035\0" | b"dex\n036\0" | b"dex\n037\0" | b"dex\n038\0" | b"dex\n039\0" => {
                info!("Found dex file")
            }
            _ => {
                return Err(DexError::ParseError(
                    format!("Invalid dex magic: {:?}", &header.magic).into(),
                ));
            }
        }

        // Verify checksum
        let computed_checksum = adler32::adler32(BufReader::new(&dexfile[12..]))?;
        if computed_checksum != header.checksum {
            warn!(
                "Checksum mismatch: computed 0x{:x} != header 0x{:x}",
                computed_checksum, header.checksum
            );
        } else {
            info!("Checksum match (0x{:x}). Valid dex found.", header.checksum);
        }

        info!("Parsing strings ids");
        let string_id_items = get_u32_items(
            dexfile,
            header.string_ids_off as usize,
            header.string_ids_size as usize,
        );

        let string_map: HashMap<u32, String> = string_id_items
            .iter()
            .map(|&item_offset| {
                let str_data_item = get_string_data_item(dexfile, item_offset as usize);
                debug!(
                    "String data item: {:?} len: {:?}",
                    str_data_item, str_data_item.size
                );
                let decoded = decode_mutf8(str_data_item.data);
                // Log decoding errors if any
                if let Some(err) = decoded.error {
                    warn!(
                        "MUTF-8 decoding error at offset 0x{:x}: {:?}",
                        item_offset, err
                    );
                }
                (item_offset, decoded.string) // Map original offset to string
            })
            .collect();

        info!("Parsing type ids");
        let type_id_items = get_items::<u32>(
            dexfile,
            header.type_ids_off as usize,
            header.type_ids_size as usize,
        );

        // type_id_items contains indices into string_ids array
        // string_ids[type_id_items[i]] gives us the offset to the string data
        // We need to use that offset to look up in string_map
        // Since type IDs are sequential from 0, we can use a Vec for O(1) indexing
        let type_map: Vec<String> = type_id_items
            .iter()
            .map(|&string_id_idx| {
                // string_id_idx is an index into string_ids array, not an offset
                let string_offset = string_id_items
                    .get(string_id_idx as usize)
                    .copied()
                    .unwrap_or(0);
                string_map
                    .get(&string_offset)
                    .cloned()
                    .unwrap_or_else(|| "<invalid_type>".to_string())
            })
            .collect();

        info!("Parsing proto ids");
        let proto_id_items = get_items::<proto_id_item>(
            dexfile,
            header.proto_ids_off as usize,
            header.proto_ids_size as usize,
        );

        info!("Parsing field ids");
        let field_id_items = get_items::<field_id_item>(
            dexfile,
            header.field_ids_off as usize,
            header.field_ids_size as usize,
        );

        info!("Parsing method ids");
        let method_id_items = get_items::<method_id_item>(
            dexfile,
            header.method_ids_off as usize,
            header.method_ids_size as usize,
        );

        info!("Parsing class definitions");
        let class_def_items = get_items::<class_def_item>(
            dexfile,
            header.class_defs_off as usize,
            header.class_defs_size as usize,
        );

        let dex_struct = Dex {
            header,
            string_ids: string_id_items,
            type_ids: type_id_items,
            proto_ids: proto_id_items,
            field_ids: field_id_items,
            method_ids: method_id_items,
            class_defs: class_def_items,

            call_site_ids: &[],
            method_handles: &[],
            data: &[],
            link_data: &[],

            string_map,
            type_map,
        };

        Ok(dex_struct)
    }
}
