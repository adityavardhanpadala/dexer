mod types;
mod utils;

use core::mem::size_of;
use log::{debug, error, info, warn};
use memmap::MmapOptions;
use simple_logger::SimpleLogger;
use std::{
    fs::File,
    hash::Hash,
    io::{BufRead, BufReader, Read},
    path::Path,
    usize,
};

use types::*;
use utils::{decode_mutf8, get_items, get_string_data_item, get_u32_items};

use adler32;

/// Dex Header Struct
/// Size : 112 bytes
// #[allow(dead_code)]
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

impl Dex<'_> {
    /// Validate dex file and parse it into a Dex struct
    /// # Arguments
    /// * `path` - Path to dex file
    fn new(path: &String) -> Dex {
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
            b"dex\n035\0" | b"dex\n036\0" | b"dex\n037\0" | b"dex\n038\0" | b"dex\n039\0" => {
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

        let string_id_items = get_u32_items(
            &dexfile,
            header.string_ids_off as usize,
            header.string_ids_size as usize,
        );

        // Create a hashmap of string ids and their corresponding strings

        let string_map = string_id_items
            .iter()
            .map(|&item| {
                let str_vec = get_string_data_item(&dexfile, item as usize);
                let decoded = decode_mutf8(&str_vec.data);
                (item, decoded.string)
            })
            .collect::<std::collections::HashMap<u32, String>>();

        println!("Len of string_id_items {}", string_id_items.len());

        // Type ids are indexes into string_id_items this type_id string must confirm to
        // TypeDescriptor syntax
        let type_id_items = get_u32_items(
            &dexfile,
            header.type_ids_off as usize,
            header.type_ids_size as usize,
        );
        let type_map: std::collections::HashMap<u32, String> = type_id_items
            .iter()
            .filter_map(|&idx| {
                string_map
                    .get(&string_id_items[idx as usize])
                    .map(|s| (idx, s.clone()))
            })
            .collect();

        let proto_id_items = get_items::<proto_id_item>(
            &dexfile,
            header.proto_ids_off as usize,
            header.proto_ids_size as usize,
        );

        println!("{:#x?}", proto_id_items[0]);

        let field_id_items = get_items::<field_id_item>(
            &dexfile,
            header.field_ids_off as usize,
            header.field_ids_size as usize,
        );

        println!("{:#x?}", field_id_items[0]);

        let method_id_items = get_items::<method_id_item>(
            &dexfile,
            header.method_ids_off as usize,
            header.method_ids_size as usize,
        );

        println!("{:#x?}", method_id_items[0]);

        let class_def_items = get_items::<class_def_item>(
            &dexfile,
            header.class_defs_off as usize,
            header.class_defs_size as usize,
        );

        println!("{:#x?}", class_def_items[0]);

        let call_site_ids = get_items<call_site_item>(
            &dexfile,
            header.data_off,
            header.data_size,
        );

        Dex {
            header: header,
            string_ids: string_id_items,
            type_ids: type_id_items,
            proto_ids: proto_id_items,
            field_ids: field_id_items,
            method_ids: method_id_items,
            class_defs: class_def_items,
            call_site_ids: ,
            method_handles: (),
            data: (),
            link_data: (),
        }               
    }
}

#[allow(dead_code)]
#[derive(Debug, Default)]
struct Dex<'a> {
    header: Header,
    string_ids: &'a [u32],
    type_ids: &'a [u32],
    proto_ids: &'a [proto_id_item],
    field_ids: &'a [field_id_item],
    method_ids: &'a [method_id_item],
    class_defs: &'a [class_def_item],
    call_site_ids: &'a [u8],
    method_handles: &'a [u8],
    data: &'a [u8],
    link_data: &'a [u8],
}

fn main() {
    SimpleLogger::new().init().unwrap();

    info!("Dexer v0.1.0");
    let args: Vec<String> = std::env::args().collect();
    let dex = Dex::new(&args[1]);

    print!("{:#?}", dex);
}
