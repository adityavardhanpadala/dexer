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
        
        println!("{:?}", string_id_items[2]);
        let string_data_item = get_string_data_item(&dexfile, string_id_items[2] as usize);
        
        println!("{:x?}", string_data_item.data);
    }
}

fn get_string_data_item(dexfile: &[u8], offset: usize) -> StringDataItem {
    let sdi_size = dexfile[offset] as u16;
    let sdi_data = &dexfile[offset + 1..offset + 1 + sdi_size as usize];

    StringDataItem {
        size: sdi_size,
        data: sdi_data,
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

fn main() {
    SimpleLogger::new().init().unwrap();

    info!("Dexer v0.1.0");
    let args: Vec<String> = std::env::args().collect();
    let dex = Dex::new(&args[1]);

    print!("{:#?}", dex);
}
