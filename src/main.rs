mod types;
mod utils;
mod disassembler;

use clap::Parser;
use color_eyre::eyre::{self, eyre, Result, WrapErr};
#[allow(unused_imports)]
use log::{debug, error, info, warn};
use memmap::{Mmap, MmapOptions};
use simple_logger::SimpleLogger;
use std::{
    collections::HashMap,
    fs::File,
    io::{BufReader, BufWriter, Write},
    path::PathBuf,
    usize,
};

use types::{
    class_def_item, field_id_item, method_id_item, proto_id_item,
    ClassDataItem, CodeItem,
};
use utils::{
    decode_mutf8, get_items, get_string_data_item, get_u32_items, parse_class_data_item,
    parse_code_item, get_method_signature,
};
use disassembler::disassemble_method;

use adler32;

/// Command line arguments
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Cli {
    /// Path to the dex file(s) to process
    #[arg(required = true)]
    files: Vec<PathBuf>,

    /// Output file for disassembly
    #[arg(long)]
    output: Option<PathBuf>,

    /// Specific method name to disassemble (e.g., "Lcom/example/MyClass;->myMethod(II)V")
    #[arg(long)]
    method: Option<String>,
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

// Renamed DexParsedData to avoid conflict with Dex struct name
#[derive(Debug)]
struct DexParsedData<'a> {
    dex_struct: Dex<'a>,
    string_map: HashMap<u32, String>,
    type_map: HashMap<u32, String>,
}

impl Dex<'_> {
    /// Validate dex file and parse it into a Dex struct and associated maps
    /// # Arguments
    /// * `dexfile` - Memory mapped dex file
    /// Returns the Dex struct, string map, and type map
    fn new(dexfile: &Mmap) -> Result<(Dex<'_>, HashMap<u32, String>, HashMap<u32, String>)> {
        info!("Parsing header");
        let header: &Header = Header::new(&dexfile[0..112]);

        match &header.magic {
            b"dex\n035\0" | b"dex\n036\0" | b"dex\n037\0" | b"dex\n038\0" | b"dex\n039\0" => {
                info!("Found dex file")
            }
            _ => return Err(eyre!("Invalid dex magic: {:?}", &header.magic)),
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
                let decoded = decode_mutf8(str_data_item.data);
                // Log decoding errors if any
                if let Some(err) = decoded.error {
                    warn!("MUTF-8 decoding error at offset 0x{:x}: {:?}", item_offset, err);
                }
                (item_offset, decoded.string) // Map original offset to string
            })
            .collect();

        info!("Parsing type ids");
        let type_id_items = get_u32_items(
            dexfile,
            header.type_ids_off as usize,
            header.type_ids_size as usize,
        );

        let type_map: HashMap<u32, String> = type_id_items
            .iter()
            .enumerate()
            .filter_map(|(type_id, &string_id_idx)| {
                string_map.get(&string_id_idx)
                          .map(|s| (type_id as u32, s.clone()))
            })
            .collect::<HashMap<u32, String>>();

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
        };

        Ok((dex_struct, string_map, type_map))
    }
}

#[allow(dead_code)]
#[derive(Debug)]
struct Dex<'a> {
    header: &'a Header,
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

fn mmap_files(fpaths: &[PathBuf]) -> Result<Vec<Mmap>> {
    let mut result = Vec::new();
    for fpath in fpaths {
        let f = File::open(fpath)
            .wrap_err_with(|| eyre!("error opening file: {}", fpath.display()))?;
        let dexfile = unsafe { MmapOptions::new().map(&f)? };
        result.push(dexfile);
    }
    return Ok(result);
}

/// Dumps the disassembly of methods to a file or stdout based on CLI args.
fn dump_disassembly(
    dex: &Dex,
    dexfile: &Mmap, // The raw memory-mapped file data
    string_map: &HashMap<u32, String>,
    type_map: &HashMap<u32, String>,
    cli: &Cli,
) -> Result<()> {
    let output_path = match &cli.output {
        Some(path) => path,
        None => return Ok(()),
    };

    info!("Opening output file for disassembly: {}", output_path.display());
    let output_file = File::create(output_path)
        .wrap_err_with(|| format!("Failed to create output file: {}", output_path.display()))?;
    let mut writer = BufWriter::new(output_file);

    info!("Starting disassembly dump...");

    let mut method_idx_counter: u32 = 0; // Track method index diff accumulation

    for (i, class_def) in dex.class_defs.iter().enumerate() {
        let class_name = type_map.get(&class_def.class_idx).cloned().unwrap_or_else(|| format!("UnknownClass{}", i));
        writeln!(writer, "\n# Class: {}", class_name)?;

        if class_def.class_data_off == 0 {
            writeln!(writer, "# (No class data)")?;
            continue;
        }

        if (class_def.class_data_off as usize) >= dexfile.len() {
             warn!("Class data_off 0x{:x} is out of bounds for class {}", class_def.class_data_off, class_name);
             writeln!(writer, "# (Error: Class data offset out of bounds)")?;
             continue;
        }

        let (class_data, _bytes_read) = parse_class_data_item(dexfile, class_def.class_data_off as usize);

        // --- Process Direct Methods ---
        method_idx_counter = 0; // Reset for direct methods
        writeln!(writer, "\n## Direct Methods:")?;
        for encoded_method in &class_data.direct_methods {
            method_idx_counter = method_idx_counter.wrapping_add(encoded_method.method_idx_diff); // Accumulate diff
            let method_id_index = method_idx_counter as usize;

            if let Some(method_id) = dex.method_ids.get(method_id_index) {
                 // Get the actual proto_id_item needed by the utils function
                 let proto_item = dex.proto_ids.get(method_id.type_idx as usize).ok_or_else(|| eyre!("Proto ID index {} out of bounds for method index {}", method_id.type_idx, method_id_index))?;
                 // Call the function from utils
                 let method_sig = get_method_signature(dexfile, proto_item, dex.string_ids, dex.type_ids)
                    .map_err(|e| eyre!("Failed to get method signature for method index {}: {}", method_id_index, e))?;

                 let should_disassemble = cli.method.is_none() || cli.method.as_deref() == Some(&method_sig);

                 if should_disassemble && encoded_method.code_off != 0 {
                    writeln!(writer, "\n### Method: {} (Index: {}, Code Offset: 0x{:x})", method_sig, method_id_index, encoded_method.code_off)?;
                    // Ensure code offset is within bounds
                    if (encoded_method.code_off as usize) < dexfile.len() {
                        let (code_item, _code_bytes_read) = parse_code_item(dexfile, encoded_method.code_off as usize);
                        let disassembled = disassemble_method(
                            &code_item,
                            dex.string_ids, // Pass the slice of string offsets
                            string_map,
                            type_map,
                        );
                        for line in disassembled {
                            writeln!(writer, "  {}", line)?;
                        }
                    } else {
                        warn!("Method code_off 0x{:x} is out of bounds for {}", encoded_method.code_off, method_sig);
                        writeln!(writer, "  (Error: Code offset out of bounds)")?;
                    }
                 } else if should_disassemble {
                     writeln!(writer, "\n### Method: {} (Index: {}, Abstract or Native)", method_sig, method_id_index)?;
                 }

            } else {
                 warn!("Invalid method_id_index {} derived for class {}", method_id_index, class_name);
                 writeln!(writer, "# (Error: Invalid method index {})", method_id_index)?;
            }
        }

        // --- Process Virtual Methods ---
        method_idx_counter = 0; // Reset for virtual methods
        writeln!(writer, "\n## Virtual Methods:")?;
         for encoded_method in &class_data.virtual_methods {
            method_idx_counter = method_idx_counter.wrapping_add(encoded_method.method_idx_diff); // Accumulate diff
            let method_id_index = method_idx_counter as usize;

            if let Some(method_id) = dex.method_ids.get(method_id_index) {
                 // Get the actual proto_id_item needed by the utils function
                 let proto_item = dex.proto_ids.get(method_id.type_idx as usize).ok_or_else(|| eyre!("Proto ID index {} out of bounds for method index {}", method_id.type_idx, method_id_index))?;
                 // Call the function from utils
                 let method_sig = get_method_signature(dexfile, proto_item, dex.string_ids, dex.type_ids)
                    .map_err(|e| eyre!("Failed to get method signature for method index {}: {}", method_id_index, e))?;

                 let should_disassemble = cli.method.is_none() || cli.method.as_deref() == Some(&method_sig);

                 if should_disassemble && encoded_method.code_off != 0 {
                    writeln!(writer, "\n### Method: {} (Index: {}, Code Offset: 0x{:x})", method_sig, method_id_index, encoded_method.code_off)?;
                     // Ensure code offset is within bounds
                    if (encoded_method.code_off as usize) < dexfile.len() {
                        let (code_item, _code_bytes_read) = parse_code_item(dexfile, encoded_method.code_off as usize);
                        let disassembled = disassemble_method(
                            &code_item,
                            dex.string_ids, // Pass the slice of string offsets
                            string_map,
                            type_map,
                        );
                        for line in disassembled {
                            writeln!(writer, "  {}", line)?;
                        }
                    } else {
                        warn!("Method code_off 0x{:x} is out of bounds for {}", encoded_method.code_off, method_sig);
                        writeln!(writer, "  (Error: Code offset out of bounds)")?;
                    }
                 } else if should_disassemble {
                     writeln!(writer, "\n### Method: {} (Index: {}, Abstract or Native)", method_sig, method_id_index)?;
                 }
            } else {
                 warn!("Invalid method_id_index {} derived for class {}", method_id_index, class_name);
                 writeln!(writer, "# (Error: Invalid method index {})", method_id_index)?;
            }
        }
    }

    writer.flush()?; 
    info!("Disassembly dump complete: {}", output_path.display());
    Ok(())
}


fn main() -> Result<()> {

    SimpleLogger::new().with_level(log::LevelFilter::Info).init().unwrap();
    color_eyre::install()?;

    info!("Dexer v0.1.0");
    let cli = Cli::parse();

    info!("Processing files: {:?}", cli.files);
    let files = mmap_files(&cli.files)?;

    // Process only the first file for now for simplicity in dumping
    // TODO: Handle multiple files more robustly if needed (e.g., append, separate outputs)
    if let Some(first_file) = files.first() {
        info!("--- Processing first file for potential disassembly ---");
        match Dex::new(first_file) {
            Ok((dex_struct, string_map, type_map)) => {
                info!("Successfully parsed DEX structure.");
                debug!("{:#?}", dex_struct); // Debug print the structure

                // Attempt to dump disassembly if requested
                if let Err(e) = dump_disassembly(&dex_struct, first_file, &string_map, &type_map, &cli) {
                    error!("Failed to dump disassembly: {}", e);
                }
            }
            Err(e) => {
                error!("Failed to parse first DEX file: {}", e);
            }
        }
    } else {
        info!("No files provided or failed to map files.");
    }

    Ok(())
}
