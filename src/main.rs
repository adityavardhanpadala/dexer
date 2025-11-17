mod dexcore;

use pico_args::Arguments;
use std::error::Error;

type Result<T> = std::result::Result<T, Box<dyn Error>>;
#[allow(unused_imports)]
use log::{debug, error, info, warn};
use memmap::{Mmap, MmapOptions};
use simple_logger::SimpleLogger;
use std::{
    collections::HashMap,
    fs::File,
    io::{BufReader, BufWriter, Write},
    path::PathBuf,
    time::{Duration, Instant},
    usize,
};

use crate::dexcore::Dex;
use crate::dexcore::disassembler::disassemble_method;
use crate::dexcore::utils::{get_method_signature, parse_class_data_item, parse_code_item};

/// Command line arguments
#[derive(Debug)]
struct Cli {
    /// Path to the dex file(s) to process
    files: Vec<PathBuf>,
    /// Output file for disassembly
    output: Option<PathBuf>,
    /// Specific method name to disassemble (e.g., "Lcom/example/MyClass;->myMethod(II)V")
    method: Option<String>,
    /// Show instruction throughput metrics
    show_stats: bool,
}

fn parse_args() -> Result<Cli> {
    let mut args = Arguments::from_env();

    // Check for help flag
    if args.contains(["-h", "--help"]) {
        print_help();
        std::process::exit(0);
    }

    // Parse optional flags
    let output = args.opt_value_from_str("--output")?;
    let method = args.opt_value_from_str("--method")?;
    let show_stats = args.contains("--show-stats");

    // Get remaining arguments as files
    let files = args.finish();

    if files.is_empty() {
        eprintln!("Error: At least one DEX file must be provided");
        print_help();
        std::process::exit(1);
    }

    let files: Vec<PathBuf> = files.into_iter().map(PathBuf::from).collect();

    Ok(Cli {
        files,
        output,
        method,
        show_stats,
    })
}

fn print_help() {
    println!("Dexer v0.1.0");
    println!("A DEX file disassembler and analyzer");
    println!();
    println!("USAGE:");
    println!("    dexer [OPTIONS] <FILES>...");
    println!();
    println!("ARGS:");
    println!("    <FILES>    Path to the dex file(s) to process");
    println!();
    println!("OPTIONS:");
    println!("    -h, --help                 Print help information");
    println!("        --output <FILE>        Output file for disassembly");
    println!("        --method <METHOD>       Specific method name to disassemble");
    println!("                               (e.g., \"Lcom/example/MyClass;->myMethod(II)V\")");
    println!("        --show-stats            Show instruction throughput metrics");
}

fn mmap_files(fpaths: &[PathBuf]) -> Result<Vec<Mmap>> {
    let mut result = Vec::new();
    for fpath in fpaths {
        let f = File::open(fpath)
            .map_err(|e| format!("error opening file: {}: {}", fpath.display(), e))?;
        let dexfile = unsafe { MmapOptions::new().map(&f)? };
        result.push(dexfile);
    }
    Ok(result)
}

/// Dumps the disassembly of methods to a file or stdout based on CLI args.
fn dump_disassembly(dex: &Dex, dexfile: &Mmap, cli: &Cli) -> Result<()> {
    info!("Starting disassembly dump...");

    let mut method_idx_counter: u32; // Track method index diff accumulation
    let now = Instant::now();
    let mut bytes: usize = 0;
    for (i, class_def) in dex.class_defs.iter().enumerate() {
        let class_name = dex
            .type_map
            .get(class_def.class_idx as usize)
            .cloned()
            .unwrap_or_else(|| format!("UnknownClass{}", i));

        if class_def.class_data_off == 0 {
            continue;
        }

        if (class_def.class_data_off as usize) >= dexfile.len() {
            // Error: Class data offset out of bounds"
            debug!("Class data offset out of file bounds");
            continue;
        }

        let (class_data, _bytes_read) =
            parse_class_data_item(dexfile, class_def.class_data_off as usize);

        // --- Process Direct Methods ---
        method_idx_counter = 0; // Reset for direct methods
        for encoded_method in &class_data.direct_methods {
            method_idx_counter = method_idx_counter.wrapping_add(encoded_method.method_idx_diff); // Accumulate diff
            let method_id_index = method_idx_counter as usize;

            if let Some(method_id) = dex.method_ids.get(method_id_index) {
                // Get the actual proto_id_item needed by the utils function
                let proto_item =
                    dex.proto_ids
                        .get(method_id.proto_idx as usize)
                        .ok_or_else(|| {
                            format!(
                                "Proto ID index {} out of bounds for method index {}",
                                method_id.proto_idx, method_id_index
                            )
                        })?;
                // Call the function from utils
                let method_sig =
                    get_method_signature(dexfile, proto_item, dex.string_ids, dex.type_ids)
                        .map_err(|e| {
                            format!(
                                "Failed to get method signature for method index {}: {}",
                                method_id_index, e
                            )
                        })?;

                // Get method name from string_ids
                let method_name_offset = dex
                    .string_ids
                    .get(method_id.name_idx as usize)
                    .copied()
                    .unwrap_or(0);
                let method_name = dex
                    .string_map
                    .get(&method_name_offset)
                    .cloned()
                    .unwrap_or_else(|| "<unknown>".to_string());

                // Combine method name with signature: methodName(Signature)
                let method_full_name = format!("{}{}", method_name, method_sig);

                let should_disassemble =
                    cli.method.is_none() || cli.method.as_deref() == Some(&method_sig);

                if should_disassemble && encoded_method.code_off != 0 {
                    // Ensure code offset is within bounds
                    if (encoded_method.code_off as usize) < dexfile.len() {
                        let (code_item, _code_bytes_read) =
                            parse_code_item(dexfile, encoded_method.code_off as usize);
                        let instructions = disassemble_method(
                            &code_item,
                            dex.string_ids, // Pass the slice of string offsets
                            &dex.string_map,
                            &dex.type_map,
                            Some(&class_name),
                            Some(&method_full_name),
                        )?;

                        // Calculate instruction bytes (each instruction is 2 bytes minimum in Dalvik)
                        let instruction_bytes = code_item.insns.len() * 2;
                        bytes += instruction_bytes;
                    } else {
                        warn!(
                            "Method code_off 0x{:x} is out of bounds for {}",
                            encoded_method.code_off, method_full_name
                        );
                    }
                } else if should_disassemble {
                }
            } else {
                warn!(
                    "Invalid method_id_index {} derived for class {}",
                    method_id_index, class_name
                );
            }
        }

        // --- Process Virtual Methods ---
        method_idx_counter = 0; // Reset for virtual methods
        for encoded_method in &class_data.virtual_methods {
            method_idx_counter = method_idx_counter.wrapping_add(encoded_method.method_idx_diff); // Accumulate diff
            let method_id_index = method_idx_counter as usize;

            if let Some(method_id) = dex.method_ids.get(method_id_index) {
                // Get the actual proto_id_item needed by the utils function
                let proto_item =
                    dex.proto_ids
                        .get(method_id.proto_idx as usize)
                        .ok_or_else(|| {
                            format!(
                                "Proto ID index {} out of bounds for method index {}",
                                method_id.proto_idx, method_id_index
                            )
                        })?;
                // Call the function from utils
                let method_sig =
                    get_method_signature(dexfile, proto_item, dex.string_ids, dex.type_ids)
                        .map_err(|e| {
                            format!(
                                "Failed to get method signature for method index {}: {}",
                                method_id_index, e
                            )
                        })?;

                // Get method name from string_ids
                let method_name_offset = dex
                    .string_ids
                    .get(method_id.name_idx as usize)
                    .copied()
                    .unwrap_or(0);
                let method_name = dex
                    .string_map
                    .get(&method_name_offset)
                    .cloned()
                    .unwrap_or_else(|| "<unknown>".to_string());

                // Combine method name with signature: methodName(Signature)
                let method_full_name = format!("{}{}", method_name, method_sig);

                let should_disassemble =
                    cli.method.is_none() || cli.method.as_deref() == Some(&method_sig);

                if should_disassemble && encoded_method.code_off != 0 {
                    // Ensure code offset is within bounds
                    if (encoded_method.code_off as usize) < dexfile.len() {
                        let (code_item, _code_bytes_read) =
                            parse_code_item(dexfile, encoded_method.code_off as usize);
                        let instructions = disassemble_method(
                            &code_item,
                            dex.string_ids, // Pass the slice of string offsets
                            &dex.string_map,
                            &dex.type_map,
                            Some(&class_name),
                            Some(&method_full_name),
                        )?;

                        // Calculate instruction bytes (each instruction is 2 bytes minimum in Dalvik)
                        let instruction_bytes = code_item.insns.len() * 2;
                        bytes += instruction_bytes;
                    } else {
                        warn!(
                            "Method code_off 0x{:x} is out of bounds for {}",
                            encoded_method.code_off, method_full_name
                        );
                    }
                } else if should_disassemble {
                }
            } else {
                warn!(
                    "Invalid method_id_index {} derived for class {}",
                    method_id_index, class_name
                );
            }
        }
    }
    let elapsed = now.elapsed();

    if cli.show_stats {
        let elapsed_ms = elapsed.as_millis();

        // Avoid division by zero
        if elapsed_ms > 0 {
            let bytes_per_ms = bytes as f64 / elapsed_ms as f64;
            let bytes_per_sec = bytes_per_ms * 1000.0;
            let mb_per_sec = bytes_per_sec / (1024.0 * 1024.0);
            info!("Throughput: {:.2} bytes/second", bytes_per_sec);
            info!("Throughput: {:.2} MB/second", mb_per_sec);
        }
    }
    info!("Disassembly complete");
    Ok(())
}

fn main() -> Result<()> {
    SimpleLogger::new()
        .with_level(log::LevelFilter::Info)
        .init()
        .unwrap();

    info!("Dexer v0.1.0");
    let cli = parse_args()?;

    info!("Processing files: {:?}", cli.files);
    let files = mmap_files(&cli.files)?;

    // Process only the first file for now for simplicity in dumping
    // TODO: Handle multiple files more robustly if needed (e.g., append, separate outputs)
    if let Some(first_file) = files.first() {
        info!("--- Processing first file for potential disassembly ---");
        match Dex::new(first_file) {
            Ok(dex_struct) => {
                info!("Successfully parsed DEX structure.");

                // Attempt to dump disassembly if requested with timing measurements
                match dump_disassembly(&dex_struct, first_file, &cli) {
                    Ok(_) => {}
                    Err(e) => {
                        error!("Failed to dump disassembly: {}", e);
                    }
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
