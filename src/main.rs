mod dexcore;

use pico_args::Arguments;
use std::error::Error;
use std::fs;

type Result<T> = std::result::Result<T, Box<dyn Error>>;
#[allow(unused_imports)]
use log::{debug, error, info, warn};
use memmap::{Mmap, MmapOptions};
use simple_logger::SimpleLogger;
use std::{collections::HashMap, fs::File, path::PathBuf, time::Instant, usize};

use crate::dexcore::disassembler::disassemble_class;
use crate::dexcore::{Dex, disassembler::Instruction};
use rayon::prelude::*;

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

    let now = Instant::now();

    // Process classes in parallel with batches of 100
    let results: Vec<_> = dex
        .class_defs
        .par_chunks(100)
        .flat_map(|batch| {
            batch
                .iter()
                .filter_map(|class_def| {
                    let class_name = dex.type_map.get(class_def.class_idx as usize)?;

                    match disassemble_class(dex, dexfile, *class_def, cli) {
                        Ok((dism, num_bytes)) => {
                            if !dism.is_empty() {
                                Some((class_name.clone(), dism, num_bytes))
                            } else {
                                None
                            }
                        }
                        Err(e) => {
                            warn!("Failed to disassemble class {}: {:?}", class_name, e);
                            None
                        }
                    }
                })
                .collect::<Vec<_>>()
        })
        .collect();

    // Collect results into class_dism HashMap
    let mut class_dism: HashMap<String, HashMap<String, Vec<Instruction>>> = HashMap::new();
    let mut bytes: usize = 0;

    for (class_name, dism, num_bytes) in results {
        class_dism.insert(class_name, dism);
        bytes += num_bytes;
    }

    let elapsed = now.elapsed();

    if cli.show_stats {
        let elapsed_ms = elapsed.as_millis();

        if elapsed_ms > 0 {
            let bytes_per_ms = bytes as f64 / elapsed_ms as f64;
            let bytes_per_sec = bytes_per_ms * 1000.0;
            let mb_per_sec = bytes_per_sec / (1024.0 * 1024.0);
            info!("Throughput: {:.2} bytes/second", bytes_per_sec);
            info!("Throughput: {:.2} MB/second", mb_per_sec);
        }
    }

    // Write the disassembly to cli.output without debug fmt
    let mut output = String::new();
    for (class_name, methods) in &class_dism {
        output.push_str(&format!("Class: {}\n", class_name));
        for (method_name, instructions) in methods {
            output.push_str(&format!("  Method: {}\n", method_name));
            for instr in instructions {
                output.push_str(&format!("    {:?}\n", instr));
            }
        }
        output.push('\n');
    }

    let output_path = cli
        .output
        .as_ref()
        .map(|p| p.as_path())
        .unwrap_or_else(|| std::path::Path::new("disassembly.txt"));
    fs::write(output_path, output)?;

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
