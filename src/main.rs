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

/// Throughput metrics for instruction processing
#[derive(Debug, Default)]
struct Stats {
    /// Total number of bytecode instructions processed
    total_instructions: u64,
    /// Total number of methods processed
    total_methods: u64,
    /// Total time spent processing instructions
    processing_duration: Duration,
    /// Total bytes of instruction data processed
    total_instruction_bytes: u64,
}

impl Stats {
    fn new() -> Self {
        Self::default()
    }

    fn add_method(&mut self, instruction_count: u64, instruction_bytes: u64) {
        self.total_instructions += instruction_count;
        self.total_methods += 1;
        self.total_instruction_bytes += instruction_bytes;
    }

    fn set_duration(&mut self, duration: Duration) {
        self.processing_duration = duration;
    }

    fn calculate_throughput(&self) -> (f64, f64) {
        let seconds = self.processing_duration.as_secs_f64();
        if seconds > 0.0 {
            let instructions_per_second = self.total_instructions as f64 / seconds;
            let megabytes_per_second =
                (self.total_instruction_bytes as f64 / 1_000_000.0) / seconds;
            (instructions_per_second, megabytes_per_second)
        } else {
            (0.0, 0.0)
        }
    }

    fn report(&self) {
        info!("=== Instruction Throughput Metrics ===");
        info!("Total instructions processed: {}", self.total_instructions);
        info!("Total methods processed: {}", self.total_methods);
        info!("Total instruction bytes: {}", self.total_instruction_bytes);
        info!(
            "Processing time: {:.3}s",
            self.processing_duration.as_secs_f64()
        );

        let (ips, mbps) = self.calculate_throughput();
        info!("Instructions per second: {:.2}", ips);
        info!("Megabytes per second: {:.2} MB/s", mbps);

        if self.total_methods > 0 {
            let avg_instructions_per_method =
                self.total_instructions as f64 / self.total_methods as f64;
            info!(
                "Average instructions per method: {:.1}",
                avg_instructions_per_method
            );
        }
    }
}

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
fn dump_disassembly(dex: &Dex, dexfile: &Mmap, cli: &Cli) -> Result<Stats> {
    let output_path = match &cli.output {
        Some(path) => path,
        None => return Ok(Stats::new()),
    };

    info!(
        "Opening output file for disassembly: {}",
        output_path.display()
    );
    let output_file = File::create(output_path).map_err(|e| {
        format!(
            "Failed to create output file {}: {}",
            output_path.display(),
            e
        )
    })?;
    let mut writer = BufWriter::new(output_file);

    info!("Starting disassembly dump...");

    let mut metrics = Stats::new();
    let mut method_idx_counter: u32 = 0; // Track method index diff accumulation

    for (i, class_def) in dex.class_defs.iter().enumerate() {
        let class_name = dex
            .type_map
            .get(class_def.class_idx as usize)
            .cloned()
            .unwrap_or_else(|| format!("UnknownClass{}", i));
        writeln!(writer, "\n# Class: {}", class_name)?;

        if class_def.class_data_off == 0 {
            continue;
        }

        if (class_def.class_data_off as usize) >= dexfile.len() {
            // Error: Class data offset out of bounds"
            continue;
        }

        let (class_data, _bytes_read) =
            parse_class_data_item(dexfile, class_def.class_data_off as usize);

        // --- Process Direct Methods ---
        method_idx_counter = 0; // Reset for direct methods
        writeln!(writer, "\n## Direct Methods:")?;
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
                    writeln!(
                        writer,
                        "\n### Method: {} (Index: {}, Code Offset: 0x{:x})",
                        method_full_name, method_id_index, encoded_method.code_off
                    )?;
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
                        metrics.add_method(instructions.len() as u64, instruction_bytes as u64);
                    } else {
                        warn!(
                            "Method code_off 0x{:x} is out of bounds for {}",
                            encoded_method.code_off, method_full_name
                        );
                        writeln!(writer, "  (Error: Code offset out of bounds)")?;
                    }
                } else if should_disassemble {
                    writeln!(
                        writer,
                        "\n### Method: {} (Index: {}, Abstract or Native)",
                        method_full_name, method_id_index
                    )?;
                }
            } else {
                warn!(
                    "Invalid method_id_index {} derived for class {}",
                    method_id_index, class_name
                );
                writeln!(
                    writer,
                    "# (Error: Invalid method index {})",
                    method_id_index
                )?;
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
                    writeln!(
                        writer,
                        "\n### Method: {} (Index: {}, Code Offset: 0x{:x})",
                        method_full_name, method_id_index, encoded_method.code_off
                    )?;
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
                        metrics.add_method(instructions.len() as u64, instruction_bytes as u64);
                    } else {
                        warn!(
                            "Method code_off 0x{:x} is out of bounds for {}",
                            encoded_method.code_off, method_full_name
                        );
                        writeln!(writer, "  (Error: Code offset out of bounds)")?;
                    }
                } else if should_disassemble {
                    writeln!(
                        writer,
                        "\n### Method: {} (Index: {}, Abstract or Native)",
                        method_full_name, method_id_index
                    )?;
                }
            } else {
                warn!(
                    "Invalid method_id_index {} derived for class {}",
                    method_id_index, class_name
                );
                writeln!(
                    writer,
                    "# (Error: Invalid method index {})",
                    method_id_index
                )?;
            }
        }
    }

    writer.flush()?;
    info!("Disassembly dump complete: {}", output_path.display());
    Ok(metrics)
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
                let start_time = Instant::now();
                match dump_disassembly(&dex_struct, first_file, &cli) {
                    Ok(mut metrics) => {
                        let elapsed = start_time.elapsed();
                        metrics.set_duration(elapsed);

                        if cli.show_stats {
                            metrics.report();
                        }
                    }
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
