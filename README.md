No frills analysis engine for Dex files. 

> [!CAUTION]
> The project is WIP and not ready for any kind of use

### Disassembling full file into a text file.
```bash
cargo run --release -- <dex_file> --output <filename> --show-stats
```

Anti-Features:
- No bytecode rewriting, instrumentation
