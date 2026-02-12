use std::path::PathBuf;
use std::process;

use clap::Parser;
use mkimage::*;

/// A Rust reimplementation of U-Boot's mkimage tool for creating and
/// inspecting U-Boot image files (legacy uImage and signed FIT).
#[derive(Parser, Debug)]
#[command(
    name = "mkimage",
    version,
    about = "Create and inspect U-Boot image files (legacy + signed FIT)"
)]
struct Cli {
    /// Set architecture (e.g. arm, arm64, x86, ppc, mips, riscv, …)
    #[arg(short = 'A', long = "architecture", default_value = "ppc")]
    arch: String,

    /// Set operating system (e.g. linux, u-boot, opensbi, …)
    #[arg(short = 'O', long = "os", default_value = "linux")]
    os: String,

    /// Set image type (e.g. kernel, ramdisk, firmware, multi, script, …)
    /// Use "list" to see all supported types.
    #[arg(short = 'T', long = "type", default_value = "kernel")]
    image_type: String,

    /// Set compression type (none, gzip, bzip2, lzma, lzo, lz4, zstd)
    #[arg(short = 'C', long = "compression", default_value = "gzip")]
    compression: String,

    /// Set load address (hex, e.g. 80008000)
    #[arg(short = 'a', long = "load-address", default_value = "0")]
    load_addr: String,

    /// Set entry point (hex, e.g. 80008000; defaults to load address)
    #[arg(short = 'e', long = "entry-point")]
    entry_point: Option<String>,

    /// Set image name
    #[arg(short = 'n', long = "config", default_value = "")]
    name: String,

    /// Use image data from file (for legacy: payload; use colon for multi-file)
    #[arg(short = 'd', long = "image")]
    datafile: Option<String>,

    /// Input .its file for FIT image (or "auto" / "auto-conf")
    #[arg(short = 'f', long = "fit")]
    fit_source: Option<String>,

    /// Re-sign existing FIT image
    #[arg(short = 'F', long = "update")]
    fit_resign: bool,

    /// Directory containing signing keys (.key files)
    #[arg(short = 'k', long = "key-dir")]
    keydir: Option<String>,

    /// Explicit signing key file (in lieu of -k)
    #[arg(short = 'G', long = "key-file")]
    keyfile: Option<String>,

    /// Mark keys used as 'required' in dtb
    #[arg(short = 'r', long = "key-required")]
    require_keys: bool,

    /// Add comment in signature node
    #[arg(short = 'c', long = "comment")]
    comment: Option<String>,

    /// Algorithm to use for signing (e.g. sha256,rsa2048)
    #[arg(short = 'o', long = "algo")]
    algo_name: Option<String>,

    /// Set DTC options
    #[arg(short = 'D', long = "dtcopts", default_value = "-I dts -O dtb -p 500")]
    dtc_opts: String,

    /// Override signer-version string (default: "2026.01")
    #[arg(long = "signer-version", default_value = "2026.01")]
    signer_version: String,

    /// List image header information
    #[arg(short = 'l', long = "list")]
    list: bool,

    /// Set XIP (execute in place)
    #[arg(short = 'x', long = "xip")]
    xip: bool,

    /// Create an image with no data
    #[arg(short = 's', long = "no-copy")]
    no_data: bool,

    /// Verbose output
    #[arg(short = 'v', long = "verbose", action = clap::ArgAction::Count)]
    verbose: u8,

    /// Quiet mode
    #[arg(short = 'q', long = "quiet")]
    quiet: bool,

    /// The output (or input for -l) image file
    #[arg()]
    imagefile: Option<PathBuf>,
}

fn parse_hex_u32(s: &str) -> Result<u32> {
    let s = s.trim_start_matches("0x").trim_start_matches("0X");
    u32::from_str_radix(s, 16).map_err(|_| MkImageError::Other(format!("invalid hex value: {}", s)))
}

fn show_valid<F: Fn() -> &'static [(u8, &'static str, &'static str)]>(category: &str, table_fn: F) {
    eprintln!("\nInvalid {category}, supported are:");
    let mut entries: Vec<_> = table_fn().to_vec();
    entries.sort_by(|a, b| a.1.cmp(&b.1));
    for (_, short, long) in &entries {
        eprintln!("\t{:<15}  {}", short, long);
    }
    eprintln!();
}

fn main() {
    let cli = Cli::parse();

    // Handle "-T list"
    if cli.image_type == "list" {
        let mut entries: Vec<_> = ImageType::table().to_vec();
        entries.sort_by(|a, b| a.1.cmp(&b.1));
        println!("Supported image types:");
        for (_, short, long) in &entries {
            println!("\t{:<15}  {}", short, long);
        }
        process::exit(0);
    }

    let imagefile = match &cli.imagefile {
        Some(f) => f.clone(),
        None => {
            eprintln!("Error: Missing output filename");
            process::exit(1);
        }
    };

    // ---- List mode ----
    if cli.list {
        match read_image(&imagefile) {
            Ok(info) => {
                if !cli.quiet {
                    print_image_info(&info);
                }
                process::exit(0);
            }
            Err(e) => {
                eprintln!("mkimage: {}: {}", imagefile.display(), e);
                process::exit(1);
            }
        }
    }

    // ---- FIT mode (-f / -F) ----
    if cli.fit_source.is_some() || cli.fit_resign {
        let fit_params = fit::FitParams {
            datafile: cli.fit_source.clone(),
            imagefile: imagefile.to_string_lossy().into_owned(),
            keydir: cli.keydir.clone(),
            keyfile: cli.keyfile.clone(),
            dtc_opts: cli.dtc_opts.clone(),
            require_keys: cli.require_keys,
            comment: cli.comment.clone(),
            algo_name: cli.algo_name.clone(),
            re_sign: cli.fit_resign && cli.fit_source.is_none(),
            signer_version: cli.signer_version.clone(),
        };

        match fit::fit_handle_file(&fit_params) {
            Ok(()) => {
                if !cli.quiet {
                    eprintln!("FIT image '{}' created successfully.", imagefile.display());
                }
                process::exit(0);
            }
            Err(e) => {
                eprintln!("mkimage: {}", e);
                process::exit(1);
            }
        }
    }

    // ---- Legacy image mode ----
    let os = match Os::from_name(&cli.os) {
        Some(v) => v,
        None => {
            show_valid("OS", Os::table);
            eprintln!("Error: Invalid operating system '{}'", cli.os);
            process::exit(1);
        }
    };

    let arch = match Arch::from_name_ext(&cli.arch) {
        Some(v) => v,
        None => {
            show_valid("CPU architecture", Arch::table);
            eprintln!("Error: Invalid architecture '{}'", cli.arch);
            process::exit(1);
        }
    };

    let image_type = match ImageType::from_name(&cli.image_type) {
        Some(v) => v,
        None => {
            show_valid("image type", ImageType::table);
            eprintln!("Error: Invalid image type '{}'", cli.image_type);
            process::exit(1);
        }
    };

    let compression = match Compression::from_name(&cli.compression) {
        Some(v) => v,
        None => {
            show_valid("compression type", Compression::table);
            eprintln!("Error: Invalid compression type '{}'", cli.compression);
            process::exit(1);
        }
    };

    let load_addr = match parse_hex_u32(&cli.load_addr) {
        Ok(v) => v,
        Err(_) => {
            eprintln!("mkimage: invalid load address '{}'", cli.load_addr);
            process::exit(1);
        }
    };

    let (entry_point, ep_set) = match cli.entry_point.as_deref() {
        Some(s) => match parse_hex_u32(s) {
            Ok(v) => (v, true),
            Err(_) => {
                eprintln!("mkimage: invalid entry point '{s}'");
                process::exit(1);
            }
        },
        None => (0, false),
    };

    let name = &cli.name;

    let params = ImageParams {
        os,
        arch,
        image_type,
        compression,
        load_addr,
        entry_point,
        name: name.to_string(),
        xip: cli.xip,
        ep_set,
    };

    // No data mode
    if cli.no_data {
        match create_empty_image(&params, &imagefile) {
            Ok(()) => {
                if cli.verbose > 0 {
                    if let Ok(info) = read_image(&imagefile) {
                        print_image_info(&info);
                    }
                }
                process::exit(0);
            }
            Err(e) => {
                eprintln!("mkimage: {}", e);
                process::exit(1);
            }
        }
    }

    let datafile = match cli.datafile.as_deref() {
        Some(d) => d,
        None => {
            eprintln!("Error: Option -d with image data file was not specified");
            process::exit(1);
        }
    };

    // Multi-file image: data files separated by ':'
    let result = if image_type == ImageType::Multi || image_type == ImageType::Script {
        let files: Vec<&str> = datafile.split(':').collect();
        let file_paths: Vec<PathBuf> = files.iter().map(PathBuf::from).collect();
        create_multi_image(&params, &file_paths, &imagefile)
    } else {
        create_image(&params, datafile, &imagefile)
    };

    match result {
        Ok(()) => {
            if !cli.quiet {
                match read_image(&imagefile) {
                    Ok(info) => print_image_info(&info),
                    Err(e) => {
                        eprintln!("mkimage: warning: could not re-read image: {}", e);
                    }
                }
            }

            match verify_image(&imagefile) {
                Ok(_) => {
                    if cli.verbose > 0 {
                        eprintln!("Image verified successfully.");
                    }
                }
                Err(e) => {
                    eprintln!("mkimage: verification failed: {}", e);
                    process::exit(1);
                }
            }
        }
        Err(e) => {
            eprintln!("mkimage: {}", e);
            process::exit(1);
        }
    }
}
