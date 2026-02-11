use std::path::PathBuf;
use std::process;

use clap::Parser;
use mkimage::*;

/// A Rust reimplementation of U-Boot's dumpimage tool for listing and
/// extracting components from U-Boot image files.
#[derive(Parser, Debug)]
#[command(
    name = "dumpimage",
    version,
    about = "List and extract components from U-Boot image files"
)]
struct Cli {
    /// List image header information
    #[arg(short = 'l')]
    list: bool,

    /// Parse image as this type
    #[arg(short = 'T')]
    image_type: Option<String>,

    /// Extract component at this position (starting at 0)
    #[arg(short = 'p', default_value = "0")]
    position: usize,

    /// Extract component to this file
    #[arg(short = 'o')]
    outfile: Option<PathBuf>,

    /// The input image file
    #[arg()]
    imagefile: PathBuf,
}

fn main() {
    let cli = Cli::parse();

    // -l and -o are mutually exclusive
    if cli.list && cli.outfile.is_some() {
        eprintln!("dumpimage: -l and -o are mutually exclusive");
        process::exit(1);
    }

    // Must specify one of -l or -o
    if !cli.list && cli.outfile.is_none() {
        eprintln!(
            "Usage: dumpimage [-T type] -l image\n\
             \x20      dumpimage [-T type] [-p position] -o outfile image"
        );
        process::exit(1);
    }

    if cli.list {
        match list_image(&cli.imagefile) {
            Ok(()) => {}
            Err(e) => {
                eprintln!(
                    "dumpimage: {}: {}",
                    cli.imagefile.display(),
                    e
                );
                process::exit(1);
            }
        }
    } else {
        let outfile = cli.outfile.unwrap();
        match extract_subimage(&cli.imagefile, cli.position, &outfile) {
            Ok(()) => {}
            Err(e) => {
                eprintln!(
                    "dumpimage: Can't extract subimage from {}: {}",
                    cli.imagefile.display(),
                    e
                );
                process::exit(1);
            }
        }
    }
}
