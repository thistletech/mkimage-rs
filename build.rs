use std::{fs::File, io::Write, path::PathBuf, str::FromStr};

const DTC_FILES: &[&str] = &[
    "vendor/dtc/src/checks.c",
    "vendor/dtc/src/data.c",
    "vendor/dtc/src/dtc.c",
    "vendor/dtc/src/flattree.c",
    "vendor/dtc/src/fstree.c",
    "vendor/dtc/src/livetree.c",
    "vendor/dtc/src/srcpos.c",
    "vendor/dtc/src/treesource.c",
    "vendor/dtc/src/util.c",
    "vendor/dtc/src/dtc-lexer.lex.c",
    "vendor/dtc/src/dtc-parser.tab.c",
];

fn main() {
    let out_dir = std::env::var("OUT_DIR").unwrap();
    let version_path = PathBuf::from_str(&out_dir).unwrap().join("version_gen.h");
    let mut version_file = File::create(&version_path).unwrap();
    writeln!(
        version_file,
        "#define DTC_VERSION \"1.7.6 (mkimage-rs)\""
    )
    .unwrap();
    drop(version_file);

    let mut build = cc::Build::new();

    for c_src in DTC_FILES {
        println!("cargo:rerun-if-changed={c_src}");
    }

    build
        .include("vendor/dtc/include/libfdt")
        .include("vendor/dtc/include")
        .include(&out_dir)
        .files(DTC_FILES)
        .warnings(false)
        .define("NO_YAML", None)
        // Rename main() so we can call it from Rust without conflicting
        .define("main(argc,argv)", Some("dtc_main(argc,argv)"));

    build.compile("dtc");
}
