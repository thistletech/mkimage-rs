use mkimage::fit::{fit_handle_file_with_signer, FitParams, FitSigner};
use mkimage::Result;

/// Dummy signer that returns fixed bytes — for demonstration only.
struct DummySigner;

impl FitSigner for DummySigner {
    fn sign(&self, algo: &str, data: &[u8], keyname: &str) -> Result<Vec<u8>> {
        eprintln!("[DummySigner] algo={algo} data_len={} keyname={keyname}", data.len());
        // Return 256 bytes of 0x11 (RSA-2048 signature size)
        Ok(vec![0x11; 256])
    }
}

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 2 {
        eprintln!("Usage: custom_signer <input.itb>");
        eprintln!("Re-signs an existing FIT image with a dummy signer.");
        std::process::exit(1);
    }

    let signer = DummySigner;
    let params = FitParams {
        datafile: None,
        imagefile: args[1].clone(),
        keydir: None,
        keyfile: None,
        dtc_opts: String::new(),
        require_keys: false,
        comment: None,
        algo_name: None,
        re_sign: true,
        signer_version: "demo".to_string(),
    };
    fit_handle_file_with_signer(&params, &signer)?;
    eprintln!("Done — signature nodes now contain 0x11 bytes");
    Ok(())
}
