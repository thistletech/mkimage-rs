//! FIT (Flattened Image Tree) image support with signing.
//!
//! Implements the `mkimage -f <its> -k <keydir> -r <output>` flow:
//! 1. Compile `.its` → `.itb` via `dtc`
//! 2. Compute hashes for image `hash-*` nodes
//! 3. Compute signatures for image and config `signature-*` nodes
//!
//! All DTB modification is done **in-place** on the raw bytes produced by
//! `dtc`, preserving the exact binary layout for bit-for-bit compatibility
//! with the original U-Boot `mkimage`.
//!
//! All crypto is pure Rust — no OpenSSL dependency.

use std::ffi::CString;
use std::fs;
use std::os::raw::{c_char, c_int};
use std::path::PathBuf;

use signature::SignatureEncoding;

use crate::dtb;
use crate::{crc32, get_source_date, MkImageError, Result};

extern "C" {
    fn dtc_main(argc: c_int, argv: *const *const c_char) -> c_int;
}

// ---------------------------------------------------------------------------
// FIT property / node name constants (matching U-Boot's image.h)
// ---------------------------------------------------------------------------

pub const FIT_IMAGES_PATH: &str = "/images";
pub const FIT_CONFS_PATH: &str = "/configurations";

pub const FIT_HASH_NODENAME: &str = "hash";
pub const FIT_SIG_NODENAME: &str = "signature";

pub const FIT_ALGO_PROP: &str = "algo";
pub const FIT_VALUE_PROP: &str = "value";
pub const FIT_KEY_HINT: &str = "key-name-hint";
pub const FIT_DATA_PROP: &str = "data";
pub const FIT_TIMESTAMP_PROP: &str = "timestamp";

/// Default image types to sign when `sign-images` is absent (matches U-Boot).
const DEFAULT_SIGN_IMAGES: &[&str] = &["kernel", "fdt", "script"];
/// Properties to exclude from FDT regions during config signing.
const EXC_PROPS: &[&str] = &["data", "data-size", "data-position", "data-offset"];

/// Signer name written into signature nodes (matches original mkimage).
const SIGNER_NAME: &str = "mkimage";

// ---------------------------------------------------------------------------
// Embedded DTC (device tree compiler)
// ---------------------------------------------------------------------------

/// Call the embedded dtc (compiled from C sources) via FFI.
///
/// `dtc_opts` is a string like "-I dts -O dtb -p 500" which gets split on
/// whitespace and forwarded as argv to `dtc_main`.
fn run_dtc(dtc_opts: &str, output: &str, input: &str) -> Result<()> {
    // Build argv: ["dtc", ...opts..., "-o", output, input]
    let mut args: Vec<String> = vec!["dtc".into()];
    args.extend(dtc_opts.split_whitespace().map(String::from));
    args.push("-o".into());
    args.push(output.into());
    args.push(input.into());

    eprintln!("Running (embedded): dtc {}", args[1..].join(" "));

    let c_args: Vec<CString> = args
        .iter()
        .map(|a| CString::new(a.as_str()).unwrap())
        .collect();
    let c_ptrs: Vec<*const c_char> = c_args.iter().map(|a| a.as_ptr()).collect();

    let ret = unsafe { dtc_main(c_ptrs.len() as c_int, c_ptrs.as_ptr()) };

    if ret != 0 {
        return Err(MkImageError::Other(format!(
            "dtc failed with exit code {ret}"
        )));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Hashing
// ---------------------------------------------------------------------------

/// Compute a hash of `data` using the named algorithm.
pub fn calculate_hash(algo: &str, data: &[u8]) -> Result<Vec<u8>> {
    match algo {
        "crc32" => Ok(crc32(data).to_be_bytes().to_vec()),
        "sha1" => {
            use sha1::Digest;
            Ok(sha1::Sha1::digest(data).to_vec())
        }
        "sha256" => {
            use sha2::Digest;
            Ok(sha2::Sha256::digest(data).to_vec())
        }
        "sha384" => {
            use sha2::Digest;
            Ok(sha2::Sha384::digest(data).to_vec())
        }
        "sha512" => {
            use sha2::Digest;
            Ok(sha2::Sha512::digest(data).to_vec())
        }
        _ => Err(MkImageError::Other(format!(
            "unsupported hash algorithm: {algo}"
        ))),
    }
}

// ---------------------------------------------------------------------------
// Signing — RSA (PKCS#1 v1.5) and ECDSA
// ---------------------------------------------------------------------------

fn parse_algo(algo: &str) -> Result<(&str, &str)> {
    algo.split_once(',').ok_or_else(|| {
        MkImageError::Other(format!(
            "invalid algo format (expected 'hash,crypto'): {algo}"
        ))
    })
}

fn load_private_key_pem(
    keydir: Option<&str>,
    keyname: &str,
    keyfile: Option<&str>,
) -> Result<Vec<u8>> {
    let path = if let Some(kf) = keyfile {
        PathBuf::from(kf)
    } else if let Some(kd) = keydir {
        PathBuf::from(kd).join(format!("{keyname}.key"))
    } else {
        return Err(MkImageError::Other("no keydir or keyfile specified".into()));
    };
    fs::read(&path)
        .map_err(|e| MkImageError::Other(format!("cannot read key file '{}': {e}", path.display())))
}

/// Sign concatenated region bytes.
pub fn sign_regions(
    algo: &str,
    regions: &[&[u8]],
    keydir: Option<&str>,
    keyname: &str,
    keyfile: Option<&str>,
) -> Result<Vec<u8>> {
    let (hash_algo, crypto_algo) = parse_algo(algo)?;
    let pem_data = load_private_key_pem(keydir, keyname, keyfile)?;
    let pem_str = std::str::from_utf8(&pem_data)
        .map_err(|_| MkImageError::Other("key file is not valid UTF-8".into()))?;

    let mut combined = Vec::new();
    for r in regions {
        combined.extend_from_slice(r);
    }

    if crypto_algo.starts_with("rsa") {
        sign_rsa(hash_algo, &combined, pem_str)
    } else if crypto_algo.starts_with("ecdsa") || crypto_algo == "secp521r1" {
        sign_ecdsa(hash_algo, crypto_algo, &combined, pem_str)
    } else {
        Err(MkImageError::Other(format!(
            "unsupported crypto algorithm: {crypto_algo}"
        )))
    }
}

fn sign_rsa(hash_algo: &str, data: &[u8], pem_str: &str) -> Result<Vec<u8>> {
    use rsa::pkcs1v15::SigningKey;
    use rsa::RsaPrivateKey;
    use signature::Signer;

    let private_key: RsaPrivateKey = if pem_str.contains("BEGIN PRIVATE KEY") {
        use pkcs8::DecodePrivateKey;
        RsaPrivateKey::from_pkcs8_pem(pem_str)
            .map_err(|e| MkImageError::Other(format!("failed to parse PKCS#8 RSA key: {e}")))?
    } else {
        use pkcs1::DecodeRsaPrivateKey;
        RsaPrivateKey::from_pkcs1_pem(pem_str)
            .map_err(|e| MkImageError::Other(format!("failed to parse PKCS#1 RSA key: {e}")))?
    };

    match hash_algo {
        "sha1" => {
            let k = SigningKey::<sha1::Sha1>::new(private_key);
            Ok(k.sign(data).to_vec())
        }
        "sha256" => {
            let k = SigningKey::<sha2::Sha256>::new(private_key);
            Ok(k.sign(data).to_vec())
        }
        "sha384" => {
            let k = SigningKey::<sha2::Sha384>::new(private_key);
            Ok(k.sign(data).to_vec())
        }
        "sha512" => {
            let k = SigningKey::<sha2::Sha512>::new(private_key);
            Ok(k.sign(data).to_vec())
        }
        _ => Err(MkImageError::Other(format!(
            "unsupported hash for RSA: {hash_algo}"
        ))),
    }
}

fn sign_ecdsa(hash_algo: &str, crypto_algo: &str, data: &[u8], pem_str: &str) -> Result<Vec<u8>> {
    match crypto_algo {
        "ecdsa256" => {
            use p256::ecdsa::{signature::Signer, SigningKey};
            use p256::pkcs8::DecodePrivateKey;
            if hash_algo != "sha256" {
                return Err(MkImageError::Other(format!(
                    "ecdsa256 requires sha256, got {hash_algo}"
                )));
            }
            let sk = SigningKey::from_pkcs8_pem(pem_str)
                .map_err(|e| MkImageError::Other(format!("P-256 key: {e}")))?;
            let sig: p256::ecdsa::DerSignature = sk.sign(data);
            Ok(sig.to_vec())
        }
        "ecdsa384" => {
            use p384::ecdsa::{signature::Signer, SigningKey};
            use p384::pkcs8::DecodePrivateKey;
            if hash_algo != "sha384" {
                return Err(MkImageError::Other(format!(
                    "ecdsa384 requires sha384, got {hash_algo}"
                )));
            }
            let sk = SigningKey::from_pkcs8_pem(pem_str)
                .map_err(|e| MkImageError::Other(format!("P-384 key: {e}")))?;
            let sig: p384::ecdsa::DerSignature = sk.sign(data);
            Ok(sig.to_vec())
        }
        _ => Err(MkImageError::Other(format!(
            "unsupported ECDSA curve: {crypto_algo}"
        ))),
    }
}

// ---------------------------------------------------------------------------
// FIT parameters
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Default)]
pub struct FitParams {
    pub datafile: Option<String>,
    pub imagefile: String,
    pub keydir: Option<String>,
    pub keyfile: Option<String>,
    pub dtc_opts: String,
    pub require_keys: bool,
    pub comment: Option<String>,
    pub algo_name: Option<String>,
    pub re_sign: bool,
    pub signer_version: String,
}

// ---------------------------------------------------------------------------
// Main pipeline
// ---------------------------------------------------------------------------

/// Main FIT file processing — mirrors U-Boot's `fit_handle_file()`.
pub fn fit_handle_file(params: &FitParams) -> Result<()> {
    let tmpfile = format!("{}.tmp", params.imagefile);

    // Step 1: compile .its or copy existing FIT
    if let Some(ref datafile) = params.datafile {
        if !params.re_sign {
            run_dtc(&params.dtc_opts, &tmpfile, datafile)?;
        } else {
            fs::copy(datafile, &tmpfile)?;
        }
    } else if params.re_sign {
        fs::copy(&params.imagefile, &tmpfile)?;
    } else {
        return Err(MkImageError::Other(
            "no input file specified (use -f)".into(),
        ));
    }

    // Step 2: add hashes and signatures in-place
    fit_add_verification_data(params, &tmpfile)?;

    // Step 3: move to final location
    fs::rename(&tmpfile, &params.imagefile).map_err(|e| {
        let _ = fs::remove_file(&tmpfile);
        MkImageError::Other(format!(
            "cannot rename '{}' → '{}': {e}",
            tmpfile, params.imagefile
        ))
    })?;

    Ok(())
}

/// Estimate extra bytes needed for all hash/signature properties.
/// Mirrors U-Boot's `fit_estimate_hash_sig_size()`.
fn fit_estimate_extra_size(dtb: &[u8], signing: bool) -> usize {
    let mut estimate = 0usize;
    let base = dtb::fdt_off_dt_struct(dtb);
    let struct_end = base + dtb::fdt_size_dt_struct(dtb);
    let mut pos = base;
    let mut depth: i32 = -1;

    loop {
        if pos >= struct_end {
            break;
        }
        let offset = pos;
        let (tag, next) = dtb::fdt_next_tag(dtb, pos);
        match tag {
            dtb::FDT_BEGIN_NODE => {
                depth += 1;
                if depth == 3 {
                    let name = dtb::fdt_get_name(dtb, offset);
                    if name.starts_with(FIT_HASH_NODENAME) {
                        estimate += 128;
                    }
                    if signing && name.starts_with(FIT_SIG_NODENAME) {
                        estimate += 1024;
                    }
                }
            }
            dtb::FDT_END_NODE => {
                depth -= 1;
            }
            dtb::FDT_END => break,
            _ => {}
        }
        pos = next;
    }

    estimate
}

/// Equivalent of `fdt_open_into()` — expand a DTB buffer to `new_totalsize`.
///
/// For version 17 DTBs (as produced by dtc), the strings block is already
/// right after the struct block. We just expand the Vec and set totalsize.
/// The extra space becomes padding at the end.
fn fdt_open_into(dtb: &mut Vec<u8>, new_totalsize: usize) {
    let old_totalsize = dtb::fdt_totalsize(dtb);
    if new_totalsize > old_totalsize {
        dtb.resize(new_totalsize, 0);
        dtb::put_u32(dtb, dtb::HDR_TOTALSIZE, new_totalsize as u32);
    }
}

/// Read the DTB, modify it in-place, write it back.
fn fit_add_verification_data(params: &FitParams, tmpfile: &str) -> Result<()> {
    let mut dtb = fs::read(tmpfile)?;
    dtb::fdt_check_header(&dtb)?;

    let signing = params.keydir.is_some() || params.keyfile.is_some();

    // Pack the DTB first, removing the dtc -p padding.  This matches
    // mkimage's fit_import_data() which calls fdt_pack() before the
    // signing pipeline sees the file.
    dtb::fdt_pack(&mut dtb);

    // Expand DTB to accommodate new properties (mirrors mkimage's behavior).
    // The original mkimage: file_size = packed_size, then ftruncate to
    // file_size + size_inc, then fdt_open_into(buf, file_size + size_inc).
    // We do the same.
    let size_inc = fit_estimate_extra_size(&dtb, signing);
    let file_size = dtb.len();
    if size_inc > 0 {
        let new_size = file_size + size_inc;
        fdt_open_into(&mut dtb, new_size);
    }

    // Set timestamp on the root node
    let root_off = dtb::fdt_path_offset(&dtb, "/")
        .ok_or_else(|| MkImageError::Other("no root node".into()))?;
    let timestamp = get_source_date(None);
    dtb::fdt_setprop_u32(&mut dtb, root_off, FIT_TIMESTAMP_PROP, timestamp);

    // Process image nodes
    process_images(&mut dtb, params, signing)?;

    // Process config signatures
    if signing {
        process_configs(&mut dtb, params)?;
    }

    // Write exactly totalsize bytes (matching mkimage's behavior — the file
    // is mmap'd at the expanded size, and msync writes exactly that)
    let totalsize = dtb::fdt_totalsize(&dtb);
    fs::write(tmpfile, &dtb[..totalsize])?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Image node processing (hashes + image-level signatures)
// ---------------------------------------------------------------------------

fn process_images(dtb: &mut Vec<u8>, params: &FitParams, signing: bool) -> Result<()> {
    let images_off = match dtb::fdt_path_offset(dtb, FIT_IMAGES_PATH) {
        Some(o) => o,
        None => return Ok(()),
    };

    // Collect image names first (offsets will shift during mutations)
    let mut image_names = Vec::new();
    let mut off = dtb::fdt_first_subnode(dtb, images_off);
    while let Some(o) = off {
        image_names.push(dtb::fdt_get_name(dtb, o).to_string());
        off = dtb::fdt_next_subnode(dtb, o);
    }

    for image_name in &image_names {
        let image_path = format!("{}/{}", FIT_IMAGES_PATH, image_name);
        let image_off = match dtb::fdt_path_offset(dtb, &image_path) {
            Some(o) => o,
            None => continue,
        };

        // Get image data
        let data: Vec<u8> = match dtb::fdt_getprop(dtb, image_off, FIT_DATA_PROP) {
            Some(d) => d.to_vec(),
            None => continue,
        };

        // Collect subnode names
        let mut sub_names = Vec::new();
        let mut sub = dtb::fdt_first_subnode(dtb, image_off);
        while let Some(s) = sub {
            sub_names.push(dtb::fdt_get_name(dtb, s).to_string());
            sub = dtb::fdt_next_subnode(dtb, s);
        }

        for sub_name in &sub_names {
            let sub_path = format!("{}/{}", image_path, sub_name);

            if sub_name.starts_with(FIT_HASH_NODENAME) {
                // --- Hash node ---
                let sub_off = match dtb::fdt_path_offset(dtb, &sub_path) {
                    Some(o) => o,
                    None => continue,
                };
                let algo = match dtb::fdt_getprop_str(dtb, sub_off, FIT_ALGO_PROP) {
                    Some(a) => a.to_string(),
                    None => continue,
                };
                let hash = calculate_hash(&algo, &data)?;
                // Re-resolve after reading (shouldn't change, but be safe)
                let sub_off = dtb::fdt_path_offset(dtb, &sub_path).unwrap();
                dtb::fdt_setprop(dtb, sub_off, FIT_VALUE_PROP, &hash);
                eprintln!("Hash '{}' in '{}': {} computed", sub_name, image_name, algo);
            } else if signing && sub_name.starts_with(FIT_SIG_NODENAME) {
                // --- Image signature node ---
                let sub_off = match dtb::fdt_path_offset(dtb, &sub_path) {
                    Some(o) => o,
                    None => continue,
                };
                let algo = match dtb::fdt_getprop_str(dtb, sub_off, FIT_ALGO_PROP) {
                    Some(a) => a.to_string(),
                    None => match &params.algo_name {
                        Some(a) => a.clone(),
                        None => continue,
                    },
                };
                let keyname = match dtb::fdt_getprop_str(dtb, sub_off, FIT_KEY_HINT) {
                    Some(k) => k.to_string(),
                    None => continue,
                };

                let sig = sign_regions(
                    &algo,
                    &[&data],
                    params.keydir.as_deref(),
                    &keyname,
                    params.keyfile.as_deref(),
                )?;

                write_sig_props(dtb, &sub_path, &sig, params, None)?;

                eprintln!(
                    "Signature '{}' in '{}': {} signed with key '{}'",
                    sub_name, image_name, algo, keyname
                );
            }
        }
    }

    Ok(())
}

/// Write the standard signature properties to a signature node.
/// Matches the exact property order of U-Boot's `fit_image_write_sig()`.
///
/// `sig_path` must be the full DTB path to the signature node (e.g.
/// "/images/kernel-1/signature-1") so we can re-resolve the offset
/// after each property insertion shifts bytes.
fn write_sig_props(
    dtb: &mut Vec<u8>,
    sig_path: &str,
    signature: &[u8],
    params: &FitParams,
    region_info: Option<(&[u8], u32)>, // (hashed_nodes_prop, string_size_before)
) -> Result<()> {
    // Helper: resolve offset, error if missing
    let resolve = |d: &[u8]| -> Result<usize> {
        dtb::fdt_path_offset(d, sig_path)
            .ok_or_else(|| MkImageError::Other(format!("sig node '{}' disappeared", sig_path)))
    };

    // 1. value
    dtb::fdt_setprop(dtb, resolve(dtb)?, FIT_VALUE_PROP, signature);

    // 2. signer-name
    dtb::fdt_setprop_string(dtb, resolve(dtb)?, "signer-name", SIGNER_NAME);

    // 3. signer-version
    let version = params.signer_version.as_ref();
    dtb::fdt_setprop_string(dtb, resolve(dtb)?, "signer-version", version);

    // 4. comment (if specified)
    if let Some(ref comment) = params.comment {
        dtb::fdt_setprop_string(dtb, resolve(dtb)?, "comment", comment);
    }

    // 5. timestamp
    let timestamp = get_source_date(None);
    dtb::fdt_setprop_u32(dtb, resolve(dtb)?, FIT_TIMESTAMP_PROP, timestamp);

    // 6. hashed-nodes + hashed-strings (config signatures only)
    if let Some((hashed_nodes_val, string_size)) = region_info {
        dtb::fdt_setprop(dtb, resolve(dtb)?, "hashed-nodes", hashed_nodes_val);

        // hashed-strings: {0 (legacy offset), string_size} in big-endian
        let mut hs = Vec::with_capacity(8);
        hs.extend_from_slice(&0u32.to_be_bytes());
        hs.extend_from_slice(&string_size.to_be_bytes());
        dtb::fdt_setprop(dtb, resolve(dtb)?, "hashed-strings", &hs);
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Config signature processing
// ---------------------------------------------------------------------------

fn process_configs(dtb: &mut Vec<u8>, params: &FitParams) -> Result<()> {
    let confs_off = match dtb::fdt_path_offset(dtb, FIT_CONFS_PATH) {
        Some(o) => o,
        None => return Ok(()),
    };

    // Collect config names
    let mut conf_names = Vec::new();
    let mut off = dtb::fdt_first_subnode(dtb, confs_off);
    while let Some(o) = off {
        conf_names.push(dtb::fdt_get_name(dtb, o).to_string());
        off = dtb::fdt_next_subnode(dtb, o);
    }

    for conf_name in conf_names {
        let conf_path = format!("{}/{}", FIT_CONFS_PATH, conf_name);
        let conf_off = match dtb::fdt_path_offset(dtb, &conf_path) {
            Some(o) => o,
            None => continue,
        };

        // Collect signature subnode names
        let mut sig_names = Vec::new();
        let mut sub = dtb::fdt_first_subnode(dtb, conf_off);
        while let Some(s) = sub {
            let name = dtb::fdt_get_name(dtb, s).to_string();
            if name.starts_with(FIT_SIG_NODENAME) {
                sig_names.push(name);
            }
            sub = dtb::fdt_next_subnode(dtb, s);
        }

        for sig_name in sig_names {
            process_one_config_sig(dtb, params, &conf_name, &sig_name)?;
        }
    }

    Ok(())
}

fn process_one_config_sig(
    dtb: &mut Vec<u8>,
    params: &FitParams,
    conf_name: &str,
    sig_name: &str,
) -> Result<()> {
    let sig_path = format!("{}/{}/{}", FIT_CONFS_PATH, conf_name, sig_name);
    let sig_off = match dtb::fdt_path_offset(dtb, &sig_path) {
        Some(o) => o,
        None => return Ok(()),
    };

    // Get algo
    let algo = match dtb::fdt_getprop_str(dtb, sig_off, FIT_ALGO_PROP) {
        Some(a) => a.to_string(),
        None => match &params.algo_name {
            Some(a) => a.clone(),
            None => return Ok(()),
        },
    };
    let keyname = match dtb::fdt_getprop_str(dtb, sig_off, FIT_KEY_HINT) {
        Some(k) => k.to_string(),
        None => return Ok(()),
    };

    // Build node inclusion list (same as U-Boot's fit_config_get_hash_list)
    let conf_path = format!("{}/{}", FIT_CONFS_PATH, conf_name);
    let conf_off = dtb::fdt_path_offset(dtb, &conf_path).unwrap();

    let mut node_inc: Vec<String> = Vec::new();
    node_inc.push("/".to_string());
    node_inc.push(conf_path.clone());

    // Determine which images to sign
    let (sign_images, allow_missing): (Vec<String>, bool) = {
        let sig_off = dtb::fdt_path_offset(
            dtb,
            &format!("{}/{}/{}", FIT_CONFS_PATH, conf_name, sig_name),
        )
        .unwrap();
        let custom = dtb::fdt_getprop_stringlist(dtb, sig_off, "sign-images");
        if custom.is_empty() {
            (
                DEFAULT_SIGN_IMAGES.iter().map(|s| s.to_string()).collect(),
                true, // allow_missing for defaults
            )
        } else {
            (custom, false)
        }
    };

    // For each image type, resolve the referenced image node(s)
    for img_type in &sign_images {
        let count = dtb::fdt_stringlist_count(dtb, conf_off, img_type);
        if count == 0 {
            if !allow_missing {
                return Err(MkImageError::Other(format!(
                    "image '{}' not found in config '{}'",
                    img_type, conf_name
                )));
            }
            continue;
        }

        let img_names = dtb::fdt_getprop_stringlist(dtb, conf_off, img_type);
        // If not a string list, try as single string
        let img_names = if img_names.is_empty() {
            match dtb::fdt_getprop_str(dtb, conf_off, img_type) {
                Some(s) => vec![s.to_string()],
                None => continue,
            }
        } else {
            img_names
        };

        for img_name in &img_names {
            let img_path = format!("{}/{}", FIT_IMAGES_PATH, img_name);
            node_inc.push(img_path.clone());

            // Include hash subnodes
            if let Some(img_off) = dtb::fdt_path_offset(dtb, &img_path) {
                let mut sub = dtb::fdt_first_subnode(dtb, img_off);
                while let Some(s) = sub {
                    let name = dtb::fdt_get_name(dtb, s);
                    if name.starts_with(FIT_HASH_NODENAME) {
                        node_inc.push(format!("{}/{}", img_path, name));
                    }
                    sub = dtb::fdt_next_subnode(dtb, s);
                }
            }
        }
    }

    eprintln!(
        "Config '{}' sig '{}': signing nodes: {:?}",
        conf_name, sig_name, node_inc
    );

    // Capture string table size BEFORE we add signature properties
    let string_size_before = dtb::fdt_size_dt_strings(dtb) as u32;

    // Compute FDT regions on current DTB state
    let regions = dtb::fdt_find_regions(dtb, &node_inc, EXC_PROPS, true)?;
    if regions.is_empty() {
        return Err(MkImageError::Other(format!(
            "no regions to sign for config '{}'",
            conf_name
        )));
    }

    // Collect region byte slices
    let region_slices: Vec<&[u8]> = regions
        .iter()
        .map(|r| &dtb[r.offset..r.offset + r.size])
        .collect();

    // Sign
    let sig = sign_regions(
        &algo,
        &region_slices,
        params.keydir.as_deref(),
        &keyname,
        params.keyfile.as_deref(),
    )?;

    // Build hashed-nodes value (null-separated list)
    let mut hashed_nodes_val = Vec::new();
    for path in &node_inc {
        hashed_nodes_val.extend_from_slice(path.as_bytes());
        hashed_nodes_val.push(0);
    }

    // Write signature properties to the sig node
    let sig_path = format!("{}/{}/{}", FIT_CONFS_PATH, conf_name, sig_name);
    write_sig_props(
        dtb,
        &sig_path,
        &sig,
        params,
        Some((&hashed_nodes_val, string_size_before)),
    )?;

    eprintln!(
        "Config '{}' sig '{}': {} signed with key '{}'",
        conf_name, sig_name, algo, keyname
    );

    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_calculate_hash_sha256() {
        let hash = calculate_hash("sha256", b"hello world").unwrap();
        assert_eq!(hash.len(), 32);
    }

    #[test]
    fn test_calculate_hash_crc32() {
        let hash = calculate_hash("crc32", b"hello").unwrap();
        assert_eq!(hash.len(), 4);
    }

    #[test]
    fn test_parse_algo() {
        let (h, c) = parse_algo("sha256,rsa2048").unwrap();
        assert_eq!(h, "sha256");
        assert_eq!(c, "rsa2048");
        assert!(parse_algo("sha256").is_err());
    }

    #[test]
    fn test_calculate_hash_sha1() {
        let hash = calculate_hash("sha1", b"test data").unwrap();
        assert_eq!(hash.len(), 20);
    }
}
