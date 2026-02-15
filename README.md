# mkimage-rs

A pure-Rust reimplementation of U-Boot's `mkimage` tool. Produces bit-for-bit identical output to the original C version — no OpenSSL required.

This project was co-written in association with Opus 4.6.

## Features

- **Legacy uImage** — create, list (`-l`), and verify single-file, multi-file, script, and XIP images with full header CRC checking.
- **FIT image signing** — compile `.its` → `.itb`, compute hashes, and cryptographically sign image and configuration nodes.
- **Pure Rust crypto** — RSA (PKCS#1 v1.5) and ECDSA (P-256, P-384) signing with no C dependencies. Keys are loaded from PEM files (PKCS#1 or PKCS#8).
- **Library + binary** — use it as a standalone CLI tool or integrate the crate directly into your Rust build system.
- **Zero runtime dependencies** — the device-tree compiler (`dtc`) is vendored and compiled into the binary. Only a C compiler is needed at build time.
- **Reproducible builds** — honours `SOURCE_DATE_EPOCH` for deterministic timestamps.

## Limitations compared to U-Boot mkimage

This project focuses on legacy image creation and FIT image signing. The following features from the original U-Boot `mkimage` are **not implemented**:

| Category | Feature | Original flag |
|---|---|---|
| FIT data layout | External data mode (data outside FIT structure) | `-E` |
| FIT data layout | External data alignment | `-B size` |
| FIT data layout | Static external data position | `-p addr` |
| FIT generation | Auto-generate FIT from DTBs | `-f auto` / `-f auto-conf` |
| FIT generation | Append device-tree binaries | `-b <dtb>` |
| FIT generation | Ramdisk input | `-i <ramdisk.cpio.gz>` |
| FIT misc | Update timestamp without re-signing | `-t` |
| Signing | Write public keys to a separate DTB | `-K <dtb>` |
| Signing | OpenSSL engine support | `-N engine` |
| Signing | Key name hint override | `-g name` |
| Signing | FIT encryption / ciphering | — |
| Signing | FIT pre-load data | — |
| Signing | FIT signature verification (signing only) | — |
| Crypto | ECDSA P-521 (secp521r1) | — |
| Legacy | Board-specific image formats (kwbimage, imximage, …) | — |
| Legacy | TFA BL31 append | `-y` / `-Y` |
| Legacy | Second image name | `-R` |

Vendor-specific image type *names* (kwbimage, imximage, stm32image, etc.) are recognised in the type enum but only the standard legacy header format is actually written — the board-specific packing logic is not ported.

_Note_: while we tested this against a few different images, there may be edge cases where the output differs from the original `mkimage` !

## Usage

### Legacy image

```bash
# Create a kernel image
mkimage -A arm -O linux -T kernel -C gzip \
        -a 80008000 -e 80008000 \
        -n "Linux" -d zImage uImage

# Inspect an existing image
mkimage -l uImage
```

### Signed FIT image

```bash
# Build and sign a FIT image (bit-for-bit compatible with U-Boot mkimage)
mkimage -f image.its -k keys/ -r signed.itb

# Re-sign an existing FIT image
mkimage -F -k keys/ -r signed.itb
```

Set `SOURCE_DATE_EPOCH=0` (or any fixed value) for fully reproducible output.

## Library usage

mkimage-rs was designed to be used within another rust project as a library.

```rust
use mkimage::{ImageParams, Os, Arch, ImageType, Compression};

let params = ImageParams::builder()
    .os(Os::Linux)
    .arch(Arch::Arm)
    .image_type(ImageType::Kernel)
    .compression(Compression::Gzip)
    .load_addr(0x80008000)
    .entry_point(0x80008000)
    .name("Linux Kernel")
    .build();

mkimage::create_image(&params, "zImage", "uImage").unwrap();
```

## Custom signing backend

mkimage-rs supports pluggable signing via the `FitSigner` trait. This lets you
route signing through a remote service, HSM, or any custom backend — the library
handles hashing, DTB manipulation, and region assembly while your implementation
only needs to produce raw signatures.

```rust
use mkimage::fit::{FitSigner, FitParams, fit_handle_file_with_signer};

struct MySigner { /* your KMS client, HSM handle, etc. */ }

impl FitSigner for MySigner {
    fn sign(&self, algo: &str, data: &[u8], keyname: &str) -> mkimage::Result<Vec<u8>> {
        // algo: "sha256,rsa2048" — hash algorithm + crypto algorithm
        // data: concatenated bytes of all regions to sign
        // keyname: key-name-hint from the signature node
        //
        // Return the raw signature bytes (e.g. 256 bytes for RSA-2048).
        todo!()
    }
}

let signer = MySigner { /* ... */ };
fit_handle_file_with_signer(&params, &signer)?;
```

The default `DefaultFitSigner` loads PEM keys from disk — see
`fit_handle_file()` which uses it internally.

See `examples/custom_signer.rs` for a complete runnable example.

## License

MIT.