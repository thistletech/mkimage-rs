//! # mkimage
//!
//! A Rust library for creating and inspecting U-Boot image files.
//!
//! This is a reimplementation of the U-Boot `mkimage` tool. It supports:
//!
//! - **Legacy images**: create, list, verify uImage files
//! - **FIT images**: compile `.its` → `.itb`, compute hashes, sign with
//!   RSA / ECDSA (pure Rust, no OpenSSL)
//! - Handle multi-file and script images
//!
//! ## Example
//!
//! ```no_run
//! use mkimage::{ImageParams, Os, Arch, ImageType, Compression};
//!
//! let params = ImageParams::builder()
//!     .os(Os::Linux)
//!     .arch(Arch::Arm)
//!     .image_type(ImageType::Kernel)
//!     .compression(Compression::Gzip)
//!     .load_addr(0x80008000)
//!     .entry_point(0x80008000)
//!     .name("Linux Kernel")
//!     .build();
//!
//! mkimage::create_image(&params, "zImage", "uImage").unwrap();
//! ```

pub mod dtb;
pub mod fit;

use std::fmt;
use std::fs;
use std::io;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use crc32fast::Hasher;
use thiserror::Error;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Magic number identifying a legacy U-Boot image.
pub const IH_MAGIC: u32 = 0x27051956;

/// Maximum length of the image name field (bytes).
pub const IH_NMLEN: usize = 32;

/// Size of the legacy image header in bytes.
pub const LEGACY_HEADER_SIZE: usize = 64; // 7*4 + 4*1 + 32 = 64

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

#[derive(Debug, Error)]
pub enum MkImageError {
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),

    #[error("bad magic number")]
    BadMagic,

    #[error("bad header checksum")]
    BadHeaderCrc,

    #[error("bad data checksum")]
    BadDataCrc,

    #[error("image too small ({size} bytes, need at least {min})")]
    TooSmall { size: usize, min: usize },

    #[error("empty input file: {0}")]
    EmptyInput(String),

    #[error("unknown {kind} name: {name}")]
    UnknownName { kind: &'static str, name: String },

    #[error("XIP buffer invalid — first {size} bytes of data must be 0xff")]
    BadXipBuffer { size: usize },

    #[error("data file too small for XIP ({file_size} < {header_size})")]
    XipTooSmall { file_size: usize, header_size: usize },

    #[error("{0}")]
    Other(String),
}

pub type Result<T> = std::result::Result<T, MkImageError>;

// ---------------------------------------------------------------------------
// Enumerations – faithfully matching the U-Boot IH_* values
// ---------------------------------------------------------------------------

macro_rules! enum_with_table {
    (
        $(#[$outer:meta])*
        pub enum $Name:ident : $kind:literal {
            $(
                $(#[$inner:meta])*
                $Variant:ident = $val:expr, $short:literal, $long:literal
            ),+ $(,)?
        }
    ) => {
        $(#[$outer])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
        #[repr(u8)]
        pub enum $Name {
            $(
                $(#[$inner])*
                $Variant = $val,
            )+
        }

        impl $Name {
            /// All known entries as `(value, short_name, long_name)`.
            pub fn table() -> &'static [(u8, &'static str, &'static str)] {
                &[
                    $(
                        ($val, $short, $long),
                    )+
                ]
            }

            /// Look up by short name (case-insensitive).
            pub fn from_name(name: &str) -> Option<Self> {
                let lower = name.to_ascii_lowercase();
                for &(val, short, _) in Self::table() {
                    if short.to_ascii_lowercase() == lower {
                        if let Some(v) = Self::from_u8(val) {
                            return Some(v);
                        }
                    }
                }
                None
            }

            /// Look up by raw u8 value.
            pub fn from_u8(v: u8) -> Option<Self> {
                $(
                    if v == $val { return Some(Self::$Variant); }
                )+
                None
            }

            /// Short name used on the CLI.
            pub fn short_name(self) -> &'static str {
                for &(val, short, _) in Self::table() {
                    if val == self as u8 { return short; }
                }
                "unknown"
            }

            /// Human-readable long name.
            pub fn long_name(self) -> &'static str {
                for &(val, _, long) in Self::table() {
                    if val == self as u8 { return long; }
                }
                "Unknown"
            }

            /// The kind label (e.g. "OS", "CPU", …).
            pub fn kind() -> &'static str {
                $kind
            }
        }

        impl fmt::Display for $Name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}", self.long_name())
            }
        }
    };
}

enum_with_table! {
    /// Operating system codes (IH_OS_*).
    pub enum Os : "OS" {
        Invalid             = 0,  "invalid",              "Invalid OS",
        OpenBsd             = 1,  "openbsd",              "OpenBSD",
        NetBsd              = 2,  "netbsd",               "NetBSD",
        FreeBsd             = 3,  "freebsd",              "FreeBSD",
        Bsd44               = 4,  "4_4bsd",               "4_4BSD",
        Linux               = 5,  "linux",                "Linux",
        Svr4                = 6,  "svr4",                 "SVR4",
        Esix                = 7,  "esix",                 "Esix",
        Solaris             = 8,  "solaris",              "Solaris",
        Irix                = 9,  "irix",                 "Irix",
        Sco                 = 10, "sco",                  "SCO",
        Dell                = 11, "dell",                 "Dell",
        Ncr                 = 12, "ncr",                  "NCR",
        LynxOs              = 13, "lynxos",               "LynxOS",
        VxWorks             = 14, "vxworks",              "VxWorks",
        PSos                = 15, "psos",                 "pSOS",
        Qnx                 = 16, "qnx",                 "QNX",
        UBoot               = 17, "u-boot",               "U-Boot",
        Rtems               = 18, "rtems",                "RTEMS",
        Artos               = 19, "artos",                "ARTOS",
        Unity               = 20, "unity",                "Unity OS",
        Integrity           = 21, "integrity",            "INTEGRITY",
        Ose                 = 22, "ose",                  "Enea OSE",
        Plan9               = 23, "plan9",                "Plan 9",
        OpenRtos            = 24, "openrtos",             "OpenRTOS",
        ArmTrustedFirmware  = 25, "arm-trusted-firmware", "ARM Trusted Firmware",
        Tee                 = 26, "tee",                  "Trusted Execution Environment",
        OpenSbi             = 27, "opensbi",              "RISC-V OpenSBI",
        Efi                 = 28, "efi",                  "EFI Firmware",
        Elf                 = 29, "elf",                  "ELF Image",
    }
}

enum_with_table! {
    /// CPU architecture codes (IH_ARCH_*).
    pub enum Arch : "CPU architecture" {
        Invalid     = 0,  "invalid",    "Invalid ARCH",
        Alpha       = 1,  "alpha",      "Alpha",
        Arm         = 2,  "arm",        "ARM",
        I386        = 3,  "x86",        "Intel x86",
        Ia64        = 4,  "ia64",       "IA64",
        Mips        = 5,  "mips",       "MIPS",
        Mips64      = 6,  "mips64",     "MIPS 64 Bit",
        Ppc         = 7,  "ppc",        "PowerPC",
        S390        = 8,  "s390",       "IBM S390",
        Sh          = 9,  "sh",         "SuperH",
        Sparc       = 10, "sparc",      "SPARC",
        Sparc64     = 11, "sparc64",    "SPARC 64 Bit",
        M68k        = 12, "m68k",       "M68K",
        Nios        = 13, "nios",       "Nios-32",
        MicroBlaze  = 14, "microblaze", "MicroBlaze",
        Nios2       = 15, "nios2",      "NIOS II",
        Blackfin    = 16, "blackfin",   "Blackfin",
        Avr32       = 17, "avr32",      "AVR32",
        St200       = 18, "st200",      "STMicroelectronics ST200",
        Sandbox     = 19, "sandbox",    "Sandbox",
        Nds32       = 20, "nds32",      "NDS32",
        OpenRisc    = 21, "or1k",       "OpenRISC 1000",
        Arm64       = 22, "arm64",      "AArch64",
        Arc         = 23, "arc",        "ARC",
        X86_64      = 24, "x86_64",     "AMD x86_64",
        Xtensa      = 25, "xtensa",     "Xtensa",
        Riscv       = 26, "riscv",      "RISC-V",
    }
}

// Provide the "powerpc" alias for Arch lookup
impl Arch {
    /// Extended lookup that also accepts "powerpc" as alias for "ppc".
    pub fn from_name_ext(name: &str) -> Option<Self> {
        if name.eq_ignore_ascii_case("powerpc") {
            return Some(Arch::Ppc);
        }
        Self::from_name(name)
    }
}

enum_with_table! {
    /// Image type codes (IH_TYPE_*).
    pub enum ImageType : "image type" {
        Invalid         = 0,  "invalid",       "Invalid Image",
        Standalone      = 1,  "standalone",    "Standalone Program",
        Kernel          = 2,  "kernel",        "Kernel Image",
        Ramdisk         = 3,  "ramdisk",       "RAMDisk Image",
        Multi           = 4,  "multi",         "Multi-File Image",
        Firmware        = 5,  "firmware",      "Firmware",
        Script          = 6,  "script",        "Script",
        Filesystem      = 7,  "filesystem",    "Filesystem Image",
        FlatDt          = 8,  "flat_dt",       "Flat Device Tree",
        KwbImage        = 9,  "kwbimage",      "Kirkwood Boot Image",
        ImxImage        = 10, "imximage",      "Freescale i.MX Boot Image",
        UblImage        = 11, "ublimage",      "Davinci UBL image",
        OmapImage       = 12, "omapimage",     "TI OMAP SPL With GP CH",
        AisImage        = 13, "aisimage",      "Davinci AIS image",
        KernelNoload    = 14, "kernel_noload", "Kernel Image (no loading done)",
        PblImage        = 15, "pblimage",      "Freescale PBL Boot Image",
        MxsImage        = 16, "mxsimage",      "Freescale MXS Boot Image",
        GpImage         = 17, "gpimage",       "TI Keystone SPL Image",
        AtmelImage      = 18, "atmelimage",    "ATMEL ROM-Boot Image",
        SocFpgaImage    = 19, "socfpgaimage",  "Altera SoCFPGA CV/AV preloader",
        X86Setup        = 20, "x86_setup",     "x86 setup.bin",
        Lpc32xxImage    = 21, "lpc32xximage",  "LPC32XX Boot Image",
        Loadable        = 22, "loadable",      "A list of typeless images",
        RkImage         = 23, "rkimage",       "Rockchip Boot Image",
        RkSd            = 24, "rksd",          "Rockchip SD Boot Image",
        RkSpi           = 25, "rkspi",         "Rockchip SPI Boot Image",
        ZynqImage       = 26, "zynqimage",     "Xilinx Zynq Boot Image",
        ZynqMpImage     = 27, "zynqmpimage",   "Xilinx ZynqMP Boot Image",
        ZynqMpBif       = 28, "zynqmpbif",     "Xilinx ZynqMP Boot Image (bif)",
        Fpga            = 29, "fpga",          "FPGA Image",
        VybridImage     = 30, "vybridimage",   "Vybrid Boot Image",
        Tee             = 31, "tee",           "Trusted Execution Environment Image",
        FirmwareIvt     = 32, "firmware_ivt",  "Firmware with HABv4 IVT",
        Pmmc            = 33, "pmmc",          "TI Power Management Micro-Controller Firmware",
        Stm32Image      = 34, "stm32image",    "STMicroelectronics STM32 Image",
        MtkImage        = 35, "mtk_image",     "MediaTek BootROM loadable Image",
        Imx8mImage      = 36, "imx8mimage",    "NXP i.MX8M Boot Image",
        Imx8Image       = 37, "imx8image",     "NXP i.MX8 Boot Image",
        Copro           = 38, "copro",         "Coprocessor Image",
        SunxiEgon       = 39, "sunxi_egon",    "Allwinner eGON Boot Image",
        SunxiToc0       = 40, "sunxi_toc0",    "Allwinner TOC0 Boot Image",
        FdtLegacy       = 41, "fdt_legacy",    "legacy Image with Flat Device Tree",
        RenasasSpkg     = 42, "spkgimage",     "Renesas SPKG Image",
        StarfiveSpl     = 43, "sfspl",         "StarFive SPL Image",
        TfaBl31         = 44, "tfa-bl31",      "TFA BL31 Image",
        Stm32ImageV2    = 45, "stm32imagev2",  "STMicroelectronics STM32 Image V2.0",
        AmlImage        = 46, "amlimage",      "Amlogic Boot Image",
    }
}

impl ImageType {
    /// Returns true if this image type is handled by the legacy (default)
    /// image handler.
    pub fn is_legacy_type(self) -> bool {
        let v = self as u8;
        (v > ImageType::Invalid as u8 && v < ImageType::FlatDt as u8)
            || self == ImageType::KernelNoload
            || self == ImageType::FirmwareIvt
            || self == ImageType::FdtLegacy
    }
}

enum_with_table! {
    /// Compression type codes (IH_COMP_*).
    pub enum Compression : "compression type" {
        None  = 0, "none",  "uncompressed",
        Gzip  = 1, "gzip",  "gzip compressed",
        Bzip2 = 2, "bzip2", "bzip2 compressed",
        Lzma  = 3, "lzma",  "lzma compressed",
        Lzo   = 4, "lzo",   "lzo compressed",
        Lz4   = 5, "lz4",   "lz4 compressed",
        Zstd  = 6, "zstd",  "zstd compressed",
    }
}

// ---------------------------------------------------------------------------
// Legacy image header (big-endian on disk)
// ---------------------------------------------------------------------------

/// The 64-byte legacy U-Boot image header.
///
/// All multi-byte fields are stored in **big-endian** (network) byte order,
/// matching the original C `struct legacy_img_hdr`.
#[derive(Clone)]
pub struct LegacyImageHeader {
    /// Image Header Magic Number (`IH_MAGIC`)
    pub ih_magic: u32,
    /// Image Header CRC Checksum
    pub ih_hcrc: u32,
    /// Image Creation Timestamp (seconds since epoch)
    pub ih_time: u32,
    /// Image Data Size (bytes, excluding header)
    pub ih_size: u32,
    /// Data Load Address
    pub ih_load: u32,
    /// Entry Point Address
    pub ih_ep: u32,
    /// Image Data CRC Checksum
    pub ih_dcrc: u32,
    /// Operating System
    pub ih_os: u8,
    /// CPU Architecture
    pub ih_arch: u8,
    /// Image Type
    pub ih_type: u8,
    /// Compression Type
    pub ih_comp: u8,
    /// Image Name (zero-padded)
    pub ih_name: [u8; IH_NMLEN],
}

impl Default for LegacyImageHeader {
    fn default() -> Self {
        Self {
            ih_magic: 0,
            ih_hcrc: 0,
            ih_time: 0,
            ih_size: 0,
            ih_load: 0,
            ih_ep: 0,
            ih_dcrc: 0,
            ih_os: 0,
            ih_arch: 0,
            ih_type: 0,
            ih_comp: 0,
            ih_name: [0u8; IH_NMLEN],
        }
    }
}

impl LegacyImageHeader {
    /// Serialize header to a 64-byte big-endian buffer.
    pub fn to_bytes(&self) -> [u8; LEGACY_HEADER_SIZE] {
        let mut buf = [0u8; LEGACY_HEADER_SIZE];
        buf[0..4].copy_from_slice(&self.ih_magic.to_be_bytes());
        buf[4..8].copy_from_slice(&self.ih_hcrc.to_be_bytes());
        buf[8..12].copy_from_slice(&self.ih_time.to_be_bytes());
        buf[12..16].copy_from_slice(&self.ih_size.to_be_bytes());
        buf[16..20].copy_from_slice(&self.ih_load.to_be_bytes());
        buf[20..24].copy_from_slice(&self.ih_ep.to_be_bytes());
        buf[24..28].copy_from_slice(&self.ih_dcrc.to_be_bytes());
        buf[28] = self.ih_os;
        buf[29] = self.ih_arch;
        buf[30] = self.ih_type;
        buf[31] = self.ih_comp;
        buf[32..64].copy_from_slice(&self.ih_name);
        buf
    }

    /// Deserialize header from a big-endian byte slice (must be >= 64 bytes).
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        if data.len() < LEGACY_HEADER_SIZE {
            return Err(MkImageError::TooSmall {
                size: data.len(),
                min: LEGACY_HEADER_SIZE,
            });
        }
        let mut name = [0u8; IH_NMLEN];
        name.copy_from_slice(&data[32..64]);
        Ok(Self {
            ih_magic: u32::from_be_bytes(data[0..4].try_into().unwrap()),
            ih_hcrc: u32::from_be_bytes(data[4..8].try_into().unwrap()),
            ih_time: u32::from_be_bytes(data[8..12].try_into().unwrap()),
            ih_size: u32::from_be_bytes(data[12..16].try_into().unwrap()),
            ih_load: u32::from_be_bytes(data[16..20].try_into().unwrap()),
            ih_ep: u32::from_be_bytes(data[20..24].try_into().unwrap()),
            ih_dcrc: u32::from_be_bytes(data[24..28].try_into().unwrap()),
            ih_os: data[28],
            ih_arch: data[29],
            ih_type: data[30],
            ih_comp: data[31],
            ih_name: name,
        })
    }

    /// Return the image name as a UTF-8 string (trimmed of NUL padding).
    pub fn name_str(&self) -> &str {
        let end = self.ih_name.iter().position(|&b| b == 0).unwrap_or(IH_NMLEN);
        std::str::from_utf8(&self.ih_name[..end]).unwrap_or("<invalid utf8>")
    }

    /// Typed OS accessor.
    pub fn os(&self) -> Option<Os> {
        Os::from_u8(self.ih_os)
    }

    /// Typed arch accessor.
    pub fn arch(&self) -> Option<Arch> {
        Arch::from_u8(self.ih_arch)
    }

    /// Typed image type accessor.
    pub fn image_type(&self) -> Option<ImageType> {
        ImageType::from_u8(self.ih_type)
    }

    /// Typed compression accessor.
    pub fn compression(&self) -> Option<Compression> {
        Compression::from_u8(self.ih_comp)
    }
}

impl fmt::Debug for LegacyImageHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LegacyImageHeader")
            .field("magic", &format_args!("0x{:08x}", self.ih_magic))
            .field("hcrc", &format_args!("0x{:08x}", self.ih_hcrc))
            .field("time", &self.ih_time)
            .field("size", &self.ih_size)
            .field("load", &format_args!("0x{:08x}", self.ih_load))
            .field("ep", &format_args!("0x{:08x}", self.ih_ep))
            .field("dcrc", &format_args!("0x{:08x}", self.ih_dcrc))
            .field("os", &self.os())
            .field("arch", &self.arch())
            .field("type", &self.image_type())
            .field("comp", &self.compression())
            .field("name", &self.name_str())
            .finish()
    }
}

// ---------------------------------------------------------------------------
// Image parameters (builder for creating images)
// ---------------------------------------------------------------------------

/// Parameters for creating a U-Boot legacy image.
#[derive(Debug, Clone)]
pub struct ImageParams {
    pub os: Os,
    pub arch: Arch,
    pub image_type: ImageType,
    pub compression: Compression,
    pub load_addr: u32,
    pub entry_point: u32,
    pub name: String,
    /// Execute-In-Place flag.
    pub xip: bool,
    /// When true, entry point was explicitly provided.
    pub ep_set: bool,
}

impl Default for ImageParams {
    fn default() -> Self {
        Self {
            os: Os::Linux,
            arch: Arch::Ppc,
            image_type: ImageType::Kernel,
            compression: Compression::Gzip,
            load_addr: 0,
            entry_point: 0,
            name: String::new(),
            xip: false,
            ep_set: false,
        }
    }
}

impl ImageParams {
    pub fn builder() -> ImageParamsBuilder {
        ImageParamsBuilder::default()
    }
}

/// Builder for [`ImageParams`].
#[derive(Default)]
pub struct ImageParamsBuilder {
    params: ImageParams,
}

impl ImageParamsBuilder {
    pub fn os(mut self, os: Os) -> Self {
        self.params.os = os;
        self
    }
    pub fn arch(mut self, arch: Arch) -> Self {
        self.params.arch = arch;
        self
    }
    pub fn image_type(mut self, t: ImageType) -> Self {
        self.params.image_type = t;
        self
    }
    pub fn compression(mut self, c: Compression) -> Self {
        self.params.compression = c;
        self
    }
    pub fn load_addr(mut self, addr: u32) -> Self {
        self.params.load_addr = addr;
        self
    }
    pub fn entry_point(mut self, ep: u32) -> Self {
        self.params.entry_point = ep;
        self.params.ep_set = true;
        self
    }
    pub fn name(mut self, name: &str) -> Self {
        self.params.name = name.to_string();
        self
    }
    pub fn xip(mut self, xip: bool) -> Self {
        self.params.xip = xip;
        self
    }
    pub fn build(self) -> ImageParams {
        self.params
    }
}

// ---------------------------------------------------------------------------
// CRC-32 helpers
// ---------------------------------------------------------------------------

/// Compute CRC-32 of a byte slice (using the standard polynomial, matching
/// U-Boot's `crc32()`).
pub fn crc32(data: &[u8]) -> u32 {
    let mut h = Hasher::new();
    h.update(data);
    h.finalize()
}

// ---------------------------------------------------------------------------
// Timestamp helper
// ---------------------------------------------------------------------------

/// Get the build timestamp.  Respects `SOURCE_DATE_EPOCH` for reproducible
/// builds, otherwise uses the current time.
pub fn get_source_date(fallback: Option<u32>) -> u32 {
    if let Ok(val) = std::env::var("SOURCE_DATE_EPOCH") {
        if let Ok(epoch) = val.parse::<u32>() {
            return epoch;
        }
        eprintln!("warning: invalid SOURCE_DATE_EPOCH value: {val}");
        return 0;
    }
    fallback.unwrap_or_else(|| {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as u32)
            .unwrap_or(0)
    })
}

// ---------------------------------------------------------------------------
// Listing / verification
// ---------------------------------------------------------------------------

/// Information obtained from reading an existing image.
#[derive(Debug, Clone)]
pub struct ImageInfo {
    pub header: LegacyImageHeader,
    /// For multi-file images: list of (offset_from_start_of_file, size) for each sub-image.
    pub sub_images: Vec<(u64, u32)>,
}

/// Read and verify a legacy U-Boot image, returning its parsed header and
/// optional multi-file information.
///
/// Verification checks:
/// 1. Magic number
/// 2. Header CRC
/// 3. Data CRC
pub fn read_image(path: impl AsRef<Path>) -> Result<ImageInfo> {
    let data = fs::read(path.as_ref())?;
    read_image_bytes(&data)
}

/// Same as [`read_image`] but works on an in-memory buffer.
pub fn read_image_bytes(data: &[u8]) -> Result<ImageInfo> {
    if data.len() < LEGACY_HEADER_SIZE {
        return Err(MkImageError::TooSmall {
            size: data.len(),
            min: LEGACY_HEADER_SIZE,
        });
    }

    let hdr = LegacyImageHeader::from_bytes(data)?;

    // 1. Magic
    if hdr.ih_magic != IH_MAGIC {
        return Err(MkImageError::BadMagic);
    }

    // 2. Header CRC – zero out ih_hcrc field in a copy, then check
    let mut hdr_bytes = hdr.to_bytes();
    hdr_bytes[4..8].copy_from_slice(&0u32.to_be_bytes()); // clear ih_hcrc
    let computed_hcrc = crc32(&hdr_bytes);
    if computed_hcrc != hdr.ih_hcrc {
        return Err(MkImageError::BadHeaderCrc);
    }

    // 3. Data CRC
    let data_start = LEGACY_HEADER_SIZE;
    let data_len = hdr.ih_size as usize;
    if data.len() < data_start + data_len {
        return Err(MkImageError::TooSmall {
            size: data.len(),
            min: data_start + data_len,
        });
    }
    let computed_dcrc = crc32(&data[data_start..data_start + data_len]);
    if computed_dcrc != hdr.ih_dcrc {
        return Err(MkImageError::BadDataCrc);
    }

    // Multi-file / script sub-images
    let sub_images = if hdr.ih_type == ImageType::Multi as u8
        || hdr.ih_type == ImageType::Script as u8
    {
        parse_multi_sizes(data)
    } else {
        Vec::new()
    };

    Ok(ImageInfo {
        header: hdr,
        sub_images,
    })
}

/// Parse the size table for multi-file images.
/// After the header there is a list of u32-be sizes terminated by 0.
/// Data for each sub-image follows, each aligned to 4 bytes.
fn parse_multi_sizes(data: &[u8]) -> Vec<(u64, u32)> {
    let mut offset = LEGACY_HEADER_SIZE;
    let mut sizes = Vec::new();

    // First pass: read the size table
    loop {
        if offset + 4 > data.len() {
            break;
        }
        let sz = u32::from_be_bytes(data[offset..offset + 4].try_into().unwrap());
        offset += 4;
        if sz == 0 {
            break;
        }
        sizes.push(sz);
    }

    // Second pass: compute file offsets (data starts right after the size table)
    let mut data_offset = offset as u64;
    let mut result = Vec::new();
    for (i, &sz) in sizes.iter().enumerate() {
        result.push((data_offset, sz));
        data_offset += sz as u64;
        // Align to 4 bytes, except for the last entry
        if i + 1 < sizes.len() {
            data_offset = (data_offset + 3) & !3;
        }
    }

    result
}

/// Print image header information to `stdout`, matching the original mkimage
/// output format.
pub fn print_image_info(info: &ImageInfo) {
    let hdr = &info.header;

    println!("Image Name:   {}", hdr.name_str());

    // Timestamp
    let ts = hdr.ih_time;
    if ts != 0 {
        let dt = chrono::DateTime::from_timestamp(ts as i64, 0);
        if let Some(dt) = dt {
            println!(
                "Created:      {}",
                dt.format("%a %b %d %H:%M:%S %Y")
            );
        } else {
            println!("Created:      (invalid timestamp)");
        }
    }

    // Image Type line: "<arch> <os> <type> (<comp>)"
    let arch_name = hdr.arch().map(|a| a.long_name()).unwrap_or("Unknown Architecture");
    let os_name = hdr.os().map(|o| o.long_name()).unwrap_or("Unknown OS");
    let type_name = hdr
        .image_type()
        .map(|t| t.long_name())
        .unwrap_or("Unknown Image");
    let comp_name = hdr
        .compression()
        .map(|c| c.long_name())
        .unwrap_or("unknown");
    println!(
        "Image Type:   {arch_name} {os_name} {type_name} ({comp_name})"
    );

    // Data size
    let size = hdr.ih_size;
    if size >= 1024 * 1024 {
        println!(
            "Data Size:    {} Bytes = {:.2} MiB = {:.2} KiB",
            size,
            size as f64 / (1024.0 * 1024.0),
            size as f64 / 1024.0,
        );
    } else if size >= 1024 {
        println!(
            "Data Size:    {} Bytes = {:.2} KiB",
            size,
            size as f64 / 1024.0,
        );
    } else {
        println!("Data Size:    {} Bytes", size);
    }

    println!("Load Address: {:08x}", hdr.ih_load);
    println!("Entry Point:  {:08x}", hdr.ih_ep);

    // Multi-file contents
    if !info.sub_images.is_empty() {
        println!("Contents:");
        for (i, &(_offset, sz)) in info.sub_images.iter().enumerate() {
            if sz >= 1024 {
                println!(
                    "   Image {:>2}: {} Bytes = {:.2} KiB",
                    i,
                    sz,
                    sz as f64 / 1024.0,
                );
            } else {
                println!("   Image {:>2}: {} Bytes", i, sz);
            }
            // For scripts, print offset of sub-images beyond the first
            if hdr.ih_type == ImageType::Script as u8 && i > 0 {
                println!("    Offset = 0x{:08x}", _offset);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Image creation
// ---------------------------------------------------------------------------

/// Create a legacy U-Boot image from a single data file.
///
/// This is the primary library entry point for image creation.
pub fn create_image(
    params: &ImageParams,
    data_file: impl AsRef<Path>,
    output_file: impl AsRef<Path>,
) -> Result<()> {
    let data_path = data_file.as_ref();
    let output_path = output_file.as_ref();

    let data = fs::read(data_path)?;
    if data.is_empty() {
        return Err(MkImageError::EmptyInput(
            data_path.display().to_string(),
        ));
    }

    let image = create_image_bytes(params, &data)?;
    fs::write(output_path, &image)?;
    Ok(())
}

/// Create a legacy U-Boot image from raw bytes, returning the complete
/// image (header + data) as a `Vec<u8>`.
pub fn create_image_bytes(params: &ImageParams, data: &[u8]) -> Result<Vec<u8>> {
    let effective_ep = if params.ep_set {
        params.entry_point
    } else {
        let mut ep = params.load_addr;
        if params.xip {
            ep += LEGACY_HEADER_SIZE as u32;
        }
        ep
    };

    // For XIP: skip the first header_size bytes of data (they must be 0xFF)
    let (data_offset, write_data) = if params.xip && params.image_type.is_legacy_type() {
        if data.len() < LEGACY_HEADER_SIZE {
            return Err(MkImageError::XipTooSmall {
                file_size: data.len(),
                header_size: LEGACY_HEADER_SIZE,
            });
        }
        // Verify first header_size bytes are 0xFF
        for (i, &b) in data[..LEGACY_HEADER_SIZE].iter().enumerate() {
            if b != 0xff {
                return Err(MkImageError::BadXipBuffer {
                    size: LEGACY_HEADER_SIZE,
                });
            }
            let _ = i; // suppress unused warning
        }
        (LEGACY_HEADER_SIZE, &data[LEGACY_HEADER_SIZE..])
    } else {
        (0, data)
    };
    let _ = data_offset;

    let image_type_val = if params.image_type == ImageType::FdtLegacy {
        ImageType::FlatDt as u8
    } else {
        params.image_type as u8
    };

    // Compute data CRC
    let dcrc = crc32(write_data);

    // Timestamp
    let time = get_source_date(None);

    // Build header
    let mut hdr = LegacyImageHeader {
        ih_magic: IH_MAGIC,
        ih_hcrc: 0,
        ih_time: time,
        ih_size: write_data.len() as u32,
        ih_load: params.load_addr,
        ih_ep: effective_ep,
        ih_dcrc: dcrc,
        ih_os: params.os as u8,
        ih_arch: params.arch as u8,
        ih_type: image_type_val,
        ih_comp: params.compression as u8,
        ih_name: [0u8; IH_NMLEN],
    };

    // Set name
    let name_bytes = params.name.as_bytes();
    let copy_len = name_bytes.len().min(IH_NMLEN);
    hdr.ih_name[..copy_len].copy_from_slice(&name_bytes[..copy_len]);

    // Compute header CRC (with ih_hcrc = 0)
    let hdr_bytes = hdr.to_bytes();
    let hcrc = crc32(&hdr_bytes);
    hdr.ih_hcrc = hcrc;

    // Assemble final image
    let mut image = Vec::with_capacity(LEGACY_HEADER_SIZE + write_data.len());
    image.extend_from_slice(&hdr.to_bytes());
    image.extend_from_slice(write_data);

    Ok(image)
}

/// Create a multi-file legacy U-Boot image from multiple data files.
pub fn create_multi_image(
    params: &ImageParams,
    data_files: &[impl AsRef<Path>],
    output_file: impl AsRef<Path>,
) -> Result<()> {
    // Read all input files
    let mut file_data: Vec<Vec<u8>> = Vec::new();
    for path in data_files {
        let data = fs::read(path.as_ref())?;
        if data.is_empty() {
            return Err(MkImageError::EmptyInput(
                path.as_ref().display().to_string(),
            ));
        }
        file_data.push(data);
    }

    let image = create_multi_image_bytes(params, &file_data)?;
    fs::write(output_file.as_ref(), &image)?;
    Ok(())
}

/// Create a multi-file legacy U-Boot image from in-memory data slices.
pub fn create_multi_image_bytes(
    params: &ImageParams,
    data_files: &[Vec<u8>],
) -> Result<Vec<u8>> {
    let effective_ep = if params.ep_set {
        params.entry_point
    } else {
        params.load_addr
    };

    let image_type_val = params.image_type as u8;

    // Build the size table + data payload
    // Size table: N * u32-be sizes + terminating 0
    let mut payload = Vec::new();
    for d in data_files {
        payload.extend_from_slice(&(d.len() as u32).to_be_bytes());
    }
    payload.extend_from_slice(&0u32.to_be_bytes()); // terminator

    // Append each file's data, aligned to 4 bytes (except last)
    for (i, d) in data_files.iter().enumerate() {
        payload.extend_from_slice(d);
        if i + 1 < data_files.len() {
            // Pad to 4-byte alignment
            let tail = d.len() % 4;
            if tail != 0 {
                payload.extend_from_slice(&vec![0u8; 4 - tail]);
            }
        }
    }

    // Compute data CRC
    let dcrc = crc32(&payload);
    let time = get_source_date(None);

    let mut hdr = LegacyImageHeader {
        ih_magic: IH_MAGIC,
        ih_hcrc: 0,
        ih_time: time,
        ih_size: payload.len() as u32,
        ih_load: params.load_addr,
        ih_ep: effective_ep,
        ih_dcrc: dcrc,
        ih_os: params.os as u8,
        ih_arch: params.arch as u8,
        ih_type: image_type_val,
        ih_comp: params.compression as u8,
        ih_name: [0u8; IH_NMLEN],
    };

    let name_bytes = params.name.as_bytes();
    let copy_len = name_bytes.len().min(IH_NMLEN);
    hdr.ih_name[..copy_len].copy_from_slice(&name_bytes[..copy_len]);

    let hdr_bytes = hdr.to_bytes();
    let hcrc = crc32(&hdr_bytes);
    hdr.ih_hcrc = hcrc;

    let mut image = Vec::with_capacity(LEGACY_HEADER_SIZE + payload.len());
    image.extend_from_slice(&hdr.to_bytes());
    image.extend_from_slice(&payload);

    Ok(image)
}

/// Create a legacy image with no data (empty body, ih_size = 0).
pub fn create_empty_image(
    params: &ImageParams,
    output_file: impl AsRef<Path>,
) -> Result<()> {
    let effective_ep = if params.ep_set {
        params.entry_point
    } else {
        params.load_addr
    };

    let time = get_source_date(None);

    let image_type_val = if params.image_type == ImageType::FdtLegacy {
        ImageType::FlatDt as u8
    } else {
        params.image_type as u8
    };

    let mut hdr = LegacyImageHeader {
        ih_magic: IH_MAGIC,
        ih_hcrc: 0,
        ih_time: time,
        ih_size: 0,
        ih_load: params.load_addr,
        ih_ep: effective_ep,
        ih_dcrc: crc32(&[]),
        ih_os: params.os as u8,
        ih_arch: params.arch as u8,
        ih_type: image_type_val,
        ih_comp: params.compression as u8,
        ih_name: [0u8; IH_NMLEN],
    };

    let name_bytes = params.name.as_bytes();
    let copy_len = name_bytes.len().min(IH_NMLEN);
    hdr.ih_name[..copy_len].copy_from_slice(&name_bytes[..copy_len]);

    let hdr_bytes = hdr.to_bytes();
    let hcrc = crc32(&hdr_bytes);
    hdr.ih_hcrc = hcrc;

    fs::write(output_file.as_ref(), hdr.to_bytes())?;
    Ok(())
}

/// Verify an existing image file. Returns `Ok(ImageInfo)` if valid.
pub fn verify_image(path: impl AsRef<Path>) -> Result<ImageInfo> {
    read_image(path)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enum_roundtrip() {
        assert_eq!(Os::from_name("linux"), Some(Os::Linux));
        assert_eq!(Os::Linux as u8, 5);
        assert_eq!(Os::from_u8(5), Some(Os::Linux));

        assert_eq!(Arch::from_name("arm64"), Some(Arch::Arm64));
        assert_eq!(Arch::from_name_ext("powerpc"), Some(Arch::Ppc));

        assert_eq!(ImageType::from_name("kernel"), Some(ImageType::Kernel));
        assert_eq!(Compression::from_name("gzip"), Some(Compression::Gzip));
    }

    #[test]
    fn header_serialize_roundtrip() {
        let mut hdr = LegacyImageHeader::default();
        hdr.ih_magic = IH_MAGIC;
        hdr.ih_size = 0x1234;
        hdr.ih_load = 0x80008000;
        hdr.ih_os = Os::Linux as u8;
        hdr.ih_arch = Arch::Arm as u8;
        hdr.ih_name[..5].copy_from_slice(b"hello");

        let bytes = hdr.to_bytes();
        assert_eq!(bytes.len(), LEGACY_HEADER_SIZE);

        let hdr2 = LegacyImageHeader::from_bytes(&bytes).unwrap();
        assert_eq!(hdr2.ih_magic, IH_MAGIC);
        assert_eq!(hdr2.ih_size, 0x1234);
        assert_eq!(hdr2.ih_load, 0x80008000);
        assert_eq!(hdr2.name_str(), "hello");
    }

    #[test]
    fn create_and_verify_roundtrip() {
        let params = ImageParams::builder()
            .os(Os::Linux)
            .arch(Arch::Arm)
            .image_type(ImageType::Kernel)
            .compression(Compression::None)
            .load_addr(0x80008000)
            .entry_point(0x80008000)
            .name("test image")
            .build();

        let data = vec![0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03, 0x04];
        let image = create_image_bytes(&params, &data).unwrap();

        let info = read_image_bytes(&image).unwrap();
        assert_eq!(info.header.ih_magic, IH_MAGIC);
        assert_eq!(info.header.ih_size, 8);
        assert_eq!(info.header.ih_load, 0x80008000);
        assert_eq!(info.header.ih_ep, 0x80008000);
        assert_eq!(info.header.ih_os, Os::Linux as u8);
        assert_eq!(info.header.ih_arch, Arch::Arm as u8);
        assert_eq!(info.header.name_str(), "test image");
        assert!(info.sub_images.is_empty());
    }

    #[test]
    fn multi_image_roundtrip() {
        let params = ImageParams::builder()
            .os(Os::Linux)
            .arch(Arch::Arm)
            .image_type(ImageType::Multi)
            .compression(Compression::None)
            .load_addr(0x80008000)
            .name("multi test")
            .build();

        let files = vec![
            vec![1u8, 2, 3, 4, 5],
            vec![10u8, 20, 30],
        ];
        let image = create_multi_image_bytes(&params, &files).unwrap();
        let info = read_image_bytes(&image).unwrap();

        assert_eq!(info.sub_images.len(), 2);
        assert_eq!(info.sub_images[0].1, 5);
        assert_eq!(info.sub_images[1].1, 3);
    }

    #[test]
    fn bad_magic_detected() {
        let image = vec![0u8; 128];
        // Not a valid magic
        let err = read_image_bytes(&image).unwrap_err();
        assert!(matches!(err, MkImageError::BadMagic));
    }

    #[test]
    fn type_listing() {
        // Verify we can iterate all image types
        let table = ImageType::table();
        assert!(table.len() > 10);
        assert!(table.iter().any(|&(_, short, _)| short == "kernel"));
    }
}
