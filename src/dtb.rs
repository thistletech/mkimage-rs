//! DTB (Device Tree Blob) manipulation.
//!
//! This module provides two interfaces:
//!
//! 1. **Tree-based** — parse DTB to an in-memory tree, modify, and serialize
//!    back. Good for creating DTBs from scratch or tests.
//!
//! 2. **Raw byte-level** — operate directly on DTB bytes, preserving the exact
//!    binary layout produced by `dtc`. This is what the FIT signing pipeline
//!    uses to achieve bit-for-bit compatibility with the original U-Boot
//!    `mkimage`.

use std::collections::HashMap;

use crate::MkImageError;

// ---------------------------------------------------------------------------
// DTB constants
// ---------------------------------------------------------------------------

pub const FDT_MAGIC: u32 = 0xd00dfeed;
pub const FDT_BEGIN_NODE: u32 = 0x00000001;
pub const FDT_END_NODE: u32 = 0x00000002;
pub const FDT_PROP: u32 = 0x00000003;
pub const FDT_NOP: u32 = 0x00000004;
pub const FDT_END: u32 = 0x00000009;

// ---------------------------------------------------------------------------
// DTB header — works on raw bytes
// ---------------------------------------------------------------------------

/// Read a big-endian u32 from a byte slice at the given offset.
pub fn get_u32(data: &[u8], off: usize) -> u32 {
    u32::from_be_bytes(data[off..off + 4].try_into().unwrap())
}

/// Write a big-endian u32 into a byte slice at the given offset.
pub fn put_u32(data: &mut [u8], off: usize, val: u32) {
    data[off..off + 4].copy_from_slice(&val.to_be_bytes());
}

// Header field offsets
pub const HDR_MAGIC: usize = 0;
pub const HDR_TOTALSIZE: usize = 4;
pub const HDR_OFF_DT_STRUCT: usize = 8;
pub const HDR_OFF_DT_STRINGS: usize = 12;
pub const HDR_OFF_MEM_RSVMAP: usize = 16;
pub const HDR_VERSION: usize = 20;
pub const HDR_LAST_COMP_VERSION: usize = 24;
pub const HDR_BOOT_CPUID_PHYS: usize = 28;
pub const HDR_SIZE_DT_STRINGS: usize = 32;
pub const HDR_SIZE_DT_STRUCT: usize = 36;
pub const HDR_SIZE: usize = 40;

#[inline]
pub fn fdt_totalsize(dtb: &[u8]) -> usize {
    get_u32(dtb, HDR_TOTALSIZE) as usize
}
#[inline]
pub fn fdt_off_dt_struct(dtb: &[u8]) -> usize {
    get_u32(dtb, HDR_OFF_DT_STRUCT) as usize
}
#[inline]
pub fn fdt_off_dt_strings(dtb: &[u8]) -> usize {
    get_u32(dtb, HDR_OFF_DT_STRINGS) as usize
}
#[inline]
pub fn fdt_size_dt_struct(dtb: &[u8]) -> usize {
    get_u32(dtb, HDR_SIZE_DT_STRUCT) as usize
}
#[inline]
pub fn fdt_size_dt_strings(dtb: &[u8]) -> usize {
    get_u32(dtb, HDR_SIZE_DT_STRINGS) as usize
}

pub fn fdt_check_header(dtb: &[u8]) -> Result<(), MkImageError> {
    if dtb.len() < HDR_SIZE {
        return Err(MkImageError::TooSmall {
            size: dtb.len(),
            min: HDR_SIZE,
        });
    }
    if get_u32(dtb, HDR_MAGIC) != FDT_MAGIC {
        return Err(MkImageError::Other("bad DTB magic".into()));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Raw DTB navigation — libfdt-like API on &[u8] / &mut Vec<u8>
// ---------------------------------------------------------------------------

/// Get the name of a NUL-terminated string from the strings block.
pub fn fdt_string<'a>(dtb: &'a [u8], nameoff: usize) -> &'a str {
    let base = fdt_off_dt_strings(dtb) + nameoff;
    let mut end = base;
    while end < dtb.len() && dtb[end] != 0 {
        end += 1;
    }
    std::str::from_utf8(&dtb[base..end]).unwrap_or("")
}

/// Advance past a tag at `offset` → return the offset after this tag's payload
/// (the next tag position). `offset` must point to a tag u32.
pub fn fdt_next_tag(dtb: &[u8], offset: usize) -> (u32, usize) {
    let tag = get_u32(dtb, offset);
    let mut pos = offset + 4;
    match tag {
        FDT_BEGIN_NODE => {
            // skip NUL-terminated name, 4-byte aligned
            while pos < dtb.len() && dtb[pos] != 0 {
                pos += 1;
            }
            pos += 1;
            pos = (pos + 3) & !3;
        }
        FDT_PROP => {
            let len = get_u32(dtb, pos) as usize;
            pos += 8 + len; // skip len + nameoff + value
            pos = (pos + 3) & !3;
        }
        FDT_END_NODE | FDT_NOP | FDT_END => {}
        _ => {}
    }
    (tag, pos)
}

/// Get the name of a node at `offset` (which must point to a FDT_BEGIN_NODE tag).
pub fn fdt_get_name<'a>(dtb: &'a [u8], offset: usize) -> &'a str {
    // name starts at offset+4, NUL terminated
    let start = offset + 4;
    let mut end = start;
    while end < dtb.len() && dtb[end] != 0 {
        end += 1;
    }
    std::str::from_utf8(&dtb[start..end]).unwrap_or("")
}

/// Find the offset of a node given a path like "/images/kernel-1".
/// Returns the offset of the FDT_BEGIN_NODE tag, or None.
pub fn fdt_path_offset(dtb: &[u8], path: &str) -> Option<usize> {
    let base = fdt_off_dt_struct(dtb);
    let mut pos = base;
    let mut depth: i32 = -1;
    let mut current_path = String::with_capacity(256);

    loop {
        if pos >= base + fdt_size_dt_struct(dtb) {
            return None;
        }
        let tag_offset = pos;
        let (tag, next) = fdt_next_tag(dtb, pos);
        match tag {
            FDT_BEGIN_NODE => {
                depth += 1;
                let name = fdt_get_name(dtb, tag_offset);
                if depth == 0 {
                    current_path.clear();
                    current_path.push('/');
                } else {
                    if current_path != "/" {
                        current_path.push('/');
                    }
                    current_path.push_str(name);
                }
                if current_path == path {
                    return Some(tag_offset);
                }
            }
            FDT_END_NODE => {
                if let Some(last_slash) = current_path.rfind('/') {
                    if last_slash == 0 {
                        current_path.truncate(1);
                    } else {
                        current_path.truncate(last_slash);
                    }
                }
                depth -= 1;
            }
            FDT_END => return None,
            _ => {}
        }
        pos = next;
    }
}

/// Return the offset of the first child node of the node at `parent_offset`.
/// `parent_offset` must point to a FDT_BEGIN_NODE tag.
pub fn fdt_first_subnode(dtb: &[u8], parent_offset: usize) -> Option<usize> {
    // Skip past the parent's BEGIN_NODE tag + name
    let (_, mut pos) = fdt_next_tag(dtb, parent_offset);
    // Now walk past properties to find the first child node
    loop {
        let (tag, next) = fdt_next_tag(dtb, pos);
        match tag {
            FDT_BEGIN_NODE => return Some(pos),
            FDT_PROP | FDT_NOP => {
                pos = next;
            }
            _ => return None, // FDT_END_NODE or FDT_END
        }
    }
}

/// Return the offset of the next sibling node after `node_offset`.
/// Skips over all children of the current node.
pub fn fdt_next_subnode(dtb: &[u8], node_offset: usize) -> Option<usize> {
    // We start inside the current node (depth=1). Walk until we find the
    // matching END_NODE (depth drops to 0), then check for a sibling.
    let mut depth = 1i32;
    let (_, mut pos) = fdt_next_tag(dtb, node_offset); // skip current BEGIN_NODE
    loop {
        let (tag, next) = fdt_next_tag(dtb, pos);
        match tag {
            FDT_BEGIN_NODE => depth += 1,
            FDT_END_NODE => {
                depth -= 1;
                if depth == 0 {
                    // We've closed the current node. Check what follows.
                    let (peek, _) = fdt_next_tag(dtb, next);
                    if peek == FDT_BEGIN_NODE {
                        return Some(next); // next sibling
                    }
                    return None; // parent's END_NODE — no more siblings
                }
            }
            FDT_END => return None,
            _ => {}
        }
        pos = next;
    }
}

/// Get a property value from a node. Returns (value_slice, prop_data_offset).
/// `node_offset` must point to a FDT_BEGIN_NODE tag.
/// The property must be a direct property of this node (not a child's property).
pub fn fdt_getprop<'a>(dtb: &'a [u8], node_offset: usize, name: &str) -> Option<&'a [u8]> {
    fdt_getprop_offset(dtb, node_offset, name).map(|(_, val_off, len)| &dtb[val_off..val_off + len])
}

/// Like `fdt_getprop` but also returns the offset of the FDT_PROP tag and
/// the offset of the value data and its length.
/// Returns (prop_tag_offset, value_data_offset, value_len).
fn fdt_getprop_offset(dtb: &[u8], node_offset: usize, name: &str) -> Option<(usize, usize, usize)> {
    let (_, mut pos) = fdt_next_tag(dtb, node_offset);
    loop {
        let tag = get_u32(dtb, pos);
        match tag {
            FDT_PROP => {
                let len = get_u32(dtb, pos + 4) as usize;
                let nameoff = get_u32(dtb, pos + 8) as usize;
                let prop_name = fdt_string(dtb, nameoff);
                let val_off = pos + 12;
                if prop_name == name {
                    return Some((pos, val_off, len));
                }
                let next = (val_off + len + 3) & !3;
                pos = next;
            }
            FDT_NOP => {
                pos += 4;
            }
            _ => return None, // FDT_BEGIN_NODE (child) or FDT_END_NODE
        }
    }
}

/// Get property as a string (strip trailing NUL).
pub fn fdt_getprop_str<'a>(dtb: &'a [u8], node_offset: usize, name: &str) -> Option<&'a str> {
    fdt_getprop(dtb, node_offset, name).and_then(|v| {
        let end = v.iter().position(|&b| b == 0).unwrap_or(v.len());
        std::str::from_utf8(&v[..end]).ok()
    })
}

/// Get property as a string list (NUL-separated).
pub fn fdt_getprop_stringlist(dtb: &[u8], node_offset: usize, name: &str) -> Vec<String> {
    let Some(val) = fdt_getprop(dtb, node_offset, name) else {
        return Vec::new();
    };
    let mut result = Vec::new();
    let mut start = 0;
    for i in 0..val.len() {
        if val[i] == 0 && i > start {
            if let Ok(s) = std::str::from_utf8(&val[start..i]) {
                result.push(s.to_string());
            }
            start = i + 1;
        } else if val[i] == 0 {
            start = i + 1;
        }
    }
    result
}

/// Count how many strings are in a stringlist property.
pub fn fdt_stringlist_count(dtb: &[u8], node_offset: usize, name: &str) -> usize {
    fdt_getprop_stringlist(dtb, node_offset, name).len()
}

// ---------------------------------------------------------------------------
// Raw DTB modification — in-place on Vec<u8>
//
// These functions mirror libfdt's behavior: all modifications happen within
// the pre-allocated `totalsize` buffer. The Vec length equals totalsize.
// Struct insertions shift the strings block forward (into padding), and
// string additions grow at the end (into padding). totalsize never changes.
// ---------------------------------------------------------------------------

/// Actual data size: off_dt_strings + size_dt_strings.
/// Everything beyond this (up to totalsize) is padding.
fn fdt_data_size(dtb: &[u8]) -> usize {
    fdt_off_dt_strings(dtb) + fdt_size_dt_strings(dtb)
}

/// Pack a DTB: set totalsize to the actual data size (removing all trailing
/// padding). Mirrors `fdt_pack()` from libfdt.  For v17 DTBs produced by
/// `dtc` the blocks are already in canonical order so we only need to adjust
/// `totalsize` and truncate the Vec.
pub fn fdt_pack(dtb: &mut Vec<u8>) {
    let data_sz = fdt_data_size(dtb);
    put_u32(dtb, HDR_TOTALSIZE, data_sz as u32);
    dtb.truncate(data_sz);
}

/// Core splice operation: within the fixed-size `dtb` buffer, replace
/// `oldlen` bytes at `soff` with `newlen` bytes (shifting data as needed).
/// Does NOT update any header fields.
///
/// Mirrors libfdt's `fdt_splice_()`. Panics if there's not enough space.
fn fdt_splice(dtb: &mut [u8], soff: usize, oldlen: usize, newlen: usize) {
    let dsize = fdt_data_size(dtb);
    let new_dsize = (dsize as isize + (newlen as isize - oldlen as isize)) as usize;
    assert!(
        new_dsize <= fdt_totalsize(dtb),
        "fdt_splice: not enough space (need {}, have {})",
        new_dsize,
        fdt_totalsize(dtb)
    );
    // memmove(p + newlen, p + oldlen, dsize - (soff + oldlen))
    let src_start = soff + oldlen;
    let count = dsize - src_start;
    dtb.copy_within(src_start..src_start + count, soff + newlen);
    // Zero-fill freed bytes at the tail (when shrinking)
    if new_dsize < dsize {
        for i in new_dsize..dsize {
            dtb[i] = 0;
        }
    }
}

/// Find or add a string in the strings block. Returns the offset within the
/// strings block. Appends at the end of the strings block (into padding),
/// matching libfdt's fdt_splice_string_ behavior.
fn fdt_find_or_add_string(dtb: &mut Vec<u8>, name: &str) -> usize {
    let strings_off = fdt_off_dt_strings(dtb);
    let strings_size = fdt_size_dt_strings(dtb);

    // Search existing strings
    let mut pos = 0;
    while pos < strings_size {
        let s_start = strings_off + pos;
        let mut s_end = s_start;
        while s_end < dtb.len() && dtb[s_end] != 0 {
            s_end += 1;
        }
        let existing = std::str::from_utf8(&dtb[s_start..s_end]).unwrap_or("");
        if existing == name {
            return pos;
        }
        pos += existing.len() + 1;
    }

    // Not found — append at the end of the strings block.
    // In libfdt, fdt_splice_string_ inserts at off_dt_strings + size_dt_strings.
    // Since strings are at the end of the data area (just before padding), this
    // effectively writes into the padding. totalsize does not change.
    let new_off = strings_size;
    let write_pos = strings_off + strings_size;
    let name_bytes = name.as_bytes();
    let need = name_bytes.len() + 1; // +1 for NUL

    // Splice (effectively a no-op memmove since we're at the end of data,
    // just need to check space)
    fdt_splice(dtb, write_pos, 0, need);

    // Write the string
    dtb[write_pos..write_pos + name_bytes.len()].copy_from_slice(name_bytes);
    dtb[write_pos + name_bytes.len()] = 0;

    // Update header: size_dt_strings += need. totalsize unchanged.
    let new_strings_size = strings_size + need;
    put_u32(dtb, HDR_SIZE_DT_STRINGS, new_strings_size as u32);

    new_off
}

/// Set a property on a node. If the property exists, its value is replaced.
/// If it doesn't exist, it's created (inserted after the last existing
/// property, before the first child node or END_NODE).
///
/// All modifications happen in-place within the existing `totalsize` buffer.
/// The DTB must have been pre-expanded with enough padding (via
/// `fdt_open_into` or `dtc -p`).
pub fn fdt_setprop(dtb: &mut Vec<u8>, node_offset: usize, name: &str, value: &[u8]) {
    let padded_len = (value.len() + 3) & !3;

    if let Some((prop_off, val_off, old_len)) = fdt_getprop_offset(dtb, node_offset, name) {
        // Property exists — replace value (like libfdt's fdt_resize_property_)
        let old_padded = (old_len + 3) & !3;

        if padded_len != old_padded {
            // Splice the value region: replace old_padded bytes with padded_len bytes
            fdt_splice(dtb, val_off, old_padded, padded_len);

            let delta = padded_len as isize - old_padded as isize;
            let s = fdt_size_dt_struct(dtb);
            put_u32(dtb, HDR_SIZE_DT_STRUCT, (s as isize + delta) as u32);
            let o = fdt_off_dt_strings(dtb);
            put_u32(dtb, HDR_OFF_DT_STRINGS, (o as isize + delta) as u32);
        }

        // Write new length + value. Do NOT zero padding bytes — match
        // libfdt behavior where padding contains residual data.
        put_u32(dtb, prop_off + 4, value.len() as u32);
        dtb[val_off..val_off + value.len()].copy_from_slice(value);
    } else {
        // Property doesn't exist — insert a new FDT_PROP entry.
        // First, ensure the property name is in the strings block.
        let nameoff = fdt_find_or_add_string(dtb, name);

        // Insert at the BEGINNING of the node's property list (right after
        // the BEGIN_NODE tag + name), matching libfdt's fdt_add_property_
        // behavior. This means properties are prepended, not appended.
        let (_, insert_pos) = fdt_next_tag(dtb, node_offset);

        // Splice in the struct block to make room
        let entry_size = 12 + padded_len;
        fdt_splice(dtb, insert_pos, 0, entry_size);

        // Write the property entry. Do NOT zero padding bytes — match
        // libfdt behavior where padding contains residual data from memmove.
        put_u32(dtb, insert_pos, FDT_PROP);
        put_u32(dtb, insert_pos + 4, value.len() as u32);
        put_u32(dtb, insert_pos + 8, nameoff as u32);
        dtb[insert_pos + 12..insert_pos + 12 + value.len()].copy_from_slice(value);

        // Update header: struct grew, strings shifted. totalsize unchanged.
        let s = fdt_size_dt_struct(dtb);
        put_u32(dtb, HDR_SIZE_DT_STRUCT, (s + entry_size) as u32);
        let o = fdt_off_dt_strings(dtb);
        put_u32(dtb, HDR_OFF_DT_STRINGS, (o + entry_size) as u32);
    }
}

/// Convenience: set a string property (auto-adds NUL terminator).
pub fn fdt_setprop_string(dtb: &mut Vec<u8>, node_offset: usize, name: &str, val: &str) {
    let mut v = val.as_bytes().to_vec();
    v.push(0);
    fdt_setprop(dtb, node_offset, name, &v);
}

/// Convenience: set a u32 property (big-endian).
pub fn fdt_setprop_u32(dtb: &mut Vec<u8>, node_offset: usize, name: &str, val: u32) {
    fdt_setprop(dtb, node_offset, name, &val.to_be_bytes());
}

// ---------------------------------------------------------------------------
// fdt_find_regions — port of U-Boot's fdt_region.c
// ---------------------------------------------------------------------------

/// A byte region within a DTB blob.
#[derive(Debug, Clone, Copy)]
pub struct FdtRegion {
    pub offset: usize,
    pub size: usize,
}

/// Find the byte regions of a DTB that correspond to specific node paths.
///
/// Faithful port of U-Boot's `fdt_find_regions()` from `boot/fdt_region.c`.
///
/// * `dtb` — raw DTB bytes
/// * `inc` — list of node paths to include (e.g. `["/", "/images/kernel-1"]`)
/// * `exc_prop` — property names to exclude (e.g. `["data", "data-size"]`)
/// * `add_string_tab` — if true, append the string table as the last region
pub fn fdt_find_regions(
    dtb: &[u8],
    inc: &[String],
    exc_prop: &[&str],
    add_string_tab: bool,
) -> Result<Vec<FdtRegion>, MkImageError> {
    fdt_check_header(dtb)?;
    let base = fdt_off_dt_struct(dtb);

    const MAX_DEPTH: usize = 32;
    let mut stack = [0i32; MAX_DEPTH];
    let mut path = String::with_capacity(256);
    let mut regions: Vec<FdtRegion> = Vec::new();
    let mut start: i64 = -1; // relative to struct block start
    let mut want: i32 = 0;
    let mut depth: i32 = -1;
    let mut pos = base;

    loop {
        let offset = pos;
        let (tag, nextoffset) = fdt_next_tag(dtb, pos);
        pos = nextoffset;

        let mut stop_at: usize;
        let include: bool;

        match tag {
            FDT_BEGIN_NODE => {
                let name = fdt_get_name(dtb, offset);
                depth += 1;
                if depth as usize >= MAX_DEPTH {
                    return Err(MkImageError::Other("DTB too deep".into()));
                }
                if depth == 0 {
                    path.clear();
                    path.push('/');
                } else {
                    if path != "/" {
                        path.push('/');
                    }
                    path.push_str(name);
                }
                stack[depth as usize] = want;
                stop_at = if want == 1 { offset } else { nextoffset };
                if inc.iter().any(|p| p == &path) {
                    want = 2;
                } else if want > 0 {
                    want -= 1;
                } else {
                    stop_at = offset;
                }
                include = want > 0;
            }
            FDT_END_NODE => {
                stop_at = nextoffset;
                if depth < 0 {
                    return Err(MkImageError::Other("DTB END_NODE underflow".into()));
                }
                include = want > 0;
                want = stack[depth as usize];
                depth -= 1;
                if let Some(last_slash) = path.rfind('/') {
                    if last_slash == 0 {
                        path.truncate(1);
                    } else {
                        path.truncate(last_slash);
                    }
                }
            }
            FDT_PROP => {
                stop_at = offset;
                let nameoff = get_u32(dtb, offset + 8) as usize;
                let prop_name = fdt_string(dtb, nameoff);
                include = want >= 2 && !exc_prop.contains(&prop_name);
            }
            FDT_NOP => {
                stop_at = offset;
                include = want >= 2;
            }
            FDT_END => {
                // FDT_END is always included
                if start == -1 {
                    if !regions.is_empty() {
                        let last = regions.last().unwrap();
                        if (offset - base) == last.offset + last.size - base {
                            start = regions.pop().unwrap().offset as i64 - base as i64;
                        } else {
                            start = (offset - base) as i64;
                        }
                    } else {
                        start = (offset - base) as i64;
                    }
                }
                break;
            }
            _ => {
                return Err(MkImageError::Other(format!(
                    "unknown DTB tag 0x{:08x} at 0x{:x}",
                    tag, offset
                )));
            }
        }

        // Region tracking
        if include && start == -1 {
            if !regions.is_empty() {
                let last = regions.last().unwrap();
                if (offset - base) == last.offset + last.size - base {
                    start = regions.pop().unwrap().offset as i64 - base as i64;
                } else {
                    start = (offset - base) as i64;
                }
            } else {
                start = (offset - base) as i64;
            }
        }

        if !include && start != -1 {
            let s = start as usize;
            regions.push(FdtRegion {
                offset: base + s,
                size: stop_at - base - s,
            });
            start = -1;
        }
    }

    // After loop: add region for END tag + optional string table
    if start >= 0 {
        let s = start as usize;
        let mut size = pos - base - s; // pos is past FDT_END
        if add_string_tab {
            size += fdt_size_dt_strings(dtb);
        }
        regions.push(FdtRegion {
            offset: base + s,
            size,
        });
    }

    Ok(regions)
}

// ---------------------------------------------------------------------------
// In-memory tree representation (kept for tests / tree-based usage)
// ---------------------------------------------------------------------------

/// A property in the device tree: name → value bytes.
#[derive(Debug, Clone)]
pub struct DtProperty {
    pub name: String,
    pub value: Vec<u8>,
}

/// A node in the device tree.
#[derive(Debug, Clone)]
pub struct DtNode {
    pub name: String,
    pub properties: Vec<DtProperty>,
    pub children: Vec<DtNode>,
}

impl DtNode {
    pub fn new(name: &str) -> Self {
        Self {
            name: name.to_string(),
            properties: Vec::new(),
            children: Vec::new(),
        }
    }

    pub fn get_property(&self, name: &str) -> Option<&[u8]> {
        self.properties
            .iter()
            .find(|p| p.name == name)
            .map(|p| p.value.as_slice())
    }

    pub fn get_property_str(&self, name: &str) -> Option<&str> {
        self.get_property(name).and_then(|v| {
            let end = v.iter().position(|&b| b == 0).unwrap_or(v.len());
            std::str::from_utf8(&v[..end]).ok()
        })
    }

    pub fn get_property_u32(&self, name: &str) -> Option<u32> {
        self.get_property(name).and_then(|v| {
            if v.len() >= 4 {
                Some(u32::from_be_bytes(v[..4].try_into().unwrap()))
            } else {
                None
            }
        })
    }

    pub fn set_property(&mut self, name: &str, value: Vec<u8>) -> Option<Vec<u8>> {
        if let Some(prop) = self.properties.iter_mut().find(|p| p.name == name) {
            let old = std::mem::replace(&mut prop.value, value);
            Some(old)
        } else {
            self.properties.push(DtProperty {
                name: name.to_string(),
                value,
            });
            None
        }
    }

    pub fn set_property_str(&mut self, name: &str, val: &str) {
        let mut v = val.as_bytes().to_vec();
        v.push(0);
        self.set_property(name, v);
    }

    pub fn set_property_u32(&mut self, name: &str, val: u32) {
        self.set_property(name, val.to_be_bytes().to_vec());
    }

    pub fn child(&self, name: &str) -> Option<&DtNode> {
        self.children.iter().find(|c| c.name == name)
    }

    pub fn child_mut(&mut self, name: &str) -> Option<&mut DtNode> {
        self.children.iter_mut().find(|c| c.name == name)
    }

    pub fn find_node(&self, path: &str) -> Option<&DtNode> {
        if path == "/" {
            return Some(self);
        }
        let path = path.strip_prefix('/').unwrap_or(path);
        let mut node = self;
        for component in path.split('/') {
            if component.is_empty() {
                continue;
            }
            node = node.child(component)?;
        }
        Some(node)
    }

    pub fn find_node_mut(&mut self, path: &str) -> Option<&mut DtNode> {
        if path == "/" {
            return Some(self);
        }
        let path = path.strip_prefix('/').unwrap_or(path);
        let mut node = self;
        for component in path.split('/') {
            if component.is_empty() {
                continue;
            }
            node = node.child_mut(component)?;
        }
        Some(node)
    }
}

// ---------------------------------------------------------------------------
// Parse DTB → tree
// ---------------------------------------------------------------------------

struct Parser<'a> {
    data: &'a [u8],
    strings_off: usize,
    pos: usize,
}

impl<'a> Parser<'a> {
    fn read_u32(&mut self) -> u32 {
        let v = get_u32(self.data, self.pos);
        self.pos += 4;
        v
    }

    fn read_string_nul(&mut self) -> String {
        let start = self.pos;
        while self.pos < self.data.len() && self.data[self.pos] != 0 {
            self.pos += 1;
        }
        let s = std::str::from_utf8(&self.data[start..self.pos])
            .unwrap_or("")
            .to_string();
        self.pos += 1;
        self.pos = (self.pos + 3) & !3;
        s
    }

    fn get_string(&self, off: usize) -> String {
        let start = self.strings_off + off;
        let mut end = start;
        while end < self.data.len() && self.data[end] != 0 {
            end += 1;
        }
        std::str::from_utf8(&self.data[start..end])
            .unwrap_or("")
            .to_string()
    }

    fn parse_node(&mut self) -> Result<DtNode, MkImageError> {
        let name = self.read_string_nul();
        let mut node = DtNode::new(&name);

        loop {
            let tag = self.read_u32();
            match tag {
                FDT_PROP => {
                    let len = self.read_u32() as usize;
                    let nameoff = self.read_u32() as usize;
                    let prop_name = self.get_string(nameoff);
                    let value = self.data[self.pos..self.pos + len].to_vec();
                    self.pos += len;
                    self.pos = (self.pos + 3) & !3;
                    node.properties.push(DtProperty {
                        name: prop_name,
                        value,
                    });
                }
                FDT_BEGIN_NODE => {
                    node.children.push(self.parse_node()?);
                }
                FDT_END_NODE => return Ok(node),
                FDT_NOP => {}
                _ => {
                    return Err(MkImageError::Other(format!(
                        "unexpected DTB tag 0x{:08x} at offset {}",
                        tag,
                        self.pos - 4
                    )));
                }
            }
        }
    }
}

/// Parse a DTB blob into an in-memory tree.
pub fn parse_dtb(data: &[u8]) -> Result<DtNode, MkImageError> {
    fdt_check_header(data)?;
    let struct_off = fdt_off_dt_struct(data);
    let strings_off = fdt_off_dt_strings(data);
    let mut parser = Parser {
        data,
        strings_off,
        pos: struct_off,
    };
    let tag = parser.read_u32();
    if tag != FDT_BEGIN_NODE {
        return Err(MkImageError::Other(
            "expected FDT_BEGIN_NODE for root".into(),
        ));
    }
    parser.parse_node()
}

// ---------------------------------------------------------------------------
// Serialize tree → DTB
// ---------------------------------------------------------------------------

struct Serializer {
    struct_buf: Vec<u8>,
    strings_buf: Vec<u8>,
    string_map: HashMap<String, u32>,
}

impl Serializer {
    fn new() -> Self {
        Self {
            struct_buf: Vec::new(),
            strings_buf: Vec::new(),
            string_map: HashMap::new(),
        }
    }

    fn write_u32(&mut self, v: u32) {
        self.struct_buf.extend_from_slice(&v.to_be_bytes());
    }

    fn intern_string(&mut self, s: &str) -> u32 {
        if let Some(&off) = self.string_map.get(s) {
            return off;
        }
        let off = self.strings_buf.len() as u32;
        self.strings_buf.extend_from_slice(s.as_bytes());
        self.strings_buf.push(0);
        self.string_map.insert(s.to_string(), off);
        off
    }

    fn serialize_node(&mut self, node: &DtNode) {
        self.write_u32(FDT_BEGIN_NODE);
        let name_bytes = node.name.as_bytes();
        self.struct_buf.extend_from_slice(name_bytes);
        self.struct_buf.push(0);
        while self.struct_buf.len() % 4 != 0 {
            self.struct_buf.push(0);
        }
        for prop in &node.properties {
            self.write_u32(FDT_PROP);
            self.write_u32(prop.value.len() as u32);
            let nameoff = self.intern_string(&prop.name);
            self.write_u32(nameoff);
            self.struct_buf.extend_from_slice(&prop.value);
            while self.struct_buf.len() % 4 != 0 {
                self.struct_buf.push(0);
            }
        }
        for child in &node.children {
            self.serialize_node(child);
        }
        self.write_u32(FDT_END_NODE);
    }
}

pub fn serialize_dtb(root: &DtNode, extra_space: usize) -> Vec<u8> {
    let mut ser = Serializer::new();
    ser.serialize_node(root);
    ser.write_u32(FDT_END);

    let struct_data = ser.struct_buf;
    let strings_data = ser.strings_buf;
    let mem_rsvmap = [0u8; 16];

    let header_size = 40u32;
    let off_mem_rsvmap = header_size;
    let off_dt_struct = off_mem_rsvmap + mem_rsvmap.len() as u32;
    let off_dt_strings = off_dt_struct + struct_data.len() as u32;
    let totalsize = off_dt_strings + strings_data.len() as u32 + extra_space as u32;

    let mut out = Vec::with_capacity(totalsize as usize);
    out.extend_from_slice(&FDT_MAGIC.to_be_bytes());
    out.extend_from_slice(&totalsize.to_be_bytes());
    out.extend_from_slice(&off_dt_struct.to_be_bytes());
    out.extend_from_slice(&off_dt_strings.to_be_bytes());
    out.extend_from_slice(&off_mem_rsvmap.to_be_bytes());
    out.extend_from_slice(&17u32.to_be_bytes());
    out.extend_from_slice(&16u32.to_be_bytes());
    out.extend_from_slice(&0u32.to_be_bytes());
    out.extend_from_slice(&(strings_data.len() as u32).to_be_bytes());
    out.extend_from_slice(&(struct_data.len() as u32).to_be_bytes());
    out.extend_from_slice(&mem_rsvmap);
    out.extend_from_slice(&struct_data);
    out.extend_from_slice(&strings_data);
    out.resize(totalsize as usize, 0);
    out
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_simple_tree() -> DtNode {
        let mut root = DtNode::new("");
        root.set_property_str("compatible", "test");
        root.set_property_u32("#address-cells", 1);
        let mut child = DtNode::new("child");
        child.set_property_str("status", "okay");
        child.set_property("data", vec![1, 2, 3, 4]);
        root.children.push(child);
        root
    }

    #[test]
    fn roundtrip_serialize_parse() {
        let tree = make_simple_tree();
        let dtb = serialize_dtb(&tree, 0);
        let parsed = parse_dtb(&dtb).unwrap();
        assert_eq!(parsed.get_property_str("compatible"), Some("test"));
        assert_eq!(parsed.get_property_u32("#address-cells"), Some(1));
        let child = parsed.child("child").unwrap();
        assert_eq!(child.get_property_str("status"), Some("okay"));
    }

    #[test]
    fn raw_fdt_path_offset() {
        let tree = make_simple_tree();
        let dtb = serialize_dtb(&tree, 0);
        assert!(fdt_path_offset(&dtb, "/").is_some());
        assert!(fdt_path_offset(&dtb, "/child").is_some());
        assert!(fdt_path_offset(&dtb, "/nonexistent").is_none());
    }

    #[test]
    fn raw_fdt_getprop() {
        let tree = make_simple_tree();
        let dtb = serialize_dtb(&tree, 0);
        let root_off = fdt_path_offset(&dtb, "/").unwrap();
        assert_eq!(fdt_getprop_str(&dtb, root_off, "compatible"), Some("test"));
        let child_off = fdt_path_offset(&dtb, "/child").unwrap();
        assert_eq!(
            fdt_getprop(&dtb, child_off, "data"),
            Some([1u8, 2, 3, 4].as_slice())
        );
    }

    #[test]
    fn raw_fdt_setprop_overwrite() {
        let tree = make_simple_tree();
        let mut dtb = serialize_dtb(&tree, 256);
        let child_off = fdt_path_offset(&dtb, "/child").unwrap();
        fdt_setprop(&mut dtb, child_off, "data", &[5, 6, 7, 8]);
        let child_off = fdt_path_offset(&dtb, "/child").unwrap();
        assert_eq!(
            fdt_getprop(&dtb, child_off, "data"),
            Some([5u8, 6, 7, 8].as_slice())
        );
    }

    #[test]
    fn raw_fdt_setprop_grow() {
        let tree = make_simple_tree();
        let mut dtb = serialize_dtb(&tree, 256);
        let child_off = fdt_path_offset(&dtb, "/child").unwrap();
        fdt_setprop(&mut dtb, child_off, "data", &[1, 2, 3, 4, 5, 6, 7, 8]);
        let child_off = fdt_path_offset(&dtb, "/child").unwrap();
        assert_eq!(
            fdt_getprop(&dtb, child_off, "data"),
            Some([1u8, 2, 3, 4, 5, 6, 7, 8].as_slice())
        );
    }

    #[test]
    fn raw_fdt_setprop_new() {
        let tree = make_simple_tree();
        let mut dtb = serialize_dtb(&tree, 256);
        let child_off = fdt_path_offset(&dtb, "/child").unwrap();
        fdt_setprop_string(&mut dtb, child_off, "new-prop", "hello");
        let child_off = fdt_path_offset(&dtb, "/child").unwrap();
        assert_eq!(fdt_getprop_str(&dtb, child_off, "new-prop"), Some("hello"));
        // Old properties still accessible
        assert_eq!(fdt_getprop_str(&dtb, child_off, "status"), Some("okay"));
    }

    #[test]
    fn raw_subnodes() {
        let tree = make_simple_tree();
        let dtb = serialize_dtb(&tree, 0);
        let root_off = fdt_path_offset(&dtb, "/").unwrap();
        let first = fdt_first_subnode(&dtb, root_off).unwrap();
        assert_eq!(fdt_get_name(&dtb, first), "child");
        assert!(fdt_next_subnode(&dtb, first).is_none());
    }

    #[test]
    fn fdt_regions_basic() {
        let tree = make_simple_tree();
        let dtb = serialize_dtb(&tree, 0);
        let regions = fdt_find_regions(
            &dtb,
            &["/".to_string(), "/child".to_string()],
            &["data"],
            true,
        )
        .unwrap();
        assert!(!regions.is_empty());
    }
}
