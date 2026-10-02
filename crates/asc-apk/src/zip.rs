//! ZIP/APK central-directory parser.
//!
//! Implements the PKWARE APPNOTE.TXT fixed-record layouts:
//!   - End of Central Directory Record (EOCD, sig `PK\x05\x06`)
//!   - ZIP64 End of Central Directory Record (sig `PK\x06\x06`)
//!   - ZIP64 End of Central Directory Locator (sig `PK\x06\x07`)
//!   - Central Directory File Header (sig `PK\x01\x02`)
//!
//! Every offset read from the input is bounds-checked before use; every
//! iteration count is bounded by the remaining bytes so that a truncated
//! file yields `Err(Truncated)` instead of a panic.

use crate::entry::{Compression, DexEntry};
use crate::error::ApkError;

/// EOCD fixed-size record: 22 bytes (without the comment).
const EOCD_FIXED_LEN: usize = 22;
/// ZIP64 EOCD locator: 20 bytes including its signature.
const ZIP64_LOCATOR_LEN: usize = 20;
/// ZIP64 EOCD record: 56 bytes including its signature.
const ZIP64_EOCD_FIXED_LEN: usize = 56;
/// Central directory file header: 46 bytes fixed (without name/extra/comment).
const CD_FIXED_LEN: usize = 46;
/// Local file header: 30 bytes fixed (without name/extra).
const LH_FIXED_LEN: usize = 30;

/// Maximum comment length the EOCD scanner is willing to scan backwards
/// through. The PKWARE APPNOTE limits this to 65535; we add the 22-byte
/// EOCD fixed record on top so the maximum search window is 65557 bytes.
const EOCD_MAX_BACKSCAN: usize = 65_557;

/// Signature magic numbers (little-endian u32).
const SIG_EOCD: u32 = 0x0605_4b50;
const SIG_EOCD64: u32 = 0x0606_4b50;
/// ZIP64 EOCD locator signature `PK\x06\x07`. Bytes are
/// `50 4B 06 07`; little-endian interpretation makes `0x07` the
/// high byte, so the u32 constant is `0x0706_4b50`. (Ascending
/// pattern across the ZIP64 family: EOCD64 record `PK\x06\x06` →
/// `0x06064b50`, locator `PK\x06\x07` → `0x07064b50`.)
const SIG_LOCATOR64: u32 = 0x0706_4b50;
const SIG_CENTRAL: u32 = 0x0201_4b50;
const SIG_LOCAL: u32 = 0x0403_4b50;

/// ZIP64 placeholder value in 16/32-bit fields.
const U16_PLACEHOLDER: u16 = 0xFFFF;
const U32_PLACEHOLDER: u32 = 0xFFFF_FFFF;
/// Extra-field header ID for ZIP64 extended information.
const ZIP64_EXTRA_ID: u16 = 0x0001;

/// Parse the ZIP central directory of a ZIP/APK archive and return every
/// entry in directory order. Both `Apk` and `ZipView` route through this.
///
/// `buf` is the entire archive mapped or loaded into memory; this function
/// performs no I/O of its own.
pub(crate) fn parse_directory(buf: &[u8]) -> Result<Vec<DexEntry>, ApkError> {
    let len = buf.len();

    // ---- Locate the EOCD ----
    // Scan backwards from EOF within min(len, 65536+22) for the EOCD signature
    // (matches the Python oracle's `mm.rfind(_EOCD_SIG, search_start)`).
    let eocd_pos = locate_eocd(buf, len)?;
    debug_assert!(eocd_pos + EOCD_FIXED_LEN <= len);

    // ---- Read EOCD fixed fields (22 bytes) ----
    let entries_disk = read_u16(buf, eocd_pos + 8);
    let entries_total = read_u16(buf, eocd_pos + 10);
    let cd_size_32 = read_u32(buf, eocd_pos + 12);
    let cd_off_32 = read_u32(buf, eocd_pos + 16);
    let comment_len = read_u16(buf, eocd_pos + 20) as usize;

    let end_of_eocd = eocd_pos + EOCD_FIXED_LEN + comment_len;
    if end_of_eocd > len {
        return Err(ApkError::Truncated("EOCD comment overruns EOF"));
    }

    let mut entries_total_u64: u64 = entries_total.into();
    let mut cd_size: u64 = cd_size_32.into();
    let mut cd_off: u64 = cd_off_32.into();

    // ---- ZIP64 resolution ----
    let needs_zip64 = entries_total == U16_PLACEHOLDER
        || cd_size_32 == U32_PLACEHOLDER
        || cd_off_32 == U32_PLACEHOLDER;

    if needs_zip64 {
        // EOCD64 locator sits in the 20 bytes immediately before the EOCD.
        if eocd_pos < ZIP64_LOCATOR_LEN {
            return Err(ApkError::Unsupported(
                "ZIP64 EOCD locator missing (file too small)",
            ));
        }
        let locator_pos = eocd_pos - ZIP64_LOCATOR_LEN;
        if read_u32(buf, locator_pos) != SIG_LOCATOR64 {
            return Err(ApkError::Unsupported(
                "ZIP64 EOCD locator signature missing where required",
            ));
        }
        let eocd64_off = read_u64(buf, locator_pos + 8);

        // EOCD64 record is fixed 56 bytes; bounds-check before reading.
        if eocd64_off
            .checked_add(ZIP64_EOCD_FIXED_LEN as u64)
            .is_none_or(|end| end > len as u64)
        {
            return Err(ApkError::Truncated("ZIP64 EOCD record overruns EOF"));
        }
        let eocd64_pos = eocd64_off as usize;
        if read_u32(buf, eocd64_pos) != SIG_EOCD64 {
            return Err(ApkError::BadSignature { at: eocd64_off });
        }
        // The 8-byte "size of zip64 EOCD record" field at offset 4 is not
        // consulted further; the APPNOTE says it includes everything after
        // itself but no version of any tool we know writes more.
        let e64_entries = read_u64(buf, eocd64_pos + 32);
        let e64_cd_size = read_u64(buf, eocd64_pos + 40);
        let e64_cd_off = read_u64(buf, eocd64_pos + 48);

        if entries_total == U16_PLACEHOLDER {
            entries_total_u64 = e64_entries;
        }
        if cd_size_32 == U32_PLACEHOLDER {
            cd_size = e64_cd_size;
        }
        if cd_off_32 == U32_PLACEHOLDER {
            cd_off = e64_cd_off;
        }
    }

    // For single-disk archives `entries_disk` (records on this disk)
    // equals `entries_total_u64`. A mismatch indicates a multi-disk
    // archive that spans more than one volume, which is not handled
    // here (rare in practice for APKs and would require holding
    // multiple disjoint mappings). When both fields are the ZIP64
    // placeholder `0xFFFF`, the real values live in the EOCD64 record
    // and this check is skipped.
    if entries_disk != U16_PLACEHOLDER && (entries_disk as u64) != entries_total_u64 {
        return Err(ApkError::Unsupported("multi-disk ZIP archives"));
    }

    // ---- Bounds-check the central directory window ----
    let cd_end = cd_off
        .checked_add(cd_size)
        .ok_or(ApkError::Truncated("CD offset + size overflow"))?;
    if cd_end > len as u64 {
        return Err(ApkError::Truncated("central directory overruns EOF"));
    }
    let cd_off = cd_off as usize;
    let cd_end = cd_end as usize;
    let _cd_size = cd_size as usize;

    // ---- Iterate central directory entries ----
    let total = entries_total_u64 as usize;
    let mut entries: Vec<DexEntry> = Vec::with_capacity(total.min(1024));
    let mut pos = cd_off;
    let mut iter_count = 0usize;
    while pos + CD_FIXED_LEN <= cd_end {
        if read_u32(buf, pos) != SIG_CENTRAL {
            return Err(ApkError::BadSignature { at: pos as u64 });
        }
        let flags = read_u16(buf, pos + 8);
        let method_raw = read_u16(buf, pos + 10);
        let crc32 = read_u32(buf, pos + 16);
        let csize32 = read_u32(buf, pos + 20);
        let usize32 = read_u32(buf, pos + 24);
        let name_len = read_u16(buf, pos + 28) as usize;
        let extra_len = read_u16(buf, pos + 30) as usize;
        let comment_len = read_u16(buf, pos + 32) as usize;
        let lho32 = read_u32(buf, pos + 42);

        let name_start = pos + CD_FIXED_LEN;
        let name_end = name_start
            .checked_add(name_len)
            .ok_or(ApkError::Truncated("name length overflow"))?;
        let extra_start = name_end;
        let extra_end = extra_start
            .checked_add(extra_len)
            .ok_or(ApkError::Truncated("extra length overflow"))?;
        let comment_start = extra_end;
        let comment_end = comment_start
            .checked_add(comment_len)
            .ok_or(ApkError::Truncated("comment length overflow"))?;

        if comment_end > cd_end {
            return Err(ApkError::Truncated("central entry overruns CD"));
        }

        // Reject encrypted entries (general-purpose bit flag bit 0).
        if flags & 0x0001 != 0 {
            return Err(ApkError::Unsupported("encrypted entry"));
        }

        // Decode compression method; reject anything we don't support.
        let method = Compression::from_method(method_raw)
            .map_err(|_m| ApkError::Unsupported("unsupported compression method"))?;

        let name_bytes = &buf[name_start..name_end];

        // ZIP64 resolution for fields whose 32-bit placeholders were hit.
        let (csize, usize, lho) =
            resolve_zip64(buf, extra_start, extra_end, csize32, usize32, lho32)?;

        // Validate declared sizes are non-negative (u64, so just sanity check
        // for absurd values that would have overflowed u32 sanity).
        let csize_u64: u64 = csize;
        let usize_u64: u64 = usize;
        let lho_u64: u64 = lho;

        // UTF-8 (bit 11) or lossy fallback.
        let name = if flags & 0x0800 != 0 {
            std::str::from_utf8(name_bytes)
                .map_err(|_| ApkError::Unsupported("non-UTF-8 name with UTF-8 flag"))?
                .to_owned()
        } else {
            String::from_utf8_lossy(name_bytes).into_owned()
        };

        entries.push(DexEntry {
            name,
            method,
            compressed_size: csize_u64,
            uncompressed_size: usize_u64,
            crc32,
            local_header_offset: lho_u64,
        });

        pos = comment_end;
        iter_count += 1;

        // Stop iterating once we've recorded all declared entries even if
        // padding bytes follow.
        if iter_count >= total {
            break;
        }
    }

    if iter_count < total {
        // The central directory ended early (corrupt/truncated). Anything we
        // did parse is still useful to report, but the spec says we must
        // error on truncation, so we honour that and discard partial state.
        return Err(ApkError::Truncated(
            "central directory ended before declared entry count",
        ));
    }
    Ok(entries)
}

/// Locate the EOCD signature by scanning backwards from EOF within the
/// PKWARE-mandated window.
///
/// Every `PK\x05\x06` candidate is validated before it is accepted: the
/// record that ends the archive is the one whose 22-byte fixed body plus
/// its declared comment length lands exactly on EOF. A bare signature
/// match is not enough — `PK\x05\x06` bytes can legitimately occur
/// inside the archive comment, and taking one of those makes us read a
/// central directory that does not exist. This is the same check
/// Info-ZIP, `java.util.zip.ZipFile` and Python's `zipfile` apply.
/// The Python oracle's `mm.rfind(_EOCD_SIG, …)` does not, so the engine
/// is deliberately stricter than the oracle here: on a well-formed
/// archive the two agree.
///
/// Residual, measured: a forgery placed as the *last* 22 bytes of the
/// comment, with its own `comment_len` set to 0, also satisfies the
/// termination check, and this parser then reads zero entries — as do
/// Python's `zipfile` and .NET's `ZipFile` on the same bytes. We match
/// mainstream ZIP readers here rather than carrying a stricter,
/// non-standard central-directory heuristic that would risk rejecting
/// real archives (trailing data, self-extracting prefixes, comment
/// layouts we have not seen). Adversarial ZIPs are hostile input by
/// definition: prefer a tool that reports the mismatch.
pub(crate) fn locate_eocd(buf: &[u8], len: usize) -> Result<usize, ApkError> {
    if len < EOCD_FIXED_LEN {
        return Err(ApkError::NotAZip);
    }
    let search_len = len.min(EOCD_MAX_BACKSCAN);
    let start = len - search_len;
    // Search inclusive of `start`. We scan byte-by-byte for the 4-byte
    // little-endian signature.
    if start + 4 > len {
        return Err(ApkError::NotAZip);
    }
    let target = SIG_EOCD.to_le_bytes();
    let mut i = len.saturating_sub(EOCD_FIXED_LEN);
    loop {
        // A valid EOCD needs its full 22-byte fixed record on disk; a
        // signature with fewer bytes behind it is garbage, not an EOCD
        // (fuzz-found: previously the field reads at eocd_pos+8..20
        // indexed past EOF and panicked). It must additionally be the
        // record that terminates the file.
        if buf[i..i + 4] == target && eocd_terminates_archive(buf, i, len) {
            return Ok(i);
        }
        if i == start {
            break;
        }
        i -= 1;
    }
    Err(ApkError::NotAZip)
}

/// `true` iff the 22-byte EOCD fixed record at `pos` plus its declared
/// comment length ends exactly at `len`.
#[inline]
fn eocd_terminates_archive(buf: &[u8], pos: usize, len: usize) -> bool {
    let comment_len = u16::from_le_bytes([buf[pos + 20], buf[pos + 21]]) as usize;
    pos + EOCD_FIXED_LEN + comment_len == len
}

/// Resolve ZIP64 extended-information fields for the three size/offset
/// fields that may have been stored as 32-bit placeholders in the central
/// directory entry. Returns `(compressed_size, uncompressed_size,
/// local_header_offset)` as `u64`.
fn resolve_zip64(
    buf: &[u8],
    extra_start: usize,
    extra_end: usize,
    csize32: u32,
    usize32: u32,
    lho32: u32,
) -> Result<(u64, u64, u64), ApkError> {
    let mut csize: u64 = csize32.into();
    let mut usize: u64 = usize32.into();
    let mut lho: u64 = lho32.into();

    // Track which fields still need resolution.
    let mut need_csize = csize32 == U32_PLACEHOLDER;
    let mut need_usize = usize32 == U32_PLACEHOLDER;
    let mut need_lho = lho32 == U32_PLACEHOLDER;

    if need_csize || need_usize || need_lho {
        walk_extra(buf, extra_start, extra_end, |header_id, data| {
            if header_id != ZIP64_EXTRA_ID {
                return Ok(());
            }
            // Per APPNOTE: fields are present in order (usize, csize, lho,
            // disk) only when the corresponding 32-bit field was a
            // placeholder; the data size tells us which.
            let mut cursor = 0usize;
            if need_usize && cursor + 8 <= data.len() {
                usize = read_u64(data, cursor);
                need_usize = false;
                cursor += 8;
            }
            if need_csize && cursor + 8 <= data.len() {
                csize = read_u64(data, cursor);
                need_csize = false;
                cursor += 8;
            }
            if need_lho && cursor + 8 <= data.len() {
                lho = read_u64(data, cursor);
                need_lho = false;
            }
            let _ = cursor;
            Ok(())
        })?;
    }

    // If anything is still a placeholder and we couldn't resolve it, the
    // file is malformed.
    if need_csize || need_usize || need_lho {
        return Err(ApkError::Truncated(
            "ZIP64 placeholder without matching extra field",
        ));
    }

    Ok((csize, usize, lho))
}

/// Iterate the extra-field blocks of a central-directory entry or local
/// header. Each block has a 4-byte header (id u16, size u16) followed by
/// `size` bytes of data. The visitor receives each block's id and data
/// slice; the data slice is always bounds-checked.
fn walk_extra(
    buf: &[u8],
    extra_start: usize,
    extra_end: usize,
    mut visit: impl FnMut(u16, &[u8]) -> Result<(), ApkError>,
) -> Result<(), ApkError> {
    let mut pos = extra_start;
    while pos + 4 <= extra_end {
        let header_id = read_u16(buf, pos);
        let data_size = read_u16(buf, pos + 2) as usize;
        let data_start = pos + 4;
        let data_end = data_start
            .checked_add(data_size)
            .ok_or(ApkError::Truncated("extra field data size overflow"))?;
        if data_end > extra_end {
            return Err(ApkError::Truncated("extra field overruns block"));
        }
        visit(header_id, &buf[data_start..data_end])?;
        pos = data_end;
    }
    if pos != extra_end {
        return Err(ApkError::Truncated("extra field byte count mismatch"));
    }
    Ok(())
}

/// Resolve the local file header for an entry and return the byte offset
/// where the entry data begins.
///
/// Only the local header's *geometry* is trusted — `name_len` and
/// `extra_len`. Its method, CRC and sizes are deliberately ignored:
/// APPNOTE 4.4.4 bit 3 requires them to be zero when a data descriptor
/// is used, and 6.3.10 lets the local extra field differ in size from
/// the central one, so cross-checking them would reject valid archives.
/// `read_entry_inner` takes the compression method and both sizes from
/// the central directory, which is the authority on content. This is
/// exactly what OpenJDK's `ZipFile.Source.initDataOffset` does. (Audit
/// F07: the absence of a local-vs-central cross-check is intentional.)
pub(crate) fn resolve_local_data_offset(buf: &[u8], entry: &DexEntry) -> Result<u64, ApkError> {
    let lho = entry.local_header_offset as usize;
    if lho
        .checked_add(LH_FIXED_LEN)
        .is_none_or(|end| end > buf.len())
    {
        return Err(ApkError::Truncated("local header overruns EOF"));
    }
    if read_u32(buf, lho) != SIG_LOCAL {
        return Err(ApkError::BadSignature { at: lho as u64 });
    }
    let name_len = read_u16(buf, lho + 26) as usize;
    let extra_len = read_u16(buf, lho + 28) as usize;
    let data_off = lho
        .checked_add(LH_FIXED_LEN)
        .and_then(|p| p.checked_add(name_len))
        .and_then(|p| p.checked_add(extra_len))
        .ok_or(ApkError::Truncated("local header offset overflow"))?;
    Ok(data_off as u64)
}

/// Little-endian u16 read with bounds check.
#[inline]
fn read_u16(buf: &[u8], off: usize) -> u16 {
    let raw = [buf[off], buf[off + 1]];
    u16::from_le_bytes(raw)
}

/// Little-endian u32 read with bounds check.
#[inline]
fn read_u32(buf: &[u8], off: usize) -> u32 {
    let raw = [buf[off], buf[off + 1], buf[off + 2], buf[off + 3]];
    u32::from_le_bytes(raw)
}

/// Little-endian u64 read with bounds check.
#[inline]
fn read_u64(buf: &[u8], off: usize) -> u64 {
    let raw = [
        buf[off],
        buf[off + 1],
        buf[off + 2],
        buf[off + 3],
        buf[off + 4],
        buf[off + 5],
        buf[off + 6],
        buf[off + 7],
    ];
    u64::from_le_bytes(raw)
}
