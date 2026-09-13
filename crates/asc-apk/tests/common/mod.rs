//! In-test ZIP builder for `asc-apk`.
//!
//! Builds minimal valid (and a few intentionally malformed) ZIP archives
//! so the engine can be exercised without an external test corpus.
//!
//! Supports:
//!   * STORED entries (method 0) and raw DEFLATE entries (method 8, encoded
//!     with `flate2::read::DeflateEncoder` over `flate2::write::DeflateEncoder`'s
//!     twin — read-side encoder — so the byte stream is exactly the raw
//!     DEFLATE form expected by `flate2::read::DeflateDecoder`).
//!   * Optional ZIP64 placeholder layout for any of {usize, csize, lho}.
//!   * Arbitrary trailing EOCD comment.
//!   * Per-entry flags and extra bytes in the central directory (used to
//!     inject corrupted local headers, encrypted flag, unsupported method,
//!     and ZIP64 extra fields).
//!
//! Limitations: only one disk (entries_disk = cd_disk = 0); no encryption
//! handler; no streaming descriptor bit.

#![allow(dead_code)] // Used only from integration tests.

use std::io::Write;

/// Compression method to record in the central-directory entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Compression {
    Stored,
    Deflated,
}

impl Compression {
    fn code(self) -> u16 {
        match self {
            Compression::Stored => 0,
            Compression::Deflated => 8,
        }
    }
}

/// A planned entry, kept around until `build()`.
#[derive(Debug, Clone)]
pub struct PlannedEntry {
    pub name: String,
    pub data: Vec<u8>,
    pub method: Compression,
    /// Override the 16-bit compression method field in the central entry
    /// (used to test "unsupported method" rejection).
    pub method_override: Option<u16>,
    /// Set the encrypted bit (general-purpose bit 0) in the central entry.
    pub force_encrypted: bool,
    /// Override the bytes emitted as the local file header signature
    /// (`Some(sig)` replaces `PK\x03\x04` with the 4-byte `sig`).
    pub force_local_sig: Option<[u8; 4]>,
    /// Extra bytes to insert into the central-directory extra field (raw,
    /// already formatted as a sequence of `(id u16, size u16, data)` blocks).
    pub extra_central: Vec<u8>,
    /// Override the declared uncompressed size in the central entry
    /// (used to test "size mismatch" rejection).
    pub usize_override: Option<u64>,
}

pub struct BuiltEntry {
    pub name: String,
    pub compressed: Vec<u8>,
    pub uncompressed_size: u64,
    pub compressed_size: u64,
    pub crc32: u32,
    pub method: u16,
    pub local_header_offset: u64,
    pub extra_central: Vec<u8>,
    pub usize_override: Option<u64>,
    pub force_encrypted: bool,
}
/// Builder state.
pub struct ZipBuilder {
    pub entries: Vec<PlannedEntry>,
    pub force_zip64: bool,
    pub comment: Vec<u8>,
}

impl Default for ZipBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl ZipBuilder {
    pub fn new() -> Self {
        ZipBuilder {
            entries: Vec::new(),
            force_zip64: false,
            comment: Vec::new(),
        }
    }

    /// Add a STORED entry whose bytes are emitted verbatim.
    pub fn add_stored(&mut self, name: &str, data: Vec<u8>) -> &mut Self {
        self.entries.push(PlannedEntry {
            name: name.to_string(),
            data,
            method: Compression::Stored,
            method_override: None,
            force_encrypted: false,
            force_local_sig: None,
            extra_central: Vec::new(),
            usize_override: None,
        });
        self
    }

    /// Force the EOCD (and optionally central entries) to use ZIP64
    /// placeholders even when the file would fit in 32-bit fields. The
    /// produced archive will include an EOCD64 record and locator.
    pub fn force_zip64(&mut self) -> &mut Self {
        self.force_zip64 = true;
        self
    }
    /// Add a DEFLATE entry. The data is compressed with `flate2` raw
    /// DEFLATE before being written to the archive.
    pub fn add_deflated(&mut self, name: &str, data: Vec<u8>) -> &mut Self {
        self.entries.push(PlannedEntry {
            name: name.to_string(),
            data,
            method: Compression::Deflated,
            method_override: None,
            force_encrypted: false,
            force_local_sig: None,
            extra_central: Vec::new(),
            usize_override: None,
        });
        self
    }

    /// Set the EOCD comment bytes.
    pub fn set_comment(&mut self, c: &[u8]) -> &mut Self {
        self.comment = c.to_vec();
        self
    }

    /// Override the next entry's compression method field (central only) to
    /// a value the engine does not support.
    pub fn next_method_override(&mut self, code: u16) -> &mut Self {
        let last = self.entries.last_mut().expect("no entry to mutate");
        last.method_override = Some(code);
        self
    }

    /// Mark the next entry as encrypted in the central directory.
    pub fn next_encrypted(&mut self) -> &mut Self {
        let last = self.entries.last_mut().expect("no entry to mutate");
        last.force_encrypted = true;
        self
    }

    /// Replace the next entry's local-header signature with `sig`.
    pub fn next_local_sig(&mut self, sig: [u8; 4]) -> &mut Self {
        let last = self.entries.last_mut().expect("no entry to mutate");
        last.force_local_sig = Some(sig);
        self
    }

    /// Append raw bytes to the next entry's central extra field. Caller is
    /// responsible for the `(id, size, data)` framing.
    pub fn next_extra_central(&mut self, raw: &[u8]) -> &mut Self {
        let last = self.entries.last_mut().expect("no entry to mutate");
        last.extra_central.extend_from_slice(raw);
        self
    }

    /// Override the next entry's declared uncompressed size (for testing
    /// the size-mismatch path).
    pub fn next_usize_override(&mut self, sz: u64) -> &mut Self {
        let last = self.entries.last_mut().expect("no entry to mutate");
        last.usize_override = Some(sz);
        self
    }

    /// Build the archive bytes.
    pub fn build(&self) -> Vec<u8> {
        let mut out = Vec::new();
        let mut built: Vec<BuiltEntry> = Vec::with_capacity(self.entries.len());

        // ---- 1. Local file headers + data ----
        for e in &self.entries {
            let local_header_offset = out.len() as u64;
            let compressed = compress_entry(&e.data, e.method);
            let crc32 = crc32(&e.data);
            let compressed_size = compressed.len() as u64;
            let uncompressed_size = e.data.len() as u64;

            let local_sig = e.force_local_sig.unwrap_or([b'P', b'K', 3, 4]);
            out.extend_from_slice(&local_sig);
            write_u16(&mut out, 20); // version needed
            let mut gp_flag: u16 = 0;
            if e.force_encrypted {
                gp_flag |= 0x0001;
            }
            write_u16(&mut out, gp_flag);
            write_u16(&mut out, e.method.code());
            write_u16(&mut out, 0); // mtime
            write_u16(&mut out, 0); // mdate
            write_u32(&mut out, crc32);
            // Local header sizes: mirror what the central will declare so
            // STORED round-trip works. ZIP64 in the local header isn't
            // exercised by this builder.
            write_u32(&mut out, compressed_size as u32);
            write_u32(&mut out, uncompressed_size as u32);
            write_u16(&mut out, e.name.len() as u16);
            write_u16(&mut out, 0); // local extra length
            out.extend_from_slice(e.name.as_bytes());
            out.extend_from_slice(&compressed);

            built.push(BuiltEntry {
                name: e.name.clone(),
                compressed,
                compressed_size,
                uncompressed_size,
                crc32,
                method: e.method_override.unwrap_or_else(|| e.method.code()),
                local_header_offset,
                extra_central: e.extra_central.clone(),
                usize_override: e.usize_override,
                force_encrypted: e.force_encrypted,
            });
        }

        // ---- 2. Central directory entries ----
        let cd_off = out.len() as u64;
        for b in &built {
            out.extend_from_slice(&[b'P', b'K', 1, 2]); // central sig
            write_u16(&mut out, 20); // version made by
            write_u16(&mut out, 20); // version needed
            let mut gp_flag: u16 = 0;
            if b.force_encrypted {
                gp_flag |= 0x0001;
            }
            // Bit 11 (0x0800) is set when the entry name is UTF-8; we
            // always emit UTF-8 names so the parser takes the strict
            // branch. This matches what `apksigner`/AAPT2 emit.
            gp_flag |= 0x0800;
            write_u16(&mut out, gp_flag);
            write_u16(&mut out, b.method);
            write_u16(&mut out, 0); // mtime
            write_u16(&mut out, 0); // mdate
            write_u32(&mut out, b.crc32);
            write_u32(&mut out, b.compressed_size as u32);
            write_u32(
                &mut out,
                b.usize_override.unwrap_or(b.uncompressed_size) as u32,
            );
            write_u16(&mut out, b.name.len() as u16);
            write_u16(&mut out, b.extra_central.len() as u16);
            write_u16(&mut out, 0); // comment length
            write_u16(&mut out, 0); // disk number start
            write_u16(&mut out, 0); // internal attrs
            write_u32(&mut out, 0); // external attrs
            write_u32(&mut out, b.local_header_offset as u32);
            out.extend_from_slice(b.name.as_bytes());
            out.extend_from_slice(&b.extra_central);
        }
        let cd_end = out.len() as u64;
        let cd_size = cd_end - cd_off;

        // ---- 3. ZIP64 record (when forced) ----
        let entries_total = built.len() as u64;
        let mut zip64_used = self.force_zip64;
        if entries_total >= 0xFFFF || cd_size >= 0xFFFF_FFFF {
            zip64_used = true;
        }

        let eocd64_off = if zip64_used { out.len() as u64 } else { 0 };

        if zip64_used {
            // EOCD64 record (sig 0x06064b50), 56 bytes.
            out.extend_from_slice(&[b'P', b'K', 6, 6]);
            write_u64(&mut out, 44); // size of zip64 EOCD record (after this u64)
            write_u16(&mut out, 20); // version made by
            write_u16(&mut out, 20); // version needed
            write_u32(&mut out, 0); // disk number
            write_u32(&mut out, 0); // disk where CD starts
            write_u64(&mut out, entries_total);
            write_u64(&mut out, entries_total);
            write_u64(&mut out, cd_size);
            write_u64(&mut out, cd_off);

            // EOCD64 locator (sig 0x07064b50 → on-disk bytes `PK\x06\x07`),
            // 20 bytes.
            out.extend_from_slice(&[b'P', b'K', 6, 7]);
            write_u32(&mut out, 0); // disk with ZIP64 EOCD
            write_u64(&mut out, eocd64_off);
            write_u32(&mut out, 1); // total disks
        }

        // ---- 4. EOCD ----
        let entries_disk = if zip64_used { 0xFFFF } else { entries_total as u16 };
        let entries_total_u16 = if zip64_used { 0xFFFF } else { entries_total as u16 };
        let cd_size_u32 = if zip64_used { 0xFFFF_FFFF } else { cd_size as u32 };
        let cd_off_u32 = if zip64_used { 0xFFFF_FFFF } else { cd_off as u32 };

        out.extend_from_slice(&[b'P', b'K', 5, 6]);
        write_u16(&mut out, 0); // disk number
        write_u16(&mut out, 0); // disk where CD starts
        write_u16(&mut out, entries_disk);
        write_u16(&mut out, entries_total_u16);
        write_u32(&mut out, cd_size_u32);
        write_u32(&mut out, cd_off_u32);
        write_u16(&mut out, self.comment.len() as u16);
        out.extend_from_slice(&self.comment);

        out
    }
}

// ---- helpers ------------------------------------------------------------

fn compress_entry(data: &[u8], method: Compression) -> Vec<u8> {
    match method {
        Compression::Stored => data.to_vec(),
        Compression::Deflated => {
            use flate2::read::DeflateEncoder;
            use flate2::Compression as Fc;
            use std::io::Read;
            let mut enc = DeflateEncoder::new(data, Fc::default());
            let mut out = Vec::with_capacity(data.len() / 4 + 16);
            enc.read_to_end(&mut out)
                .expect("DeflateEncoder to local Vec never fails");
            out
        }
    }
}

fn crc32(data: &[u8]) -> u32 {
    let mut h = crc32fast::Hasher::new();
    h.update(data);
    h.finalize()
}

pub fn write_u16(out: &mut Vec<u8>, v: u16) {
    out.extend_from_slice(&v.to_le_bytes());
}

pub fn write_u32(out: &mut Vec<u8>, v: u32) {
    out.extend_from_slice(&v.to_le_bytes());
}

pub fn write_u64(out: &mut Vec<u8>, v: u64) {
    out.extend_from_slice(&v.to_le_bytes());
}

/// Build a ZIP64 extra-field block (header id 0x0001) that fully replaces
/// the 32-bit placeholders for usize, csize, and lho. The block layout
/// matches the APPNOTE.
pub fn zip64_extra(usize_v: u64, csize_v: u64, lho_v: u64) -> Vec<u8> {
    let mut out = Vec::new();
    write_u16(&mut out, 0x0001); // header id
    let data_size: u16 = 24; // 3 * u64
    write_u16(&mut out, data_size);
    write_u64(&mut out, usize_v);
    write_u64(&mut out, csize_v);
    write_u64(&mut out, lho_v);
    out
}

#[allow(unused)]
pub fn write_bytes(out: &mut Vec<u8>, data: &[u8]) {
    out.extend_from_slice(data);
}

/// Convenience: write the provided bytes to a fresh temp file and return
/// the path. The file is not auto-deleted; tests do so explicitly via
/// `tempfile::NamedTempFile::persist` patterns. For our use cases, just
/// letting the OS clean up `std::env::temp_dir()` is fine — the temp
/// crate deletes on drop.
pub fn write_to_temp(bytes: &[u8]) -> tempfile::NamedTempFile {
    let mut f = tempfile::NamedTempFile::new().expect("create temp file");
    f.write_all(bytes).expect("write temp file");
    f.flush().expect("flush temp file");
    f
}

pub fn _use_write_bytes_marker(_: &mut Vec<u8>, _: &[u8]) {}
