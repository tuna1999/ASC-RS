//! Minimal ZIP writer for synthetic test fixtures (STORED + raw DEFLATE).
//!
//! Exists because the `zip` 0.6 dev-dependency carries
//! RUSTSEC-2026-0367/0368/0369 and is only patched in the `zip` 9 fork;
//! these fixtures only ever need to WRITE tiny archives, so the byte
//! layout is emitted here instead (mirrors `asc-apk`'s test builder).
//!
//! Scope: single disk, no ZIP64, no encryption, no streaming data
//! descriptor (GP bit 3) — CRC and sizes are known when each entry is
//! closed, so the local header is written last-but-once with real values.
#![allow(dead_code)] // shared per test crate: not every test writes a ZIP

use std::io::{self, Write};

/// Compression method recorded in both the local and central headers.
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

struct Central {
    name: String,
    method: u16,
    crc32: u32,
    compressed_size: u32,
    uncompressed_size: u32,
    local_header_offset: u32,
}

enum Sink {
    /// STORED bytes are buffered: the local header needs the CRC first.
    Raw(Vec<u8>),
    /// DEFLATE streams so a huge, highly compressible entry stays small
    /// in RAM (one test writes 300 MiB of zeros).
    Deflating(Box<flate2::write::DeflateEncoder<Vec<u8>>>),
}

struct OpenEntry {
    name: String,
    method: Compression,
    hasher: crc32fast::Hasher,
    uncompressed_size: u64,
    sink: Sink,
}

/// Drop-in replacement for the small slice of `zip::ZipWriter` the
/// fixtures use.
pub struct ZipWriter<W: Write> {
    out: W,
    open: Option<OpenEntry>,
    central: Vec<Central>,
    /// Bytes already written to `out` (local headers + payloads + CD).
    offset: u64,
}

fn u16le(out: &mut Vec<u8>, v: u16) {
    out.extend_from_slice(&v.to_le_bytes());
}

fn u32le(out: &mut Vec<u8>, v: u32) {
    out.extend_from_slice(&v.to_le_bytes());
}

impl<W: Write> ZipWriter<W> {
    pub fn new(out: W) -> Self {
        Self {
            out,
            open: None,
            central: Vec::new(),
            offset: 0,
        }
    }

    /// Begin an entry. Any previous entry is closed first.
    pub fn start_file(&mut self, name: &str, method: Compression) -> io::Result<()> {
        self.close_entry()?;
        let sink = match method {
            Compression::Stored => Sink::Raw(Vec::new()),
            Compression::Deflated => Sink::Deflating(Box::new(flate2::write::DeflateEncoder::new(
                Vec::new(),
                flate2::Compression::default(),
            ))),
        };
        self.open = Some(OpenEntry {
            name: name.to_string(),
            method,
            hasher: crc32fast::Hasher::new(),
            uncompressed_size: 0,
            sink,
        });
        Ok(())
    }

    /// Close the archive: flush the open entry, write the central
    /// directory and the end-of-central-directory record.
    pub fn finish(mut self) -> io::Result<W> {
        self.close_entry()?;
        let cd_off = self.offset;
        for c in &self.central {
            let mut h = Vec::with_capacity(46 + c.name.len());
            h.extend_from_slice(b"PK\x01\x02");
            u16le(&mut h, 20); // version made by
            u16le(&mut h, 20); // version needed
            // Bit 11 marks a UTF-8 name; the parser takes its strict branch
            // for it, and every fixture name is ASCII/UTF-8.
            u16le(&mut h, 0x0800);
            u16le(&mut h, c.method);
            u16le(&mut h, 0); // mtime
            u16le(&mut h, 0); // mdate
            u32le(&mut h, c.crc32);
            u32le(&mut h, c.compressed_size);
            u32le(&mut h, c.uncompressed_size);
            u16le(&mut h, c.name.len() as u16);
            u16le(&mut h, 0); // extra length
            u16le(&mut h, 0); // comment length
            u16le(&mut h, 0); // disk number start
            u16le(&mut h, 0); // internal attributes
            u32le(&mut h, 0); // external attributes
            u32le(&mut h, c.local_header_offset);
            h.extend_from_slice(c.name.as_bytes());
            self.out.write_all(&h)?;
            self.offset += h.len() as u64;
        }
        let cd_size = self.offset - cd_off;
        let count = self.central.len() as u16;
        let mut eocd = Vec::with_capacity(22);
        eocd.extend_from_slice(b"PK\x05\x06");
        u16le(&mut eocd, 0); // disk number
        u16le(&mut eocd, 0); // disk with central directory
        u16le(&mut eocd, count);
        u16le(&mut eocd, count);
        u32le(&mut eocd, cd_size as u32);
        u32le(&mut eocd, cd_off as u32);
        u16le(&mut eocd, 0); // comment length
        self.out.write_all(&eocd)?;
        self.out.flush()?;
        Ok(self.out)
    }

    fn close_entry(&mut self) -> io::Result<()> {
        let Some(entry) = self.open.take() else {
            return Ok(());
        };
        let payload = match entry.sink {
            Sink::Raw(v) => v,
            Sink::Deflating(enc) => enc.finish()?,
        };
        let crc32 = entry.hasher.finalize();
        let compressed_size = payload.len() as u32;
        let uncompressed_size = entry.uncompressed_size as u32;
        let local_header_offset = self.offset as u32;

        let mut h = Vec::with_capacity(30 + entry.name.len());
        h.extend_from_slice(b"PK\x03\x04");
        u16le(&mut h, 20); // version needed
        u16le(&mut h, 0); // general purpose flags
        u16le(&mut h, entry.method.code());
        u16le(&mut h, 0); // mtime
        u16le(&mut h, 0); // mdate
        u32le(&mut h, crc32);
        u32le(&mut h, compressed_size);
        u32le(&mut h, uncompressed_size);
        u16le(&mut h, entry.name.len() as u16);
        u16le(&mut h, 0); // extra length
        h.extend_from_slice(entry.name.as_bytes());
        self.out.write_all(&h)?;
        self.out.write_all(&payload)?;
        self.offset += (h.len() + payload.len()) as u64;

        self.central.push(Central {
            name: entry.name,
            method: entry.method.code(),
            crc32,
            compressed_size,
            uncompressed_size,
            local_header_offset,
        });
        Ok(())
    }
}

impl<W: Write> Write for ZipWriter<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let entry = self
            .open
            .as_mut()
            .ok_or_else(|| io::Error::other("ZipWriter: write without start_file"))?;
        match &mut entry.sink {
            Sink::Raw(v) => v.write_all(buf)?,
            Sink::Deflating(enc) => enc.write_all(buf)?,
        }
        entry.hasher.update(buf);
        entry.uncompressed_size += buf.len() as u64;
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        match &mut self.open.as_mut().map(|e| &mut e.sink) {
            Some(Sink::Deflating(enc)) => enc.flush(),
            _ => Ok(()),
        }
    }
}
