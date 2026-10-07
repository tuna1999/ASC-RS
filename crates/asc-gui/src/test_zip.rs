//! Test-only helper: build minimal APK (ZIP) fixtures without adding a ZIP
//! writer dependency. Duplicated per crate by house style, but shared by
//! asc-gui's own test modules so there is exactly one copy in this crate.

use std::io::Write as _;
use std::path::PathBuf;

/// Bitwise CRC-32 (IEEE) — the ZIP central directory needs it; `crc32fast`
/// is not a dependency of this crate.
fn crc32(data: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFFu32;
    for &byte in data {
        crc ^= u32::from(byte);
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
        }
    }
    !crc
}

/// A STORED-only ZIP containing exactly `entries`, in order — the minimum
/// `asc_apk::Apk::open` accepts.
pub(crate) fn stored_zip(entries: &[(&str, &[u8])]) -> Vec<u8> {
    let mut zip: Vec<u8> = Vec::new();
    let mut central: Vec<(u32, u32, u32, &str)> = Vec::new();

    for (name, payload) in entries {
        let crc = crc32(payload);
        let local_offset = zip.len() as u32;
        zip.extend_from_slice(b"PK\x03\x04");
        zip.extend_from_slice(&20u16.to_le_bytes()); // version needed
        zip.extend_from_slice(&0u16.to_le_bytes()); // flags
        zip.extend_from_slice(&0u16.to_le_bytes()); // compression = stored
        zip.extend_from_slice(&0u16.to_le_bytes()); // mod time
        zip.extend_from_slice(&0u16.to_le_bytes()); // mod date
        zip.extend_from_slice(&crc.to_le_bytes());
        zip.extend_from_slice(&(payload.len() as u32).to_le_bytes()); // compressed
        zip.extend_from_slice(&(payload.len() as u32).to_le_bytes()); // uncompressed
        zip.extend_from_slice(&(name.len() as u16).to_le_bytes());
        zip.extend_from_slice(&0u16.to_le_bytes()); // extra
        zip.extend_from_slice(name.as_bytes());
        zip.extend_from_slice(payload);
        central.push((crc, payload.len() as u32, local_offset, name));
    }

    let central_off = zip.len() as u32;
    for (crc, len, local_offset, name) in &central {
        zip.extend_from_slice(b"PK\x01\x02");
        zip.extend_from_slice(&20u16.to_le_bytes()); // version made by
        zip.extend_from_slice(&20u16.to_le_bytes()); // version needed
        zip.extend_from_slice(&0u16.to_le_bytes()); // flags
        zip.extend_from_slice(&0u16.to_le_bytes()); // compression
        zip.extend_from_slice(&0u16.to_le_bytes()); // mod time
        zip.extend_from_slice(&0u16.to_le_bytes()); // mod date
        zip.extend_from_slice(&crc.to_le_bytes());
        zip.extend_from_slice(&len.to_le_bytes());
        zip.extend_from_slice(&len.to_le_bytes());
        zip.extend_from_slice(&(name.len() as u16).to_le_bytes());
        zip.extend_from_slice(&0u16.to_le_bytes()); // extra
        zip.extend_from_slice(&0u16.to_le_bytes()); // comment
        zip.extend_from_slice(&0u16.to_le_bytes()); // disk number start
        zip.extend_from_slice(&0u16.to_le_bytes()); // internal attr
        zip.extend_from_slice(&0u32.to_le_bytes()); // external attr
        zip.extend_from_slice(&local_offset.to_le_bytes());
        zip.extend_from_slice(name.as_bytes());
    }
    let central_size = (zip.len() as u32) - central_off;

    zip.extend_from_slice(b"PK\x05\x06");
    zip.extend_from_slice(&0u16.to_le_bytes()); // disk number
    zip.extend_from_slice(&0u16.to_le_bytes()); // disk with CD
    zip.extend_from_slice(&(central.len() as u16).to_le_bytes()); // entries on this disk
    zip.extend_from_slice(&(central.len() as u16).to_le_bytes()); // total entries
    zip.extend_from_slice(&central_size.to_le_bytes());
    zip.extend_from_slice(&central_off.to_le_bytes());
    zip.extend_from_slice(&0u16.to_le_bytes()); // comment length
    zip
}

/// Writes `entries` as an APK to a process-unique temp path and returns it.
/// The caller removes it (`remove_file`); a panicking assertion may leave
/// the file behind, which is harmless.
pub(crate) fn write_temp_apk(tag: &str, entries: &[(&str, &[u8])]) -> PathBuf {
    let path = std::env::temp_dir().join(format!("asc_gui_{}_{tag}.apk", std::process::id()));
    std::fs::File::create(&path)
        .expect("create temp apk")
        .write_all(&stored_zip(entries))
        .expect("write temp apk");
    path
}
