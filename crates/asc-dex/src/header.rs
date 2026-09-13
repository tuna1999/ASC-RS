//! DEX header parsing and the [`DexVersion`] enum.

use crate::error::DexError;

/// DEX byte-code version. We support 035..=041 inclusive.
///
/// The magic byte is `dex\n0XX\x00`; anything else is rejected at parse.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum DexVersion {
    /// DEX 035 — original Dalvik bytecode.
    V035,
    /// DEX 037 — some optimisations / new opcodes.
    V037,
    /// DEX 038 — adds `call_site_ids` / `method_handles` (lambda support).
    V038,
    /// DEX 039.
    V039,
    /// DEX 040.
    V040,
    /// DEX 041 — supports a container with multiple logical DEX back-to-back.
    V041,
}

impl DexVersion {
    /// Recognises the 8-byte magic prefix.
    pub fn from_magic(magic: &[u8; 8]) -> Result<Self, DexError> {
        // All supported magics share the form  b"dex\n0XX\x00".
        if &magic[..4] != b"dex\n" || magic[7] != 0 {
            return Err(DexError::BadVersion(*magic));
        }
        let version = match &magic[4..7] {
            b"035" => DexVersion::V035,
            b"037" => DexVersion::V037,
            b"038" => DexVersion::V038,
            b"039" => DexVersion::V039,
            b"040" => DexVersion::V040,
            b"041" => DexVersion::V041,
            _ => return Err(DexError::BadVersion(*magic)),
        };
        Ok(version)
    }

    /// Returns the 3-digit decimal version string, like `"035"` or `"041"`.
    pub const fn as_str(self) -> &'static str {
        match self {
            DexVersion::V035 => "035",
            DexVersion::V037 => "037",
            DexVersion::V038 => "038",
            DexVersion::V039 => "039",
            DexVersion::V040 => "040",
            DexVersion::V041 => "041",
        }
    }
}

/// Minimal in-memory view of a parsed DEX header.
///
/// All offsets are interpreted against the physical container (i.e. the
/// original bytes the `DexView` was constructed from); the `DexView` keeps
/// `header_off` separately so it can subtract before exposing pool offsets
/// to callers via the accessors. This matches the way logical DEX views
/// inside a DEX-041 container are encoded: each logical header's offsets are
/// already absolute.
#[derive(Debug, Clone, Copy)]
pub struct DexHeader {
    /// Magic + version. Re-derived from bytes, not trusted.
    pub version: DexVersion,

    /// Adler-32 / SHA-1 of the file (we don't re-verify them).
    pub checksum: u32,
    pub signature: [u8; 20],

    /// Total size of this logical DEX in bytes.
    pub file_size: u32,

    /// Header size in bytes. The spec mandates 0x70.
    pub header_size: u32,

    /// Endian tag — must be 0x12345678.
    pub endian_tag: u32,

    /// Link table size + offset. Unused by `asc-dex`.
    pub link_size: u32,
    pub link_off: u32,

    /// Map list offset (in bytes).
    pub map_off: u32,

    /// String pool: count + offset (each entry is a `u32` string-data offset).
    pub string_ids_size: u32,
    pub string_ids_off: u32,

    /// Type pool: each entry is a `u32` descriptor-string index.
    pub type_ids_size: u32,
    pub type_ids_off: u32,

    /// Proto pool: each entry is 12 bytes (shorty, return, params_off).
    pub proto_ids_size: u32,
    pub proto_ids_off: u32,

    /// Field pool: each entry is 8 bytes (class, type, name).
    pub field_ids_size: u32,
    pub field_ids_off: u32,

    /// Method pool: each entry is 8 bytes (class, proto, name).
    pub method_ids_size: u32,
    pub method_ids_off: u32,

    /// Class-def pool: each entry is 32 bytes.
    pub class_defs_size: u32,
    pub class_defs_off: u32,

    /// Data section size + offset. We don't use them directly, but we
    /// validate that they are consistent with the pools.
    pub data_size: u32,
    pub data_off: u32,
}

impl DexHeader {
    /// Expected header size, in bytes.
    pub const SIZE: usize = 0x70;

    /// Expected endian tag (`0x12345678`).
    pub const ENDIAN_TAG: u32 = 0x12345678;

    /// Parses a header from `bytes[header_off..]`; returns
    /// `Truncated`/`InvalidHeader`/`BadVersion` if any required field is
    /// out of range or has the wrong magic.
    pub fn parse(bytes: &[u8], header_off: usize) -> Result<Self, DexError> {
        let end = header_off
            .checked_add(Self::SIZE)
            .ok_or(DexError::InvalidHeader {
                off: header_off,
                message: "header_off overflow",
            })?;
        if end > bytes.len() {
            return Err(DexError::truncated(end, bytes.len()));
        }

        let mut magic = [0u8; 8];
        let s = crate::read::slice(bytes, header_off, 8)?;
        magic.copy_from_slice(s);
        let version = DexVersion::from_magic(&magic)?;

        let checksum = crate::read::read_u32(bytes, header_off + 0x08)?;
        let mut signature = [0u8; 20];
        signature.copy_from_slice(crate::read::slice(bytes, header_off + 0x0C, 20)?);

        let file_size = crate::read::read_u32(bytes, header_off + 0x20)?;
        let header_size = crate::read::read_u32(bytes, header_off + 0x24)?;
        let endian_tag = crate::read::read_u32(bytes, header_off + 0x28)?;

        if header_size != Self::SIZE as u32 {
            return Err(DexError::InvalidHeader {
                off: header_off + 0x24,
                message: "header_size != 0x70",
            });
        }
        if endian_tag != Self::ENDIAN_TAG {
            return Err(DexError::InvalidHeader {
                off: header_off + 0x28,
                message: "endian_tag != 0x12345678",
            });
        }

        let link_size = crate::read::read_u32(bytes, header_off + 0x2C)?;
        let link_off = crate::read::read_u32(bytes, header_off + 0x30)?;
        let map_off = crate::read::read_u32(bytes, header_off + 0x34)?;
        let string_ids_size = crate::read::read_u32(bytes, header_off + 0x38)?;
        let string_ids_off = crate::read::read_u32(bytes, header_off + 0x3C)?;
        let type_ids_size = crate::read::read_u32(bytes, header_off + 0x40)?;
        let type_ids_off = crate::read::read_u32(bytes, header_off + 0x44)?;
        let proto_ids_size = crate::read::read_u32(bytes, header_off + 0x48)?;
        let proto_ids_off = crate::read::read_u32(bytes, header_off + 0x4C)?;
        let field_ids_size = crate::read::read_u32(bytes, header_off + 0x50)?;
        let field_ids_off = crate::read::read_u32(bytes, header_off + 0x54)?;
        let method_ids_size = crate::read::read_u32(bytes, header_off + 0x58)?;
        let method_ids_off = crate::read::read_u32(bytes, header_off + 0x5C)?;
        let class_defs_size = crate::read::read_u32(bytes, header_off + 0x60)?;
        let class_defs_off = crate::read::read_u32(bytes, header_off + 0x64)?;
        let data_size = crate::read::read_u32(bytes, header_off + 0x68)?;
        let data_off = crate::read::read_u32(bytes, header_off + 0x6C)?;

        Ok(Self {
            version,
            checksum,
            signature,
            file_size,
            header_size,
            endian_tag,
            link_size,
            link_off,
            map_off,
            string_ids_size,
            string_ids_off,
            type_ids_size,
            type_ids_off,
            proto_ids_size,
            proto_ids_off,
            field_ids_size,
            field_ids_off,
            method_ids_size,
            method_ids_off,
            class_defs_size,
            class_defs_off,
            data_size,
            data_off,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn magic_recognition() {
        assert_eq!(
            DexVersion::from_magic(b"dex\n035\0").unwrap(),
            DexVersion::V035
        );
        assert_eq!(
            DexVersion::from_magic(b"dex\n041\0").unwrap(),
            DexVersion::V041
        );
        assert!(DexVersion::from_magic(b"dex\n036\0").is_err());
        assert!(DexVersion::from_magic(b"dex\n035x").is_err());
        assert!(DexVersion::from_magic(b"DEX\n035\0").is_err());
    }
}
