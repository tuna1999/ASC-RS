//! Test helpers: builds a tiny valid DEX byte-by-byte.
//!
//! Layout:
//! ```text
//! 0x0000 header (0x70 bytes)
//! 0x0070 string_ids: 3 * u32 (offsets into string_data)
//! 0x007C type_ids: 2 * u32 (descriptor string indices)
//! 0x0084 proto_ids: 1 * 12 bytes
//! 0x0090 field_ids: 1 * 8 bytes
//! 0x0098 method_ids: 2 * 8 bytes
//! 0x00A8 class_defs: 1 * 32 bytes
//! 0x00C8 type_list for proto params: 4 + 2 bytes
//! 0x00CE pad to 4-byte boundary
//! 0x00D0 string_data
//! ...
//! ```
//!
//! All offsets are computed by the constants in `layout`.

#![allow(dead_code)]

/// Layout constants used in `build_tiny_dex`.
pub mod layout {
    pub const HEADER_SIZE: u32 = 0x70;

    pub const STRING_IDS_OFF: u32 = 0x70;
    pub const STRING_IDS_SIZE: u32 = 3;
    pub const STRING_IDS_END: u32 = STRING_IDS_OFF + STRING_IDS_SIZE * 4;

    pub const TYPE_IDS_OFF: u32 = STRING_IDS_END;
    pub const TYPE_IDS_SIZE: u32 = 2;
    pub const TYPE_IDS_END: u32 = TYPE_IDS_OFF + TYPE_IDS_SIZE * 4;

    pub const PROTO_IDS_OFF: u32 = TYPE_IDS_END;
    pub const PROTO_IDS_SIZE: u32 = 1;
    pub const PROTO_IDS_END: u32 = PROTO_IDS_OFF + PROTO_IDS_SIZE * 12;

    pub const FIELD_IDS_OFF: u32 = PROTO_IDS_END;
    pub const FIELD_IDS_SIZE: u32 = 1;
    pub const FIELD_IDS_END: u32 = FIELD_IDS_OFF + FIELD_IDS_SIZE * 8;

    pub const METHOD_IDS_OFF: u32 = FIELD_IDS_END;
    pub const METHOD_IDS_SIZE: u32 = 2;
    pub const METHOD_IDS_END: u32 = METHOD_IDS_OFF + METHOD_IDS_SIZE * 8;

    pub const CLASS_DEFS_OFF: u32 = METHOD_IDS_END;
    pub const CLASS_DEFS_SIZE: u32 = 1;
    pub const CLASS_DEFS_END: u32 = CLASS_DEFS_OFF + CLASS_DEFS_SIZE * 32;

    pub const TYPE_LIST_PARAMS_OFF: u32 = CLASS_DEFS_END;
    pub const TYPE_LIST_PARAMS_SIZE: u32 = 1;
    pub const TYPE_LIST_PARAMS_END: u32 = TYPE_LIST_PARAMS_OFF + 4 + TYPE_LIST_PARAMS_SIZE * 2;

    pub const STRING_DATA_OFF: u32 = align4(TYPE_LIST_PARAMS_END);

    pub const STR0_DATA_OFF: u32 = STRING_DATA_OFF;
    pub const STR0_PAYLOAD: &[u8] = b"LTest;";
    pub const STR0_END: u32 = STR0_DATA_OFF + 1 + STR0_PAYLOAD.len() as u32 + 1;

    pub const STR1_DATA_OFF: u32 = STR0_END;
    pub const STR1_PAYLOAD: &[u8] = b"main";
    pub const STR1_END: u32 = STR1_DATA_OFF + 1 + STR1_PAYLOAD.len() as u32 + 1;

    pub const STR2_DATA_OFF: u32 = STR1_END;
    pub const STR2_PAYLOAD: &[u8] = b"V";
    pub const STR2_END: u32 = STR2_DATA_OFF + 1 + STR2_PAYLOAD.len() as u32 + 1;

    pub const STR3_DATA_OFF: u32 = STR2_END;
    /// 6-byte MUTF-8 sequence for U+1F600 + 1-byte uleb + 1-byte terminator.
    pub const STR3_PAYLOAD: &[u8] = &[0xED, 0xA0, 0xBD, 0xED, 0xB8, 0x80];
    pub const STR3_END: u32 = STR3_DATA_OFF + 1 + STR3_PAYLOAD.len() as u32 + 1;

    pub const STRING_DATA_END: u32 = STR3_END;
    pub const CLASS_DATA_OFF: u32 = align4(STRING_DATA_END);
    pub const CLASS_DATA_END: u32 = CLASS_DATA_OFF + 8; // 4 uleb sizes + 3 ulebs for 1 method = 7, pad to 8

    pub const CODE_OFF: u32 = align4(CLASS_DATA_END);
    pub const INSNS_SIZE: u32 = 3;
    pub const TRIES_SIZE: u16 = 1;
    pub const CODE_HEADER_END: u32 = CODE_OFF + 16;
    pub const INSNS_END: u32 = CODE_HEADER_END + INSNS_SIZE * 2 + 2; // +2 padding
    pub const TRIES_END: u32 = INSNS_END + 8;
    pub const HANDLER_LIST_OFF: u32 = align4(TRIES_END);
    // 4-byte list size + entry bytes (1 byte sleb + 1 byte uleb + 1 byte uleb = 3 bytes).
    pub const HANDLER_LIST_END: u32 = HANDLER_LIST_OFF + 4 + 3;

    pub const DEBUG_OFF: u32 = align4(HANDLER_LIST_END);
    pub const DEBUG_END: u32 = DEBUG_OFF + 4;

    pub const ANNOTATIONS_DIR_OFF: u32 = align4(DEBUG_END);
    pub const ANNOTATIONS_DIR_END: u32 = ANNOTATIONS_DIR_OFF + 16;

    pub const MAP_OFF: u32 = align4(ANNOTATIONS_DIR_END);
    pub const MAP_END: u32 = MAP_OFF + 4 + 4 * 12; // size + 4 entries

    pub const FILE_SIZE: u32 = align4(MAP_END);

    #[inline]
    pub const fn align4(x: u32) -> u32 {
        (x + 3) & !3
    }
}

pub fn tiny_dex() -> Vec<u8> {
    use layout::*;
    let mut buf = vec![0u8; FILE_SIZE as usize];
    write_header(&mut buf);
    write_string_ids(&mut buf);
    write_type_ids(&mut buf);
    write_proto_ids(&mut buf);
    write_field_ids(&mut buf);
    write_method_ids(&mut buf);
    write_class_defs(&mut buf);
    write_type_list_params(&mut buf);
    write_string_data(&mut buf);
    write_class_data(&mut buf);
    write_code_item(&mut buf);
    write_debug_info(&mut buf);
    write_annotations_directory(&mut buf);
    write_map(&mut buf);
    buf
}

fn put_u8(buf: &mut [u8], off: u32, v: u8) {
    buf[off as usize] = v;
}
fn put_u16(buf: &mut [u8], off: u32, v: u16) {
    buf[off as usize..off as usize + 2].copy_from_slice(&v.to_le_bytes());
}
fn put_u32(buf: &mut [u8], off: u32, v: u32) {
    buf[off as usize..off as usize + 4].copy_from_slice(&v.to_le_bytes());
}
fn put_bytes(buf: &mut [u8], off: u32, s: &[u8]) {
    buf[off as usize..off as usize + s.len()].copy_from_slice(s);
}

fn write_header(buf: &mut [u8]) {
    use layout::*;
    put_bytes(buf, 0, b"dex\n035\0");
    put_u32(buf, 0x08, 0);
    put_u32(buf, 0x20, FILE_SIZE);
    put_u32(buf, 0x24, HEADER_SIZE);
    put_u32(buf, 0x28, 0x12345678);
    put_u32(buf, 0x2C, 0);
    put_u32(buf, 0x30, 0);
    put_u32(buf, 0x34, MAP_OFF);
    put_u32(buf, 0x38, STRING_IDS_SIZE);
    put_u32(buf, 0x3C, STRING_IDS_OFF);
    put_u32(buf, 0x40, TYPE_IDS_SIZE);
    put_u32(buf, 0x44, TYPE_IDS_OFF);
    put_u32(buf, 0x48, PROTO_IDS_SIZE);
    put_u32(buf, 0x4C, PROTO_IDS_OFF);
    put_u32(buf, 0x50, FIELD_IDS_SIZE);
    put_u32(buf, 0x54, FIELD_IDS_OFF);
    put_u32(buf, 0x58, METHOD_IDS_SIZE);
    put_u32(buf, 0x5C, METHOD_IDS_OFF);
    put_u32(buf, 0x60, CLASS_DEFS_SIZE);
    put_u32(buf, 0x64, CLASS_DEFS_OFF);
    put_u32(buf, 0x68, 0);
    put_u32(buf, 0x6C, 0);
}

fn write_string_ids(buf: &mut [u8]) {
    use layout::*;
    put_u32(buf, STRING_IDS_OFF, STR0_DATA_OFF);
    put_u32(buf, STRING_IDS_OFF + 4, STR1_DATA_OFF);
    put_u32(buf, STRING_IDS_OFF + 8, STR2_DATA_OFF);
}

fn write_type_ids(buf: &mut [u8]) {
    use layout::*;
    put_u32(buf, TYPE_IDS_OFF, 0);
    put_u32(buf, TYPE_IDS_OFF + 4, 2);
}

fn write_proto_ids(buf: &mut [u8]) {
    use layout::*;
    put_u32(buf, PROTO_IDS_OFF, 1);
    put_u32(buf, PROTO_IDS_OFF + 4, 1);
    put_u32(buf, PROTO_IDS_OFF + 8, TYPE_LIST_PARAMS_OFF);
}

fn write_field_ids(buf: &mut [u8]) {
    use layout::*;
    put_u16(buf, FIELD_IDS_OFF, 0);
    put_u16(buf, FIELD_IDS_OFF + 2, 1);
    put_u32(buf, FIELD_IDS_OFF + 4, 0);
}

fn write_method_ids(buf: &mut [u8]) {
    use layout::*;
    put_u16(buf, METHOD_IDS_OFF, 0);
    put_u16(buf, METHOD_IDS_OFF + 2, 0);
    put_u32(buf, METHOD_IDS_OFF + 4, 1);
    put_u16(buf, METHOD_IDS_OFF + 8, 0);
    put_u16(buf, METHOD_IDS_OFF + 10, 0);
    put_u32(buf, METHOD_IDS_OFF + 12, 1);
}

fn write_class_defs(buf: &mut [u8]) {
    use layout::*;
    put_u32(buf, CLASS_DEFS_OFF, 0);
    put_u32(buf, CLASS_DEFS_OFF + 4, 1);
    put_u32(buf, CLASS_DEFS_OFF + 8, 0xFFFF_FFFF);
    put_u32(buf, CLASS_DEFS_OFF + 12, 0);
    put_u32(buf, CLASS_DEFS_OFF + 16, 0xFFFF_FFFF);
    put_u32(buf, CLASS_DEFS_OFF + 20, 0);
    put_u32(buf, CLASS_DEFS_OFF + 24, CLASS_DATA_OFF);
    put_u32(buf, CLASS_DEFS_OFF + 28, 0);
}

fn write_type_list_params(buf: &mut [u8]) {
    use layout::*;
    put_u32(buf, TYPE_LIST_PARAMS_OFF, TYPE_LIST_PARAMS_SIZE);
    put_u16(buf, TYPE_LIST_PARAMS_OFF + 4, 1);
}

fn write_string_data(buf: &mut [u8]) {
    use layout::*;
    put_u8(buf, STR0_DATA_OFF, 7);
    put_bytes(buf, STR0_DATA_OFF + 1, STR0_PAYLOAD);
    put_u8(buf, STR0_END - 1, 0);

    put_u8(buf, STR1_DATA_OFF, 4);
    put_bytes(buf, STR1_DATA_OFF + 1, STR1_PAYLOAD);
    put_u8(buf, STR1_END - 1, 0);

    put_u8(buf, STR2_DATA_OFF, 1);
    put_bytes(buf, STR2_DATA_OFF + 1, STR2_PAYLOAD);
    put_u8(buf, STR2_END - 1, 0);

    put_u8(buf, STR3_DATA_OFF, 2);
    put_bytes(buf, STR3_DATA_OFF + 1, STR3_PAYLOAD);
    put_u8(buf, STR3_END - 1, 0);
}

fn write_class_data(buf: &mut [u8]) {
    use layout::*;
    let mut off = CLASS_DATA_OFF;
    off = put_uleb(buf, off, 0);
    off = put_uleb(buf, off, 0);
    off = put_uleb(buf, off, 1);
    off = put_uleb(buf, off, 0);
    off = put_uleb(buf, off, 0);
    off = put_uleb(buf, off, 1);
    off = put_uleb(buf, off, CODE_OFF);
    debug_assert_eq!(off, CLASS_DATA_END);
}

fn put_uleb(buf: &mut [u8], mut off: u32, mut v: u32) -> u32 {
    while v > 0x7F {
        put_u8(buf, off, ((v & 0x7F) as u8) | 0x80);
        v >>= 7;
        off += 1;
    }
    put_u8(buf, off, v as u8);
    off + 1
}

fn put_sleb(buf: &mut [u8], mut off: u32, mut v: i32) -> u32 {
    let mut more = true;
    while more {
        let byte = (v as u8) & 0x7F;
        v >>= 7;
        let sign = (byte & 0x40) != 0;
        if (v == 0 && !sign) || (v == -1 && sign) {
            put_u8(buf, off, byte);
            off += 1;
            more = false;
        } else {
            put_u8(buf, off, byte | 0x80);
            off += 1;
        }
    }
    off
}

fn write_code_item(buf: &mut [u8]) {
    use layout::*;
    let mut off = CODE_OFF;
    put_u16(buf, off, 1);
    off += 2;
    put_u16(buf, off, 1);
    off += 2;
    put_u16(buf, off, 0);
    off += 2;
    put_u16(buf, off, TRIES_SIZE);
    off += 2;
    put_u32(buf, off, DEBUG_OFF);
    off += 4;
    put_u32(buf, off, INSNS_SIZE);
    off += 4;
    put_u16(buf, off, 0x000E);
    off += 2;
    put_u16(buf, off, 0x000E);
    off += 2;
    put_u16(buf, off, 0x000E);
    off += 2;
    put_u8(buf, off, 0);
    off += 1;
    put_u8(buf, off, 0);
    off += 1;
    debug_assert_eq!(off, INSNS_END);
    put_u32(buf, off, 0);
    off += 4;
    put_u16(buf, off, 3);
    off += 2;
    put_u16(buf, off, 0);
    off += 2;
    debug_assert_eq!(off, TRIES_END);
    let mut ho = HANDLER_LIST_OFF;
    put_u32(buf, ho, HANDLER_LIST_END - ho - 4);
    ho += 4;
    ho = put_sleb(buf, ho, 1);
    ho = put_uleb(buf, ho, 1);
    ho = put_uleb(buf, ho, 0);
    debug_assert_eq!(ho, HANDLER_LIST_END);
}

fn write_debug_info(buf: &mut [u8]) {
    use layout::*;
    let mut off = DEBUG_OFF;
    off = put_uleb(buf, off, 1);
    off = put_uleb(buf, off, 1);
    off = put_uleb(buf, off, 2);
    put_u8(buf, off, 0x00);
    off += 1;
    debug_assert_eq!(off, DEBUG_END);
}

fn write_annotations_directory(buf: &mut [u8]) {
    use layout::*;
    let mut off = ANNOTATIONS_DIR_OFF;
    put_u32(buf, off, 0);
    off += 4;
    put_u32(buf, off, 0);
    off += 4;
    put_u32(buf, off, 0);
    off += 4;
    put_u32(buf, off, 0);
    off += 4;
    debug_assert_eq!(off, ANNOTATIONS_DIR_END);
}

fn write_map(buf: &mut [u8]) {
    use layout::*;
    let mut off = MAP_OFF;
    put_u32(buf, off, 4);
    off += 4;
    put_u16(buf, off, 0x0000);
    off += 2;
    put_u16(buf, off, 0);
    off += 2;
    put_u32(buf, off, 1);
    off += 4;
    put_u32(buf, off, 0);
    off += 4;

    put_u16(buf, off, 0x2001);
    off += 2;
    put_u16(buf, off, 0);
    off += 2;
    put_u32(buf, off, 1);
    off += 4;
    put_u32(buf, off, CODE_OFF);
    off += 4;

    put_u16(buf, off, 0x2005);
    off += 2;
    put_u16(buf, off, 0);
    off += 2;
    put_u32(buf, off, 1);
    off += 4;
    put_u32(buf, off, DEBUG_OFF);
    off += 4;

    put_u16(buf, off, 0x2006);
    off += 2;
    put_u16(buf, off, 0);
    off += 2;
    put_u32(buf, off, 1);
    off += 4;
    put_u32(buf, off, ANNOTATIONS_DIR_OFF);
    off += 4;

    debug_assert_eq!(off, MAP_END);
}
