//! Contract: `asc_decompile::droidsaw::DroidsawBackend::disassemble`
//! never panics, never returns an untyped failure, and terminates.
//!
//! `DroidsawBackend` runs every parse/emit step under
//! `std::panic::catch_unwind`, so an upstream `droidsaw-dex` panic is
//! swallowed and re-labelled as
//! `DecompileError::BackendError("droidsaw-dex panicked during
//! disassemble")`. That is exactly the failure this target must
//! catch: a caught panic is still a crash upstream and is reported as
//! one here (the runner's panic hook then dumps the input to
//! `crashes/`). Every other outcome — `Ok`, or any of the typed
//! `ClassNotFound` / `MethodNotFound` / `MalformedDex` /
//! `UnsupportedVersion` / `BackendError` variants — is ordinary parse
//! behaviour and is classified as deep (`Ok`) or boundary.
//!
//! Two calls per input, as the contract requires: one with a fixed
//! descriptor and no method filter, one with a descriptor resolved
//! from the input itself plus a `Some("a")` filter, so a mutated DEX
//! that still parses drives the real listing path.
//!
//! ## Re-sealing
//!
//! `DexFile::parse` verifies the header adler32 over `bytes[0x0C..]`
//! (and records, but does not enforce, the SHA-1 signature), so an
//! unmodified mutation of a seed dies at the checksum and never
//! reaches the renderer. [`reseal`] recomputes both over the mutated
//! bytes. It is applied to 7 of every 8 inputs — keyed on a header
//! byte the mutation already perturbs, so the choice needs no RNG and
//! stays deterministic — and the remaining eighth exercises the
//! un-sealed checksum path.
//!
//! Bounded work: per-execution cost is linear in the input, and the
//! mutation engine already caps its output at 256 KiB
//! (`MAX_OUTPUT_LEN` in `src/bin/fuzz-runner.rs`) and seeds at 16 MiB.
//! No cap of our own is applied because `--regress` is pointed at real
//! multi-megabyte `corpus/dex/*.dex` files, which is where the listing
//! path actually gets exercised.
//!
//! Behind the `decompile` feature (which enables `dex` too — the
//! descriptor lookup goes through `asc_dex::DexView`).

use crate::FuzzOutcome;

/// Substring of the message `DroidsawBackend` produces when its
/// `catch_unwind` caught a panic. Covers the `disassemble` and
/// `decompile_class` variants.
const PANIC_MARKER: &str = "droidsaw-dex panicked during";

/// Header bytes the mutation engine perturbs for essentially every
/// input, and which carry no format meaning: `file_size` (0x20) and
/// `link_size` (0x2C). Used to pick the 1-in-8 un-sealed case.
const ENTROPY_BYTE_1: usize = 0x20;
const ENTROPY_BYTE_2: usize = 0x2C;

#[cfg(feature = "decompile")]
pub fn run(input: &[u8]) -> FuzzOutcome {
    use asc_decompile::ClassDecompiler;
    use asc_decompile::droidsaw::DroidsawBackend;

    let bytes = reseal(input);
    let backend = DroidsawBackend::new();
    let mut deep = false;
    // Two calls per input: a fixed descriptor with no filter, then
    // the input's own first class with a method-name filter. The
    // filter is the seed's real method name — a short prefix is
    // equally valid for the renderer, but an empty filter always
    // resolves and so never exercises the `MethodNotFound` /
    // resolved-listing path.
    for (descriptor, method) in [
        ("Lfoo/Bar;".to_string(), None),
        (
            first_descriptor(&bytes).unwrap_or_else(|| "Ljava/lang/Object;".to_string()),
            Some("a"),
        ),
    ] {
        deep |= reached_renderer(backend.disassemble(&bytes, &descriptor, method));
    }

    if deep {
        FuzzOutcome::Ok
    } else {
        FuzzOutcome::BoundaryHit("disasm_gate")
    }
}

/// `true` when the call got past the cheap input gates — i.e. the
/// bytes were recognised as a DEX and the renderer (or class
/// resolution) actually ran.
#[cfg(feature = "decompile")]
fn reached_renderer(res: Result<String, asc_decompile::DecompileError>) -> bool {
    use asc_decompile::DecompileError;

    match res {
        Ok(_) => true,
        // A caught panic must be surfaced as a failure of the fuzz
        // run, not swallowed like a parse error.
        Err(DecompileError::BackendError(msg)) if msg.contains(PANIC_MARKER) => {
            panic!("upstream panic converted to a typed error: {msg}")
        }
        Err(DecompileError::MalformedDex(_)) | Err(DecompileError::UnsupportedVersion(_)) => false,
        Err(_) => true,
    }
}

/// Recompute the header signature (0x0C..0x20) and checksum
/// (0x08..0x0C) over the mutated DEX, so mutations reach the
/// renderer instead of dying at the checksum.
///
/// Borrowed when no re-seal is needed (not a DEX, too short, or the
/// 1-in-8 un-sealed case); the real DEX fixtures replayed by
/// `--regress` are passed through untouched.
#[cfg(feature = "decompile")]
fn reseal(input: &[u8]) -> std::borrow::Cow<'_, [u8]> {
    const HEADER: usize = 0x70;
    if input.len() < HEADER
        || &input[..4] != b"dex\n"
        || (input[ENTROPY_BYTE_1].wrapping_add(input[ENTROPY_BYTE_2]) as u32).is_multiple_of(8)
    {
        return std::borrow::Cow::Borrowed(input);
    }
    let mut b = input.to_vec();
    // The parser verifies adler32 over `bytes[0x0C .. header.file_size]`
    // and rejects a `file_size` past the buffer, so a truncated
    // mutation has to declare its real length to get a checksum check
    // at all.
    let file_size = (b.len() as u32).to_le_bytes();
    b[0x20..0x24].copy_from_slice(&file_size);
    // Same for the other two header constants: `header_size` and
    // `endian_tag` are validated on every parse, and leaving them
    // mutated would keep most inputs out of the pool/code sections
    // even after a correct checksum.
    b[0x24..0x28].copy_from_slice(&(HEADER as u32).to_le_bytes());
    b[0x28..0x2C].copy_from_slice(&0x1234_5678u32.to_le_bytes());
    let sig = sha1(&b[0x20..]);
    let adler = adler32(&b[0x0C..]).to_le_bytes();
    b[0x0C..0x20].copy_from_slice(&sig);
    b[0x08..0x0C].copy_from_slice(&adler);
    std::borrow::Cow::Owned(b)
}

/// Adler-32 (RFC 1950) — the DEX header checksum.
#[cfg(feature = "decompile")]
fn adler32(data: &[u8]) -> u32 {
    let (mut a, mut b) = (1u32, 0u32);
    for chunk in data.chunks(5552) {
        for &byte in chunk {
            a += u32::from(byte);
            b += a;
        }
        a %= 65521;
        b %= 65521;
    }
    (b << 16) | a
}

/// SHA-1 (FIPS 180-4) — the DEX header signature. The parser records
/// it but does not enforce it; writing it anyway keeps the header
/// self-consistent, so a mutated file is rejected for the reason it
/// actually violates rather than for a stale signature.
#[cfg(feature = "decompile")]
fn sha1(data: &[u8]) -> [u8; 20] {
    let mut h: [u32; 5] = [
        0x6745_2301,
        0xEFCD_AB89,
        0x98BA_DCFE,
        0x1032_5476,
        0xC3D2_E1F0,
    ];
    let bit_len = (data.len() as u64).wrapping_mul(8);
    let mut msg = data.to_vec();
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bit_len.to_be_bytes());

    let mut w = [0u32; 80];
    for block in msg.chunks_exact(64) {
        for (i, word) in w.iter_mut().take(16).enumerate() {
            let o = i * 4;
            *word = u32::from_be_bytes([block[o], block[o + 1], block[o + 2], block[o + 3]]);
        }
        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }
        let [mut a, mut b, mut c, mut d, mut e] = h;
        for (i, wi) in w.iter().enumerate() {
            let (f, k) = match i {
                0..=19 => ((b & c) | (!b & d), 0x5A82_7999u32),
                20..=39 => (b ^ c ^ d, 0x6ED9_EBA1),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8F1B_BCDC),
                _ => (b ^ c ^ d, 0xCA62_C1D6),
            };
            let tmp = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(*wi);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = tmp;
        }
        for (slot, v) in h.iter_mut().zip([a, b, c, d, e]) {
            *slot = slot.wrapping_add(v);
        }
    }

    let mut out = [0u8; 20];
    for (i, word) in h.iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
    }
    out
}

/// Descriptor of the first `class_def` in `bytes`, so a fuzz input
/// that still parses drives a real listing instead of a
/// `ClassNotFound`. `None` when the bytes do not parse — the
/// fixed-descriptor call covers that case.
#[cfg(feature = "decompile")]
fn first_descriptor(bytes: &[u8]) -> Option<String> {
    use asc_dex::DexView;

    let view = DexView::parse(bytes).ok()?;
    let def = view.class_def(0).ok()?;
    let name = view.string(view.type_(def.class).ok()?).ok()?;
    Some(name.decode_lossy().into_owned())
}

#[cfg(not(feature = "decompile"))]
pub fn run(_input: &[u8]) -> FuzzOutcome {
    FuzzOutcome::SkippedDisabled
}
