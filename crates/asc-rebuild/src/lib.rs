//! # asc-rebuild
//!
//! Minimal standalone DEX reconstruction: dependency closure → selected IDs
//! (sorted by original index) → old→new remaps → reference rewriting →
//! valid DEX layout → map_list → SHA-1 signature → Adler32 checksum.
//!
//! ## API
//!
//! ```no_run
//! use asc_dex::DexView;
//! use asc_rebuild::rebuild;
//!
//! let bytes = std::fs::read("classes.dex").unwrap();
//! let view = DexView::parse(&bytes).unwrap();
//! let out = rebuild(&view, "Lcom/foo/Bar;").unwrap();
//! std::fs::write("out.dex", &out.bytes).unwrap();
//! ```
//!
//! ## Pipeline
//!
//! 1. **Closure** (`closure.rs`): walk the target `ClassDef` and every
//!    reachable index — fields, methods (proto + code refs + debug_info
//!    + try/catch types), annotations (class / field / method / param),
//!      static values, call-sites, method-handles.
//! 2. **Remap** (`remap.rs`): sort selected IDs by original index and
//!    assign new index = rank. BTreeSet guarantees stable ordering.
//! 3. **Rewrite** (`rewrite.rs`): patch bytecode ref slots in place,
//!    re-encode catch-handler / debug_info / encoded_value uleb payloads.
//! 4. **Layout** (`layout.rs`): canonical section order (string_data,
//!    type_lists, encoded arrays, debug_info, annotations, code_items,
//!    class_data, then pools, then map_list). Header is written last
//!    once every cross-reference is known.
//! 5. **Seal** (`layout::seal`): SHA-1 signature over `file[32..]` and
//!    Adler-32 checksum over `file[12..]`, both computed AFTER the
//!    signature is placed.
//!
//! ## DEX-version policy
//!
//! The output version matches the source. It is automatically raised
//! to 038 if the closure picked any `call_site_id` or `method_handle`
//! entries (those pools don't exist before 038). The output is **never**
//! a 041 multi-DEX container — `rebuild` operates on one `DexView`.

#![doc(html_root_url = "https://docs.rs/asc-rebuild/0.2.0")]
#![deny(unsafe_op_in_unsafe_fn)]

pub mod error;

mod closure;
mod layout;
mod remap;
mod rewrite;
mod util;

pub use crate::error::RebuildError;

use asc_dex::DexView;

/// The rebuilt standalone DEX plus a tally of how much was kept.
#[derive(Debug, Clone)]
pub struct RebuiltDex {
    /// The complete DEX bytes (header + pools + data + map_list).
    pub bytes: Vec<u8>,
    /// Output DEX version (matches source; bumped to 038 only when
    /// call_sites/method_handles are selected).
    pub version: asc_dex::DexVersion,
    /// Size of the rebuilt file in bytes.
    pub file_size: u32,
    /// New `type_idx` assigned to the target class.
    pub target_type_idx: u32,
    /// New `class_def` offset (always `class_defs_off` in the header).
    pub class_def_off: u32,
    /// Pool sizes in the rebuilt file (new).
    pub kept: PoolCounts,
    /// Pool sizes in the source (old). Ratio of `kept`/`source`
    /// measures minimality.
    pub source: PoolCounts,
}

/// Pool size tally — both for the source DEX and the rebuilt DEX.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PoolCounts {
    pub strings: u32,
    pub types: u32,
    pub protos: u32,
    pub fields: u32,
    pub methods: u32,
    pub classes: u32,
    pub call_sites: u32,
    pub method_handles: u32,
}

/// Reconstructs a minimal standalone DEX containing only the target
/// class and its dependency closure.
///
/// `target_descriptor` must be a valid DEX class descriptor in
/// canonical form (`Lcom/foo/Bar;` or `[Lcom/foo/Bar;`).
pub fn rebuild(view: &DexView<'_>, target_descriptor: &str) -> Result<RebuiltDex, RebuildError> {
    let started = std::time::Instant::now();
    let closure = closure::Closure::compute(view, target_descriptor)?;
    let closure_us = started.elapsed().as_micros();
    let maps = remap::PoolMaps::build(&closure, view);
    let remap_us = started.elapsed().as_micros() - closure_us;
    let lo = layout::emit(view, &closure, &maps)?;
    let layout_us = started.elapsed().as_micros() - closure_us - remap_us;

    // Only emit timings when ASC_REBUILD_DEBUG=1 is set in the env so
    // the hot path stays untouched. This is the cheapest possible
    // instrumentation: a single env read at entry.
    if std::env::var_os("ASC_REBUILD_DEBUG").is_some() {
        eprintln!(
            "[ASC_REBUILD_DEBUG] closure_us={closure_us} remap_us={remap_us} layout_us={layout_us} out_bytes={}",
            lo.out.len()
        );
    }

    Ok(RebuiltDex {
        bytes: lo.out.clone(),
        version: lo.version,
        file_size: lo.out.len() as u32,
        target_type_idx: lo.target_new_type_idx,
        class_def_off: lo.class_defs_off,
        kept: PoolCounts {
            strings: lo.kept_string_count,
            types: lo.kept_type_count,
            protos: lo.kept_proto_count,
            fields: lo.kept_field_count,
            methods: lo.kept_method_count,
            classes: 1,
            call_sites: lo.kept_call_site_count,
            method_handles: lo.kept_method_handle_count,
        },
        source: PoolCounts {
            strings: lo.source_string_count,
            types: lo.source_type_count,
            protos: lo.source_proto_count,
            fields: lo.source_field_count,
            methods: lo.source_method_count,
            classes: lo.source_class_count,
            call_sites: 0,
            method_handles: 0,
        },
    })
}
