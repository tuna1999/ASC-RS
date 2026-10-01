//! Opt-in Paranoid / LSParanoid string deobfuscation (`--paranoid`).
//!
//! The deobfuscator class may live in any `classes*.dex`, so its chunk
//! table is collected APK-wide first; call sites are then resolved per
//! DEX with [`asc_paranoid::Resolver`].

use asc_apk::Apk;
use asc_dex::view::DexView;
use asc_paranoid::{Deobfuscator, Resolver, find_deobfuscators};
use asc_query::CodeOwners;
use asc_rebuild::StringPatch;

/// Calls `f` on every logical DEX view in one entry's bytes.
fn for_each_view(bytes: &[u8], mut f: impl FnMut(&DexView<'_>)) {
    let offsets = if bytes.starts_with(b"dex\n041\0") {
        DexView::logical_header_offsets(bytes).unwrap_or_default()
    } else {
        vec![0]
    };
    for off in offsets {
        if let Ok(view) = DexView::parse_at(bytes, off) {
            f(&view);
        }
    }
}

/// Every Paranoid deobfuscator defined anywhere in `apk`. Unreadable or
/// unparsable entries contribute nothing.
pub(crate) fn collect(apk: &Apk) -> Vec<Deobfuscator> {
    let mut out = Vec::new();
    for entry in apk.dex_entries() {
        if let Ok(bytes) = apk.read_entry(&entry) {
            for_each_view(bytes.as_slice(), |view| {
                out.extend(find_deobfuscators(view))
            });
        }
    }
    out
}

/// `(caller method idx, code-unit offset, decoded string)` for every
/// resolved `getString` call in `view` whose value contains `pattern`.
pub(crate) fn decoded_hits(
    view: &DexView<'_>,
    deobs: &[Deobfuscator],
    pattern: &str,
) -> Vec<(u32, u32, String)> {
    let resolver = Resolver::new(view, deobs);
    let mut out = Vec::new();
    if resolver.is_empty() {
        return out;
    }
    for owner in CodeOwners::build(view).owners() {
        let Ok(Some(code)) = view.code_item(owner.code_off) else {
            continue;
        };
        for call in resolver.calls(view, &code) {
            let value = String::from_utf16_lossy(&call.value);
            if value.contains(pattern) {
                out.extend(
                    owner
                        .methods
                        .iter()
                        .map(|m| (m.0, call.offset, value.clone())),
                );
            }
        }
    }
    out
}

/// Rebuild patches turning every resolvable `getString` call (whose
/// result is used) in class `target` into a string constant.
pub(crate) fn class_patches(
    view: &DexView<'_>,
    target: &str,
    deobs: &[Deobfuscator],
) -> Vec<StringPatch> {
    let resolver = Resolver::new(view, deobs);
    let mut out = Vec::new();
    if resolver.is_empty() {
        return out;
    }
    let data = (0..view.class_def_count()).find_map(|i| {
        let def = view.class_def(i).ok()?;
        let desc = view.string(view.type_(def.class).ok()?).ok()?;
        (desc.raw_mutf8() == target.as_bytes())
            .then(|| view.class_data(def.class_data_off).ok().flatten())?
    });
    let Some(data) = data else { return out };
    for m in data.direct_methods.iter().chain(&data.virtual_methods) {
        let Ok(Some(code)) = view.code_item(m.code_off) else {
            continue;
        };
        for call in resolver.calls(view, &code) {
            if let Some(result) = call.result {
                out.push(StringPatch {
                    code_off: m.code_off,
                    offset: call.offset,
                    result,
                    value: call.value,
                });
            }
        }
    }
    out
}

// ---------------- XOR const-array deobfuscation (--decode-xor) ----------

use asc_paranoid::XorDecoder;

/// Every XOR decoder defined anywhere in `apk` (see
/// `asc_paranoid::xor` for the recognized shape).
pub(crate) fn collect_xor(apk: &Apk) -> Vec<XorDecoder> {
    let mut out = Vec::new();
    for entry in apk.dex_entries() {
        if let Ok(bytes) = apk.read_entry(&entry) {
            for_each_view(bytes.as_slice(), |view| {
                out.extend(asc_paranoid::find_xor_decoders(view))
            });
        }
    }
    out
}

/// `(caller method idx, code-unit offset, decoded string)` for every
/// provable XOR call in `view` whose value contains `pattern`.
pub(crate) fn xor_decoded_hits(
    view: &DexView<'_>,
    decoders: &[XorDecoder],
    pattern: &str,
) -> Vec<(u32, u32, String)> {
    let resolver = asc_paranoid::XorResolver::new(view, decoders);
    let mut out = Vec::new();
    if resolver.is_empty() {
        return out;
    }
    for owner in CodeOwners::build(view).owners() {
        let Ok(Some(code)) = view.code_item(owner.code_off) else {
            continue;
        };
        for call in resolver.calls(view, &code) {
            let value = String::from_utf16_lossy(&call.value);
            if value.contains(pattern) {
                out.extend(
                    owner
                        .methods
                        .iter()
                        .map(|m| (m.0, call.offset, value.clone())),
                );
            }
        }
    }
    out
}

/// Rebuild patches turning every provable, alias-free XOR decoder call in
/// class `target` into a string constant.
pub(crate) fn xor_class_patches(
    view: &DexView<'_>,
    target: &str,
    decoders: &[XorDecoder],
) -> Vec<StringPatch> {
    let resolver = asc_paranoid::XorResolver::new(view, decoders);
    let mut out = Vec::new();
    if resolver.is_empty() {
        return out;
    }
    let data = (0..view.class_def_count()).find_map(|i| {
        let def = view.class_def(i).ok()?;
        let desc = view.string(view.type_(def.class).ok()?).ok()?;
        (desc.raw_mutf8() == target.as_bytes())
            .then(|| view.class_data(def.class_data_off).ok().flatten())?
    });
    let Some(data) = data else { return out };
    for m in data.direct_methods.iter().chain(&data.virtual_methods) {
        let Ok(Some(code)) = view.code_item(m.code_off) else {
            continue;
        };
        for call in resolver.calls(view, &code) {
            if call.patchable
                && let Some(result) = call.result
            {
                out.push(StringPatch {
                    code_off: m.code_off,
                    offset: call.offset,
                    result,
                    value: call.value,
                });
            }
        }
    }
    out
}
