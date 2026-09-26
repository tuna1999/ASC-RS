//! `DroidsawBackend` — thin adapter over the `droidsaw-dex` crate.
//!
//! The backend handles all parsing, class resolution, and Java source
//! emission internally; asc-decompile callers only see
//! [`crate::ClassDecompiler::decompile`].
//!
//! The version is pinned exactly (`=1.0.0`) because droidsaw-dex has
//! no documented SemVer stability promise across minor versions (the
//! 2.0.0 release requires Rust 1.93, breaks `droidsaw-common` 1.x, and
//! rearranges its public re-exports — see `BACKENDS.md` §2 for the
//! evaluation). Until upstream ships a stable API, asc-rs treats each
//! minor as breaking and pins exact.
//!
//! All parse/emit steps run inside `std::panic::catch_unwind` so a
//! panic from the third-party crate is converted into
//! [`DecompileError::BackendError`] rather than aborting the caller.
//!
//! ## Parse cache
//!
//! [`DexFile::parse`] is the dominant cost in `decompile` (~70% of
//! wall time on the workload fixture per `BACKENDS.md` §4). When the
//! GUI/CLI decompiles multiple classes from the same minimal DEX
//! (typical workflow — open APK, click around several classes), the
//! rebuild output for each is small (KB-MB) and parsed afresh on every
//! call. We cache by `crc32fast::hash(dex_bytes)` in a bounded
//! `HashMap`. On hit we still re-resolve the class_def for the
//! requested descriptor, so cache-key collisions cannot yield a wrong
//! class.

use std::collections::HashMap;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::Arc;
use std::sync::Mutex;

use droidsaw_dex::{
    classes::decompile_class_with_census, parser::DexFile, r8_inversion::build_trampoline_census,
};

use crate::{ClassDecompiler, DecompileError, normalize_class_name};

/// DEX magic prefix `dex\n` plus the 3-byte version (`035`..=`041`).
const DEX_MAGIC_PREFIX: &[u8; 4] = b"dex\n";

/// Maximum number of cached parsed `DexFile`s. Most sessions decompile
/// <16 distinct classes; over that we drop the oldest by insertion
/// order (cheap FIFO; no real LRU needed at this size).
const PARSE_CACHE_CAP: usize = 16;

/// Adapter over the [`droidsaw-dex`](https://crates.io/crates/droidsaw-dex) crate.
///
/// Construct with [`DroidsawBackend::new`]; pass to anything that takes
/// `&dyn ClassDecompiler`. The backend holds a small parse cache so
/// repeated `decompile` calls on the same DEX bytes (the rebuild output
/// for `(apk, target)` is deterministic) skip the expensive
/// `DexFile::parse` step.
#[derive(Debug, Default, Clone)]
pub struct DroidsawBackend {
    /// `(crc32(dex_bytes) → parsed DexFile)`. Bounded FIFO; on insert
    /// past `PARSE_CACHE_CAP` we drop the first inserted entry.
    cache: Arc<Mutex<HashMap<u32, Arc<DexFile>>>>,
}

impl DroidsawBackend {
    /// Build a backend instance with an empty parse cache.
    pub fn new() -> Self {
        Self::default()
    }
}

impl ClassDecompiler for DroidsawBackend {
    fn decompile(&self, dex_bytes: &[u8], target: &str) -> Result<String, DecompileError> {
        // 1. Input shape gates — cheap checks before invoking the parser.
        if dex_bytes.is_empty() {
            return Err(DecompileError::MalformedDex("empty input".into()));
        }
        if dex_bytes.len() < 8 || &dex_bytes[..4] != DEX_MAGIC_PREFIX {
            return Err(DecompileError::MalformedDex("missing dex\\n magic".into()));
        }
        // Version gate — droidsaw-dex claims 035..=041 support (CHANGELOG
        // §1.0.0). Reject anything outside so callers get a typed error.
        let ver = &dex_bytes[4..7];
        let version_ok = matches!(
            ver,
            b"035" | b"036" | b"037" | b"038" | b"039" | b"040" | b"041"
        );
        if !version_ok {
            return Err(DecompileError::UnsupportedVersion(format!(
                "magic version {:?} not in 035..=041",
                std::str::from_utf8(ver).unwrap_or("<non-utf8>"),
            )));
        }

        // 2. Normalise the class name. Empty → ClassNotFound.
        let descriptor = normalize_class_name(target)?;

        // 3. Hash the DEX bytes (fast content fingerprint) and consult
        //    the parse cache. On hit we still re-resolve the class_def
        //    for the requested descriptor, so cache-key collisions
        //    cannot yield a wrong class.
        let hash = crc32fast::hash(dex_bytes);
        let dex = if let Some(cached) = self
            .cache
            .lock()
            .expect("parse-cache mutex poisoned")
            .get(&hash)
            .cloned()
        {
            cached
        } else {
            let parsed = Arc::new(DexFile::parse(dex_bytes, None).map_err(|e| {
                DecompileError::MalformedDex(format!("droidsaw_dex::DexError: {e:?}"))
            })?);
            let mut cache = self.cache.lock().expect("parse-cache mutex poisoned");
            // FIFO eviction: when over cap, remove the first inserted
            // entry. `HashMap` iteration order in Rust is insertion order
            // for non-rehashed maps, which is enough for a 16-entry
            // cap (no measurable churn in practice).
            if cache.len() >= PARSE_CACHE_CAP {
                if let Some(&oldest) = cache.keys().next() {
                    cache.remove(&oldest);
                }
            }
            cache.insert(hash, Arc::clone(&parsed));
            parsed
        };

        // 4. Locate the matching class_def. droidsaw-dex ships
        //    `find_class` which does exact-descriptor → exact-short-name
        //    → substring lookup in one call (see droidsaw-dex `api.rs`).
        let found = dex.find_class(&descriptor);
        let class_def = match found {
            Some((_idx, cd)) => cd,
            None => return Err(DecompileError::ClassNotFound(descriptor.clone())),
        };

        // 5. Build the trampoline census (amortises the R8-inversion
        //    pre-scan across all methods in the class). This cost is
        //    small relative to DexFile::parse, so we re-run on every
        //    call rather than caching.
        let census = build_trampoline_census(&dex);

        // 6. Decompile. Wrap in catch_unwind so a third-party panic is
        //    turned into a typed BackendError.
        let result = catch_unwind(AssertUnwindSafe(|| {
            decompile_class_with_census(&dex, dex_bytes, class_def, &census)
        }));
        match result {
            Ok(java) if java.is_empty() => Err(DecompileError::BackendError(
                "decompile_class_with_census returned empty string".into(),
            )),
            Ok(java) => Ok(java),
            Err(_) => Err(DecompileError::BackendError(
                "droidsaw-dex panicked during decompile_class".into(),
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_input_is_malformed() {
        let backend = DroidsawBackend::new();
        let err = backend.decompile(&[], "Lfoo/Bar;").unwrap_err();
        assert!(matches!(err, DecompileError::MalformedDex(_)));
    }

    #[test]
    fn short_input_is_malformed() {
        let backend = DroidsawBackend::new();
        let bytes = b"dex\n039";
        let err = backend.decompile(bytes, "Lfoo/Bar;").unwrap_err();
        assert!(matches!(err, DecompileError::MalformedDex(_)));
    }

    #[test]
    fn wrong_magic_is_malformed() {
        let backend = DroidsawBackend::new();
        // Same length as a valid header prefix, but wrong magic.
        let bytes = b"ELF\x01\x01\x01";
        let err = backend.decompile(bytes, "Lfoo/Bar;").unwrap_err();
        assert!(matches!(err, DecompileError::MalformedDex(_)));
    }

    #[test]
    fn unsupported_version_is_unsupported() {
        let backend = DroidsawBackend::new();
        let mut bytes = vec![0u8; 64];
        bytes[..4].copy_from_slice(b"dex\n");
        bytes[4..7].copy_from_slice(b"999");
        let err = backend.decompile(&bytes, "Lfoo/Bar;").unwrap_err();
        assert!(matches!(err, DecompileError::UnsupportedVersion(_)));
    }

    #[test]
    fn garbage_but_magic_compliant_is_typed_error_not_panic() {
        let backend = DroidsawBackend::new();
        let mut bytes = vec![0xABu8; 4096];
        bytes[..4].copy_from_slice(b"dex\n");
        bytes[4..7].copy_from_slice(b"039");
        // Should return *some* typed error, never panic.
        let res =
            std::panic::catch_unwind(AssertUnwindSafe(|| backend.decompile(&bytes, "Lfoo/Bar;")));
        let inner = res.expect("DroidsawBackend must not panic on garbage input");
        assert!(inner.is_err(), "expected Err, got {:?}", inner);
    }

    #[test]
    fn normalize_accepts_dalvik_descriptor() {
        assert_eq!(
            normalize_class_name("Lcom/foo/Bar;").unwrap(),
            "Lcom/foo/Bar;"
        );
    }

    #[test]
    fn normalize_accepts_java_dotted() {
        assert_eq!(
            normalize_class_name("com.foo.Bar").unwrap(),
            "Lcom/foo/Bar;"
        );
    }

    #[test]
    fn normalize_rejects_empty() {
        let err = normalize_class_name("").unwrap_err();
        assert!(matches!(err, DecompileError::ClassNotFound(_)));
    }
}
