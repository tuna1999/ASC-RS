//! `DroidsawBackend` — thin adapter over the `droidsaw-dex` crate.
//!
//! The backend handles all parsing, class resolution, and Java source
//! emission internally; asc-decompile callers only see
//! [`crate::ClassDecompiler::decompile`].
//!
//! Version is declared as `2.0.0` (caret, not exact): the surface we
//! use — `DexFile::parse`, `DexFile::find_class`,
//! `decompile_class_with_census`, `build_trampoline_census` — is
//! unchanged across the 1.x → 2.0 bump, and `Cargo.lock` pins the
//! exact resolved version. Upstream still advertises no SemVer
//! stability statement, so treat a future minor as potentially
//! breaking and re-verify `BACKENDS.md` §4 when bumping.
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
//! call. We cache in a bounded FIFO keyed by `crc32fast::hash(dex_bytes)`
//! and confirm a hit by comparing the full DEX bytes, so a CRC collision
//! degrades to a cache miss instead of pairing a `DexFile` with foreign
//! bytes.

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
/// <16 distinct classes; over that we drop the oldest entry (true FIFO;
/// no real LRU needed at this size).
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
    /// Insertion-ordered `(crc32(dex_bytes), dex_bytes, parsed DexFile)`.
    /// Bounded FIFO; on insert past `PARSE_CACHE_CAP` the first entry is
    /// dropped.
    cache: Arc<Mutex<Vec<CacheEntry>>>,
}

type CacheEntry = (u32, Arc<[u8]>, Arc<DexFile>);

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

        // 3. Parse / resolve / emit. Everything that touches untrusted
        //    bytes runs under catch_unwind so a third-party panic becomes
        //    a typed BackendError.
        catch_unwind(AssertUnwindSafe(|| {
            self.decompile_inner(dex_bytes, &descriptor)
        }))
        .unwrap_or_else(|_| {
            Err(DecompileError::BackendError(
                "droidsaw-dex panicked during decompile_class".into(),
            ))
        })
    }
}

impl DroidsawBackend {
    fn parsed(&self, dex_bytes: &[u8]) -> Result<Arc<DexFile>, DecompileError> {
        let hash = crc32fast::hash(dex_bytes);
        let lock = || self.cache.lock().unwrap_or_else(|e| e.into_inner());
        if let Some((_, _, dex)) = lock()
            .iter()
            .find(|(h, bytes, _)| *h == hash && **bytes == *dex_bytes)
        {
            return Ok(Arc::clone(dex));
        }
        let parsed =
            Arc::new(DexFile::parse(dex_bytes, None).map_err(|e| {
                DecompileError::MalformedDex(format!("droidsaw_dex::DexError: {e:?}"))
            })?);
        let mut cache = lock();
        if cache.len() >= PARSE_CACHE_CAP {
            cache.remove(0);
        }
        cache.push((hash, Arc::from(dex_bytes), Arc::clone(&parsed)));
        Ok(parsed)
    }

    fn decompile_inner(
        &self,
        dex_bytes: &[u8],
        descriptor: &str,
    ) -> Result<String, DecompileError> {
        let dex = self.parsed(dex_bytes)?;

        // `find_class` does exact-descriptor → exact-short-name →
        // substring lookup in one call (see droidsaw-dex `api.rs`).
        let Some((_idx, class_def)) = dex.find_class(descriptor) else {
            return Err(DecompileError::ClassNotFound(descriptor.to_owned()));
        };

        // Trampoline census amortises the R8-inversion pre-scan across all
        // methods in the class; cheap relative to parse, so not cached.
        let census = build_trampoline_census(&dex);
        let java = decompile_class_with_census(&dex, dex_bytes, class_def, &census);
        if java.is_empty() {
            return Err(DecompileError::BackendError(
                "decompile_class_with_census returned empty string".into(),
            ));
        }
        Ok(java)
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

    /// Mirrors oracle `_format_class_name`: partial descriptors are
    /// completed, and dots are replaced even when the input starts with `L`.
    #[test]
    fn normalize_completes_partial_descriptors_like_oracle() {
        assert_eq!(
            normalize_class_name("Lcom/foo/Main").unwrap(),
            "Lcom/foo/Main;"
        );
        assert_eq!(
            normalize_class_name("Lcom.poc.Main;").unwrap(),
            "Lcom/poc/Main;"
        );
        assert_eq!(
            normalize_class_name("com/foo/Bar").unwrap(),
            "Lcom/foo/Bar;"
        );
    }
}
