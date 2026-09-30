//! Contract: `Apk::open` + the whole file-backed read surface never panic
//! on arbitrary bytes. The input must reach the parser as a real file, so
//! it is staged into a uniquely named temp file that is always removed.
//! Behind `apk` feature.

use crate::FuzzOutcome;

/// Bytes sampled from every entry via `read_entry_prefix`. Big enough to
/// cover a DEX/ZIP/ELF magic, small enough to keep the loop O(entries).
#[cfg(feature = "apk")]
const PREFIX_CAP: usize = 4096;
/// `parse_directory` allocates at most 46 bytes per central-directory
/// record and every record needs >= 46 bytes of CD, so this many entries
/// already costs at least 4 GiB. Cheap per-input work bound; it should
/// never fire.
#[cfg(feature = "apk")]
const ENTRY_BUDGET: usize = 1 << 16;

#[cfg(feature = "apk")]
pub fn run(input: &[u8]) -> FuzzOutcome {
    use asc_apk::Apk;

    // Staged under %TEMP% with a name unique per (pid, target, content)
    // so a leftover file from a killed process cannot be re-read.
    let staged = match crate::stage_temp_file("apk_open", input) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("fuzz_apk_open: cannot stage temp file: {e}");
            return FuzzOutcome::BoundaryHit("apk_temp_file_io");
        }
    };
    let path = &staged.0;
    let result = (|| {
        let apk = match Apk::open(path) {
            Ok(a) => a,
            Err(_) => return FuzzOutcome::BoundaryHit("apk_open_reject"),
        };
        assert!(apk.entry_count() <= ENTRY_BUDGET, "entry count unbounded");

        let mut n = 0usize;
        for e in apk.entries() {
            n += 1;
            // Bounded per entry: returns bytes or an error, never a panic.
            if let Ok((bytes, _complete)) = apk.read_entry_prefix(&e, PREFIX_CAP) {
                assert!(bytes.len() <= PREFIX_CAP, "prefix cap exceeded");
            }
        }
        assert_eq!(n, apk.entry_count(), "entries() != entry_count()");

        let dex = apk.dex_entries();
        assert!(dex.len() <= n, "dex_entries not a subset of entries");
        for e in &dex {
            let _ = apk.read_entry_prefix(e, PREFIX_CAP);
            assert!(!e.name.contains('/'), "dex entry not rooted");
        }

        let scan = apk.signing_scan();
        assert!(scan.pairs.len() <= 1024, "signing pairs unbounded");
        for s in &scan.schemes {
            assert!(s.signers.len() <= 16, "signers unbounded");
            for sg in &s.signers {
                assert!(sg.certs.len() <= 16, "certs unbounded");
            }
        }
        FuzzOutcome::Ok
    })();
    result
}

#[cfg(not(feature = "apk"))]
pub fn run(_input: &[u8]) -> FuzzOutcome {
    FuzzOutcome::SkippedDisabled
}
