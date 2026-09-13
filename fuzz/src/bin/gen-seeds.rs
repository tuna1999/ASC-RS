//! gen-seeds: thin CLI wrapper around `asc_fuzz::seeds::emit_all`.
//! See `fuzz/src/seeds.rs` for the byte constructors.

use std::io;
use std::path::PathBuf;

fn main() -> io::Result<()> {
    let root = PathBuf::from(asc_fuzz::seeds::SEEDS_ROOT);
    let n = asc_fuzz::seeds::emit_all(&root)?;
    println!("gen-seeds: emitted {n} file(s) under {}", root.display());
    Ok(())
}
