//! Build script for `stenoxide-core`.
//!
//! This script is intentionally passive. The only work it will ever perform is
//! compiling and linking the external libsdc++ Syndrome-Trellis Codes library,
//! and that step is gated behind the `ffi-stc` feature.
//!
//! With the feature disabled the script is a no-op, so a plain
//! `cargo build`/`cargo check` never depends on `LIBSDC_PATH` and never needs a
//! C++ toolchain. Enabling the feature makes both mandatory, which is why the
//! failures below are loud: a build that silently produced a crate whose STC
//! symbols are missing would only fail at link time, far from the cause.

use std::env;
use std::fs;
use std::path::{Path, PathBuf};

/// Name of the static library produced from the libsdc++ sources.
///
/// `cc` turns this into `libsdc.a` (or `sdc.lib`) and emits the link directives
/// for it, so nothing else in the crate has to name it.
const STATIC_LIB_NAME: &str = "sdc";

fn main() {
    // Declared unconditionally: the variable decides what this script does, so
    // Cargo must re-run it when the variable appears, changes or goes away —
    // including in builds where the feature is currently disabled.
    println!("cargo:rerun-if-env-changed=LIBSDC_PATH");

    // Build scripts are not compiled with the crate's `--cfg feature=...` flags,
    // so `#[cfg(feature = "ffi-stc")]` would be silently false here no matter
    // what the user asked for. Cargo exports one `CARGO_FEATURE_<NAME>` variable
    // per enabled feature instead, with the name upper-cased and dashes turned
    // into underscores; that is the only reliable way to branch on a feature in
    // this file.
    if env::var_os("CARGO_FEATURE_FFI_STC").is_none() {
        return;
    }

    compile_libsdc();
}

/// Compiles the libsdc++ sources found under `LIBSDC_PATH` into a static
/// library and links it into the crate.
fn compile_libsdc() {
    let Some(root) = env::var_os("LIBSDC_PATH").map(PathBuf::from) else {
        panic!(
            "the \"ffi-stc\" feature is enabled but LIBSDC_PATH is not set.\n\
             Point it at the directory holding the libsdc++ (DDE Lab Syndrome-Trellis Codes) \
             sources, for example:\n  \
             PowerShell:  $env:LIBSDC_PATH = \"C:\\\\src\\\\libsdc\"\n  \
             sh:          export LIBSDC_PATH=/usr/local/src/libsdc\n\
             Build without the feature to skip this step entirely."
        );
    };

    if !root.is_dir() {
        panic!(
            "LIBSDC_PATH points at {}, which is not a directory.\n\
             It must name the directory holding the libsdc++ sources.",
            root.display()
        );
    }

    let mut sources = Vec::new();
    collect_cpp_sources(&root, &mut sources);

    if sources.is_empty() {
        panic!(
            "no .cpp file was found under {}.\n\
             LIBSDC_PATH must point at the libsdc++ sources themselves, not at an install prefix \
             or an archive.",
            root.display()
        );
    }

    for source in &sources {
        println!("cargo:rerun-if-changed={}", source.display());
    }

    cc::Build::new()
        .cpp(true)
        .include(&root)
        .files(&sources)
        .compile(STATIC_LIB_NAME);
}

/// Collects every `.cpp` file under `directory`, recursively.
///
/// Sorted at each level so that the file order handed to `cc` — and therefore
/// the resulting archive — depends only on the contents of the tree, not on the
/// order the filesystem happens to return entries in. Unreadable directories are
/// skipped rather than fatal: the emptiness check in the caller is what decides
/// whether enough was found to build.
fn collect_cpp_sources(directory: &Path, sources: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(directory) else {
        return;
    };

    let mut paths: Vec<PathBuf> = entries.flatten().map(|entry| entry.path()).collect();
    paths.sort();

    for path in paths {
        if path.is_dir() {
            collect_cpp_sources(&path, sources);
        } else if path.extension().is_some_and(|ext| ext == "cpp") {
            sources.push(path);
        }
    }
}
