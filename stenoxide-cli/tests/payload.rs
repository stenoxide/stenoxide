//! Tests of `--payload`, `--payload-out` and `--force`, driven through the
//! binary itself.
//!
//! # Why these run the process rather than call a function
//!
//! What is being asserted is an *ordering*: that a payload path which cannot be
//! read, and a destination that already exists, are both refused before
//! anything asks the user for a passphrase. Inside the process that ordering is
//! two statements in sequence and nothing observes it. From outside it is the
//! difference between a command that exits and one that sits waiting on a
//! terminal that is not attached — which is exactly the failure the ordering
//! exists to prevent, and the only vantage point from which it is visible.
//!
//! Everything that is *not* an ordering — the signature table, the three path
//! cases, the write and its permissions — is unit-tested beside the code it
//! belongs to, in `src/payload.rs`, where it costs nothing to run.
//!
//! # Why only the cases that fail early are here
//!
//! `rpassword` reads the passphrase from the terminal device, not from standard
//! input, so a test that spawns this binary cannot answer the prompt and cannot
//! drive a complete embed or extract. Every case below therefore ends before
//! the prompt; the round trip itself is covered by the core suite, which calls
//! the pipeline directly.
//!
//! # Cost policy
//!
//! The usable container is expensive — a 2000x2000 textured field, and a search
//! for a seed whose perceptual hash is stable — so it is built once for the
//! whole file and copied where a test needs one.

// The crate-wide bans on panicking helpers do not reach a separate test binary,
// but the project's standard does. A test that cannot panic cannot fail, so
// they are lifted here explicitly rather than by omission.
#![allow(clippy::expect_used)]
#![allow(clippy::panic)]

use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::OnceLock;

use stenoxide_core::test_support;
use tempfile::TempDir;

/// Seed the shared container is searched from.
const COVER_SEED: u64 = 337;

/// The container every test that needs a usable image copies from.
///
/// Built once per test binary and kept alive for its whole run: the directory
/// is dropped when the process exits, which is exactly when the last test that
/// could read it has finished.
static SHARED_COVER: OnceLock<(TempDir, PathBuf)> = OnceLock::new();

/// Path of the shared container.
fn shared_cover() -> &'static Path {
    let (_directory, path) = SHARED_COVER.get_or_init(|| {
        let directory = TempDir::new().expect("temporary directory");
        let path = directory.path().join("cover.png");
        test_support::write_stable_cover(&path, COVER_SEED);

        (directory, path)
    });

    path
}

/// Copies the shared container into `directory` under `name`.
fn place_cover(directory: &Path, name: &str) -> PathBuf {
    let path = directory.join(name);
    std::fs::copy(shared_cover(), &path).expect("the cover should be copyable");

    path
}

/// Runs the binary under test with the given arguments.
///
/// Standard input is closed rather than inherited. Every test here expects a
/// command that never reads it, and a closed handle turns a regression that
/// would otherwise hang the suite into an immediate end-of-file.
fn stenoxide(arguments: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_stenoxide"))
        .args(arguments)
        .stdin(Stdio::null())
        .output()
        .expect("the binary under test should be runnable")
}

/// Everything the command said, on either stream.
///
/// The password prompt goes to the terminal and the diagnostics to standard
/// error, so an assertion that the prompt never appeared has to look at both to
/// mean anything.
fn everything_said(output: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stderr),
        String::from_utf8_lossy(&output.stdout)
    )
}

/// A path as the shell would have written it.
fn arg(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

/// A payload path that does not exist is refused, by name, before the prompt.
///
/// The container is valid, so the only thing that can refuse this command is
/// the payload check — and it has to happen early. A mistyped path found after
/// the passphrase would be a passphrase typed for nothing, which is the precise
/// thing the container check already exists to avoid.
#[test]
fn a_missing_payload_file_is_refused_before_the_password_is_read() {
    let directory = TempDir::new().expect("temporary directory");
    let cover = place_cover(directory.path(), "cover.png");
    let stego = directory.path().join("stego.png");
    let missing = directory.path().join("no-such-notes.txt");

    let output = stenoxide(&[
        "embed",
        "--input",
        &arg(&cover),
        "--output",
        &arg(&stego),
        "--payload",
        &arg(&missing),
    ]);

    assert!(!output.status.success(), "the command should have failed");

    let said = everything_said(&output);
    assert!(
        said.contains("no-such-notes.txt"),
        "the refusal must name the file, got: {said}"
    );
    assert!(
        said.contains("does not exist"),
        "the refusal must say what is wrong, got: {said}"
    );
    assert!(
        !said.contains("Password"),
        "the password was asked for before the payload path was judged: {said}"
    );

    // The other half of "refused before anything happened".
    assert!(!stego.exists(), "no stego image should have been written");
}

/// A directory given as a payload is refused with advice, not with an I/O error.
///
/// The mistake behind it is naming the folder the file is in, which is common
/// enough that "is a directory" alone would leave the user to work out what the
/// program wanted instead.
#[test]
fn a_directory_as_the_payload_is_refused_with_advice() {
    let directory = TempDir::new().expect("temporary directory");
    let cover = place_cover(directory.path(), "cover.png");
    let stego = directory.path().join("stego.png");
    let folder = directory.path().join("documents");
    std::fs::create_dir(&folder).expect("the folder should be creatable");

    let output = stenoxide(&[
        "embed",
        "--input",
        &arg(&cover),
        "--output",
        &arg(&stego),
        "--payload",
        &arg(&folder),
    ]);

    assert!(!output.status.success(), "the command should have failed");

    let said = everything_said(&output);
    assert!(said.contains("documents"), "got: {said}");
    assert!(said.contains("directory"), "got: {said}");
    assert!(
        said.contains("not the folder"),
        "the refusal must say what to name instead, got: {said}"
    );
    assert!(
        !said.contains("Password"),
        "the password was asked for before the payload path was judged: {said}"
    );
    assert!(!stego.exists());
}

/// An existing destination is refused by name, before the password is read.
///
/// The one message in the extraction path that is allowed to be specific, and
/// it is allowed precisely because it is printed before the passphrase has been
/// used for anything: at that moment the program does not know whether the
/// password is right, so naming the file cannot reveal that it was. Every
/// failure *after* the extraction prints the same sentence a wrong password
/// prints.
#[test]
fn an_existing_destination_is_refused_before_the_password_is_read() {
    let directory = TempDir::new().expect("temporary directory");
    let cover = place_cover(directory.path(), "stego.png");
    let destination = directory.path().join("recovered.zip");
    std::fs::write(&destination, b"something the user already had").expect("fixture write");

    let output = stenoxide(&[
        "extract",
        "--input",
        &arg(&cover),
        "--payload-out",
        &arg(&destination),
    ]);

    assert!(!output.status.success(), "the command should have failed");

    let said = everything_said(&output);
    assert!(said.contains("recovered.zip"), "got: {said}");
    assert!(said.contains("already exists"), "got: {said}");
    assert!(
        said.contains("--force"),
        "the refusal must name the way out, got: {said}"
    );
    assert!(
        !said.contains("Password"),
        "the password was asked for before the destination was judged: {said}"
    );

    let kept = std::fs::read(&destination).expect("the file must still be there");
    assert_eq!(
        kept, b"something the user already had",
        "the existing file must be untouched"
    );
}

/// `--force` on its own is a usage error, not a silent no-op.
///
/// It authorises overwriting a file, and with nothing to overwrite it means
/// nothing at all. Accepting it would let someone believe they had asked for
/// something they had not.
#[test]
fn force_without_a_destination_is_rejected_by_the_parser() {
    let directory = TempDir::new().expect("temporary directory");
    let cover = place_cover(directory.path(), "stego.png");

    let output = stenoxide(&["extract", "--input", &arg(&cover), "--force"]);

    // Two, not one: a command line the parser refuses is a different kind of
    // failure from a command that ran and did not work, and shells distinguish
    // them.
    assert_eq!(
        output.status.code(),
        Some(2),
        "got: {}",
        everything_said(&output)
    );

    let said = everything_said(&output);
    assert!(said.contains("--payload-out"), "got: {said}");
    assert!(!said.contains("Password"), "got: {said}");
}
