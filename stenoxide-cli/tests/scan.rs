//! Tests of `stenoxide scan`, driven through the binary itself.
//!
//! # Why these run the process rather than call a function
//!
//! What `scan` is for is answering a question at a terminal, and the answer is
//! the process's output: the listing a person reads, the document a script
//! parses, the exit code a shell branches on. None of those is observable from
//! a function call, and the parts that *are* — the glob matcher, the JSON
//! escaper, the renderers — are unit-tested beside the code they belong to.
//!
//! Running the binary is also the only way to show the property the last test
//! here asserts: that a container is refused before anything asks the user for
//! a password. Inside the process that is an ordering between two statements;
//! from outside it is the observable difference between a command that exits
//! and one that waits on a terminal that is not there.
//!
//! # Cost policy
//!
//! Containers are expensive to build — a 2000x2000 field with grain on top, and
//! a search for a seed whose perceptual hash is stable — so the usable one is
//! built once for the whole file and shared. The images that exist to be
//! *refused* are cheap and are written per test.

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

/// Writes a PNG that is a valid image and too small to be a container.
fn place_undersized(directory: &Path, name: &str) -> PathBuf {
    let path = directory.join(name);
    image::RgbImage::from_fn(400, 400, |x, y| {
        image::Rgb([(x % 256) as u8, (y % 256) as u8, 0])
    })
    .save_with_format(&path, image::ImageFormat::Png)
    .expect("a small png should be writable");

    path
}

/// Writes a JPEG, the format a directory of photographs is actually full of.
fn place_jpeg(directory: &Path, name: &str) -> PathBuf {
    let path = directory.join(name);
    image::RgbImage::from_fn(64, 64, |x, y| image::Rgb([(x + y) as u8, 0, 0]))
        .save_with_format(&path, image::ImageFormat::Jpeg)
        .expect("a jpeg should be writable");

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

/// The standard output of a command that was expected to succeed.
fn stdout_of(output: &Output) -> String {
    assert!(
        output.status.success(),
        "the command failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    String::from_utf8_lossy(&output.stdout).into_owned()
}

/// TEST 21 — a directory with no PNGs in it is an empty report, not an error.
#[test]
fn scanning_an_empty_directory_reports_nothing_and_succeeds() {
    let directory = TempDir::new().expect("temporary directory");
    let path = directory.path().to_string_lossy().into_owned();

    let listing = stdout_of(&stenoxide(&["scan", &path]));
    assert!(
        listing.contains("Summary: 0 valid, 0 invalid (0 scanned)"),
        "got: {listing}"
    );

    let document = stdout_of(&stenoxide(&["scan", &path, "--json"]));
    assert!(document.contains("\"scanned\": 0"), "got: {document}");
    assert!(document.contains("\"valid\": []"), "got: {document}");
    assert!(document.contains("\"invalid\": []"), "got: {document}");
}

/// TEST 22 — a mixed directory lists what can be used, and what cannot only
/// when asked.
///
/// The default is the answer the user came for. A folder of holiday photos is
/// mostly JPEGs, and a listing that reported every one of them as a rejection
/// would bury the two files that are actually usable.
#[test]
fn a_mixed_directory_lists_the_usable_images_and_hides_the_rest() {
    let directory = TempDir::new().expect("temporary directory");
    place_cover(directory.path(), "usable.png");
    place_undersized(directory.path(), "small.png");
    place_jpeg(directory.path(), "photo.jpg");

    let path = directory.path().to_string_lossy().into_owned();

    let listing = stdout_of(&stenoxide(&["scan", &path]));
    assert!(listing.contains("usable.png"), "got: {listing}");
    assert!(!listing.contains("small.png"), "got: {listing}");
    assert!(!listing.contains("photo.jpg"), "got: {listing}");

    // The rejected files are hidden from the listing but still counted: a
    // summary that said "1 scanned" for a directory of three would be telling
    // the user the scan had not looked at their photographs.
    assert!(
        listing.contains("Summary: 1 valid, 2 invalid (3 scanned)"),
        "got: {listing}"
    );
    assert!(listing.contains("--all"), "got: {listing}");

    let full = stdout_of(&stenoxide(&["scan", &path, "--all"]));
    assert!(full.contains("usable.png"), "got: {full}");
    assert!(full.contains("small.png"), "got: {full}");
    assert!(full.contains("ImageTooSmall 400x400"), "got: {full}");
    assert!(full.contains("photo.jpg"), "got: {full}");
    assert!(full.contains("UnsupportedFormat"), "got: {full}");
    assert!(
        full.contains("Summary: 1 valid, 2 invalid (3 scanned)"),
        "got: {full}"
    );
}

/// TEST 23 — subdirectories are visited only when asked for.
#[test]
fn only_a_recursive_scan_descends() {
    let directory = TempDir::new().expect("temporary directory");
    let nested = directory.path().join("nested");
    std::fs::create_dir(&nested).expect("subdirectory should be creatable");

    place_cover(directory.path(), "top.png");
    place_cover(&nested, "deep.png");

    let path = directory.path().to_string_lossy().into_owned();

    let shallow = stdout_of(&stenoxide(&["scan", &path]));
    assert!(shallow.contains("top.png"), "got: {shallow}");
    assert!(!shallow.contains("deep.png"), "got: {shallow}");
    assert!(
        shallow.contains("Summary: 1 valid, 0 invalid (1 scanned)"),
        "got: {shallow}"
    );

    let deep = stdout_of(&stenoxide(&["scan", &path, "--recursive"]));
    assert!(deep.contains("top.png"), "got: {deep}");
    assert!(deep.contains("deep.png"), "got: {deep}");
    assert!(
        deep.contains("Summary: 2 valid, 0 invalid (2 scanned)"),
        "got: {deep}"
    );
}

/// TEST 24 — the JSON form is a document and nothing else.
///
/// Parsed here rather than merely searched for substrings: the point of the
/// flag is that a script can read the output, and a report that happens to
/// contain the right keys inside a banner is not one.
#[test]
fn the_json_form_carries_the_whole_answer() {
    let directory = TempDir::new().expect("temporary directory");
    place_cover(directory.path(), "usable.png");
    place_undersized(directory.path(), "small.png");

    let path = directory.path().to_string_lossy().into_owned();
    let document = stdout_of(&stenoxide(&["scan", &path, "--json", "--all"]));

    assert!(
        document.trim_start().starts_with('{'),
        "the document must not be preceded by anything: {document}"
    );
    assert!(
        !document.contains("Scanning"),
        "the document must carry no banner: {document}"
    );

    let keys = parse(&document);
    for key in ["valid", "invalid", "summary"] {
        assert!(
            keys.iter().any(|found| found == key),
            "the document has no {key} key: {document}"
        );
    }

    assert!(document.contains("\"scanned\": 2"), "got: {document}");
    assert!(document.contains("\"capacity_kb\":"), "got: {document}");
    assert!(
        document.contains("\"dimensions\": [2000, 2000]"),
        "got: {document}"
    );
    assert!(
        document.contains("\"reason\": \"ImageTooSmall\""),
        "got: {document}"
    );
}

/// TEST 25 — a single file and a glob pattern name the same thing.
#[test]
fn a_file_and_a_pattern_reach_the_same_image() {
    let directory = TempDir::new().expect("temporary directory");
    let cover = place_cover(directory.path(), "usable.png");
    place_jpeg(directory.path(), "photo.jpg");

    let by_name = stdout_of(&stenoxide(&["scan", &cover.to_string_lossy()]));
    assert!(
        by_name.contains("Summary: 1 valid, 0 invalid (1 scanned)"),
        "got: {by_name}"
    );

    let pattern = directory
        .path()
        .join("*.png")
        .to_string_lossy()
        .into_owned();
    // The pattern reaches the PNG and not the JPEG beside it, which is what
    // distinguishes it from scanning the directory.
    let by_pattern = stdout_of(&stenoxide(&["scan", &pattern]));
    assert!(by_pattern.contains("usable.png"), "got: {by_pattern}");
    assert!(
        by_pattern.contains("Summary: 1 valid, 0 invalid (1 scanned)"),
        "got: {by_pattern}"
    );

    // A pattern matching nothing is an error, because the user asked about
    // files they believe exist.
    let missing = directory
        .path()
        .join("*.tiff")
        .to_string_lossy()
        .into_owned();
    let output = stenoxide(&["scan", &missing]);
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("does not name"),
        "got: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

/// TEST 26 — an unusable container is refused before a password is asked for.
///
/// The ordering this is about is not observable from inside the process, and it
/// is the whole point of the change: a user who picked the wrong file must be
/// told so *before* they type a passphrase, not after. From outside, the
/// difference is visible in two ways at once — the command exits instead of
/// waiting on a terminal that is not attached, and the prompt never appears in
/// its output.
///
/// Both subcommands that read a password are checked, because both had the same
/// ordering.
#[test]
fn an_unusable_container_is_refused_before_the_password_is_read() {
    let directory = TempDir::new().expect("temporary directory");
    let jpeg = place_jpeg(directory.path(), "photo.jpg");
    let output_path = directory.path().join("stego.png");

    let embedding = stenoxide(&[
        "embed",
        "--input",
        &jpeg.to_string_lossy(),
        "--output",
        &output_path.to_string_lossy(),
    ]);

    assert!(!embedding.status.success());

    let complaint = String::from_utf8_lossy(&embedding.stderr);
    assert!(complaint.contains("JPEG"), "got: {complaint}");
    // The advice, not merely the diagnosis: the user is told what to do.
    assert!(complaint.contains("magick"), "got: {complaint}");

    let everything = format!("{complaint}{}", String::from_utf8_lossy(&embedding.stdout));
    assert!(
        !everything.contains("Password"),
        "the password was asked for before the container was judged: {everything}"
    );

    // Nothing was written, which is the other half of "refused before anything
    // happened".
    assert!(!output_path.exists());

    let extraction = stenoxide(&["extract", "--input", &jpeg.to_string_lossy()]);
    assert!(!extraction.status.success());
    assert!(
        !String::from_utf8_lossy(&extraction.stderr).contains("Password"),
        "the extraction path asked for a password first"
    );
}

/// TEST 27 — every rejection the scan can report tells the user what is wrong.
///
/// One test over the whole set rather than one per condition: the property is
/// about the vocabulary being complete and each name reaching the report
/// intact, which is a statement about the set.
#[test]
fn every_rejection_names_itself_in_the_report() {
    let directory = TempDir::new().expect("temporary directory");

    place_undersized(directory.path(), "small.png");
    place_jpeg(directory.path(), "photo.jpg");

    // A PNG signature over a stream no decoder can read.
    let mut corrupt = vec![0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];
    corrupt.extend_from_slice(&[0x42; 128]);
    std::fs::write(directory.path().join("corrupt.png"), corrupt)
        .expect("a corrupt png should be writable");

    // A container of the right size with no texture anywhere: it passes every
    // gate of layer 1 and is refused by the first thing that reads its content.
    image::RgbImage::from_pixel(2000, 2000, image::Rgb([128, 128, 128]))
        .save_with_format(directory.path().join("flat.png"), image::ImageFormat::Png)
        .expect("a flat png should be writable");

    let path = directory.path().to_string_lossy().into_owned();
    let report = stdout_of(&stenoxide(&["scan", &path, "--all"]));

    for reason in [
        "ImageTooSmall",
        "UnsupportedFormat",
        "DecodingError",
        "InsufficientTexture",
    ] {
        assert!(
            report.contains(reason),
            "{reason} is missing from: {report}"
        );
    }

    assert!(
        report.contains("Summary: 0 valid, 4 invalid (4 scanned)"),
        "got: {report}"
    );
}

/// TEST 28 — a container too large to analyse is refused, and refused fast.
///
/// The case this limit was written for. A 32767x32767 PNG is a legal file and
/// compresses to a few hundred kilobytes when it is mostly one colour, so it
/// costs nothing to produce and nothing to store — and analysing it asks for
/// some sixteen gibibytes, which on any ordinary machine means paging to disk
/// for as long as the user is willing to wait.
///
/// Both halves are asserted. That the verdict is `ImageTooLarge` says the gate
/// fired; that the whole scan finishes in seconds says it fired *before*
/// anything was allocated, which is the only version of this that helps.
#[test]
fn a_container_too_large_to_analyse_is_refused_immediately() {
    let directory = TempDir::new().expect("temporary directory");
    let path = directory.path().join("enormous.png");

    // A well-formed PNG header declaring that geometry, and nothing behind it.
    //
    // Written by hand rather than through the encoder because encoding a real
    // one means allocating and compressing a gigapixel, which costs a minute
    // and a gigabyte to produce a file this test never decodes. The header is
    // genuine down to its checksum — 13-byte `IHDR`, 32767x32767, 8-bit
    // grayscale — and the image data is deliberately absent.
    //
    // The missing body is what makes this a regression test rather than a
    // tautology. If the size gate were ever moved back behind the decoder, this
    // file would be reported as a decoding failure instead, and the assertions
    // below would fail.
    let mut header = vec![0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A];
    header.extend_from_slice(&13u32.to_be_bytes());
    header.extend_from_slice(b"IHDR");
    header.extend_from_slice(&32_767u32.to_be_bytes());
    header.extend_from_slice(&32_767u32.to_be_bytes());
    header.extend_from_slice(&[8, 0, 0, 0, 0]);
    header.extend_from_slice(&0x6C99_59E1u32.to_be_bytes());

    std::fs::write(&path, &header).expect("the header should be writable");

    let started = std::time::Instant::now();
    let report = stdout_of(&stenoxide(&["scan", &path.to_string_lossy(), "--all"]));
    let elapsed = started.elapsed();

    assert!(report.contains("ImageTooLarge"), "got: {report}");
    assert!(report.contains("32767x32767"), "got: {report}");
    assert!(
        report.contains("Summary: 0 valid, 1 invalid (1 scanned)"),
        "got: {report}"
    );

    // Generous by two orders of magnitude against the version that decoded
    // first, which did not finish at all on a machine with sixteen gibibytes.
    assert!(
        elapsed < std::time::Duration::from_secs(10),
        "the refusal took {elapsed:?}, which means it read more than the header"
    );
}

/// The set of top-level keys of a JSON object.
///
/// A parser sufficient for the question being asked: the document this crate
/// emits has three keys at the top level, and what has to be shown is that all
/// three are there and that the braces balance. Depth is tracked so that a key
/// of a nested record is not mistaken for a top-level one.
fn parse(document: &str) -> Vec<String> {
    let mut keys = Vec::new();
    let mut depth = 0i32;
    let mut in_string = false;
    let mut escaped = false;
    let mut current = String::new();

    for character in document.chars() {
        if in_string {
            match character {
                _ if escaped => escaped = false,
                '\\' => escaped = true,
                '"' => {
                    in_string = false;
                    if depth == 1 {
                        keys.push(std::mem::take(&mut current));
                    } else {
                        current.clear();
                    }
                }
                other => current.push(other),
            }
            continue;
        }

        match character {
            '"' => in_string = true,
            '{' | '[' => depth += 1,
            '}' | ']' => depth -= 1,
            _ => {}
        }
    }

    assert_eq!(depth, 0, "the document does not balance: {document}");
    assert!(!in_string, "the document ends inside a string: {document}");

    keys
}
