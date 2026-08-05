//! Reading the payload from a file, and writing a recovered one back to disk.
//!
//! The payload has always been arbitrary bytes — the pipeline compresses and
//! encrypts whatever it is handed and never looks at it — but the only way in
//! and out used to be standard input and standard output, which made the file
//! case a shell redirection the user had to arrange themselves. This module is
//! the other half: a path in, a path out.
//!
//! # Why the payload carries no file name
//!
//! Storing the original name inside the payload was considered and rejected. It
//! is not a cryptographic question: the name would sit inside the
//! XChaCha20-Poly1305 like everything else, an adversary without the password
//! would still see noise, and no oracle would appear, because the AEAD
//! authenticates before anything is decompressed — a header would never be
//! parsed under the wrong password. There is already a header inside the
//! encryption, the Zstandard frame header, and it troubles nobody. The rule
//! about carrying no header, salt, nonce or marker is about the *container*,
//! about what travels outside the encryption.
//!
//! It was rejected for two other reasons.
//!
//! The first is the endpoint, which is where this project stops making
//! promises. The name a person gives a file is descriptive, because they chose
//! it for themselves, and restoring it automatically materialises it on the
//! recipient's disk: in the filesystem journal, in the search index, in the
//! backup, in the wastebasket. That the name is chosen by whoever extracts
//! means they can choose one that says nothing. It is a protection that exists
//! almost by accident, and giving it up buys too little.
//!
//! The second is that a name which comes from the payload and is then used to
//! build a path is the shape of bug that has broken a long line of archive
//! programs. It can be sanitised, but it is attack surface that does not exist
//! today at all, because the destination path is written by the user in full.
//!
//! # So the type is recovered from the content
//!
//! [`detect_extension`] gives back the convenience that was wanted — that the
//! file comes out with the right type without anybody having to remember it —
//! from the bytes, which are already there, rather than from sender metadata
//! that would have to be invented, transported and sanitised. The table is
//! closed and lives in this file, so the payload cannot influence anything
//! beyond picking one of its entries.

use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use zeroize::Zeroizing;

/// The largest file that will be read into memory as a payload.
///
/// This is not a capacity check and must not be mistaken for one. What fits in
/// a container is decided by the pipeline *after* Zstandard has run, and a
/// 200 KB text file goes comfortably into a container that admits 22 KB. The
/// ceiling exists only so that pointing the tool at a disk image does not load
/// the disk image.
const MAX_PAYLOAD_FILE_BYTES: u64 = 64 * 1024 * 1024;

/// The extension used when no signature matches and the bytes are text.
const TEXT_EXTENSION: &str = "txt";

/// The extension used when no signature matches and the bytes are not text.
///
/// Also the answer to "was the type recognised at all?", which is why it is
/// visible outside this module: a caller naming the type of a payload has
/// nothing to name when [`detect_extension`] returns this one.
pub(crate) const BINARY_EXTENSION: &str = "bin";

/// Stem of the file written when the requested path is a directory.
const DEFAULT_STEM: &str = "payload";

/// One entry of the closed signature table.
struct Signature {
    /// Offset at which the magic bytes start.
    offset: usize,
    /// The bytes themselves, matched in full or not at all.
    magic: &'static [u8],
    /// Second run of magic bytes, at [`Signature::second_offset`].
    ///
    /// Only the container formats that put a type tag after a length field need
    /// it — RIFF/WebP is the example — and every other entry leaves it empty.
    second: &'static [u8],
    /// Offset of [`Signature::second`].
    second_offset: usize,
    /// Extension given to a payload that matches, without the dot.
    extension: &'static str,
}

/// Every file type this crate will name, and nothing else.
///
/// Deliberately blunt. A ZIP is a `zip`, whether it is really a `docx`, an
/// `xlsx`, an `odt` or a `jar`: telling those apart means opening the archive
/// and reading what is inside it, which is the one thing this program does not
/// do to a payload. The order matters only in that the longer, more specific
/// magic numbers come before any prefix of them.
const SIGNATURES: &[Signature] = &[
    signature(0, &[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A], "png"),
    signature(0, &[0xFF, 0xD8, 0xFF], "jpg"),
    signature(0, &[0x47, 0x49, 0x46, 0x38], "gif"),
    // RIFF is a family, not a format: the four bytes after the size field are
    // what make this one a WebP rather than a WAV or an AVI.
    Signature {
        offset: 0,
        magic: &[0x52, 0x49, 0x46, 0x46],
        second: &[0x57, 0x45, 0x42, 0x50],
        second_offset: 8,
        extension: "webp",
    },
    signature(0, &[0x25, 0x50, 0x44, 0x46], "pdf"),
    signature(0, &[0x50, 0x4B, 0x03, 0x04], "zip"),
    signature(0, &[0x1F, 0x8B], "gz"),
    signature(0, &[0x28, 0xB5, 0x2F, 0xFD], "zst"),
    signature(0, &[0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C], "7z"),
    signature(0, &[0x52, 0x61, 0x72, 0x21, 0x1A, 0x07], "rar"),
    signature(0, &[0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00], "xz"),
    signature(
        0,
        &[0x53, 0x51, 0x4C, 0x69, 0x74, 0x65, 0x20, 0x66],
        "sqlite",
    ),
    signature(0, &[0x4F, 0x67, 0x67, 0x53], "ogg"),
    signature(0, &[0x66, 0x4C, 0x61, 0x43], "flac"),
    signature(0, &[0x49, 0x44, 0x33], "mp3"),
    // ISO base media: the brand box begins at offset 4, and the four bytes
    // before it are its length, which is not a constant.
    signature(4, &[0x66, 0x74, 0x79, 0x70], "mp4"),
];

/// A signature with one run of magic bytes.
const fn signature(offset: usize, magic: &'static [u8], extension: &'static str) -> Signature {
    Signature {
        offset,
        magic,
        second: &[],
        second_offset: 0,
        extension,
    }
}

/// Why a payload could not be written to the path the user asked for.
///
/// The distinction between an existing file and everything else is the whole
/// reason this is an enum rather than a string: `main` reports the two very
/// differently, and for a reason that has nothing to do with how bad each one
/// is. See the extraction path.
#[derive(Debug)]
pub enum PayloadWriteError {
    /// The destination already exists and `--force` was not given.
    AlreadyExists,
    /// The filesystem refused the create, the write or the flush.
    Io(std::io::Error),
}

impl std::fmt::Display for PayloadWriteError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PayloadWriteError::AlreadyExists => write!(f, "the file already exists"),
            PayloadWriteError::Io(err) => write!(f, "{err}"),
        }
    }
}

impl std::error::Error for PayloadWriteError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            PayloadWriteError::AlreadyExists => None,
            PayloadWriteError::Io(err) => Some(err),
        }
    }
}

/// Opens the payload file and checks it can be read, without reading it.
///
/// Split from [`read_payload_file`] so that the embedding path can settle every
/// question a mistyped path raises *before* it asks for a passphrase, and then
/// read from the very handle it checked. Re-opening by path afterwards would
/// leave a window in which the file that was checked and the file that is read
/// are not the same one.
///
/// The two halves are only ever called in sequence, and the reason they are two
/// functions rather than one is entirely that a password prompt sits between
/// them.
///
/// # Errors
///
/// Returns the message to print when the path does not exist, is a directory,
/// cannot be opened, is empty, or is larger than [`MAX_PAYLOAD_FILE_BYTES`].
pub fn open_payload_file(path: &Path) -> Result<File, String> {
    let file = path.display();

    let handle = File::open(path).map_err(|err| describe_open_failure(path, &err))?;

    let metadata = handle
        .metadata()
        .map_err(|err| format!("Error: {file} cannot be read: {err}"))?;

    if metadata.is_dir() {
        return Err(format!(
            "Error: {file} is a directory.\n       \
             Name the file to hide, not the folder it is in."
        ));
    }

    if metadata.len() == 0 {
        return Err(format!("Error: {file} is empty; there is nothing to hide."));
    }

    // Refused on the metadata, so that a file far too large to be a payload is
    // never read at all — the point of the ceiling is to not allocate it.
    if metadata.len() > MAX_PAYLOAD_FILE_BYTES {
        return Err(format!(
            "Error: {file} is {} bytes, and the limit is {} bytes ({} MiB).\n       \
             This is a ceiling on what is read into memory, not the capacity of \
             a container:\n       \
             the payload is compressed before it is measured, so a much smaller \
             file may still\n       \
             be refused for not fitting. Run stenoxide scan to see what a \
             container admits.",
            metadata.len(),
            MAX_PAYLOAD_FILE_BYTES,
            MAX_PAYLOAD_FILE_BYTES / (1024 * 1024)
        ));
    }

    Ok(handle)
}

/// Explains why the payload file could not be opened.
///
/// The directory case is asked about first, and by path rather than by error
/// kind, because the two platforms disagree about what a directory even is at
/// this point: Windows refuses to open one and calls it a permission problem,
/// while Unix opens it happily and fails later at the read. Neither answer is
/// one a user can act on, and the mistake behind both — naming the folder
/// instead of the file inside it — is the same. The extra `stat` costs nothing
/// worth counting: it runs only once an open has already failed.
fn describe_open_failure(path: &Path, err: &std::io::Error) -> String {
    let file = path.display();

    if path.is_dir() {
        return format!(
            "Error: {file} is a directory.\n       \
             Name the file to hide, not the folder it is in."
        );
    }

    match err.kind() {
        std::io::ErrorKind::NotFound => format!("Error: {file} does not exist."),
        std::io::ErrorKind::PermissionDenied => {
            format!("Error: {file} cannot be read: permission denied.")
        }
        _ => format!("Error: {file} cannot be read: {err}"),
    }
}

/// Reads a payload file, from the handle [`open_payload_file`] returned.
///
/// The bytes land straight in a [`Zeroizing`], which is the buffer the pipeline
/// takes ownership of: the payload is never copied into a plain `Vec` on its
/// way there.
///
/// # Errors
///
/// Returns the message to print when the read fails partway through.
pub fn read_payload_file(mut handle: File, path: &Path) -> Result<Zeroizing<Vec<u8>>, String> {
    let mut payload = Zeroizing::new(Vec::new());

    handle
        .read_to_end(&mut payload)
        .map_err(|err| format!("Error: {} could not be read: {err}", path.display()))?;

    Ok(payload)
}

/// Decides where a recovered payload is actually written.
///
/// Three cases, in this order:
///
/// - `requested` is an existing directory — the file is written inside it, as
///   `payload.<ext>`.
/// - `requested` has no extension — the detected one is appended.
/// - `requested` has an extension — it is used exactly as given. Someone who
///   asks for `.txt` and gets a PNG gets a `.txt`; the user is in charge of the
///   name, and second-guessing them here would be the one place this program
///   overrode an explicit instruction.
///
/// No component of the path is ever derived from the payload beyond the
/// extension, and the extension comes from the closed table in this file. The
/// payload cannot influence the destination directory.
pub fn resolve_output_path(requested: &Path, payload: &[u8]) -> PathBuf {
    if requested.is_dir() {
        return requested.join(format!("{DEFAULT_STEM}.{}", detect_extension(payload)));
    }

    if requested.extension().is_some() {
        return requested.to_path_buf();
    }

    let mut named = requested.as_os_str().to_os_string();
    named.push(".");
    named.push(detect_extension(payload));

    PathBuf::from(named)
}

/// Names the type of a payload from its leading bytes.
///
/// A signature matches in full or does not match: a file truncated four bytes
/// into a PNG header is not a PNG, and calling it one would put a name on the
/// file that no viewer can open. Anything the table does not recognise is
/// `txt` when the whole payload is valid UTF-8 and `bin` when it is not.
pub fn detect_extension(payload: &[u8]) -> &'static str {
    for signature in SIGNATURES {
        if matches(payload, signature) {
            return signature.extension;
        }
    }

    if std::str::from_utf8(payload).is_ok() {
        TEXT_EXTENSION
    } else {
        BINARY_EXTENSION
    }
}

/// Whether `payload` carries every byte `signature` demands.
///
/// The length is checked before the slice is taken, so a payload shorter than
/// the magic number is a non-match rather than a panic.
fn matches(payload: &[u8], signature: &Signature) -> bool {
    run_matches(payload, signature.offset, signature.magic)
        && run_matches(payload, signature.second_offset, signature.second)
}

/// Whether `payload` holds `magic` at `offset`.
fn run_matches(payload: &[u8], offset: usize, magic: &[u8]) -> bool {
    let Some(end) = offset.checked_add(magic.len()) else {
        return false;
    };

    match payload.get(offset..end) {
        Some(window) => window == magic,
        None => false,
    }
}

/// Writes a recovered payload to `path`.
///
/// Without `force` the file is created with `create_new`, so an existing one is
/// never touched; with it, the file is truncated. The check is done by the open
/// itself rather than by a preceding `exists()` because only the open is
/// atomic.
///
/// # Permissions
///
/// On Unix the file is created `0600`, set in the same `open` call that creates
/// it, so it never exists — not even for an instant — with wider permissions
/// than its owner. Windows has no equivalent: `OpenOptions` cannot express an
/// ACL, and the file inherits the one its directory hands down. A payload
/// extracted into a shared or synchronised folder on Windows is therefore
/// readable by whoever that folder is readable by, and choosing the directory
/// is the only control the user has over it.
///
/// # Errors
///
/// Returns [`PayloadWriteError::AlreadyExists`] when the file is there and
/// `force` is not set, and [`PayloadWriteError::Io`] for everything else. A
/// write or flush that fails partway deletes the partial file first: a payload
/// is plaintext, and half of one left behind under a name nobody is watching is
/// the worst outcome of an interrupted write. The deletion cannot mask the
/// original failure — if it fails too, the write error is still what comes
/// back.
pub fn write_payload_file(
    path: &Path,
    payload: &[u8],
    force: bool,
) -> Result<(), PayloadWriteError> {
    let mut options = OpenOptions::new();
    options.write(true);

    if force {
        options.create(true).truncate(true);
    } else {
        options.create_new(true);
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }

    let mut file = options.open(path).map_err(|err| {
        if err.kind() == std::io::ErrorKind::AlreadyExists {
            PayloadWriteError::AlreadyExists
        } else {
            PayloadWriteError::Io(err)
        }
    })?;

    if let Err(err) = file.write_all(payload).and_then(|()| file.sync_all()) {
        // Dropped first: a Windows filesystem will not remove a file that is
        // still open, and the removal is the point of this branch.
        drop(file);
        let _ = std::fs::remove_file(path);

        return Err(PayloadWriteError::Io(err));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;

    use tempfile::TempDir;

    /// The whole read, from a path, as the embedding path performs it.
    ///
    /// The two halves are only ever called one after the other; a test that
    /// exercised them apart would be measuring the split rather than the
    /// behaviour.
    fn read_from_path(path: &Path) -> Result<Zeroizing<Vec<u8>>, String> {
        let handle = open_payload_file(path)?;

        read_payload_file(handle, path)
    }

    /// A payload that begins with `prefix` and is padded out to `length`.
    fn padded(prefix: &[u8], length: usize) -> Vec<u8> {
        let mut payload = prefix.to_vec();
        payload.resize(length.max(prefix.len()), 0x00);

        payload
    }

    /// Every signature in the table is recognised from a sample that carries it.
    ///
    /// The samples are padded well past the magic number, which is what a real
    /// file of each type would be: a table entry that accidentally matched on
    /// length rather than on content would still pass a test built from the
    /// magic bytes alone.
    #[test]
    fn every_signature_in_the_table_is_recognised() {
        let cases: &[(&[u8], &str)] = &[
            (&[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A], "png"),
            (&[0xFF, 0xD8, 0xFF, 0xE0], "jpg"),
            (b"GIF89a", "gif"),
            (b"RIFF\x24\x00\x00\x00WEBPVP8 ", "webp"),
            (b"%PDF-1.7", "pdf"),
            (&[0x50, 0x4B, 0x03, 0x04, 0x14, 0x00], "zip"),
            (&[0x1F, 0x8B, 0x08, 0x00], "gz"),
            (&[0x28, 0xB5, 0x2F, 0xFD, 0x00, 0x00], "zst"),
            (&[0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C, 0x00], "7z"),
            (b"Rar!\x1A\x07\x00", "rar"),
            (&[0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00, 0x00], "xz"),
            (b"SQLite format 3\x00", "sqlite"),
            (b"OggS\x00\x02", "ogg"),
            (b"fLaC\x00\x00", "flac"),
            (b"ID3\x03\x00", "mp3"),
            (b"\x00\x00\x00\x20ftypisom", "mp4"),
        ];

        for (sample, expected) in cases {
            let payload = padded(sample, 64);
            assert_eq!(
                detect_extension(&payload),
                *expected,
                "sample {sample:02X?} should be {expected}"
            );
        }
    }

    /// Text is `txt`, whether or not it is ASCII.
    #[test]
    fn text_payloads_are_named_as_text() {
        assert_eq!(detect_extension(b"Meet me at six.\n"), "txt");
        assert_eq!(
            detect_extension("una nota con acentos: ñ, á, ü".as_bytes()),
            "txt"
        );
    }

    /// Bytes that are neither a known type nor valid UTF-8 are `bin`.
    #[test]
    fn unrecognised_binary_payloads_are_named_as_binary() {
        // A lone continuation byte: never the start of a UTF-8 sequence, and
        // not the prefix of anything in the table.
        assert_eq!(detect_extension(&[0x80, 0x91, 0xA2, 0xB3]), "bin");
        assert_eq!(detect_extension(&[0xC3, 0x28, 0x00, 0xFF]), "bin");
    }

    /// A payload shorter than any signature is answered, not indexed into.
    ///
    /// Every entry in the table is longer than these, so the whole table is
    /// walked with a payload that cannot satisfy any of it. The empty case is
    /// valid UTF-8 by definition, which is why it is `txt`.
    #[test]
    fn very_short_payloads_do_not_read_out_of_bounds() {
        assert_eq!(detect_extension(&[]), "txt");
        assert_eq!(detect_extension(&[0x89]), "bin");
        assert_eq!(detect_extension(&[0x89, 0x50]), "bin");
        assert_eq!(detect_extension(&[0x89, 0x50, 0x4E]), "bin");
        assert_eq!(detect_extension(b"a"), "txt");
        assert_eq!(detect_extension(b"ab"), "txt");
    }

    /// Half a PNG header is not a PNG.
    ///
    /// The property the whole matcher rests on: a signature is checked entire
    /// or not at all, so a truncated file is never given a name that promises a
    /// decoder something it cannot deliver.
    #[test]
    fn a_truncated_signature_does_not_match() {
        assert_eq!(detect_extension(&[0x89, 0x50, 0x4E, 0x47]), "bin");
        assert_eq!(
            detect_extension(&[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A]),
            "bin"
        );

        // And the byte that completes it flips the answer.
        assert_eq!(
            detect_extension(&[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]),
            "png"
        );
    }

    /// A RIFF container that is not a WebP is not called one.
    #[test]
    fn a_riff_that_is_not_a_webp_is_not_a_webp() {
        assert_ne!(detect_extension(b"RIFF\x24\x00\x00\x00WAVEfmt "), "webp");
    }

    /// An existing directory receives `payload.<ext>` inside it.
    #[test]
    fn a_directory_receives_a_named_file_inside_it() {
        let directory = TempDir::new().expect("temporary directory");

        let resolved = resolve_output_path(directory.path(), b"%PDF-1.7");
        assert_eq!(resolved, directory.path().join("payload.pdf"));

        let resolved = resolve_output_path(directory.path(), b"plain text");
        assert_eq!(resolved, directory.path().join("payload.txt"));
    }

    /// A path without an extension gets the detected one.
    #[test]
    fn a_path_without_an_extension_gets_the_detected_one() {
        let directory = TempDir::new().expect("temporary directory");
        let requested = directory.path().join("recovered");

        assert_eq!(
            resolve_output_path(&requested, b"%PDF-1.7"),
            directory.path().join("recovered.pdf")
        );
        assert_eq!(
            resolve_output_path(&requested, &[0x80, 0x81]),
            directory.path().join("recovered.bin")
        );
    }

    /// A path with an extension is used exactly as written.
    ///
    /// Including — especially including — when the extension contradicts the
    /// content. The name is the user's to choose.
    #[test]
    fn a_path_with_an_extension_is_left_alone() {
        let directory = TempDir::new().expect("temporary directory");

        let requested = directory.path().join("recovered.zip");
        assert_eq!(resolve_output_path(&requested, b"%PDF-1.7"), requested);

        let requested = directory.path().join("notes.txt");
        assert_eq!(
            resolve_output_path(
                &requested,
                &[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]
            ),
            requested
        );
    }

    /// Without `force`, an existing file is reported and left untouched.
    #[test]
    fn an_existing_file_is_not_overwritten() {
        let directory = TempDir::new().expect("temporary directory");
        let path = directory.path().join("recovered.txt");
        std::fs::write(&path, b"the file that was already there").expect("fixture write");

        let outcome = write_payload_file(&path, b"the new payload", false);
        assert!(
            matches!(outcome, Err(PayloadWriteError::AlreadyExists)),
            "got: {outcome:?}"
        );

        let kept = std::fs::read(&path).expect("the file must still be readable");
        assert_eq!(kept, b"the file that was already there");
    }

    /// With `force`, it is replaced.
    #[test]
    fn force_overwrites_an_existing_file() {
        let directory = TempDir::new().expect("temporary directory");
        let path = directory.path().join("recovered.txt");
        std::fs::write(&path, b"a much longer previous content").expect("fixture write");

        write_payload_file(&path, b"short", true).expect("force must overwrite");

        let written = std::fs::read(&path).expect("the file must be readable");
        assert_eq!(written, b"short", "the previous content must be truncated");
    }

    /// A file that does not exist is created and holds exactly the payload.
    #[test]
    fn a_new_file_holds_exactly_the_payload() {
        let directory = TempDir::new().expect("temporary directory");
        let path = directory.path().join("recovered.bin");
        let payload = [0x00, 0xFF, 0x80, 0x0A, 0x0D, 0x1A];

        write_payload_file(&path, &payload, false).expect("a new file must be writable");

        let written = std::fs::read(&path).expect("the file must be readable");
        assert_eq!(written, payload);
    }

    /// On Unix the file is born with owner-only permissions.
    #[cfg(unix)]
    #[test]
    fn the_written_file_is_owner_only() {
        use std::os::unix::fs::PermissionsExt as _;

        let directory = TempDir::new().expect("temporary directory");
        let path = directory.path().join("recovered.txt");

        write_payload_file(&path, b"plaintext on a disk", false).expect("write");

        let mode = std::fs::metadata(&path)
            .expect("metadata")
            .permissions()
            .mode();

        assert_eq!(mode & 0o777, 0o600, "got mode {:o}", mode & 0o777);
    }

    /// An empty file is refused rather than embedded as nothing.
    #[test]
    fn an_empty_payload_file_is_refused() {
        let directory = TempDir::new().expect("temporary directory");
        let path = directory.path().join("empty.txt");
        std::fs::write(&path, b"").expect("fixture write");

        let message = read_from_path(&path).expect_err("an empty file must be refused");
        assert!(message.contains("empty"), "got: {message}");
    }

    /// A directory is refused with advice rather than with an I/O error.
    #[test]
    fn a_directory_is_refused_as_a_payload() {
        let directory = TempDir::new().expect("temporary directory");

        let message = read_from_path(directory.path()).expect_err("a directory must be refused");
        assert!(message.contains("directory"), "got: {message}");
    }

    /// A path that is not there says so, by name.
    #[test]
    fn a_missing_payload_file_is_named() {
        let directory = TempDir::new().expect("temporary directory");
        let path = directory.path().join("nowhere.txt");

        let message = read_from_path(&path).expect_err("a missing file must be refused");
        assert!(message.contains("nowhere.txt"), "got: {message}");
        assert!(message.contains("does not exist"), "got: {message}");
    }

    /// A file over the ceiling is refused from its metadata, unread.
    ///
    /// Built as a sparse file so that the test costs a `set_len` rather than 64
    /// mebibytes of writing — which is also what makes the "unread" half of the
    /// claim observable: reading it would materialise the zeroes and take long
    /// enough to notice.
    #[test]
    fn a_file_over_the_ceiling_is_refused_before_it_is_read() {
        let directory = TempDir::new().expect("temporary directory");
        let path = directory.path().join("huge.bin");
        let oversized = MAX_PAYLOAD_FILE_BYTES + 1;

        let file = File::create(&path).expect("fixture create");
        file.set_len(oversized).expect("fixture size");
        drop(file);

        let started = std::time::Instant::now();
        let message = read_from_path(&path).expect_err("an oversized file must be refused");
        let elapsed = started.elapsed();

        assert!(
            message.contains(&oversized.to_string()),
            "the message must state the real size, got: {message}"
        );
        assert!(
            message.contains(&MAX_PAYLOAD_FILE_BYTES.to_string()),
            "the message must state the limit, got: {message}"
        );

        // Generous by two orders of magnitude against reading 64 MiB, which is
        // the thing the metadata check exists to avoid.
        assert!(
            elapsed < std::time::Duration::from_secs(5),
            "the refusal took {elapsed:?}, which means it read the file"
        );
    }

    /// A file at exactly the ceiling is accepted.
    ///
    /// The boundary is inclusive, and a limit written with the wrong comparison
    /// would be invisible from either side of it alone.
    #[test]
    fn a_file_at_the_ceiling_is_accepted() {
        let directory = TempDir::new().expect("temporary directory");
        let path = directory.path().join("borderline.bin");

        let file = File::create(&path).expect("fixture create");
        file.set_len(MAX_PAYLOAD_FILE_BYTES).expect("fixture size");
        drop(file);

        assert!(
            open_payload_file(&path).is_ok(),
            "the ceiling itself must be admissible"
        );
    }

    /// Both write failures explain themselves and chain to their cause.
    ///
    /// The vocabulary is what makes the enum worth having over a string, and an
    /// error whose `Display` was never exercised is one nobody has read.
    #[test]
    fn write_failures_explain_themselves() {
        let existing = PayloadWriteError::AlreadyExists;
        assert!(existing.to_string().contains("already exists"));
        assert!(std::error::Error::source(&existing).is_none());

        let refused = PayloadWriteError::Io(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "the directory is read-only",
        ));
        assert!(refused.to_string().contains("read-only"));
        assert!(std::error::Error::source(&refused).is_some());
    }

    /// The ordinary path: a file on disk arrives as its bytes.
    #[test]
    fn a_payload_file_is_read_whole() {
        let directory = TempDir::new().expect("temporary directory");
        let path = directory.path().join("secret.bin");
        let contents: Vec<u8> = (0..=255u8).cycle().take(4096).collect();
        std::fs::write(&path, &contents).expect("fixture write");

        let payload = read_from_path(&path).expect("a readable file must be read");
        assert_eq!(payload.as_slice(), contents.as_slice());
    }
}
