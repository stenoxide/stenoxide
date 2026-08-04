//! The `scan` subcommand: which of these images can carry a payload?
//!
//! Picking a container is the part of using this tool that a user gets wrong,
//! and the gates that decide are not ones anybody can apply by eye — whether a
//! PNG was once a JPEG, whether its perceptual hash survives embedding, whether
//! the cost model finds texture anywhere. Before this existed the only way to
//! ask was to attempt an embedding, which meant typing a passphrase to find out
//! that the photo was unusable.
//!
//! So this runs exactly the checks the embedding path runs, over as many files
//! as the user points at, and reports the verdict for each. Nothing is written
//! and no password is read.
//!
//! # What the reported capacity means
//!
//! The figure is what the container admits *after* encryption: the ciphertext,
//! its authentication tag and the frame the pipeline writes around them. The
//! message itself is compressed before any of that, so ordinary text usually
//! fits at two or three times the number shown. Reporting the compressed figure
//! instead would be a promise this layer cannot keep, because how far a payload
//! compresses is a property of the payload.

use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use stenoxide_core::image_io::buffer::CoverSource;
use stenoxide_core::image_io::validate::{load_and_validate, probe_geometry};

use crate::progress::Progress;
use crate::{container_capacity, terminal_renders_unicode, ScanArgs};

/// The extension a container must have, in lower case.
const PNG_EXTENSION: &str = "png";

/// Bytes in a kibibyte, named where the conversion happens.
const BYTES_PER_KIB: f64 = 1024.0;

/// Column width of the path in the default listing.
///
/// Wide enough for a relative path a person would type; longer paths push the
/// rest of the line right rather than being truncated, because a shortened path
/// is not a path the user can act on.
const PATH_COLUMN: usize = 28;

/// Column width of the dimensions in the default listing.
const SIZE_COLUMN: usize = 11;

/// What a scan that accepted nothing says at the end of its summary.
///
/// The one place `stenoxide generate` is offered, and it is offered rather than
/// proposed: no prompt, no yes-or-no, nothing that turns a scan into a
/// decision. A user who has run `scan` over their pictures and been told that
/// none of them can be used has demonstrated that they looked, which is exactly
/// the person the generative mode exists for — and nobody else.
///
/// It says what the mode does not do in the same breath as what it does,
/// because someone in this position will otherwise read "undetectable" as
/// covering the folder as well as the file.
const NOTHING_USABLE_HINT: &str = "\n\
  None of these can be used as a container.\n\
  stenoxide generate builds one around your message instead. It is a last\n\
  resort: the container does not hide that it was generated, only which of\n\
  several generated containers carries anything.\n";

/// What a scan found in one file.
enum Verdict {
    /// The file is a container, and this is what it can carry.
    Usable {
        /// Dimensions as `(width, height)`, in pixels.
        dimensions: (u32, u32),
        /// Payload bytes it admits, after encryption.
        capacity_bytes: usize,
    },
    /// The file cannot be used, for the reason named.
    ///
    /// The reason is the variant name of the layer that refused rather than its
    /// sentence: a listing has one line per file, and the sentences are
    /// paragraphs. `stenoxide embed` on the file prints the full advice.
    Unusable {
        /// Short name of the condition, e.g. `JpegDetected`.
        reason: &'static str,
        /// Dimensions, when the file decoded far enough to have any.
        dimensions: Option<(u32, u32)>,
    },
}

/// One examined file.
struct Entry {
    /// Path as the user would type it.
    path: PathBuf,
    /// What the checks said about it.
    verdict: Verdict,
}

/// Runs `stenoxide scan`.
///
/// # Errors
///
/// Returns the message to print when the path names nothing that can be read.
/// A file that is merely unusable is not an error: it is a line of the report.
pub fn run(args: &ScanArgs) -> Result<(), String> {
    let files = collect_files(&args.path, args.recursive)?;

    // Two passes, because the two costs are four orders of magnitude apart.
    //
    // The first reads twenty-four bytes of each file and settles every question
    // that geometry alone can answer: the format, and whether the image is
    // within the size range at all. On a real folder of pictures that disposes
    // of most of the files — snapshots, icons, screenshots, anything below
    // 2000x2000 — for the price of opening them.
    //
    // The second decodes what is left and runs the analysis. It is the pass
    // worth measuring, and by the time it starts the total amount of work is
    // known exactly: the survivors' pixel counts were read in the first pass.
    let probed: Vec<(PathBuf, Option<u64>)> = files
        .into_iter()
        .map(|path| {
            let pixels = candidate_pixels(&path);
            (path, pixels)
        })
        .collect();

    let total_megapixels: u64 = probed
        .iter()
        .filter_map(|(_, pixels)| *pixels)
        .map(megapixels)
        .sum();

    let progress = Progress::new(
        &format!(
            "Analysing {} of {} files",
            probed.iter().filter(|(_, pixels)| pixels.is_some()).count(),
            probed.len()
        ),
        total_megapixels,
    );

    let entries: Vec<Entry> = probed
        .into_iter()
        .map(|(path, pixels)| {
            if let Some(pixels) = pixels {
                progress.set_detail(&file_name(&path));
                let entry = examine(path);
                progress.advance(megapixels(pixels));
                entry
            } else {
                examine(path)
            }
        })
        .collect();

    progress.finish();

    let report = if args.json {
        // Always complete, whatever `--all` says. That flag exists to keep a
        // listing readable for a person, and a script that asked for a document
        // is not helped by having records withheld from it.
        render_json(&entries)
    } else {
        render_listing(&args.path, &entries, args.all)
    };

    print!("{report}");
    Ok(())
}

/// Pixels a file will cost to analyse, or `None` if it will not be analysed.
///
/// The header probe answers this without decoding anything, so it is what makes
/// an honest estimate possible: the work of the expensive pass is known before
/// that pass begins. A file the probe already rejects costs nothing more, and
/// [`examine`] will reach the same verdict again from the same bytes.
fn candidate_pixels(path: &Path) -> Option<u64> {
    let is_png = path
        .extension()
        .map(|extension| extension.to_string_lossy().to_lowercase() == PNG_EXTENSION)
        .unwrap_or(false);

    if !is_png {
        return None;
    }

    probe_geometry(path)
        .ok()
        .map(|geometry| geometry.pixel_count())
}

/// A pixel count in megapixels, rounded up so that no file counts as zero work.
fn megapixels(pixels: u64) -> u64 {
    pixels.div_ceil(1024 * 1024)
}

/// The last component of a path, for a one-line label.
fn file_name(path: &Path) -> String {
    path.file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| path.display().to_string())
}

/// Every file the path argument names, in a stable order.
///
/// The argument is one of three things and is not declared to be any of them:
/// an existing file is itself, an existing directory is its contents, and
/// anything else is read as a glob pattern. Trying them in that order is what
/// lets a path containing a bracket be scanned by name — a real possibility on
/// a filesystem, and impossible to express if the pattern were tried first.
///
/// # Errors
///
/// Returns the message to print when the argument names nothing at all.
fn collect_files(argument: &str, recursive: bool) -> Result<Vec<PathBuf>, String> {
    let path = Path::new(argument);

    if path.is_file() {
        return Ok(vec![path.to_path_buf()]);
    }

    if path.is_dir() {
        let mut found = BTreeSet::new();
        walk(path, recursive, &mut found)?;

        return Ok(found.into_iter().collect());
    }

    let matched = glob_matches(argument, recursive)?;
    if matched.is_empty() {
        return Err(format!(
            "Error: {argument} does not name a file, a directory or any matching path."
        ));
    }

    Ok(matched)
}

/// Adds every regular file under `directory` to `found`.
///
/// Ordered by [`BTreeSet`] rather than by the order the filesystem hands
/// entries over, which differs between platforms and between two runs on the
/// same one. A listing whose order moves is a listing nobody can diff.
///
/// # Errors
///
/// Returns the message to print when a directory cannot be read. A single
/// unreadable entry inside a readable directory is skipped instead: one file
/// the user has no permission for should not hide the rest of the scan.
fn walk(directory: &Path, recursive: bool, found: &mut BTreeSet<PathBuf>) -> Result<(), String> {
    let entries = std::fs::read_dir(directory)
        .map_err(|err| format!("Error: cannot read {}: {err}", directory.display()))?;

    for entry in entries.flatten() {
        let path = entry.path();

        if path.is_dir() {
            if recursive {
                walk(&path, recursive, found)?;
            }
        } else {
            found.insert(path);
        }
    }

    Ok(())
}

/// Expands a glob pattern into the paths it matches.
///
/// Written here rather than taken from a dependency because the patterns a
/// person types at this subcommand are `*.png`, `photos/*.png` and
/// `photos/**/*.png`, and supporting exactly those is a dozen lines: the
/// pattern is split at the path separator, each component is matched against
/// the names in the directory reached so far, and `**` stands for "this
/// directory and everything under it".
///
/// # Errors
///
/// Returns the message to print when a directory named by the pattern cannot be
/// read.
fn glob_matches(pattern: &str, recursive: bool) -> Result<Vec<PathBuf>, String> {
    let (root, rest) = split_pattern(pattern);
    let mut current = vec![root];

    for component in rest {
        let mut next = BTreeSet::new();

        for directory in &current {
            if component.as_str() == "**" {
                // Everything at or below this point, so that a later component
                // can be matched against any depth.
                next.insert(directory.clone());
                collect_directories(directory, &mut next)?;
                continue;
            }

            let entries = match std::fs::read_dir(directory) {
                Ok(entries) => entries,
                // A component that names no directory simply contributes
                // nothing; the pattern as a whole may still match elsewhere.
                Err(_) => continue,
            };

            for entry in entries.flatten() {
                let path = entry.path();
                let name = entry.file_name().to_string_lossy().into_owned();

                if matches_component(&name, &component) {
                    next.insert(path);
                }
            }
        }

        current = next.into_iter().collect();
    }

    // A pattern that resolved to a directory is scanned like one, so that
    // `scan "photos/*"` behaves as a person would expect rather than reporting
    // a directory as an unusable image.
    let mut files = BTreeSet::new();
    for path in current {
        if path.is_dir() {
            walk(&path, recursive, &mut files)?;
        } else if path.is_file() {
            files.insert(path);
        }
    }

    Ok(files.into_iter().collect())
}

/// Splits a pattern into the deepest directory it names outright and the
/// components that still have to be matched.
///
/// The leading run of components carrying no wildcard is a path, not a pattern,
/// and treating it as one is what makes an absolute path work. Rejoining that
/// run with a separator rather than pushing its parts onto a [`PathBuf`] one at
/// a time is deliberate: on Windows a bare drive letter is a *drive-relative*
/// root, so pushing `Users` onto `C:` yields `C:Users` — the working directory
/// of drive C — where `C:/Users` is the absolute path the user typed.
///
/// A pattern with no fixed part at all is anchored at the working directory,
/// which is what `scan "*.png"` means.
fn split_pattern(pattern: &str) -> (PathBuf, Vec<String>) {
    let components: Vec<&str> = pattern.split(['/', '\\']).collect();
    let fixed = components
        .iter()
        .position(|component| component.contains(['*', '?']))
        .unwrap_or(components.len());

    let root = match &components[..fixed] {
        // No fixed part: the pattern is relative to where the user is standing.
        [] => PathBuf::from("."),
        // The whole fixed part is the leading separator of an absolute Unix
        // path, which rejoining would lose.
        [""] => PathBuf::from("/"),
        fixed => PathBuf::from(fixed.join("/")),
    };

    let rest = components[fixed..]
        .iter()
        .map(|component| (*component).to_owned())
        .collect();

    (root, rest)
}

/// Adds every directory under `directory`, recursively, to `found`.
///
/// # Errors
///
/// Returns the message to print when a directory cannot be read.
fn collect_directories(directory: &Path, found: &mut BTreeSet<PathBuf>) -> Result<(), String> {
    let entries = match std::fs::read_dir(directory) {
        Ok(entries) => entries,
        Err(_) => return Ok(()),
    };

    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            found.insert(path.clone());
            collect_directories(&path, found)?;
        }
    }

    Ok(())
}

/// Whether a file name matches one component of a glob pattern.
///
/// `*` stands for any run of characters, including none, and `?` for exactly
/// one. Matched greedily with backtracking, which is quadratic in the worst
/// case and irrelevant at the length of a file name.
fn matches_component(name: &str, pattern: &str) -> bool {
    let name: Vec<char> = name.chars().collect();
    let pattern: Vec<char> = pattern.chars().collect();

    // `matched` walks the name, `consumed` walks the pattern, and the two
    // `star` cursors remember where to resume from if the current run of the
    // wildcard turns out to be too short.
    let (mut matched, mut consumed) = (0usize, 0usize);
    let (mut star, mut resume) = (None, 0usize);

    while matched < name.len() {
        match pattern.get(consumed) {
            Some('*') => {
                star = Some(consumed);
                resume = matched;
                consumed += 1;
            }
            Some('?') => {
                matched += 1;
                consumed += 1;
            }
            Some(&literal) if literal == name[matched] => {
                matched += 1;
                consumed += 1;
            }
            _ => match star {
                // Backtrack: let the last wildcard swallow one more character.
                Some(position) => {
                    consumed = position + 1;
                    resume += 1;
                    matched = resume;
                }
                None => return false,
            },
        }
    }

    // Trailing wildcards may still match the empty remainder.
    pattern[consumed..]
        .iter()
        .all(|&character| character == '*')
}

/// Runs the checks on one file.
///
/// Every file examined produces an entry, including the ones that are not PNGs
/// at all. Deciding which of them a person wants to *read* about belongs to the
/// renderer; deciding it here would make the summary disagree with the number
/// of files the scan actually looked at.
fn examine(path: PathBuf) -> Entry {
    let is_png = path
        .extension()
        .map(|extension| extension.to_string_lossy().to_lowercase() == PNG_EXTENSION)
        .unwrap_or(false);

    if !is_png {
        return Entry {
            path,
            verdict: Verdict::Unusable {
                reason: "UnsupportedFormat",
                dimensions: None,
            },
        };
    }

    let verdict = match load_and_validate(&path) {
        Ok(image) => {
            let dimensions = image.dimensions();

            // The cost layer has the last word, and it is the expensive one:
            // it is only reached for files that already passed every gate of
            // layer 1.
            match container_capacity(&image) {
                Some(capacity_bytes) => Verdict::Usable {
                    dimensions,
                    capacity_bytes,
                },
                None => Verdict::Unusable {
                    reason: "InsufficientTexture",
                    dimensions: Some(dimensions),
                },
            }
        }
        Err(error) => {
            let (reason, dimensions) = describe(&error);
            Verdict::Unusable { reason, dimensions }
        }
    };

    Entry { path, verdict }
}

/// The short name of a validation failure, and the dimensions it carries.
fn describe(
    error: &stenoxide_core::image_io::validate::ValidationError,
) -> (&'static str, Option<(u32, u32)>) {
    use stenoxide_core::image_io::validate::ValidationError as Error;

    match error {
        Error::IoError(_) => ("IoError", None),
        Error::JpegDetected => ("JpegDetected", None),
        Error::WebpDetected => ("WebpDetected", None),
        Error::NotPng => ("NotPng", None),
        Error::UnsupportedColorSpace { .. } => ("UnsupportedColorSpace", None),
        Error::ImageTooSmall { width, height, .. } => ("ImageTooSmall", Some((*width, *height))),
        Error::ImageTooLarge { width, height, .. } => ("ImageTooLarge", Some((*width, *height))),
        Error::DecodingError(_) => ("DecodingError", None),
        Error::JpegArtifactsDetected { .. } => ("JpegArtifactsDetected", None),
    }
}

/// The human-readable report.
fn render_listing(argument: &str, entries: &[Entry], all: bool) -> String {
    let (usable_mark, unusable_mark) = if terminal_renders_unicode() {
        ("\u{2713}", "\u{2717}")
    } else {
        ("[OK]", "[--]")
    };

    let mut report = String::new();
    let _ = writeln!(report, "Scanning {argument} ...\n");

    let mut usable = 0usize;
    let mut unusable = 0usize;

    for entry in entries {
        let path = entry.path.display().to_string();

        match &entry.verdict {
            Verdict::Usable {
                dimensions: (width, height),
                capacity_bytes,
            } => {
                usable += 1;
                let size = format!("{width}x{height}");
                let capacity = *capacity_bytes as f64 / BYTES_PER_KIB;
                let _ = writeln!(
                    report,
                    "  {usable_mark} {path:<PATH_COLUMN$} {size:<SIZE_COLUMN$} ~{capacity:.1} KB payload"
                );
            }
            Verdict::Unusable { reason, dimensions } => {
                unusable += 1;
                if !all {
                    continue;
                }

                let size = dimensions
                    .map(|(width, height)| format!(" {width}x{height}"))
                    .unwrap_or_default();
                let _ = writeln!(
                    report,
                    "  {unusable_mark} {path:<PATH_COLUMN$} {reason}{size}"
                );
            }
        }
    }

    let scanned = usable + unusable;
    let _ = writeln!(report);

    if usable > 0 {
        let _ = writeln!(
            report,
            "  * Estimated payload capacity after encryption overhead"
        );
    }

    let _ = writeln!(
        report,
        "  Summary: {usable} valid, {unusable} invalid ({scanned} scanned)"
    );

    if unusable > 0 && !all {
        let _ = writeln!(report, "  Run with --all to see why an image was rejected.");
    }

    if usable == 0 && scanned > 0 {
        let _ = write!(report, "{NOTHING_USABLE_HINT}");
    }

    report
}

/// The machine-readable report.
///
/// Assembled by hand rather than through a serialisation crate. The document
/// has three fixed keys and two shapes of record, none of which is going to
/// grow a field without this function being edited anyway, and the only value
/// that is not a number is a path — see [`escape`] for the one thing that has
/// to be got right about that.
fn render_json(entries: &[Entry]) -> String {
    let mut valid = Vec::new();
    let mut invalid = Vec::new();

    for entry in entries {
        let path = escape(&entry.path.display().to_string());

        match &entry.verdict {
            Verdict::Usable {
                dimensions: (width, height),
                capacity_bytes,
            } => valid.push(format!(
                "    {{\n      \"path\": \"{path}\",\n      \"dimensions\": [{width}, {height}],\n      \"capacity_kb\": {:.1}\n    }}",
                *capacity_bytes as f64 / BYTES_PER_KIB
            )),
            Verdict::Unusable { reason, .. } => invalid.push(format!(
                "    {{\n      \"path\": \"{path}\",\n      \"reason\": \"{reason}\"\n    }}"
            )),
        }
    }

    let render = |records: &[String]| {
        if records.is_empty() {
            "[]".to_owned()
        } else {
            format!("[\n{}\n  ]", records.join(",\n"))
        }
    };

    format!(
        "{{\n  \"valid\": {},\n  \"invalid\": {},\n  \"summary\": {{\n    \"scanned\": {},\n    \"valid\": {},\n    \"invalid\": {}\n  }}\n}}\n",
        render(&valid),
        render(&invalid),
        valid.len() + invalid.len(),
        valid.len(),
        invalid.len()
    )
}

/// Escapes a string for a JSON document.
///
/// The backslash matters more than it looks: every path on Windows is full of
/// them, and a document that emitted them raw would not parse. Control
/// characters are escaped as well — a file name may legally contain a newline
/// on most filesystems, and that would otherwise end the string mid-value.
fn escape(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());

    for character in value.chars() {
        match character {
            '"' => escaped.push_str("\\\""),
            '\\' => escaped.push_str("\\\\"),
            '\n' => escaped.push_str("\\n"),
            '\r' => escaped.push_str("\\r"),
            '\t' => escaped.push_str("\\t"),
            control if control < ' ' => {
                let _ = write!(escaped, "\\u{:04x}", control as u32);
            }
            other => escaped.push(other),
        }
    }

    escaped
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The fixed head of a pattern is a path and is kept whole.
    ///
    /// The Windows case is the one that matters and the one that was wrong: a
    /// bare drive letter is a drive-*relative* root, so a pattern anchored at
    /// `C:` and walked component by component would resolve against the working
    /// directory of that drive rather than against its root.
    #[test]
    fn a_pattern_splits_into_a_root_and_the_parts_still_to_match() {
        let split = |pattern: &str| {
            let (root, rest) = split_pattern(pattern);

            (root.to_string_lossy().into_owned(), rest.join("|"))
        };

        assert_eq!(split("*.png"), (".".to_owned(), "*.png".to_owned()));
        assert_eq!(
            split("photos/*.png"),
            ("photos".to_owned(), "*.png".to_owned())
        );
        assert_eq!(
            split("photos/**/*.png"),
            ("photos".to_owned(), "**|*.png".to_owned())
        );
        assert_eq!(
            split(r"C:\Users\me\photos\*.png"),
            ("C:/Users/me/photos".to_owned(), "*.png".to_owned())
        );
        assert_eq!(
            split("/home/me/*.png"),
            ("/home/me".to_owned(), "*.png".to_owned())
        );
        assert_eq!(split("/*.png"), ("/".to_owned(), "*.png".to_owned()));

        // A pattern with no wildcard at all has nothing left to match, so the
        // walk below returns the root itself.
        assert_eq!(
            split("photos/a.png"),
            ("photos/a.png".to_owned(), String::new())
        );
    }

    /// Literals match themselves and nothing else.
    #[test]
    fn a_component_with_no_wildcard_matches_only_itself() {
        assert!(matches_component("photo.png", "photo.png"));
        assert!(!matches_component("photo.png", "photo.jpg"));
        assert!(!matches_component("photo.png", "photo"));
    }

    /// A star stands for any run of characters, including none.
    #[test]
    fn a_star_matches_any_run() {
        assert!(matches_component("photo.png", "*.png"));
        assert!(matches_component("photo.png", "*"));
        assert!(matches_component(".png", "*.png"));
        assert!(matches_component("a-b-c.png", "a-*-c.png"));
        assert!(!matches_component("photo.jpg", "*.png"));

        // Backtracking: the first run the wildcard takes is too long, and the
        // match only succeeds because it gives characters back.
        assert!(matches_component("aaa.png.png", "*.png"));
    }

    /// A question mark stands for exactly one character.
    #[test]
    fn a_question_mark_matches_exactly_one() {
        assert!(matches_component("a.png", "?.png"));
        assert!(!matches_component("ab.png", "?.png"));
        assert!(!matches_component(".png", "?.png"));
    }

    /// Trailing wildcards may still match nothing at all.
    #[test]
    fn a_trailing_star_may_match_nothing() {
        assert!(matches_component("photo", "photo*"));
        assert!(matches_component("photo", "photo**"));
        assert!(!matches_component("photo", "photo?"));
    }

    /// Paths are escaped so that a Windows separator does not break the
    /// document.
    #[test]
    fn json_strings_are_escaped() {
        assert_eq!(escape(r"photos\a.png"), r"photos\\a.png");
        assert_eq!(escape("a\"b"), "a\\\"b");
        assert_eq!(escape("line\nbreak"), "line\\nbreak");
        assert_eq!(escape("bell\u{7}"), "bell\\u0007");
        assert_eq!(escape("plain/path.png"), "plain/path.png");
    }

    /// An empty scan is a valid document with three empty answers.
    #[test]
    fn an_empty_scan_renders_an_empty_document() {
        let rendered = render_json(&[]);

        assert!(rendered.contains("\"valid\": []"), "got: {rendered}");
        assert!(rendered.contains("\"invalid\": []"), "got: {rendered}");
        assert!(rendered.contains("\"scanned\": 0"), "got: {rendered}");
    }

    /// Both shapes of record appear under the key their verdict belongs to.
    #[test]
    fn both_verdicts_reach_the_document() {
        let entries = vec![
            Entry {
                path: PathBuf::from("good.png"),
                verdict: Verdict::Usable {
                    dimensions: (2000, 2400),
                    capacity_bytes: 12_698,
                },
            },
            Entry {
                path: PathBuf::from("bad.png"),
                verdict: Verdict::Unusable {
                    reason: "JpegDetected",
                    dimensions: None,
                },
            },
        ];

        let rendered = render_json(&entries);

        assert!(
            rendered.contains("\"path\": \"good.png\""),
            "got: {rendered}"
        );
        assert!(
            rendered.contains("\"dimensions\": [2000, 2400]"),
            "got: {rendered}"
        );
        assert!(
            rendered.contains("\"capacity_kb\": 12.4"),
            "got: {rendered}"
        );
        assert!(
            rendered.contains("\"reason\": \"JpegDetected\""),
            "got: {rendered}"
        );
        assert!(rendered.contains("\"scanned\": 2"), "got: {rendered}");
        assert!(rendered.contains("\"valid\": 1"), "got: {rendered}");
        assert!(rendered.contains("\"invalid\": 1"), "got: {rendered}");
    }

    /// The listing names every file it examined and counts them.
    #[test]
    fn the_listing_reports_every_entry() {
        let entries = vec![
            Entry {
                path: PathBuf::from("photos/good.png"),
                verdict: Verdict::Usable {
                    dimensions: (3840, 2160),
                    capacity_bytes: 76_000,
                },
            },
            Entry {
                path: PathBuf::from("photos/small.png"),
                verdict: Verdict::Unusable {
                    reason: "ImageTooSmall",
                    dimensions: Some((400, 400)),
                },
            },
        ];

        let rendered = render_listing("./photos", &entries, true);

        assert!(rendered.contains("Scanning ./photos"), "got: {rendered}");
        assert!(rendered.contains("photos/good.png"), "got: {rendered}");
        assert!(rendered.contains("3840x2160"), "got: {rendered}");
        assert!(rendered.contains("74.2 KB payload"), "got: {rendered}");
        assert!(
            rendered.contains("ImageTooSmall 400x400"),
            "got: {rendered}"
        );
        assert!(
            rendered.contains("Summary: 1 valid, 1 invalid (2 scanned)"),
            "got: {rendered}"
        );
    }

    /// A scan that accepted nothing names the way out; one that accepted
    /// something does not.
    ///
    /// The condition is the whole design of this line. It is advice for a user
    /// who has looked and has nothing, and noise — or worse, a suggestion to
    /// use the weaker mode — for anyone holding a usable photograph.
    #[test]
    fn only_a_scan_that_found_nothing_offers_to_generate_a_container() {
        let refused = vec![Entry {
            path: PathBuf::from("a.png"),
            verdict: Verdict::Unusable {
                reason: "JpegDetected",
                dimensions: None,
            },
        }];

        let listing = render_listing(".", &refused, true);
        assert!(listing.contains("stenoxide generate"), "got: {listing}");
        assert!(
            listing.contains("does not hide that it was generated"),
            "the offer must state what the mode does not do: {listing}"
        );

        let mut mixed = refused;
        mixed.push(Entry {
            path: PathBuf::from("b.png"),
            verdict: Verdict::Usable {
                dimensions: (2000, 2000),
                capacity_bytes: 8_300,
            },
        });
        assert!(!render_listing(".", &mixed, true).contains("stenoxide generate"));

        // Nothing was scanned at all, so there is nothing to conclude from.
        assert!(!render_listing(".", &[], true).contains("stenoxide generate"));
    }

    /// Without `--all` the listing points at the flag that would explain a
    /// rejection, rather than leaving the count unaccounted for.
    #[test]
    fn a_short_listing_says_how_to_see_the_rest() {
        let entries = vec![Entry {
            path: PathBuf::from("a.png"),
            verdict: Verdict::Unusable {
                reason: "JpegDetected",
                dimensions: None,
            },
        }];

        assert!(render_listing(".", &entries, false).contains("--all"));
        assert!(!render_listing(".", &entries, true).contains("--all"));
    }
}
