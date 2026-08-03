//! Command line front-end of `stenoxide`.
//!
//! Three subcommands, two of which read the password interactively:
//!
//! ```text
//! stenoxide scan    ./photos --recursive
//! stenoxide embed   --input cover.png --output stego.png   < message.txt
//! stenoxide extract --input stego.png                      > message.txt
//! ```
//!
//! # Why nothing secret is an argument
//!
//! Neither the password nor the message can be passed on the command line. A
//! password given as an argument survives in the shell history, in the process
//! table for as long as the process runs, and in whatever the shell's own
//! logging does with the line — three places the user cannot wipe and did not
//! choose. The password is therefore read from the terminal with echo disabled
//! and the message from standard input, which leaves no trace whether it is
//! piped in or typed. Typing it is in fact the more private of the two: a
//! message given to `echo` is a command line like any other and lands in the
//! shell's history. See [`read_plaintext`] for how a typed message is ended.
//!
//! # Why the container is validated before the password is asked for
//!
//! The pipeline would refuse an unusable container anyway, but it does so after
//! it has stretched the password — so a user who picked the wrong file would
//! have typed their passphrase for nothing and be told why only afterwards.
//! Both subcommands therefore load and validate the image first and only prompt
//! once it is known to be usable. Nothing about the security of the operation
//! changes: the pipeline runs the very same gates again on the path it is
//! given, and it is the pipeline's verdict, not this one, that decides whether
//! anything is embedded.
//!
//! # Why the two subcommands report failure so differently
//!
//! Embedding is a local operation whose failures are the user's to fix — a
//! container that is too small, a message that does not fit, an unwritable
//! output path — so its errors are printed in full.
//!
//! Extraction is not. Its three failure modes are a wrong password, an image
//! that carries nothing, and a payload that was damaged in transit, and telling
//! them apart is exactly the oracle an attacker holding an intercepted image
//! wants: it would confirm that the image is a container at all, and turn a
//! password search into a test with a yes-or-no answer. So extraction prints
//! one sentence and never says which of the three happened.

#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(missing_docs)]

use std::io::{self, BufRead, IsTerminal, Read, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Args, Parser, Subcommand};
use zeroize::Zeroizing;

use stenoxide_core::cost::hill::HillCostProvider;
use stenoxide_core::cost::CostProvider;
use stenoxide_core::image_io::buffer::ImageBuffer;
use stenoxide_core::image_io::phash::compute_stable_phash;
use stenoxide_core::image_io::validate::{load_and_validate, ValidationError};
use stenoxide_core::pipeline::{EmbedPipeline, EmbedReport};
use stenoxide_core::stego::sizer::{compute_capacity, EmbeddingMode};

mod progress;
mod scan;

/// The one thing the user is told when extraction fails, whatever the cause.
///
/// See the module documentation: distinguishing a wrong password from an image
/// that carries no payload would answer, for free, the question an attacker is
/// actually asking.
const EXTRACTION_FAILED: &str = "Could not extract the payload.";

/// Prompt shown when the password is read from the terminal.
const PASSWORD_PROMPT: &str = "Password: ";

/// The line that ends a message typed at the terminal.
///
/// The convention `mail` established, chosen over end of file for the reason
/// given in [`read_plaintext`]: it is ordinary text, so no shell can intercept
/// it on its way to this process.
const END_OF_MESSAGE: &str = ".";

/// What the user is told before they are expected to type a message.
///
/// Plain ASCII on purpose: this is printed before anything else knows whether
/// the console can render a nicer mark, and a guidance line that arrives as a
/// row of question marks would defeat its own point.
const TYPING_GUIDANCE: &str = "\
Message to hide. It may span as many lines as you need.
Finish with a line containing a single dot:  .
";

/// Hide encrypted messages inside lossless images.
#[derive(Parser)]
#[command(name = "stenoxide", version, about, long_about = None)]
struct Cli {
    /// Operation to perform.
    #[command(subcommand)]
    command: Command,
}

/// The operations the front-end exposes.
#[derive(Subcommand)]
enum Command {
    /// Report which images can be used as containers, and how much each can
    /// carry.
    Scan(ScanArgs),
    /// Hide a message, read from standard input, inside a PNG container.
    Embed {
        /// Container image. Must be a PNG of at least 2000x2000 pixels that has
        /// never been JPEG-compressed.
        #[arg(long, value_name = "PATH")]
        input: PathBuf,
        /// Where to write the resulting stego image. Always written as PNG.
        #[arg(long, value_name = "PATH")]
        output: PathBuf,
    },
    /// Recover a hidden message from a stego image and write it to standard
    /// output.
    Extract {
        /// The stego image to read.
        #[arg(long, value_name = "PATH")]
        input: PathBuf,
    },
}

/// Everything `stenoxide scan` accepts.
#[derive(Args)]
struct ScanArgs {
    /// File, directory or glob pattern to examine. Defaults to the working
    /// directory.
    #[arg(value_name = "PATH", default_value = ".")]
    path: String,
    /// Also list the images that cannot be used, with the reason.
    #[arg(long, short = 'a')]
    all: bool,
    /// Descend into subdirectories.
    #[arg(long, short = 'r')]
    recursive: bool,
    /// Write the result as JSON, and nothing else.
    #[arg(long)]
    json: bool,
}

fn main() -> ExitCode {
    let cli = Cli::parse();

    let outcome = match &cli.command {
        Command::Scan(args) => scan::run(args),
        Command::Embed { input, output } => run_embed(input, output),
        Command::Extract { input } => run_extract(input),
    };

    match outcome {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            // On stderr, so that a caller redirecting stdout to a file gets the
            // message rather than a file with an error in it.
            eprintln!("{message}");
            ExitCode::FAILURE
        }
    }
}

/// Reads the password from the terminal with echo disabled.
///
/// The bytes are moved into a [`Zeroizing`] the moment they arrive, so the only
/// copy that outlives this function is one that wipes itself. The `String`
/// `rpassword` returns is consumed by [`String::into_bytes`], which reuses its
/// allocation instead of leaving a second copy behind.
///
/// # Errors
///
/// Returns a message describing why the terminal could not be read.
fn read_password() -> Result<Zeroizing<Vec<u8>>, String> {
    rpassword::prompt_password(PASSWORD_PROMPT)
        .map(|password| Zeroizing::new(password.into_bytes()))
        .map_err(|err| format!("Error: could not read the password: {err}"))
}

/// Reads the message to hide from standard input.
///
/// Two situations arrive at the same file descriptor, and they are not served
/// by the same code:
///
/// - **A pipe or a redirection.** `echo … | stenoxide embed`, or `< message.txt`.
///   Every byte is message, end of file arrives on its own, and nothing needs
///   to be said to anybody. Read to the end and change nothing.
///
/// - **A terminal.** Nothing was piped in, so what the program is waiting for
///   is a person typing. "Until end of file" then means "until the user sends
///   one", and that is a worse instruction than it looks: `Ctrl+Z` on Windows
///   only counts on an otherwise empty line, and PowerShell's line editor
///   claims the key for undo, so the shell most Windows users are in never
///   delivers it. The honest instruction is one they cannot act on — and until
///   they are given any instruction at all, what they see is a cursor sitting
///   under a password prompt with nothing to say the program wants anything,
///   which reads as a hang.
///
/// So the terminal path states what it wants and accepts a terminator no line
/// editor can intercept, because it is ordinary text: a line holding a single
/// dot, as `mail` has done for decades. End of file still ends the message for
/// the terminals that do send it; it is simply no longer the only way out.
///
/// # Errors
///
/// Returns a message describing why standard input could not be read.
fn read_plaintext() -> Result<Zeroizing<Vec<u8>>, String> {
    let stdin = io::stdin();

    if stdin.is_terminal() {
        // On stderr, like every other thing said to the person at the keyboard:
        // it keeps `embed` usable with its stdout redirected, and it is the
        // stream the progress indicators already respect.
        eprint!("{TYPING_GUIDANCE}");

        let message = collect_typed_lines(&mut stdin.lock())
            .map_err(|err| format!("Error: could not read the message you typed: {err}"))?;

        // Confirms that the terminator was recognised and that something was
        // captured, at the one moment the user can still do something about it
        // — the next thing that happens is a minute inside Argon2id and HILL.
        eprintln!("Read {} bytes.", message.len());

        return Ok(message);
    }

    let mut plaintext = Zeroizing::new(Vec::new());

    stdin
        .lock()
        .read_to_end(&mut plaintext)
        .map_err(|err| format!("Error: could not read the message from standard input: {err}"))?;

    Ok(plaintext)
}

/// Accumulates typed lines until [`END_OF_MESSAGE`] or end of file.
///
/// Split out from [`read_plaintext`] so that the terminator can be asserted
/// against a buffer rather than against a console nobody can drive from a test.
///
/// # Errors
///
/// Returns whatever the underlying reader failed with.
fn collect_typed_lines(input: &mut impl BufRead) -> io::Result<Zeroizing<Vec<u8>>> {
    let mut message = Zeroizing::new(Vec::new());
    let mut line = Zeroizing::new(Vec::new());

    loop {
        line.clear();

        // Bytes rather than `read_line`, which insists on valid UTF-8 and would
        // turn a message typed on a console running some other code page into
        // an error. What the user typed is what gets hidden.
        if input.read_until(b'\n', &mut line)? == 0 {
            break;
        }

        if strip_line_ending(&line) == END_OF_MESSAGE.as_bytes() {
            break;
        }

        message.extend_from_slice(&line);
    }

    // The newline that submitted the last line belongs to the terminator rather
    // than to the message: someone who typed one line and closed it with a dot
    // meant one line, not one line and an empty second one.
    let without_trailing_newline = strip_line_ending(&message).len();
    message.truncate(without_trailing_newline);

    Ok(message)
}

/// A line without its ending, under either of the two conventions.
///
/// A Windows console submits `\r\n` and everything else submits `\n`; neither
/// pair of bytes is something the user typed, so neither may decide whether the
/// line is the terminator.
fn strip_line_ending(line: &[u8]) -> &[u8] {
    let line = match line.strip_suffix(b"\n") {
        Some(rest) => rest,
        None => line,
    };

    match line.strip_suffix(b"\r") {
        Some(rest) => rest,
        None => line,
    }
}

/// Loads a container and reports an unusable one in words the user can act on.
///
/// # Errors
///
/// Returns the message to print, already phrased for a terminal; see
/// [`describe_rejection`].
fn load_container(path: &Path) -> Result<ImageBuffer, String> {
    load_and_validate(path).map_err(|error| describe_rejection(path, &error))
}

/// Turns a validation failure into advice.
///
/// The layer that refused says what is wrong with the file, which is the right
/// thing for a library to report and half of what a person at a terminal needs:
/// the other half is what to do instead. Only the cases with an actionable
/// answer are rewritten here — converting a JPEG, picking a larger image — and
/// everything else keeps the sentence the layer wrote, because inventing advice
/// for a corrupt file would be noise.
fn describe_rejection(path: &Path, error: &ValidationError) -> String {
    let file = path.display();

    match error {
        ValidationError::JpegDetected => format!(
            "Error: {file} is a JPEG and cannot be used as a container.\n       \
             Convert it to PNG first: magick input.jpg output.png\n       \
             Note that a PNG converted from a JPEG is refused as well; the \
             container must never have been JPEG-compressed."
        ),
        ValidationError::WebpDetected => format!(
            "Error: {file} is a WebP and cannot be used as a container.\n       \
             Only PNG containers that have never been through a lossy codec are \
             supported."
        ),
        ValidationError::NotPng => format!(
            "Error: {file} is not a PNG image.\n       \
             Containers must be PNG files of at least 2000x2000 pixels."
        ),
        ValidationError::ImageTooSmall { width, height, min } => format!(
            "Error: {file} is {width}x{height}, which is too small.\n       \
             Both sides must be at least {min} pixels."
        ),
        ValidationError::ImageTooLarge {
            width,
            height,
            pixels,
            max,
        } => format!(
            "Error: {file} is {width}x{height}, which is {} megapixels.\n       \
             Analysing an image that size needs more memory than this limit \
             allows,\n       \
             so it is refused immediately rather than left to exhaust the \
             machine.\n       \
             The maximum is {} megapixels; scale it down or use another photo.",
            pixels / (1024 * 1024),
            max / (1024 * 1024)
        ),
        ValidationError::UnsupportedColorSpace { .. } => format!(
            "Error: the pixel layout of {file} is not supported.\n       \
             Use an 8-bit or 16-bit RGB, RGBA or grayscale PNG."
        ),
        ValidationError::JpegArtifactsDetected { .. } => format!(
            "Error: {file} was JPEG-compressed at some point and re-saved as a \
             PNG.\n       \
             The 8x8 block grid it left behind is exactly what a steganalyst \
             looks for.\n       \
             Use a photo straight from a camera that was never saved as a JPEG."
        ),
        ValidationError::IoError(_) | ValidationError::DecodingError(_) => {
            format!("Error: {file}: {error}")
        }
    }
}

/// Runs the embedding path.
///
/// # Errors
///
/// Returns the message to print when the container is unusable, the message
/// does not fit, or the stego image cannot be written. The text comes from the
/// layer that refused, which already phrases its failures for a user.
fn run_embed(input: &Path, output: &Path) -> Result<(), String> {
    // Before anything is asked of the user: a container that will be refused is
    // refused now, rather than after a passphrase has been typed for nothing.
    drop(load_container(input)?);

    let password = read_password()?;
    let plaintext = read_plaintext()?;

    if plaintext.is_empty() {
        return Err("Error: the message is empty; nothing to hide.".to_string());
    }

    // Embedding spends most of a minute on a large container — Argon2id at 128
    // MiB, then a HILL analysis of every pixel — with nothing to show for it
    // until it finishes. An indicator here reveals nothing: the work is a
    // function of the container's size and the payload's length, and the report
    // printed below states both.
    let activity = progress::Activity::start();

    let outcome = EmbedPipeline::default_secure()
        .embed(input, plaintext, password, output)
        .map_err(|err| format!("Error: {err}"));

    activity.finish();

    let report = outcome?;

    print_report(&report, output);
    Ok(())
}

/// Prints what the embedding did, on stdout.
fn print_report(report: &EmbedReport, output: &Path) {
    let (width, height) = report.image_dimensions;

    println!("Stego image written to {}", output.display());
    println!("  Image dimensions: {width}x{height}");
    println!("  Pixels modified:  {}", report.pixels_modified);
    println!("  Payload embedded: {} bytes", report.payload_bytes);
    println!("  Effective rate:   {:.6} bpp", report.effective_bpp);
}

/// Runs the extraction path.
///
/// # Errors
///
/// Returns [`EXTRACTION_FAILED`], and nothing else, for every failure of the
/// pipeline. The error value is dropped without being formatted: a message
/// assembled from it would say which layer refused, which is the distinction
/// this function exists to withhold.
///
/// The pre-flight load is the one exception, and it is not one in substance: a
/// file that is not a PNG at all, or that no decoder can read, is not a stego
/// image anybody could have produced, and saying so reveals nothing an attacker
/// could not determine by opening the file themselves.
fn run_extract(input: &Path) -> Result<(), String> {
    drop(load_container(input)?);

    let password = read_password()?;

    // The indeterminate indicator, and only that one. It names no stage and
    // reads identically whether the extraction is about to succeed or about to
    // fail; a staged bar here would announce which of the three failure modes
    // occurred, which is precisely what this function exists to withhold. See
    // the `progress` module.
    let activity = progress::Activity::start();

    let outcome = EmbedPipeline::default_secure()
        .extract(input, password)
        .map_err(|_| EXTRACTION_FAILED.to_string());

    // Cleared before the result is inspected, so that the last frame drawn is
    // the same one on both paths.
    activity.finish();

    let (plaintext, _report) = outcome?;

    // Written as raw bytes rather than printed as text: the payload is whatever
    // the sender put in, and forcing it through a string conversion would
    // corrupt any message that is not valid UTF-8.
    io::stdout()
        .write_all(plaintext.as_slice())
        .and_then(|()| io::stdout().flush())
        // A broken pipe or a full disk is not a failed extraction, but naming
        // the difference here would reintroduce the oracle: the same sentence
        // covers both.
        .map_err(|_| EXTRACTION_FAILED.to_string())
}

/// Payload bytes `image` can carry, after encryption.
///
/// `None` when a layer above the loader refuses the container, which is a
/// verdict of "unusable" rather than a capacity of zero.
///
/// # Why the hash is checked here and not only the cost map
///
/// A uniform image passes every gate of layer 1 — it is a PNG, it is large
/// enough, and it carries no block structure — and the cost model accepts it
/// too: cost is the reciprocal of texture energy, so a flat container yields
/// the *highest* cost everywhere and clears a floor written to catch images
/// that are high-energy everywhere. What refuses it is the perceptual hash,
/// whose 64 coefficients all pile up around a near-zero median.
///
/// That makes the hash a load-bearing part of the answer rather than a detail
/// of the embedding path: without it `scan` would report a smooth photograph as
/// a usable container and `embed` would refuse the very same file.
fn container_capacity(image: &ImageBuffer) -> Option<usize> {
    compute_stable_phash(image).ok()?;

    let cost_map = HillCostProvider::new().compute(image).ok()?;

    Some(compute_capacity(&cost_map, EmbeddingMode::Symmetric).available_bytes())
}

/// Whether the terminal can be expected to render the marks `scan` prints.
///
/// A pipe gets the Unicode forms unconditionally: its consumer is a file or
/// another program, and the encoding of a terminal that is not attached says
/// nothing about what that consumer can read. A Windows console gets them only
/// when its code page is UTF-8, because the legacy pages have no glyph for
/// either mark and would print a question mark or a box.
fn terminal_renders_unicode() -> bool {
    #[cfg(windows)]
    {
        if io::stdout().is_terminal() {
            // 65001 is CP_UTF8. Read through the same call the console itself
            // is configured with rather than through an environment variable,
            // which a shell may set without the console honouring it.
            return console_output_code_page() == 65_001;
        }
    }

    true
}

/// The code page the Windows console is writing in.
#[cfg(windows)]
fn console_output_code_page() -> u32 {
    // The one foreign call in this crate, and the reason it is here rather than
    // behind a dependency: asking the console what it can print is a single
    // parameterless query, and pulling in a Windows API crate to make it would
    // be a larger surface than the question deserves.
    extern "system" {
        fn GetConsoleOutputCP() -> u32;
    }

    // SAFETY: `GetConsoleOutputCP` takes no arguments, returns a plain integer,
    // touches no memory the caller owns and cannot fail — a process with no
    // console attached gets zero, which this crate reads as "not UTF-8".
    #[allow(unsafe_code)]
    unsafe {
        GetConsoleOutputCP()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;

    /// Runs the typed-message reader over what a console would have delivered.
    fn typed(keystrokes: &str) -> String {
        let mut input = io::Cursor::new(keystrokes.as_bytes().to_vec());
        let message = collect_typed_lines(&mut input).expect("a cursor cannot fail to read");

        String::from_utf8(message.to_vec()).expect("the fixtures are all UTF-8")
    }

    /// A dot on its own line ends the message and is not part of it.
    ///
    /// The whole reason the terminator exists: `Ctrl+Z` never reaches this
    /// process under PowerShell, so if this line did not end the message there
    /// would be no way to finish one at a Windows prompt.
    #[test]
    fn a_lone_dot_ends_the_message() {
        assert_eq!(typed("a secret\n.\n"), "a secret");
        assert_eq!(typed("a secret\r\n.\r\n"), "a secret");
    }

    /// Anything typed after the terminator is not read.
    ///
    /// The reader stops at the dot rather than draining the stream, so that
    /// whatever the user types next belongs to their shell and not to a message
    /// they thought they had already closed.
    #[test]
    fn nothing_after_the_terminator_is_taken() {
        assert_eq!(typed("kept\n.\nnot this\n"), "kept");
    }

    /// A message may span lines, blank ones included.
    #[test]
    fn the_message_may_span_several_lines() {
        assert_eq!(typed("one\ntwo\n\nfour\n.\n"), "one\ntwo\n\nfour");
    }

    /// End of file still ends the message, terminator or not.
    ///
    /// The dot is an addition rather than a replacement: a terminal that does
    /// deliver `Ctrl+D` or `Ctrl+Z` keeps working exactly as it used to.
    #[test]
    fn end_of_file_still_ends_the_message() {
        assert_eq!(typed("a secret\n"), "a secret");
        assert_eq!(typed("no newline at all"), "no newline at all");
        assert_eq!(typed(""), "");
    }

    /// A dot is only a terminator on a line of its own.
    ///
    /// Ordinary prose ends in one constantly, and a message truncated at its
    /// first full stop would be a data-loss bug in the name of convenience.
    #[test]
    fn a_dot_within_a_line_is_text() {
        assert_eq!(
            typed("Meet me at six. Bring it.\n.\n"),
            "Meet me at six. Bring it."
        );
        assert_eq!(typed("..\n.\n"), "..");
        assert_eq!(typed(" .\n.\n"), " .");
    }

    /// Typing only the terminator produces nothing.
    ///
    /// Which is what makes `run_embed`'s empty-message check the thing that
    /// reports it, rather than the pipeline failing later over a payload nobody
    /// meant to send.
    #[test]
    fn a_message_that_is_only_the_terminator_is_empty() {
        assert!(typed(".\n").is_empty());
    }

    /// Bytes that are not valid UTF-8 survive the trip.
    ///
    /// A console running a legacy code page hands over whatever it hands over,
    /// and the message is bytes to everything downstream of here.
    #[test]
    fn invalid_utf8_is_carried_through_unchanged() {
        let mut input = io::Cursor::new(b"caf\xe9\n.\n".to_vec());
        let message = collect_typed_lines(&mut input).expect("a cursor cannot fail to read");

        assert_eq!(message.as_slice(), b"caf\xe9");
    }

    /// The guidance names the terminator it expects.
    ///
    /// A guard against the obvious future edit: rewording the guidance without
    /// noticing that the dot is load-bearing would leave the user with a prompt
    /// that tells them to do something the reader does not implement.
    #[test]
    fn the_guidance_states_how_to_finish() {
        assert!(
            TYPING_GUIDANCE.contains(END_OF_MESSAGE),
            "the guidance must name the terminator, got: {TYPING_GUIDANCE:?}"
        );
        assert!(
            TYPING_GUIDANCE.is_ascii(),
            "the guidance is printed before the console's code page is known"
        );
    }
}
