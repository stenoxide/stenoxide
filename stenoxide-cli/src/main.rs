//! Command line front-end of `stenoxide`.
//!
//! Four subcommands, three of which read the password interactively:
//!
//! ```text
//! stenoxide scan     ./photos --recursive
//! stenoxide embed    --input cover.png --output stego.png   < message.txt
//! stenoxide embed    --input cover.png --output stego.png --payload secret.zip
//! stenoxide extract  --input stego.png                      > message.txt
//! stenoxide extract  --input stego.png --payload-out secret.zip
//! stenoxide generate --output container.png --input message.txt
//! stenoxide generate --output container.png --input big.bin --width 2500 --height 2500
//! ```
//!
//! The payload has always been arbitrary bytes rather than text, so the file
//! forms are not a new capability so much as the end of a shell redirection the
//! user had to arrange themselves. They change nothing about what is embedded:
//! an image produced with `--payload` is indistinguishable from one produced by
//! piping the same bytes in.
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
//! A path is not a secret, and `--payload` does not weaken any of that: what
//! reaches the command line is where the file is, never a byte of what is in
//! it.
//!
//! # Why the recovered file is named by whoever extracts it
//!
//! `--payload-out` takes a full path, and the sender has no say in it: the
//! payload carries no file name, because nothing but the bytes is hidden. The
//! extension is recovered from the content instead, against a closed table. The
//! reasoning — which is about the recipient's disk and about paths built from
//! untrusted input, not about cryptography — is in the [`payload`] module.
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
//! # Why `generate` is a subcommand and not an offer
//!
//! `embed` needs a container, and the tempting interface is to notice that it
//! was given none and offer to make one. It is the wrong place for it twice
//! over. A user who omitted `--input` made a typo and is not asking to change
//! their security model, so the offer would turn a slip into a hurried
//! decision; and the operation that fits behind such a prompt is *generate,
//! then embed*, which is the weaker of the two constructions by a wide margin —
//! roughly 7 KB of capacity against 1.4 MB, and a detectable container against
//! one that provably is not. The convenient path would deliver the worse mode.
//!
//! Discoverability belongs in `scan` instead: when it walks a directory and
//! accepts nothing at all, it says so in one line. That user has already
//! demonstrated that they looked.
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
//!
//! # The one thing extraction says beyond that sentence
//!
//! A recovered payload with no `--payload-out` goes to standard output, and a
//! payload that is binary cannot go to a *terminal*: a Windows console rejects
//! bytes that are not valid UTF-8, and a Unix terminal would be sprayed with
//! control codes. So a binary payload bound for a terminal is announced instead
//! of written. That notice reveals the extraction succeeded — but so does a text
//! payload printed to the same terminal, and so does any file written under
//! `--payload-out`; success is inherent in producing the plaintext. The single
//! sentence still covers the three failures and every post-success write error
//! on the redirected path, which is all it ever protected. See
//! [`write_recovered_to_stdout`].

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
use stenoxide_core::generate::{
    generate_container, ContainerDimensions, GenerateError, GenerateReport, DEFAULT_CONTAINER_SIDE,
    MIN_CONTAINER_SIDE,
};
use stenoxide_core::image_io::buffer::ImageBuffer;
use stenoxide_core::image_io::phash::compute_stable_phash;
use stenoxide_core::image_io::validate::{load_and_validate, ValidationError};
use stenoxide_core::pipeline::{EmbedPipeline, EmbedReport, PipelineError};
use stenoxide_core::stego::sizer::{compute_capacity, EmbeddingMode, SizerError};

mod payload;
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

/// The long help of `generate`, which has one thing it must say.
///
/// A user reaches this subcommand because nothing they own can be used as a
/// container, and the mode answers a narrower question than they are likely to
/// assume. It hides *which* of several generated containers carries a message,
/// completely and provably. It does not hide that the file was generated: it
/// looks like a synthetic texture, and a folder of them is conspicuous in a way
/// no analysis of any single file needs to be.
const GENERATE_LONG_ABOUT: &str = "\
Build a container around a message instead of hiding it inside an existing image.

For when there is no usable photograph — a camera that only writes JPEG, no way
to move pictures across from a phone. The container is drawn sample by sample,
each one conditioned on the ciphertext bit it carries, so a container holding a
message and one holding nothing are draws from the same distribution and no
detector can separate them. It carries about 1.4 MB, against the 8 KB an image
of the same size admits by embedding.

The default container is 2000x2000, the smallest and least conspicuous the mode
draws. A payload that does not fit needs a larger one: raise --width and
--height together (each at least 2000). Capacity grows with the pixel count, so
the error printed when a payload overflows names a size that would hold it.

It does not hide that the container was generated. It looks like a synthetic
texture, and a folder full of them is itself the thing worth explaining. Prefer
a photograph of your own that has never been published, whenever you have one.";

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
        /// File to hide. Read from standard input when absent; when given,
        /// standard input is not read at all and any redirection is ignored.
        #[arg(long, value_name = "PATH")]
        payload: Option<PathBuf>,
    },
    /// Build a container around a message, for when there is no usable photo.
    #[command(long_about = GENERATE_LONG_ABOUT)]
    Generate {
        /// Where to write the container. Always written as PNG.
        #[arg(long, value_name = "PATH")]
        output: PathBuf,
        /// File to hide. Read from standard input when absent; when given,
        /// standard input is not read at all and any redirection is ignored.
        #[arg(long, value_name = "PATH")]
        input: Option<PathBuf>,
        /// Width of the container to draw, in pixels. Defaults to 2000, the
        /// smallest — and least conspicuous — the mode will produce; raise it,
        /// together with --height, only when a payload does not fit. Must be at
        /// least 2000.
        #[arg(long, value_name = "PIXELS", default_value_t = DEFAULT_CONTAINER_SIDE,
              value_parser = clap::value_parser!(u32).range(i64::from(MIN_CONTAINER_SIDE)..))]
        width: u32,
        /// Height of the container to draw, in pixels. Defaults to 2000. Must be
        /// at least 2000; a larger container carries more, in proportion to its
        /// pixel count.
        #[arg(long, value_name = "PIXELS", default_value_t = DEFAULT_CONTAINER_SIDE,
              value_parser = clap::value_parser!(u32).range(i64::from(MIN_CONTAINER_SIDE)..))]
        height: u32,
    },
    /// Recover a hidden message from a stego image and write it to standard
    /// output.
    Extract {
        /// The stego image to read.
        #[arg(long, value_name = "PATH")]
        input: PathBuf,
        /// Where to write the recovered payload. Written to standard output
        /// when absent. A directory receives a file named after the type of
        /// the content; a path without an extension is given one.
        #[arg(long, value_name = "PATH")]
        payload_out: Option<PathBuf>,
        /// Overwrite the output file if it already exists.
        #[arg(long, requires = "payload_out")]
        force: bool,
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
        Command::Embed {
            input,
            output,
            payload,
        } => run_embed(input, output, payload.as_deref()),
        Command::Generate {
            output,
            input,
            width,
            height,
        } => run_generate(output, input.as_deref(), *width, *height),
        Command::Extract {
            input,
            payload_out,
            force,
        } => run_extract(input, payload_out.as_deref(), *force),
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
/// Returns the message to print when the container is unusable, the payload
/// file cannot be read, the message does not fit, or the stego image cannot be
/// written. Most of the text comes from the layer that refused, which already
/// phrases its failures for a user; see [`describe_embed_failure`] for the one
/// case that is rewritten.
fn run_embed(input: &Path, output: &Path, payload: Option<&Path>) -> Result<(), String> {
    // Before anything is asked of the user: a container that will be refused is
    // refused now, rather than after a passphrase has been typed for nothing.
    drop(load_container(input)?);

    // And for the same reason, a payload path that cannot be read is settled
    // here too — a mistyped path is exactly as much a wasted passphrase as a
    // JPEG is. The handle is kept rather than the verdict: reopening by path
    // after the prompt would leave a window in which the file that was checked
    // and the file that is read need not be the same one.
    let source = match payload {
        Some(path) => Some((payload::open_payload_file(path)?, path)),
        None => None,
    };

    let password = read_password()?;

    // With `--payload` standard input is not touched at all, redirected or not.
    let plaintext = match source {
        Some((handle, path)) => payload::read_payload_file(handle, path)?,
        None => read_plaintext()?,
    };

    if plaintext.is_empty() {
        return Err("Error: the message is empty; nothing to hide.".to_string());
    }

    // Embedding spends most of a minute on a large container — Argon2id at 128
    // MiB, then a HILL analysis of every pixel — with nothing to show for it
    // until it finishes. An indicator here reveals nothing: the work is a
    // function of the container's size and the payload's length, and the report
    // printed below states both.
    let activity = progress::Activity::start();

    let outcome = EmbedPipeline::default_secure().embed(input, plaintext, password, output);

    activity.finish();

    let report = outcome.map_err(|err| describe_embed_failure(&err))?;

    print_report(&report, output);
    Ok(())
}

/// Turns an embedding failure into the sentence the user reads.
///
/// Only one case is rewritten, on the same principle as [`describe_rejection`]:
/// the sizer knows the three numbers that make the refusal actionable but is
/// forbidden from printing them, because the same type answers a question about
/// a container the user may not own. At this end of the program the container
/// is theirs and the numbers are the whole answer.
///
/// The figure quoted is the payload *after* compression and encryption, and the
/// message says so. Reporting the file's size instead would tell a user that
/// their 30 KB of notes do not fit in a container that admits 22 KB, which is
/// false: Zstandard runs first, and text collapses.
fn describe_embed_failure(error: &PipelineError) -> String {
    let PipelineError::Sizer(SizerError::PayloadTooLarge {
        payload,
        available,
        deficit,
    }) = error
    else {
        return format!("Error: {error}");
    };

    format!(
        "Error: the payload does not fit in this container.\n       \
         Compressed and encrypted it is {payload} bytes; the container admits \
         {available}.\n       \
         It is {deficit} bytes over.\n       \
         That first figure is the payload after compression, not the size of \
         the file:\n       \
         text shrinks a great deal, so a much larger file may still fit and a \
         smaller one may not.\n       \
         Use a container of higher resolution; stenoxide scan reports what each \
         one can carry."
    )
}

/// Runs the generative path.
///
/// The shape of [`run_embed`] minus the container: the payload is settled
/// before the passphrase is asked for, for the same reason, and there is no
/// image to validate because there is no image yet.
///
/// The requested size is settled first of all — before even the payload — so
/// that `--width 1999` is refused instantly rather than after a file has been
/// read and a passphrase typed. `clap` has already held each side to the 2000
/// floor; this is where the two are checked against the pixel ceiling together.
///
/// # Errors
///
/// Returns the message to print when the size is out of range, the payload file
/// cannot be read, the payload does not fit, or the container cannot be
/// generated or written.
fn run_generate(
    output: &Path,
    input: Option<&Path>,
    width: u32,
    height: u32,
) -> Result<(), String> {
    let dimensions =
        ContainerDimensions::new(width, height).map_err(|err| describe_generate_failure(&err))?;

    // A payload path that cannot be read is settled before the prompt, exactly
    // as in `run_embed`: a mistyped path is a wasted passphrase either way, and
    // the handle is kept so that the file checked and the file read are one.
    let source = match input {
        Some(path) => Some((payload::open_payload_file(path)?, path)),
        None => None,
    };

    let password = read_password()?;

    let plaintext = match source {
        Some((handle, path)) => payload::read_payload_file(handle, path)?,
        None => read_plaintext()?,
    };

    if plaintext.is_empty() {
        return Err("Error: the message is empty; nothing to hide.".to_string());
    }

    // Generation is the slowest thing this program does — two renders of twelve
    // million samples, the container gates over four megapixels, and a PNG of
    // incompressible content — and it says nothing while it works. The
    // indicator reveals nothing either: the cost is a function of a fixed
    // container size and of how many candidate textures the gates refuse.
    let activity = progress::Activity::start();

    let outcome = generate_container(plaintext, password, dimensions, output);

    activity.finish();

    let report = outcome.map_err(|err| describe_generate_failure(&err))?;

    print_generate_report(&report, output);
    Ok(())
}

/// Turns a failure of the generator into the sentence the user reads.
///
/// Two cases are rewritten, and the rest keep the sentence their own layer
/// wrote. The capacity refusal is rewritten on the same principle as
/// [`describe_embed_failure`]: the figure quoted is the payload *after*
/// compression, and a message that did not say so would read as a false claim
/// about the size of the user's file. It now also names a larger container that
/// would fit and the two flags that ask for one — the whole point of the size
/// being a parameter is undone if the error does not say it is.
///
/// The out-of-range refusal is rewritten only to prefix it with `Error:` and to
/// name the two flags, so that a user who reached for them and overshot is
/// pointed back at the range rather than left with a bare library sentence.
fn describe_generate_failure(error: &GenerateError) -> String {
    match error {
        GenerateError::PayloadTooLarge {
            payload,
            available,
            deficit,
            recommended_side,
        } => describe_payload_too_large(*payload, *available, *deficit, *recommended_side),
        GenerateError::DimensionsOutOfRange { .. } => format!(
            "Error: {error}.\n       \
             Set the size with --width and --height; both must be at least 2000 \
             pixels."
        ),
        other => format!("Error: {other}"),
    }
}

/// The capacity refusal, with a container size to reach for.
///
/// The advice is the reason the size became a parameter: rather than "your
/// payload is too large, full stop", it quotes a square that would hold this
/// payload and the flags that ask for it. The suggestion is square because one
/// figure describes a square; a user who wants a different shape now knows the
/// area to aim for and can spend it on whatever width and height they like.
fn describe_payload_too_large(
    payload: usize,
    available: usize,
    deficit: usize,
    recommended_side: Option<u32>,
) -> String {
    let advice = match recommended_side {
        Some(side) => format!(
            "A larger container would hold it: at about {side}x{side} it fits.\n       \
             Ask for one with  --width {side} --height {side}  (both must be at \
             least 2000).\n       \
             Any width and height whose area is at least that will do; the \
             suggestion is square only because one number is easier to quote."
        ),
        // No permitted container is large enough. This is the payload's size,
        // not a dial the user can turn, so it is said plainly rather than
        // dressed up as a resolution to reach for.
        None => "No permitted container is large enough for a payload this size; \
                 a generated container is capped at 128 megapixels.\n       \
                 Split the payload, or compress it further before hiding it."
            .to_owned(),
    };

    format!(
        "Error: the payload does not fit in the requested container.\n       \
         Compressed and encrypted it is {payload} bytes; the container admits \
         {available}.\n       \
         It is {deficit} bytes over.\n       \
         That first figure is the payload after compression, not the size of \
         the file.\n       \
         {advice}"
    )
}

/// Prints what the generation did, on stdout.
///
/// The last line is not decoration. Someone reaching this subcommand has no
/// usable photograph and is likely to read "undetectable" as covering more than
/// it does, so the one thing the mode does not do is said where it cannot be
/// missed.
fn print_generate_report(report: &GenerateReport, output: &Path) {
    let (width, height) = report.image_dimensions;

    println!("Container generated at {}", output.display());
    println!("  Image dimensions: {width}x{height}");
    println!(
        "  Payload carried:  {} of {} bytes, compressed",
        report.payload_bytes, report.capacity_bytes
    );
    println!(
        "\nThis container does not hide that it was generated. It hides which of \
         several\ngenerated containers carries a message. Prefer an unpublished \
         photograph of your\nown whenever you have one."
    );
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
///
/// A successful extraction whose binary payload is bound for a terminal returns a
/// distinct guidance message instead; see [`write_recovered_to_stdout`] for why
/// that is not the oracle the failure sentence avoids.
fn run_extract(input: &Path, payload_out: Option<&Path>, force: bool) -> Result<(), String> {
    drop(load_container(input)?);

    if let Some(path) = payload_out {
        if !force {
            refuse_existing_destination(path)?;
        }
    }

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

    // The buffer is still the `Zeroizing` the pipeline handed over, and it stays
    // one until the write is done: both destinations take a borrow of it, so no
    // copy of the plaintext is made that would outlive this function.
    match payload_out {
        Some(path) => write_recovered_file(path, plaintext.as_slice(), force),
        None => write_recovered_to_stdout(plaintext.as_slice()),
    }
}

/// Refuses a destination that already exists, before the password is asked for.
///
/// This check and the `create_new` inside [`payload::write_payload_file`] ask
/// the same question and are reported in opposite ways, which looks like an
/// inconsistency and is the opposite of one.
///
/// This one runs *before* anything has been attempted. At this point the
/// program does not yet know whether the password is right — it has not been
/// typed — so naming the file reveals nothing about the extraction. It is
/// ordinary, useful advice: the user mistyped a path or forgot `--force`, and
/// they are told so while it still costs them nothing.
///
/// The one inside the writer runs *after* a successful extraction, and by then
/// any message specific to it would be an admission that the password was
/// correct. So the file that appears in the gap between the two checks — a rare
/// race, but the rule takes no exceptions for rarity — is reported as
/// [`EXTRACTION_FAILED`], with everything else.
///
/// # Errors
///
/// Returns the message to print when `path` exists and is not a directory.
fn refuse_existing_destination(path: &Path) -> Result<(), String> {
    // A directory is not a collision: the payload is written *inside* it, under
    // a name that depends on content nobody has extracted yet.
    if path.is_dir() || !path.exists() {
        return Ok(());
    }

    Err(format!(
        "Error: {} already exists and would be overwritten.\n       \
         Choose another path, or pass --force to replace it.",
        path.display()
    ))
}

/// Writes the recovered payload to disk, and says nothing at all.
///
/// Success is silence and exit code zero: the user asked for a file, they got a
/// file, and a report printed alongside it would be one more thing to redirect.
///
/// # Errors
///
/// Returns [`EXTRACTION_FAILED`], whatever went wrong. A full disk, a directory
/// that stopped being writable and a destination that appeared a moment ago all
/// print the sentence a wrong password prints, because by this line the
/// extraction has already succeeded and any message specific to the write would
/// say so.
fn write_recovered_file(requested: &Path, plaintext: &[u8], force: bool) -> Result<(), String> {
    let destination = payload::resolve_output_path(requested, plaintext);

    payload::write_payload_file(&destination, plaintext, force)
        .map_err(|_| EXTRACTION_FAILED.to_string())
}

/// What extraction should do with a recovered payload bound for standard output.
#[derive(Debug, PartialEq, Eq)]
enum StdoutDelivery {
    /// Write the bytes to standard output unchanged.
    Raw,
    /// Refuse: the payload is binary and standard output is a terminal.
    RefuseBinary,
}

/// Decides how a recovered payload reaches standard output.
///
/// The bytes go out raw whenever standard output is **not** a terminal — a
/// redirection or a pipe takes binary and text alike, and that path must never
/// change, because it is the whole way a binary payload is captured
/// (`extract > payload.bin`). Only a payload that is *both* binary *and* bound
/// for an interactive terminal is refused: a terminal cannot render it. On
/// Windows the console rejects bytes that are not valid UTF-8 outright — the
/// write fails, which is the bug this function exists to turn into a clear
/// message — and on a Unix terminal the same bytes would reset colours, move the
/// cursor and ring the bell.
///
/// "Binary" is "not valid UTF-8", the same test [`payload::detect_extension`]
/// draws between a `txt` and a `bin` payload, so the two agree on what counts as
/// text.
fn stdout_delivery(stdout_is_terminal: bool, plaintext: &[u8]) -> StdoutDelivery {
    if stdout_is_terminal && std::str::from_utf8(plaintext).is_err() {
        StdoutDelivery::RefuseBinary
    } else {
        StdoutDelivery::Raw
    }
}

/// Writes a recovered payload to standard output, or explains why it will not.
///
/// Two destinations wear the same file descriptor and are not served the same
/// way, as in [`read_plaintext`]:
///
/// - **A pipe or a redirection.** `extract > payload.bin`, or a pipe into
///   another program. Every byte matters and the payload goes out raw whatever
///   it contains. A write that fails here — a broken pipe, a full disk — folds
///   into [`EXTRACTION_FAILED`] like every other post-success write error, so it
///   cannot become an admission that the password was right.
///
/// - **A terminal.** A person is watching. A text payload is shown; a binary one
///   is announced rather than dumped, with the two ways to capture it, for the
///   reasons in [`stdout_delivery`].
///
/// # Why the terminal notice is not the oracle the failure sentence avoids
///
/// The notice reveals that extraction succeeded — but a text payload shown on
/// the same terminal reveals exactly as much, and so does a file that appears
/// under `--payload-out` or a redirection. Success is inherent in producing the
/// plaintext and cannot be hidden from whoever runs the command. What the single
/// [`EXTRACTION_FAILED`] sentence hides is *which* of the three failures happened
/// and whether a post-success *write* failed on the redirected path; the notice
/// is a refusal decided *before* any write and touches neither.
///
/// # Errors
///
/// Returns [`EXTRACTION_FAILED`] when the raw write fails, and the binary-payload
/// guidance when standard output is a terminal the payload cannot be shown on.
fn write_recovered_to_stdout(plaintext: &[u8]) -> Result<(), String> {
    match stdout_delivery(io::stdout().is_terminal(), plaintext) {
        // The payload is whatever the sender put in, written as raw bytes rather
        // than through a string conversion that would corrupt anything not valid
        // UTF-8.
        StdoutDelivery::Raw => io::stdout()
            .write_all(plaintext)
            .and_then(|()| io::stdout().flush())
            .map_err(|_| EXTRACTION_FAILED.to_string()),
        StdoutDelivery::RefuseBinary => Err(format!(
            "The payload is {} bytes of binary data and will not be written to the terminal.\n       \
             Redirect it to a file (for example: > payload.bin) or pass --payload-out PATH.",
            plaintext.len()
        )),
    }
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

    /// A payload that does not fit is told the three numbers, and what they mean.
    ///
    /// The sizer refuses without naming any of them, deliberately, because the
    /// same type answers questions about containers the caller may not own. At
    /// this end of the program the container is the user's and the numbers are
    /// the entire answer — but only if the message also says that the figure is
    /// the *compressed* payload, because otherwise it reads as a claim about
    /// their file that is simply false.
    #[test]
    fn a_payload_that_does_not_fit_is_told_by_how_much() {
        let message = describe_embed_failure(&PipelineError::Sizer(SizerError::PayloadTooLarge {
            payload: 30_000,
            available: 22_016,
            deficit: 7_984,
        }));

        assert!(message.contains("30000"), "got: {message}");
        assert!(message.contains("22016"), "got: {message}");
        assert!(message.contains("7984"), "got: {message}");
        assert!(
            message.contains("after compression"),
            "the message must not read as a claim about the file's size: {message}"
        );
        assert!(message.contains("stenoxide scan"), "got: {message}");
    }

    /// Every other pipeline failure keeps the sentence its own layer wrote.
    #[test]
    fn other_failures_are_printed_as_the_layer_phrased_them() {
        let error = PipelineError::Validation(ValidationError::NotPng);
        let message = describe_embed_failure(&error);

        assert_eq!(message, format!("Error: {error}"));
    }

    /// An oversized generated payload is told the numbers and a size to reach.
    ///
    /// The generator's counterpart of the embed test above, plus the one thing
    /// this mode adds: the size is a parameter, so the message names a container
    /// that would fit and the two flags that ask for it. Quoting the numbers but
    /// not the way out would leave the user with a resolution they cannot act on.
    #[test]
    fn an_oversized_generated_payload_names_a_size_and_the_flags() {
        let message = describe_generate_failure(&GenerateError::PayloadTooLarge {
            payload: 1_782_778,
            available: 1_499_980,
            deficit: 282_798,
            recommended_side: Some(2_200),
        });

        assert!(message.contains("1782778"), "got: {message}");
        assert!(message.contains("1499980"), "got: {message}");
        assert!(message.contains("282798"), "got: {message}");
        assert!(
            message.contains("after compression"),
            "the message must not read as a claim about the file's size: {message}"
        );
        // The way out: a concrete size and the flags that request it.
        assert!(message.contains("2200x2200"), "got: {message}");
        assert!(message.contains("--width 2200"), "got: {message}");
        assert!(message.contains("--height 2200"), "got: {message}");
    }

    /// A payload no container can hold is told so plainly, with no size to chase.
    ///
    /// The `None` recommendation is not "try a bigger number"; it is the pixel
    /// ceiling, so the advice has to change from a resolution to a suggestion to
    /// split or compress the payload.
    #[test]
    fn a_payload_beyond_every_container_is_told_plainly() {
        let message = describe_generate_failure(&GenerateError::PayloadTooLarge {
            payload: 60_000_000,
            available: 1_499_980,
            deficit: 58_500_020,
            recommended_side: None,
        });

        assert!(message.contains("No permitted container"), "got: {message}");
        assert!(message.contains("128 megapixels"), "got: {message}");
        assert!(!message.contains("--width"), "no size to reach: {message}");
    }

    /// An out-of-range size is prefixed and pointed back at the two flags.
    #[test]
    fn an_out_of_range_size_names_the_flags() {
        let message = describe_generate_failure(&GenerateError::DimensionsOutOfRange {
            width: 1_500,
            height: 3_000,
            min_side: MIN_CONTAINER_SIDE,
            max_pixels: stenoxide_core::generate::MAX_CONTAINER_PIXELS,
        });

        assert!(message.starts_with("Error:"), "got: {message}");
        assert!(message.contains("1500x3000"), "got: {message}");
        assert!(message.contains("--width"), "got: {message}");
        assert!(message.contains("--height"), "got: {message}");
    }

    /// A destination that is not there yet, and a directory, are both fine.
    ///
    /// The directory case is the one worth pinning: the payload is written
    /// *inside* it under a name that depends on content nobody has extracted
    /// yet, so treating it as a collision would refuse a command that is
    /// perfectly well formed.
    #[test]
    fn only_an_existing_file_blocks_the_destination() {
        let directory = tempfile::TempDir::new().expect("temporary directory");

        assert!(refuse_existing_destination(directory.path()).is_ok());
        assert!(refuse_existing_destination(&directory.path().join("new.zip")).is_ok());

        let taken = directory.path().join("taken.zip");
        std::fs::write(&taken, b"already here").expect("fixture write");

        let message =
            refuse_existing_destination(&taken).expect_err("an existing file must be refused");
        assert!(message.contains("taken.zip"), "got: {message}");
        assert!(message.contains("--force"), "got: {message}");
    }

    /// A redirection or a pipe takes binary and text alike.
    ///
    /// The path a binary payload is captured through — `extract > payload.bin` —
    /// and the one that must never start sniffing content, because its consumer
    /// is a file or another program that asked for every byte.
    #[test]
    fn a_redirection_takes_binary_and_text_alike() {
        assert_eq!(stdout_delivery(false, b"plain text"), StdoutDelivery::Raw);
        assert_eq!(
            stdout_delivery(false, &[0xFF, 0xD8, 0xFF, 0xE0]),
            StdoutDelivery::Raw,
            "a redirection must take a JPEG's bytes unchanged"
        );
    }

    /// A terminal shows text and refuses binary.
    ///
    /// The bug this fixes: a JPEG begins `FF D8 FF`, which is invalid UTF-8, and
    /// a Windows console cannot be handed it — the write fails and the extraction
    /// looks like it failed when it did not.
    #[test]
    fn a_terminal_shows_text_but_refuses_binary() {
        assert_eq!(
            stdout_delivery(true, b"a readable message"),
            StdoutDelivery::Raw
        );
        assert_eq!(
            stdout_delivery(true, &[0xFF, 0xD8, 0xFF, 0xE0]),
            StdoutDelivery::RefuseBinary
        );
    }

    /// Accented text is still text on a terminal.
    ///
    /// The binary test is UTF-8 validity, not ASCII, so a message with accents
    /// is shown rather than refused.
    #[test]
    fn accented_text_is_shown_on_a_terminal() {
        assert_eq!(
            stdout_delivery(true, "café — ñandú".as_bytes()),
            StdoutDelivery::Raw
        );
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
