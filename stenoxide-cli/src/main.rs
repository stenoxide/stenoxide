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
//! and the message from standard input, which is a pipe and leaves no trace.
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

use std::io::{self, IsTerminal, Read, Write};
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

/// Reads the message to hide from standard input, until end of file.
///
/// # Errors
///
/// Returns a message describing why standard input could not be read.
fn read_plaintext() -> Result<Zeroizing<Vec<u8>>, String> {
    let mut plaintext = Zeroizing::new(Vec::new());

    io::stdin()
        .read_to_end(&mut plaintext)
        .map_err(|err| format!("Error: could not read the message from standard input: {err}"))?;

    Ok(plaintext)
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
