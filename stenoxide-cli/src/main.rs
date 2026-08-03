//! Command line front-end of `stenoxide`.
//!
//! Two subcommands, both of which read the password interactively:
//!
//! ```text
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

use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use zeroize::Zeroizing;

use stenoxide_core::pipeline::{EmbedPipeline, EmbedReport};

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

fn main() -> ExitCode {
    let cli = Cli::parse();

    let outcome = match &cli.command {
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

/// Runs the embedding path.
///
/// # Errors
///
/// Returns the message to print when the container is unusable, the message
/// does not fit, or the stego image cannot be written. The text comes from the
/// layer that refused, which already phrases its failures for a user.
fn run_embed(input: &Path, output: &Path) -> Result<(), String> {
    let password = read_password()?;
    let plaintext = read_plaintext()?;

    if plaintext.is_empty() {
        return Err("Error: the message is empty; nothing to hide.".to_string());
    }

    let report = EmbedPipeline::default_secure()
        .embed(input, plaintext, password, output)
        .map_err(|err| format!("Error: {err}"))?;

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
fn run_extract(input: &Path) -> Result<(), String> {
    let password = read_password()?;

    let (plaintext, _report) = EmbedPipeline::default_secure()
        .extract(input, password)
        .map_err(|_| EXTRACTION_FAILED.to_string())?;

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
