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

use clap::{Args, CommandFactory, Parser, Subcommand};
use clap_complete::aot::{generate, Shell};
use zeroize::Zeroizing;

use stenoxide_core::cost::hill::HillCostProvider;
use stenoxide_core::cost::CostProvider;
use stenoxide_core::generate::{
    generate_container, ContainerDimensions, GenerateError, GenerateReport, DEFAULT_CONTAINER_SIDE,
    MIN_CONTAINER_SIDE,
};
use stenoxide_core::image_io::buffer::ImageBuffer;
use stenoxide_core::image_io::phash::{compute_stable_phash, PHashError};
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

/// The line `embed` adds when it refuses the photograph it was given.
///
/// The same pointer `scan` prints when it accepts nothing, from the other side:
/// there, a user who looked is told that `generate` exists; here, a user who
/// picked one file straight away is told that there is a way to find out which
/// of the others would have worked. It is offered only by `embed`, because it
/// answers a question only that user is asking — see [`describe_embed_rejection`].
///
/// The leading newline and seven spaces are the continuation indent every
/// multi-line message in this file already uses, so the advice lines up under
/// the sentence it belongs to rather than under `Error:`.
const ANOTHER_CONTAINER_HINT: &str = "\n       \
     stenoxide scan <folder> reports which of your other photos can be used.";

/// What the user is told before they are expected to type a message.
///
/// Plain ASCII on purpose: this is printed before anything else knows whether
/// the console can render a nicer mark, and a guidance line that arrives as a
/// row of question marks would defeat its own point.
///
/// # Why it says a submitted line cannot be edited
///
/// Because the arrow keys look as though they should. They reach the console's
/// own line editor, which recalls what was typed at the *shell* — so a user
/// trying to correct the line above finds a command from their history where
/// their message was, and no way back to it. Saying so costs one line and is
/// cheaper than discovering it halfway through a message.
///
/// # Why there is no line editor here
///
/// Every candidate worth taking brings a history with it, and a history is a
/// place the secret message can end up written down, in memory or on disk. That
/// is the same surface the password and the message avoid by never being
/// arguments. The way to revise a message before hiding it is to write it in a
/// file, which is what the flag named below is for — `-p` in both subcommands
/// that read a typed message, where the long forms differ.
const TYPING_GUIDANCE: &str = "\
Message to hide. It may span as many lines as you need.
Finish with a line containing a single dot:  .
A line you have sent cannot be edited; to revise one first, put the message in
a file and pass it with -p.
";

/// The whole of what `stenoxide --help` prints.
///
/// `clap` replaces rather than extends: the moment `long_about` has content it
/// becomes the entire body of the long help, and the sentence `about` carries
/// would simply vanish from it. So that sentence opens this text — read from the
/// manifest, the same place `about` reads it, rather than copied where the two
/// could drift apart — and the examples follow. The short help is untouched and
/// still prints that one sentence alone.
///
/// What the examples add is the one thing the list of commands underneath
/// cannot: the order. A reader sees four verbs and no indication that `scan`
/// comes first and `extract` last.
///
/// `completions` and `man` are deliberately left out. They are installation
/// utilities rather than steps of the flow, they are already visible in the list
/// clap prints below, and naming them here would dilute the only thing this text
/// exists to say.
const CLI_LONG_ABOUT: &str = concat!(
    env!("CARGO_PKG_DESCRIPTION"),
    "\n\n",
    "Find a photograph that can hold a message, hide one in it, read it back:\n\n",
    "  stenoxide scan ./photos\n",
    "  stenoxide embed --input photo.png --output stego.png\n",
    "  stenoxide extract --input stego.png\n\n",
    "When none of the photographs can be used, stenoxide generate builds a\n",
    "container around the message instead."
);

/// Hide encrypted messages inside lossless images.
#[derive(Parser)]
#[command(name = "stenoxide", version, about, long_about = CLI_LONG_ABOUT)]
struct Cli {
    /// Operation to perform.
    #[command(subcommand)]
    command: Command,
}

/// The operations the front-end exposes.
///
/// # The short flags, and the collision they had to resolve
///
/// A letter means the same thing in every subcommand that has it. That rule is
/// worth more than covering every flag, because a short form is memorised once
/// and typed everywhere, and one that meant two things would be worse than none.
///
/// `--input` already means three things. In `embed` it is the container, in
/// `extract` it is the stego image, and in `generate` it is the file to hide.
/// Giving all three `-i` would have set that inconsistency in a single letter.
/// Renaming any of the long forms was not an option — they are the interface
/// this program already shipped — so the letters follow the *meaning*:
///
/// - `-i` — the image being read: `embed --input`, `extract --input`. Never
///   `generate`, which reads no image.
/// - `-o` — where the result of the operation goes: `embed --output`,
///   `generate --output`, `extract --payload-out`.
/// - `-p` — the file to hide: `embed --payload`, and `generate --input`, where
///   the letter does not match the long form but does match what the flag is
///   for, which is the thing being fixed.
/// - `-f` — `--force`, everywhere it exists.
///
/// `-h` is `--help` and is never taken. That rules out a short form for
/// `generate --height`, and `--width` goes without one too rather than leave a
/// pair of flags where one half is abbreviated and the other is not.
#[derive(Subcommand)]
enum Command {
    /// Report which images can be used as containers, and how much each can
    /// carry.
    Scan(ScanArgs),
    /// Hide a message, read from standard input, inside a PNG container.
    Embed {
        /// Container image: the photo the message is hidden inside. Must be a
        /// PNG of at least 2000x2000 pixels that has never been
        /// JPEG-compressed.
        #[arg(long, short = 'i', value_name = "PATH")]
        input: PathBuf,
        // Why there is no default, and why one will not be added. A name
        // derived from the container — cover.png becoming cover.stego.png —
        // writes the link between the two files into the filesystem, which is
        // the one relationship this program exists not to reveal. A random name
        // leaks nothing but leaves a file the user did not ask for, in a place
        // they did not choose and then have to go looking for. What the
        // requirement costs is one immediate retry against a clap error that
        // already prints the full usage, which is the cheapest of the three.
        /// Where to write the resulting stego image: the full path, file name
        /// included. Always written as PNG. There is no default, because a name
        /// derived from the container would record the link between the two on
        /// disk.
        #[arg(long, short = 'o', value_name = "PATH")]
        output: PathBuf,
        /// File to hide. Read from standard input when absent; when given,
        /// standard input is not read at all and any redirection is ignored.
        #[arg(long, short = 'p', value_name = "PATH")]
        payload: Option<PathBuf>,
        /// Overwrite the output file if it already exists.
        #[arg(long, short = 'f')]
        force: bool,
    },
    /// Build a container around a message, for when there is no usable photo.
    #[command(long_about = GENERATE_LONG_ABOUT)]
    Generate {
        /// Where to write the container: the full path, file name included.
        /// Always written as PNG.
        #[arg(long, short = 'o', value_name = "PATH")]
        output: PathBuf,
        /// File to hide. Read from standard input when absent; when given,
        /// standard input is not read at all and any redirection is ignored.
        ///
        /// Its short form is -p, the letter every subcommand uses for the file
        /// being hidden, rather than -i, which is the image being read.
        #[arg(long, short = 'p', value_name = "PATH")]
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
        /// Overwrite the output file if it already exists.
        #[arg(long, short = 'f')]
        force: bool,
    },
    /// Recover a hidden message from a stego image and write it to standard
    /// output.
    Extract {
        /// The stego image to read.
        #[arg(long, short = 'i', value_name = "PATH")]
        input: PathBuf,
        /// Where to write the recovered payload, the hidden file or message.
        /// Written to standard output when absent. A directory receives a file
        /// named after the type of the content; a path without an extension is
        /// given one.
        // Its short form is `-o` because that is the letter for where the
        // result goes; see the map on the enum. It is not spelled out in the
        // help the way `generate --input` is, because there the letter does not
        // match the long form and here it does.
        #[arg(long, short = 'o', value_name = "PATH")]
        payload_out: Option<PathBuf>,
        /// Overwrite the output file if it already exists.
        #[arg(long, short = 'f', requires = "payload_out")]
        force: bool,
    },
    /// Write a shell completion script to standard output.
    ///
    /// The script and nothing else, so that it can be sourced directly —
    /// `source <(stenoxide completions bash)` — or saved wherever the shell
    /// looks for its completions.
    Completions {
        /// Shell the script is written for.
        #[arg(value_name = "SHELL", value_enum)]
        shell: Shell,
    },
    /// Write the manual page to standard output.
    ///
    /// The roff source of `stenoxide.1`, for a packager to redirect into a
    /// file: `stenoxide man > stenoxide.1`. It is produced at run time rather
    /// than by a build script because a build script compiles as a separate
    /// crate and cannot see the command definition it would have to describe.
    ///
    /// # Why there is one page and not one per subcommand
    ///
    /// The page rendered is the root command, whose SUBCOMMANDS section lists
    /// every verb with its summary. Separate `stenoxide-embed.1` style pages
    /// are deliberately not produced, and this subcommand takes no argument
    /// asking for one: a single page is what `man stenoxide` finds, and it is
    /// the whole of what this tool needs to document. The absence is a
    /// decision, not an oversight.
    Man,
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
            force,
        } => run_embed(input, output, payload.as_deref(), *force),
        Command::Generate {
            output,
            input,
            width,
            height,
            force,
        } => run_generate(output, input.as_deref(), *width, *height, *force),
        Command::Extract {
            input,
            payload_out,
            force,
        } => run_extract(input, payload_out.as_deref(), *force),
        Command::Completions { shell } => run_completions(*shell),
        Command::Man => run_man(),
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

/// Loads a container for `embed`, which has one more thing to say than
/// [`load_container`].
///
/// # Errors
///
/// Returns the message to print, already phrased for a terminal; see
/// [`describe_embed_rejection`].
fn load_container_for_embed(path: &Path) -> Result<ImageBuffer, String> {
    load_and_validate(path).map_err(|error| describe_embed_rejection(path, &error))
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

/// The rejection as `embed` reports it: [`describe_rejection`], plus a way to
/// find a container that would work.
///
/// A layer above that function rather than a change to it, because the very
/// same text serves `extract` — [`load_container`] is called by both — and there
/// the advice would answer a question nobody asked. Whoever runs `extract` was
/// handed one particular image and is trying to recover what is in it; they are
/// not looking through a folder for a better photograph, and `scan` has nothing
/// to offer them.
///
/// Only the refusals that are about *this image* are extended. A file that
/// cannot be read, or whose PNG stream is malformed, is a broken file rather
/// than a wrong choice of photograph: that user needs their file back, not a
/// different one, and pointing them at `scan` would be changing the subject.
fn describe_embed_rejection(path: &Path, error: &ValidationError) -> String {
    let message = describe_rejection(path, error);

    match error {
        ValidationError::JpegDetected
        | ValidationError::WebpDetected
        | ValidationError::NotPng
        | ValidationError::ImageTooSmall { .. }
        | ValidationError::ImageTooLarge { .. }
        | ValidationError::UnsupportedColorSpace { .. }
        | ValidationError::JpegArtifactsDetected { .. } => {
            format!("{message}{ANOTHER_CONTAINER_HINT}")
        }
        ValidationError::IoError(_) | ValidationError::DecodingError(_) => message,
    }
}

/// Runs the embedding path.
///
/// # Errors
///
/// Returns the message to print when the container is unusable, the destination
/// cannot receive a file, the payload file cannot be read, the message does not
/// fit, or the stego image cannot be written. Most of the text comes from the
/// layer that refused, which already phrases its failures for a user; see
/// [`describe_embed_failure`] for the one case that is rewritten.
fn run_embed(
    input: &Path,
    output: &Path,
    payload: Option<&Path>,
    force: bool,
) -> Result<(), String> {
    // Before anything is asked of the user: a container that will be refused is
    // refused now, rather than after a passphrase has been typed for nothing.
    drop(load_container_for_embed(input)?);

    // And the destination, for the same reason and at the same cost. Everything
    // this checks was knowable before the first byte was read; leaving it to the
    // write means learning it after the passphrase, the message and a minute of
    // Argon2id and HILL, with nothing to show for any of it.
    refuse_unwritable_output(output, force)?;

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
///
/// Two other refusals are left in the words their own layer wrote and given the
/// pointer at `scan` that [`describe_embed_rejection`] adds, for the same
/// reason: a container too smooth to hide anything in, and one whose perceptual
/// hash will not survive the embedding, are both verdicts on this photograph and
/// on no other. They arrive here rather than at the validation gate because
/// neither can be decided without analysing every pixel. This function is
/// reached only from `run_embed`, so the pointer stays out of `extract` as it
/// does there.
fn describe_embed_failure(error: &PipelineError) -> String {
    match error {
        PipelineError::Sizer(SizerError::PayloadTooLarge {
            payload,
            available,
            deficit,
        }) => format!(
            "Error: the payload does not fit in this container.\n       \
             Compressed and encrypted it is {payload} bytes; the container \
             admits {available}.\n       \
             It is {deficit} bytes over.\n       \
             That first figure is the payload after compression, not the size \
             of the file:\n       \
             text shrinks a great deal, so a much larger file may still fit and \
             a smaller one may not.\n       \
             Use a container of higher resolution; stenoxide scan reports what \
             each one can carry."
        ),
        PipelineError::Cost(_)
        | PipelineError::PHash(PHashError::InsufficientStability { .. }) => {
            format!("Error: {error}.{ANOTHER_CONTAINER_HINT}")
        }
        other => format!("Error: {other}"),
    }
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
/// Returns the message to print when the size is out of range, the destination
/// cannot receive a file, the payload file cannot be read, the payload does not
/// fit, or the container cannot be generated or written.
fn run_generate(
    output: &Path,
    input: Option<&Path>,
    width: u32,
    height: u32,
    force: bool,
) -> Result<(), String> {
    let dimensions =
        ContainerDimensions::new(width, height).map_err(|err| describe_generate_failure(&err))?;

    // Settled before the prompt, exactly as in `run_embed`: a destination that
    // cannot receive a file is knowable now, and generation is the slowest thing
    // this program does to find it out at the end.
    refuse_unwritable_output(output, force)?;

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

/// Refuses a destination `embed` and `generate` cannot write their image to.
///
/// # Why this is not [`refuse_existing_destination`]
///
/// The two ask what looks like the same question of the same kind of path, and
/// they have to answer it differently, because the destinations are not the same
/// kind of thing.
///
/// `extract` writes a payload whose *name* it derives from the content, so a
/// directory is a perfectly ordinary destination there: the file is written
/// inside it. That function therefore has to let a directory through, and
/// teaching it to refuse one would break the case it exists to serve.
///
/// `embed` and `generate` write an image to a path the user named in full. A
/// directory is not a destination they can complete — no name is derived from
/// anything — so it is a mistake, and the only useful answer is to say so. The
/// two functions are kept apart rather than given a flag because a shared
/// implementation would hold a condition that reverses the verdict on the one
/// case that separates them, which is the shape that gets edited wrong later.
///
/// # Why the missing folder is not created
///
/// Naming a folder that is not there is as likely to be a typo as an
/// instruction, and creating directories nobody asked for is the same silent
/// write this check exists to remove. The folder is named and nothing is
/// touched.
///
/// # Errors
///
/// Returns the message to print when `path` is a directory, when the folder that
/// would contain it does not exist, or when it already exists and `force` was not
/// given. The first two are refused whatever `force` says: that flag answers
/// "replace what is there", and neither of them is a file to replace.
fn refuse_unwritable_output(path: &Path, force: bool) -> Result<(), String> {
    if path.is_dir() {
        return Err(format!(
            "Error: {} is a directory, and --output names the file to write.\n       \
             Give the whole path, file name included: --output {}",
            path.display(),
            path.join("stego.png").display()
        ));
    }

    // An empty parent is what a bare file name yields, and it means the working
    // directory, which exists by definition.
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() && !parent.is_dir() {
            return Err(format!(
                "Error: the folder {} does not exist.\n       \
                 Create it first, or choose a path inside a folder that is \
                 already there.",
                parent.display()
            ));
        }
    }

    if !force && path.exists() {
        return Err(format!(
            "Error: {} already exists and would be overwritten.\n       \
             Choose another path, or pass --force to replace it.",
            path.display()
        ));
    }

    Ok(())
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
        StdoutDelivery::RefuseBinary => Err(binary_payload_notice(plaintext)),
    }
}

/// The notice a binary payload bound for a terminal gets instead of its bytes.
///
/// It names the type, because the program already knows it:
/// [`payload::detect_extension`] is what puts a name on the file written under
/// `--payload-out`, and reading it here costs nothing and turns "binary data,
/// try `> payload.bin`" into an example the user can paste. Nothing new is
/// revealed by it — by this line the extraction has already succeeded and the
/// plaintext is in the caller's hands; see [`write_recovered_to_stdout`] for why
/// that is not the oracle the single failure sentence avoids.
///
/// Both ways of capturing the payload are kept, in the same order they were
/// offered in: naming the type is an improvement to the example, not a
/// replacement for the advice.
fn binary_payload_notice(plaintext: &[u8]) -> String {
    let extension = payload::detect_extension(plaintext);

    // `bin` is the table's way of saying it recognised nothing, so there is no
    // type to name and the sentence keeps the words it always used.
    let described = if extension == payload::BINARY_EXTENSION {
        "binary data".to_owned()
    } else {
        format!("{} data", extension.to_uppercase())
    };

    format!(
        "The payload is {} bytes of {described} and will not be written to the terminal.\n       \
         Redirect it to a file (for example: > payload.{extension}) or pass --payload-out PATH.",
        plaintext.len()
    )
}

/// Writes the completion script for `shell` to standard output.
///
/// # Errors
///
/// Returns the message to print when standard output cannot be written.
fn run_completions(shell: Shell) -> Result<(), String> {
    write_artifact(&completion_script(shell), "completion script")
}

/// The completion script for `shell`, as the bytes that make it up.
///
/// Rendered into memory rather than straight onto standard output for two
/// reasons. The generator writes through an interface that cannot report a
/// failure, so a closed pipe would end the process on its terms rather than on
/// this program's; and a buffer is something a test can read back, which a
/// console is not.
fn completion_script(shell: Shell) -> Vec<u8> {
    let mut command = Cli::command();
    let name = command.get_name().to_string();
    let mut script = Vec::new();

    generate(shell, &mut command, name, &mut script);

    script
}

/// Writes the manual page to standard output.
///
/// # Errors
///
/// Returns the message to print when the page cannot be rendered or standard
/// output cannot be written.
fn run_man() -> Result<(), String> {
    write_artifact(&manual_page()?, "manual page")
}

/// The roff source of `stenoxide.1`, as the bytes that make it up.
///
/// One page, for the root command; see the `man` subcommand for why there is no
/// page per subcommand.
///
/// # Errors
///
/// Returns the message to print when the renderer fails, which for a buffer in
/// memory it cannot — the case is carried rather than discarded so that no
/// failure of the layer below is swallowed here.
fn manual_page() -> Result<Vec<u8>, String> {
    let mut page = Vec::new();

    clap_mangen::Man::new(Cli::command())
        .render(&mut page)
        .map_err(|err| format!("Error: could not render the manual page: {err}"))?;

    Ok(page)
}

/// Writes a generated artifact to standard output, and nothing besides it.
///
/// No banner, no progress line, no blank line of courtesy. What is written here
/// is read by a shell being asked to source it or by a packager's redirection
/// into a `.1` file, and a single byte of this program's own would break the
/// first and corrupt the second. Only the failure speaks, and it speaks on
/// stderr like everything else addressed to a person.
///
/// # Errors
///
/// Returns the message to print when standard output cannot be written, naming
/// `what` was being written.
fn write_artifact(bytes: &[u8], what: &str) -> Result<(), String> {
    io::stdout()
        .write_all(bytes)
        .and_then(|()| io::stdout().flush())
        .map_err(|err| format!("Error: could not write the {what}: {err}"))
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

    use clap::ValueEnum;
    use stenoxide_core::cost::hill::CostError;

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

    /// A container refused for this image alone points at `scan`.
    ///
    /// Every rejection that says something about *this photograph* — its
    /// format, its size, its pixel layout, the JPEG grid in it — is a rejection
    /// the user answers by choosing a different one, and `scan` is how they find
    /// which of theirs would do. The reason the whole list is pinned rather than
    /// one case: the hint is added per variant, so a variant left out is a user
    /// who reaches the same dead end through a different door.
    #[test]
    fn a_rejected_photograph_is_pointed_at_scan() {
        let path = Path::new("photo.png");
        let rejections = [
            ValidationError::JpegDetected,
            ValidationError::WebpDetected,
            ValidationError::NotPng,
            ValidationError::ImageTooSmall {
                width: 800,
                height: 600,
                min: 2_000,
            },
            ValidationError::ImageTooLarge {
                width: 20_000,
                height: 20_000,
                pixels: 400_000_000,
                max: 134_217_728,
            },
            ValidationError::UnsupportedColorSpace {
                found: "Rgb32F".to_owned(),
            },
            ValidationError::JpegArtifactsDetected { ratio: 1.8 },
        ];

        for error in &rejections {
            let message = describe_embed_rejection(path, error);

            assert!(
                message.contains("stenoxide scan"),
                "{error:?} must point at scan, got: {message}"
            );
            // The advice is added to the existing explanation, never in place
            // of it: the user still has to be told what was wrong with the file.
            assert!(
                message.starts_with(&describe_rejection(path, error)),
                "the original explanation must survive, got: {message}"
            );
        }
    }

    /// A file that is broken is not told to go and find another one.
    ///
    /// The distinction the hint rests on: a missing file and a malformed PNG are
    /// problems with the file itself, and a user whose disk failed mid-copy is
    /// not choosing between photographs.
    #[test]
    fn a_broken_file_is_not_pointed_at_scan() {
        let path = Path::new("photo.png");
        let broken = [
            ValidationError::IoError(io::Error::new(io::ErrorKind::NotFound, "no such file")),
            ValidationError::DecodingError("truncated stream".to_owned()),
        ];

        for error in &broken {
            let message = describe_embed_rejection(path, error);

            assert_eq!(
                message,
                describe_rejection(path, error),
                "{error:?} must be reported exactly as it always was"
            );
        }
    }

    /// Extraction reports a rejected image exactly as it always did.
    ///
    /// The hint belongs to `embed` alone. Somebody running `extract` was given
    /// one image and wants what is inside it; telling them to scan a folder for
    /// a better photograph would answer a question they did not ask, which is
    /// why the advice is a layer above the shared description rather than in it.
    #[test]
    fn extraction_keeps_the_plain_rejection() {
        let path = Path::new("stego.png");
        let message = describe_rejection(path, &ValidationError::NotPng);

        assert!(
            !message.contains("stenoxide scan"),
            "the shared description must stay free of the embed hint, got: {message}"
        );
    }

    /// A container too smooth, or too unstable, to embed in points at `scan`.
    ///
    /// These two refusals arrive after the analysis rather than at the door,
    /// because neither can be decided without reading every pixel — but they say
    /// the same thing as the rejections above: this photograph will not do. The
    /// sentence the layer wrote is kept in full; only the way out is added.
    #[test]
    fn an_untextured_container_is_pointed_at_scan() {
        let smooth = PipelineError::Cost(CostError::ExcessiveSmoothRegions { ratio: 0.42 });
        let message = describe_embed_failure(&smooth);

        assert!(message.contains("too smooth"), "got: {message}");
        assert!(message.contains("stenoxide scan"), "got: {message}");

        let unstable = PipelineError::PHash(PHashError::InsufficientStability {
            unstable_bits: 3,
            threshold: 0.05,
        });
        let message = describe_embed_failure(&unstable);

        assert!(message.contains("perceptually unstable"), "got: {message}");
        assert!(message.contains("stenoxide scan"), "got: {message}");
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

    /// Every shell the generator supports produces a script.
    ///
    /// The list is walked rather than spelled out, so that a shell added by a
    /// future release of the generator is covered the day it appears.
    #[test]
    fn every_supported_shell_gets_a_script() {
        for shell in Shell::value_variants() {
            let script = completion_script(*shell);

            assert!(!script.is_empty(), "{shell} produced no completion script");
        }
    }

    /// The manual page carries the title macro every man page opens with.
    ///
    /// A cheap guard against the failure that would matter: anything printed to
    /// standard output that is not the page itself ends up inside the `.1` file
    /// a packager redirects, and a message would be as invisible there as it is
    /// obvious here. The macro is looked for rather than required at the very
    /// start of the file because the renderer emits the two-line apostrophe
    /// definition every roff page carries ahead of it.
    #[test]
    fn the_manual_page_is_roff() {
        let page = manual_page().expect("a page rendered into memory cannot fail");
        let page = String::from_utf8(page).expect("the page is UTF-8");

        assert!(page.contains(".TH stenoxide 1"), "no title macro in: {page}");
        assert!(page.contains(".SH NAME"), "no name section in: {page}");
    }

    /// Nothing precedes the artifact on standard output.
    ///
    /// The direct check of the rule these two subcommands exist under: the very
    /// first line is already the script or the page. A banner, or a blank line
    /// of courtesy, would break `source <(stenoxide completions bash)` and
    /// corrupt a redirected manual page — and would pass every other test here.
    #[test]
    fn the_first_line_is_already_the_artifact() {
        let script = completion_script(Shell::Bash);
        let script = String::from_utf8(script).expect("the script is UTF-8");
        let first = script.lines().next().unwrap_or_default();

        assert!(
            first.starts_with('#') || first.starts_with('_'),
            "a bash script opens with a comment or a function, got: {first:?}"
        );

        let page = manual_page().expect("a page rendered into memory cannot fail");
        let page = String::from_utf8(page).expect("the page is UTF-8");
        let first = page.lines().next().unwrap_or_default();

        assert!(
            first.starts_with('.'),
            "a roff page opens with a control line, got: {first:?}"
        );
    }

    /// The command definition still parses every argument it used to.
    ///
    /// Two subcommands were added beside the four that do the work; this pins
    /// that they were added and nothing was disturbed — the flags of `embed`
    /// and `extract` keep their names, and the definition itself stays
    /// internally consistent, which is what `debug_assert` on a `clap` command
    /// checks.
    #[test]
    fn the_existing_arguments_are_untouched() {
        Cli::command().debug_assert();

        let cli = Cli::try_parse_from([
            "stenoxide",
            "embed",
            "--input",
            "cover.png",
            "--output",
            "stego.png",
            "--payload",
            "secret.zip",
        ])
        .expect("the embed arguments must keep parsing");

        assert!(
            matches!(
                cli.command,
                Command::Embed { input, output, payload, force }
                    if input == Path::new("cover.png")
                        && output == Path::new("stego.png")
                        && payload.as_deref() == Some(Path::new("secret.zip"))
                        && !force
            ),
            "embed must still parse into the same three paths"
        );
    }

    /// Every short flag parses to exactly what its long form parses to.
    ///
    /// Written as whole command lines rather than as a table of letters,
    /// because what has to hold is that the two spellings are interchangeable —
    /// a short form attached to the wrong field would still be a valid flag and
    /// would still parse, and only the value it lands in tells them apart. The
    /// short line is built by substitution, so the two differ in nothing else.
    #[test]
    fn every_short_flag_means_what_its_long_form_means() {
        let cases: &[(&[&str], &[&str])] = &[
            (
                &[
                    "stenoxide",
                    "embed",
                    "--input",
                    "cover.png",
                    "--output",
                    "stego.png",
                    "--payload",
                    "secret.zip",
                    "--force",
                ],
                &[
                    "stenoxide", "embed", "-i", "cover.png", "-o", "stego.png", "-p", "secret.zip",
                    "-f",
                ],
            ),
            (
                &[
                    "stenoxide",
                    "extract",
                    "--input",
                    "stego.png",
                    "--payload-out",
                    "secret.zip",
                    "--force",
                ],
                &[
                    "stenoxide",
                    "extract",
                    "-i",
                    "stego.png",
                    "-o",
                    "secret.zip",
                    "-f",
                ],
            ),
            (
                &[
                    "stenoxide",
                    "generate",
                    "--output",
                    "container.png",
                    "--input",
                    "message.txt",
                    "--force",
                ],
                &[
                    "stenoxide",
                    "generate",
                    "-o",
                    "container.png",
                    "-p",
                    "message.txt",
                    "-f",
                ],
            ),
            (
                &["stenoxide", "scan", "./photos", "--all", "--recursive"],
                &["stenoxide", "scan", "./photos", "-a", "-r"],
            ),
        ];

        for (long, short) in cases {
            let spelled_out = Cli::try_parse_from(*long).map(|cli| format!("{:?}", Rendered(&cli)));
            let abbreviated = Cli::try_parse_from(*short).map(|cli| format!("{:?}", Rendered(&cli)));

            assert_eq!(
                spelled_out.as_deref().ok(),
                abbreviated.as_deref().ok(),
                "{short:?} must parse to what {long:?} parses to"
            );
            assert!(spelled_out.is_ok(), "{long:?} stopped parsing");
        }
    }

    /// Every field of a parsed command line, as text two parses can be compared
    /// on.
    ///
    /// `Command` carries paths and flags and derives nothing, and deriving
    /// `Debug` on it for the sake of one test would put a formatter on a type
    /// that holds the user's file names. Rendering it here keeps that where the
    /// test is.
    struct Rendered<'cli>(&'cli Cli);

    impl std::fmt::Debug for Rendered<'_> {
        fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match &self.0.command {
                Command::Scan(args) => write!(
                    formatter,
                    "scan {} all={} recursive={} json={}",
                    args.path, args.all, args.recursive, args.json
                ),
                Command::Embed {
                    input,
                    output,
                    payload,
                    force,
                } => write!(
                    formatter,
                    "embed {} {} {payload:?} force={force}",
                    input.display(),
                    output.display()
                ),
                Command::Generate {
                    output,
                    input,
                    width,
                    height,
                    force,
                } => write!(
                    formatter,
                    "generate {} {input:?} {width}x{height} force={force}",
                    output.display()
                ),
                Command::Extract {
                    input,
                    payload_out,
                    force,
                } => write!(
                    formatter,
                    "extract {} {payload_out:?} force={force}",
                    input.display()
                ),
                Command::Completions { shell } => write!(formatter, "completions {shell}"),
                Command::Man => write!(formatter, "man"),
            }
        }
    }

    /// `-h` is `--help` in every subcommand, and nothing else ever takes it.
    ///
    /// The one letter that cannot be reassigned: a user who types it expects the
    /// help, and `generate --height` is exactly the flag that would have been
    /// tempting to give it to.
    #[test]
    fn the_help_letter_is_never_reassigned() {
        for subcommand in ["scan", "embed", "extract", "generate"] {
            let outcome = Cli::try_parse_from(["stenoxide", subcommand, "-h"])
                .err()
                .map(|error| error.kind());

            assert_eq!(
                outcome,
                Some(clap::error::ErrorKind::DisplayHelp),
                "-h must print the help of {subcommand}"
            );
        }
    }

    /// A directory is refused as an output, and `--force` does not change that.
    ///
    /// The reported failure: `--output .\5-salida\` was accepted, the passphrase
    /// and the message were typed, a minute of Argon2id and HILL was spent, and
    /// the operating system refused the write at the end. Everything needed to
    /// say no was on disk before any of it started.
    #[test]
    fn a_directory_is_not_an_output_path() {
        let directory = tempfile::TempDir::new().expect("temporary directory");

        for force in [false, true] {
            let message = refuse_unwritable_output(directory.path(), force)
                .expect_err("a directory cannot receive the image");

            assert!(message.contains("is a directory"), "got: {message}");
            // The way out is the whole point: the user has to be told that the
            // flag takes a file name, and shown one.
            assert!(message.contains("--output"), "got: {message}");
            assert!(message.contains("stego.png"), "got: {message}");
        }
    }

    /// An existing file is refused, and `--force` is what replaces it.
    ///
    /// Without the check the write truncates it silently and reports success,
    /// which destroys the stego image that was there and the message it carried.
    #[test]
    fn an_existing_output_is_refused_unless_forced() {
        let directory = tempfile::TempDir::new().expect("temporary directory");
        let taken = directory.path().join("stego.png");
        std::fs::write(&taken, b"an earlier stego image").expect("fixture write");

        let message =
            refuse_unwritable_output(&taken, false).expect_err("an existing file must be refused");
        assert!(message.contains("stego.png"), "got: {message}");
        assert!(message.contains("already exists"), "got: {message}");
        assert!(message.contains("--force"), "got: {message}");

        assert!(
            refuse_unwritable_output(&taken, true).is_ok(),
            "--force is what replaces a file that is already there"
        );
    }

    /// A folder that is not there is named, and is not created.
    ///
    /// `--force` does not apply: there is no file to replace, and creating the
    /// folder would be exactly the write nobody asked for that this check exists
    /// to remove.
    #[test]
    fn a_missing_folder_is_named_and_left_alone() {
        let directory = tempfile::TempDir::new().expect("temporary directory");
        let missing = directory.path().join("nowhere");
        let destination = missing.join("stego.png");

        for force in [false, true] {
            let message = refuse_unwritable_output(&destination, force)
                .expect_err("a missing folder must be refused");

            assert!(message.contains("nowhere"), "got: {message}");
            assert!(message.contains("does not exist"), "got: {message}");
        }

        assert!(!missing.exists(), "the folder must not have been created");
    }

    /// A free path in a folder that exists is accepted, bare name included.
    ///
    /// The bare name is the case a naive parent check gets wrong: `stego.png`
    /// has an empty parent, which is the working directory rather than a folder
    /// that is missing.
    #[test]
    fn a_free_destination_is_accepted() {
        let directory = tempfile::TempDir::new().expect("temporary directory");

        assert!(refuse_unwritable_output(&directory.path().join("stego.png"), false).is_ok());
        assert!(refuse_unwritable_output(Path::new("stego.png"), false).is_ok());
    }

    /// `extract` keeps the destination rules it always had.
    ///
    /// The two checks look alike and disagree about a directory on purpose: a
    /// payload is written *inside* one, under a name derived from its content,
    /// so refusing it here would break the case that function exists for.
    #[test]
    fn extraction_still_accepts_a_directory_as_a_destination() {
        let directory = tempfile::TempDir::new().expect("temporary directory");

        assert!(refuse_existing_destination(directory.path()).is_ok());
        assert!(
            refuse_unwritable_output(directory.path(), false).is_err(),
            "the two must not have been collapsed into one"
        );
    }

    /// The long help opens with the short one and names the four verbs in order.
    ///
    /// Two failures this guards against, both invisible until someone runs the
    /// binary. Dropping the description would silently remove it from
    /// `--help` — `clap` replaces the short text with the long one rather than
    /// printing both — and rewording the examples until a verb disappears would
    /// leave the flow half-explained, which is the whole reason the text exists.
    #[test]
    fn the_long_help_opens_with_the_short_one() {
        assert!(
            CLI_LONG_ABOUT.starts_with(env!("CARGO_PKG_DESCRIPTION")),
            "the long help must open with the sentence -h prints, got: {CLI_LONG_ABOUT}"
        );

        for verb in ["scan", "embed", "extract", "generate"] {
            assert!(
                CLI_LONG_ABOUT.contains(&format!("stenoxide {verb}")),
                "the flow must still name {verb}, got: {CLI_LONG_ABOUT}"
            );
        }

        // The two installation utilities stay out: they are not steps of the
        // flow, and the list of commands clap prints below already has them.
        assert!(
            !CLI_LONG_ABOUT.contains("completions") && !CLI_LONG_ABOUT.contains("stenoxide man"),
            "the quickstart is about the four verbs only, got: {CLI_LONG_ABOUT}"
        );
    }

    /// The notice names the type it recognised, and offers it as the extension.
    ///
    /// The program already knew: the same table names the file written under
    /// `--payload-out`. Saying "binary data" and suggesting `payload.bin` for a
    /// ZIP was throwing away an answer it had in hand.
    #[test]
    fn the_binary_notice_names_the_type_it_recognised() {
        let mut archive = vec![0x50, 0x4B, 0x03, 0x04, 0x14, 0x00];
        archive.resize(267, 0x00);

        let notice = binary_payload_notice(&archive);

        assert!(notice.contains("267 bytes"), "got: {notice}");
        assert!(notice.contains("ZIP data"), "got: {notice}");
        assert!(notice.contains("> payload.zip"), "got: {notice}");
        // Both ways of capturing it survive naming the type.
        assert!(notice.contains("--payload-out"), "got: {notice}");
    }

    /// A type the table does not recognise keeps the words it always had.
    ///
    /// `bin` is not a type; it is the table saying it matched nothing, and a
    /// notice announcing "BIN data" would be inventing an answer.
    #[test]
    fn an_unrecognised_payload_is_still_called_binary_data() {
        let notice = binary_payload_notice(&[0x80, 0x91, 0xA2, 0xB3]);

        assert!(notice.contains("binary data"), "got: {notice}");
        assert!(notice.contains("> payload.bin"), "got: {notice}");
        assert!(!notice.contains("BIN data"), "got: {notice}");
    }

    /// The guidance says that a line already sent is gone.
    ///
    /// The arrow keys reach the console's own editor and recall the shell's
    /// history, so the correction a user reaches for silently replaces their
    /// message with a command. The way out named is the file, because a line
    /// editor here would bring a history the message could be written into.
    #[test]
    fn the_guidance_says_a_sent_line_cannot_be_taken_back() {
        assert!(
            TYPING_GUIDANCE.contains("cannot be edited"),
            "got: {TYPING_GUIDANCE:?}"
        );
        assert!(
            TYPING_GUIDANCE.contains("-p"),
            "the way out must be named: {TYPING_GUIDANCE:?}"
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
