//! Command line front-end of `stenoxide`.
//!
//! Placeholder entry point: it only reports the crate version. Subcommands are
//! implemented in PROMPT 8.

#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]

fn main() {
    println!("stenoxide {}", env!("CARGO_PKG_VERSION"));
}
