//! The single-line text form the key files are written in.
//!
//! A key that cannot survive being pasted into a chat window is a key nobody
//! will publish, so both files are one line of printable ASCII: a label, a
//! colon, and the key material in Base64. No line wrapping, no block delimiters,
//! nothing a mail client or a messaging app can reflow into something that no
//! longer parses.
//!
//! # Why the label is not decoration
//!
//! The label carries a version. A file that does not say what it is cannot be
//! migrated: the day this crate changes how a key is represented, every
//! existing file has to be recognisable as the old form rather than guessed at
//! from its length. It also separates the two roles — a public key handed to
//! `extract` as an identity is refused by name instead of being decoded into
//! nonsense and reported as a broken file.
//!
//! # Why Base64 is written out here
//!
//! Hexadecimal would be a third longer for a 1568-byte key, and every Base64
//! crate is a dependency this project does not need for forty lines of table
//! lookup. The encoding is RFC 4648 with the standard alphabet and padding, so
//! anything else that reads these files reads a format it already knows.

use std::fmt;

/// The RFC 4648 standard alphabet, in value order.
const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// The RFC 4648 padding symbol.
const PAD: u8 = b'=';

/// Symbols in one encoded group.
const GROUP_SYMBOLS: usize = 4;

/// Bytes in one decoded group.
const GROUP_BYTES: usize = 3;

/// The character that separates the label from the body.
const SEPARATOR: char = ':';

/// Every way a key file can fail to be one.
#[derive(Debug, PartialEq, Eq)]
pub enum ArmorError {
    /// The line does not carry the label this reader was looking for.
    ///
    /// Holds what was found, so that a caller handed a public key where a
    /// private one belongs can say so rather than reporting a corrupt file.
    /// The label is not secret: it is a constant of the format.
    WrongLabel {
        /// The label the reader expected.
        expected: String,
        /// The label the file carries, or the empty string when it carries
        /// nothing recognisable as one.
        found: String,
    },
    /// The body is not valid Base64, or the line has no label at all.
    Malformed,
}

impl fmt::Display for ArmorError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ArmorError::WrongLabel { expected, found } if found.is_empty() => {
                write!(f, "this is not a {expected} file")
            }
            ArmorError::WrongLabel { expected, found } => {
                write!(f, "this is a {found} file, not a {expected} one")
            }
            ArmorError::Malformed => write!(f, "the key material is not valid base64"),
        }
    }
}

impl std::error::Error for ArmorError {}

/// Writes `bytes` as the labelled line a key file holds.
///
/// The trailing newline is part of the file rather than of the value: a text
/// file without one is a nuisance to every tool that reads it, and the reader
/// trims whitespace, so it never travels back into the decoded material.
pub(crate) fn encode_labelled(label: &str, bytes: &[u8]) -> String {
    format!("{label}{SEPARATOR}{}\n", encode(bytes))
}

/// Reads the material out of a labelled line, checking the label first.
///
/// Whitespace anywhere around the line is discarded, which is what makes a
/// pasted key survive the newline a chat window adds.
///
/// # Errors
///
/// Returns [`ArmorError::WrongLabel`] when the line carries a different label —
/// the case worth telling apart, because it is a file mix-up rather than
/// damage — and [`ArmorError::Malformed`] when there is no label or the body is
/// not Base64.
pub(crate) fn decode_labelled(label: &str, text: &str) -> Result<Vec<u8>, ArmorError> {
    let line = text.trim();

    let Some((found, body)) = line.split_once(SEPARATOR) else {
        return Err(ArmorError::WrongLabel {
            expected: label.to_owned(),
            found: String::new(),
        });
    };

    if found != label {
        return Err(ArmorError::WrongLabel {
            expected: label.to_owned(),
            found: found.to_owned(),
        });
    }

    decode(body)
}

/// Encodes `bytes` as RFC 4648 Base64, with padding.
fn encode(bytes: &[u8]) -> String {
    let mut encoded = String::with_capacity(bytes.len().div_ceil(GROUP_BYTES) * GROUP_SYMBOLS);

    for group in bytes.chunks(GROUP_BYTES) {
        // Absent bytes are packed as zero and the symbols that would carry them
        // are replaced by padding below, which is exactly what RFC 4648 asks
        // for on a short final group.
        let packed = group
            .iter()
            .enumerate()
            .fold(0u32, |packed, (slot, &byte)| {
                packed | (u32::from(byte) << (16 - 8 * slot))
            });

        for slot in 0..GROUP_SYMBOLS {
            let symbol = if slot <= group.len() {
                let index = ((packed >> (18 - 6 * slot)) & 0x3F) as usize;
                ALPHABET.get(index).copied().unwrap_or(PAD)
            } else {
                PAD
            };

            encoded.push(char::from(symbol));
        }
    }

    encoded
}

/// Decodes RFC 4648 Base64 with padding.
///
/// # Errors
///
/// Returns [`ArmorError::Malformed`] for an empty body, a length that is not a
/// multiple of four, a symbol outside the alphabet, or padding anywhere but at
/// the very end.
fn decode(text: &str) -> Result<Vec<u8>, ArmorError> {
    let body = text.trim().as_bytes();

    if body.is_empty() || body.len() % GROUP_SYMBOLS != 0 {
        return Err(ArmorError::Malformed);
    }

    let padding = body.iter().rev().take_while(|&&byte| byte == PAD).count();

    // Padding is only ever the last one or two symbols. Counting from the end
    // and comparing against the total is what rejects `AB=C`, which would
    // otherwise decode as though the `=` were a zero.
    if padding > 2 || body.iter().filter(|&&byte| byte == PAD).count() != padding {
        return Err(ArmorError::Malformed);
    }

    let mut decoded = Vec::with_capacity(body.len() / GROUP_SYMBOLS * GROUP_BYTES);

    for group in body.chunks(GROUP_SYMBOLS) {
        let mut packed = 0u32;

        for (slot, &symbol) in group.iter().enumerate() {
            let value = if symbol == PAD {
                0
            } else {
                value_of(symbol).ok_or(ArmorError::Malformed)?
            };

            packed |= u32::from(value) << (18 - 6 * slot);
        }

        decoded.push(((packed >> 16) & 0xFF) as u8);
        decoded.push(((packed >> 8) & 0xFF) as u8);
        decoded.push((packed & 0xFF) as u8);
    }

    // The bytes the padding stood in for were decoded as zeros; they are not
    // part of the material.
    decoded.truncate(decoded.len() - padding);

    Ok(decoded)
}

/// The six-bit value a Base64 symbol stands for, or `None` if it is not one.
fn value_of(symbol: u8) -> Option<u8> {
    match symbol {
        b'A'..=b'Z' => Some(symbol - b'A'),
        b'a'..=b'z' => Some(symbol - b'a' + 26),
        b'0'..=b'9' => Some(symbol - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    // The crate-wide bans on panicking helpers reach into `cfg(test)` code as
    // well. A test that cannot panic cannot fail, so they are lifted here and
    // only here.
    #![allow(clippy::expect_used)]
    #![allow(clippy::panic)]

    use super::*;

    /// The label the tests round-trip under.
    const LABEL: &str = "stenoxide-test-v1";

    /// The published vectors of RFC 4648, section 10.
    ///
    /// Pinned rather than merely round-tripped: an encoder that agrees with its
    /// own decoder and with nothing else would pass every property test here
    /// and produce files no other tool can read.
    #[test]
    fn encoding_matches_the_published_vectors() {
        let vectors = [
            ("", ""),
            ("f", "Zg=="),
            ("fo", "Zm8="),
            ("foo", "Zm9v"),
            ("foob", "Zm9vYg=="),
            ("fooba", "Zm9vYmE="),
            ("foobar", "Zm9vYmFy"),
        ];

        for (plain, expected) in vectors {
            assert_eq!(encode(plain.as_bytes()), expected, "encoding {plain:?}");

            if !plain.is_empty() {
                assert_eq!(
                    decode(expected).expect("a published vector must decode"),
                    plain.as_bytes(),
                    "decoding {expected:?}"
                );
            }
        }
    }

    /// Every byte value survives the round trip, at every alignment.
    #[test]
    fn every_byte_round_trips_at_every_alignment() {
        let all: Vec<u8> = (0..=255u8).collect();

        for length in 1..=all.len() {
            let slice = &all[..length];
            let decoded = decode(&encode(slice)).expect("our own encoding must decode");

            assert_eq!(decoded, slice, "at length {length}");
        }
    }

    /// The labelled form round-trips, newline and stray whitespace included.
    #[test]
    fn a_labelled_line_survives_being_pasted() {
        let material = [0x9Au8; 64];
        let line = encode_labelled(LABEL, &material);

        assert!(line.ends_with('\n'));
        assert!(line.starts_with(LABEL));

        for pasted in [line.clone(), format!("  {}  \r\n", line.trim())] {
            assert_eq!(
                decode_labelled(LABEL, &pasted).expect("a pasted key must decode"),
                material
            );
        }
    }

    /// A file carrying the other label is named, not called corrupt.
    #[test]
    fn the_wrong_kind_of_key_file_says_which_it_is() {
        let line = encode_labelled("stenoxide-other-v1", &[1u8; 8]);

        match decode_labelled(LABEL, &line) {
            Err(ArmorError::WrongLabel { expected, found }) => {
                assert_eq!(expected, LABEL);
                assert_eq!(found, "stenoxide-other-v1");
            }
            other => panic!("a mislabelled file must be reported as one: {other:?}"),
        }

        // A line with no separator at all has no label to name.
        match decode_labelled(LABEL, "not a key file") {
            Err(ArmorError::WrongLabel { found, .. }) => assert!(found.is_empty()),
            other => panic!("a line without a label must be refused: {other:?}"),
        }
    }

    /// Everything that is not Base64 is refused rather than decoded.
    #[test]
    fn malformed_bodies_are_refused() {
        for body in ["", "Zg=", "Zg===", "Z g=", "Zm9v!!!!", "AB=C", "====", "Z m9v"] {
            let line = format!("{LABEL}{SEPARATOR}{body}");

            assert_eq!(
                decode_labelled(LABEL, &line).map(|_| ()),
                Err(ArmorError::Malformed),
                "body {body:?} must be refused"
            );
        }
    }

    /// Both failures explain themselves.
    #[test]
    fn every_failure_explains_itself() {
        assert!(ArmorError::Malformed.to_string().contains("base64"));

        let mislabelled = ArmorError::WrongLabel {
            expected: "private key".to_owned(),
            found: "public key".to_owned(),
        };
        assert!(mislabelled.to_string().contains("public key"));
        assert!(mislabelled.to_string().contains("private key"));

        let unlabelled = ArmorError::WrongLabel {
            expected: "private key".to_owned(),
            found: String::new(),
        };
        assert!(unlabelled.to_string().contains("not a private key"));
    }
}
