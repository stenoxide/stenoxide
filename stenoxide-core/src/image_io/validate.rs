//! Validation gates of the image type-state pipeline.
//!
//! The loader is a three-state automaton. Each state is a distinct private
//! type, and the only way to move between them is the transition function that
//! consumes the previous state by value:
//!
//! ```text
//! RawBytes --validate_magic_bytes--> VerifiedPngFile
//!          --decode_png-------------> DecodedPng
//!          --validate_no_jpeg_artifacts--> ImageBuffer
//! ```
//!
//! Because the intermediate states are private to this module and
//! [`crate::image_io::buffer::ImageBuffer::new`] is `pub(crate)`, no caller can
//! fabricate a validated image or skip a gate: the ordering is enforced by the
//! type system rather than by convention.

use std::fmt;
use std::io::Cursor;
use std::path::Path;

use image::{codecs::png::PngDecoder, ColorType, DynamicImage, ImageDecoder};

use crate::image_io::buffer::{ColorSpace, ImageBuffer};
use crate::image_io::jpeg_detect;

/// Minimum accepted side length, in pixels.
///
/// Smaller containers do not offer enough embeddable samples for the STC
/// encoder to stay below the `max_bpp` limit while carrying a useful payload.
const MIN_DIMENSION: u32 = 2000;

/// Number of leading bytes required before any format probing can be trusted.
const MIN_HEADER_LEN: usize = 12;

/// The eight-byte PNG signature.
const PNG_MAGIC: [u8; 8] = [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];

/// Every way the validation pipeline can reject a candidate container image.
#[derive(Debug)]
pub enum ValidationError {
    /// The file could not be read from disk.
    IoError(std::io::Error),
    /// The file is a JPEG. Lossy containers destroy embedded payloads.
    JpegDetected,
    /// The file is a WebP. Lossy containers destroy embedded payloads.
    WebpDetected,
    /// The file is not a PNG, and not a format we can name specifically.
    NotPng,
    /// The PNG decodes to a pixel layout the embedder cannot use.
    UnsupportedColorSpace {
        /// Debug representation of the layout reported by the decoder.
        found: String,
    },
    /// The image is smaller than the minimum accepted size.
    ImageTooSmall {
        /// Width reported by the decoder, in pixels.
        width: u32,
        /// Height reported by the decoder, in pixels.
        height: u32,
        /// Minimum accepted side length, in pixels.
        min: u32,
    },
    /// The PNG stream is malformed or truncated.
    DecodingError(String),
    /// The image is a lossless re-encoding of previously JPEG-compressed data.
    JpegArtifactsDetected {
        /// Fraction of sampled blocks showing JPEG blocking artifacts.
        ratio: f32,
    },
}

impl fmt::Display for ValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ValidationError::IoError(err) => write!(f, "failed to read the image file: {err}"),
            ValidationError::JpegDetected => {
                write!(
                    f,
                    "the file is a JPEG; only lossless PNG containers are supported"
                )
            }
            ValidationError::WebpDetected => {
                write!(
                    f,
                    "the file is a WebP; only lossless PNG containers are supported"
                )
            }
            ValidationError::NotPng => write!(f, "the file is not a PNG image"),
            ValidationError::UnsupportedColorSpace { found } => {
                write!(f, "unsupported pixel layout: {found}")
            }
            ValidationError::ImageTooSmall { width, height, min } => write!(
                f,
                "image is {width}x{height}; both sides must be at least {min} pixels"
            ),
            ValidationError::DecodingError(message) => {
                write!(f, "failed to decode the PNG stream: {message}")
            }
            ValidationError::JpegArtifactsDetected { ratio } => write!(
                f,
                "image shows JPEG compression artifacts in {:.1}% of the sampled blocks",
                ratio * 100.0
            ),
        }
    }
}

impl std::error::Error for ValidationError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            ValidationError::IoError(err) => Some(err),
            _ => None,
        }
    }
}

impl From<std::io::Error> for ValidationError {
    fn from(err: std::io::Error) -> Self {
        ValidationError::IoError(err)
    }
}

/// State 1 — bytes read from disk, of unknown format.
struct RawBytes(Vec<u8>);

/// State 2 — bytes whose magic number identifies them as a PNG file.
struct VerifiedPngFile(Vec<u8>);

/// State 3 — decoded samples with a layout the embedder understands.
struct DecodedPng {
    pixels: Vec<u8>,
    width: u32,
    height: u32,
    color_space: ColorSpace,
}

/// Transition 1 — identifies the container format from its magic number.
///
/// JPEG and WebP get dedicated errors because they are the two formats a user
/// is most likely to hand over by mistake, and a precise message saves them a
/// round of guessing.
fn validate_magic_bytes(raw: RawBytes) -> Result<VerifiedPngFile, ValidationError> {
    let bytes = raw.0;

    if bytes.len() < MIN_HEADER_LEN {
        return Err(ValidationError::NotPng);
    }

    if bytes[0..3] == [0xFF, 0xD8, 0xFF] {
        return Err(ValidationError::JpegDetected);
    }

    if &bytes[0..4] == b"RIFF" && &bytes[8..12] == b"WEBP" {
        return Err(ValidationError::WebpDetected);
    }

    if bytes[0..8] != PNG_MAGIC {
        return Err(ValidationError::NotPng);
    }

    Ok(VerifiedPngFile(bytes))
}

/// Transition 2 — decodes the PNG and normalises its samples.
///
/// Dimensions and colour type are read from the decoder header before the
/// pixel data is expanded, so an oversized image with an unusable layout is
/// rejected without paying for a full decode.
fn decode_png(file: VerifiedPngFile) -> Result<DecodedPng, ValidationError> {
    let decoder = PngDecoder::new(Cursor::new(file.0))
        .map_err(|err| ValidationError::DecodingError(err.to_string()))?;

    let (width, height) = decoder.dimensions();
    if width < MIN_DIMENSION || height < MIN_DIMENSION {
        return Err(ValidationError::ImageTooSmall {
            width,
            height,
            min: MIN_DIMENSION,
        });
    }

    let color_type = decoder.color_type();
    let color_space = match color_type {
        ColorType::Rgb8 => ColorSpace::Rgb8,
        ColorType::Rgb16 => ColorSpace::Rgb16,
        ColorType::Rgba8 => ColorSpace::Rgba8,
        ColorType::L8 => ColorSpace::Luma8,
        other => {
            return Err(ValidationError::UnsupportedColorSpace {
                found: format!("{other:?}"),
            });
        }
    };

    let decoded = DynamicImage::from_decoder(decoder)
        .map_err(|err| ValidationError::DecodingError(err.to_string()))?;

    // The decoder is asked for the exact layout its header advertised, so none
    // of these conversions resamples anything.
    let pixels = match color_space {
        ColorSpace::Rgb8 => decoded.into_rgb8().into_raw(),
        ColorSpace::Rgba8 => decoded.into_rgba8().into_raw(),
        ColorSpace::Luma8 => decoded.into_luma8().into_raw(),
        // `image` hands 16-bit samples over as native-endian `u16`. Storing
        // them as explicit little-endian pairs keeps the buffer layout, and
        // therefore every offset computed by the embedder, identical on
        // big-endian hosts.
        ColorSpace::Rgb16 => decoded
            .into_rgb16()
            .into_raw()
            .into_iter()
            .flat_map(u16::to_le_bytes)
            .collect(),
    };

    Ok(DecodedPng {
        pixels,
        width,
        height,
        color_space,
    })
}

/// Transition 3 — the final gate, rejecting laundered JPEG content.
///
/// A PNG that was produced by re-encoding a JPEG carries blocking artifacts
/// whose statistics are a well-known steganalysis lead, so such images must
/// never be used as containers.
fn validate_no_jpeg_artifacts(decoded: DecodedPng) -> Result<ImageBuffer, ValidationError> {
    let DecodedPng {
        pixels,
        width,
        height,
        color_space,
    } = decoded;

    match jpeg_detect::detect_jpeg_artifacts(&pixels, width, height, color_space) {
        Some(ratio) => Err(ValidationError::JpegArtifactsDetected { ratio }),
        None => Ok(ImageBuffer::new(pixels, width, height, color_space)),
    }
}

/// Loads a container image from disk and runs it through every validation gate.
///
/// This is the only public entry point of the type-state, and the only way for
/// any caller to obtain an [`ImageBuffer`].
///
/// # Errors
///
/// Returns a [`ValidationError`] if the file cannot be read, is not a PNG,
/// decodes to an unsupported pixel layout, is smaller than 2000x2000, or shows
/// traces of previous JPEG compression.
pub fn load_and_validate(path: &Path) -> Result<ImageBuffer, ValidationError> {
    let raw = RawBytes(std::fs::read(path)?);
    let verified = validate_magic_bytes(raw)?;
    let decoded = decode_png(verified)?;
    validate_no_jpeg_artifacts(decoded)
}
