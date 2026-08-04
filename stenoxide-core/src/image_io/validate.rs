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
//! `ImageBuffer::new` is `pub(crate)`, no caller can
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
///
/// Readable inside the crate rather than private to this module: the generator
/// sizes its containers against the very same floor, so that a container it
/// draws is one this loader would accept back.
pub(crate) const MIN_DIMENSION: u32 = 2000;

/// Largest container the analysis will attempt, in pixels.
///
/// A ceiling on memory rather than on capacity. Analysing a container costs
/// about sixteen bytes per pixel at its peak — the decoded samples, three
/// `f32` planes of the cost model live at once, and the flood fill's visit
/// map — so the working set is a straight multiple of the pixel count and
/// nothing else. At 128 megapixels that peak is about two gibibytes, which is
/// what a desktop can be expected to spare.
///
/// Without this the failure mode is not an error but a machine that stops
/// responding: a 32767x32767 PNG is a legal file, and analysing one asks for
/// some sixteen gibibytes, which on any ordinary machine means paging to disk
/// for as long as the user is willing to wait. A refusal that arrives
/// immediately is strictly better than a correct answer that never does.
///
/// The limit is far above any camera: a 100-megapixel medium-format back
/// produces a quarter of it, and the largest consumer sensor a tenth.
///
/// Readable inside the crate rather than private to this module, for the reason
/// given on [`MIN_DIMENSION`]: the generator caps the containers it draws at the
/// same ceiling the loader refuses above.
pub(crate) const MAX_PIXELS: u64 = 128 * 1024 * 1024;

/// Number of leading bytes required before any format probing can be trusted.
const MIN_HEADER_LEN: usize = 12;

/// Bytes of a PNG file spanned by the signature and the whole `IHDR` chunk.
///
/// The format requires `IHDR` to be the first chunk, so a container's geometry
/// is always readable from this prefix and never depends on how the rest of the
/// file is laid out.
const PNG_HEADER_LEN: usize = 33;

/// Offset of the big-endian `u32` width inside a PNG file.
///
/// Eight bytes of signature, four of chunk length and four of chunk type.
const IHDR_WIDTH_OFFSET: usize = 16;

/// Payload length the `IHDR` chunk always declares.
///
/// Fixed by the format: width and height as `u32`, then one byte each of bit
/// depth, colour type, compression, filter and interlace.
const IHDR_CHUNK_LENGTH: u32 = 13;

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
    /// The image has more pixels than the analysis will attempt.
    ///
    /// Reported from the header, before anything is decoded; see
    /// [`MAX_PIXELS`] for why a limit exists at all.
    ImageTooLarge {
        /// Width reported by the header, in pixels.
        width: u32,
        /// Height reported by the header, in pixels.
        height: u32,
        /// Pixels the image contains.
        pixels: u64,
        /// Pixels the analysis will attempt.
        max: u64,
    },
    /// The PNG stream is malformed or truncated.
    DecodingError(String),
    /// The image is a lossless re-encoding of previously JPEG-compressed data.
    JpegArtifactsDetected {
        /// Blocking ratio measured over the sampled 8x8 blocks. Around `1.0`
        /// for a clean image; the higher it is, the stronger the JPEG grid. See
        /// [`crate::image_io::jpeg_detect::detect_jpeg_artifacts`].
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
            ValidationError::ImageTooLarge {
                width,
                height,
                pixels,
                max,
            } => write!(
                f,
                "image is {width}x{height}, which is {} megapixels; analysing it would need more \
                 memory than this limit allows, so it is refused rather than attempted. The \
                 maximum is {} megapixels",
                pixels / (1024 * 1024),
                max / (1024 * 1024)
            ),
            ValidationError::DecodingError(message) => {
                write!(f, "failed to decode the PNG stream: {message}")
            }
            ValidationError::JpegArtifactsDetected { ratio } => write!(
                f,
                "image shows an 8x8 JPEG block structure (blocking ratio {ratio:.2}, a clean \
                 image scores about 1.00); use a container that was never JPEG-compressed"
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

/// Geometry of a candidate container, read from its header alone.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ImageGeometry {
    /// Width, in pixels.
    pub width: u32,
    /// Height, in pixels.
    pub height: u32,
}

impl ImageGeometry {
    /// Pixels the image contains.
    ///
    /// Widened to `u64` before multiplying: two `u32` sides multiply to as much
    /// as `2^64`, and a product that wrapped would turn the largest images into
    /// the ones that look smallest.
    pub fn pixel_count(&self) -> u64 {
        u64::from(self.width) * u64::from(self.height)
    }
}

/// Applies the two size gates to a geometry.
///
/// Shared by the header probe and the decode path so that the two can never
/// disagree about which containers are the right size.
fn check_dimensions(geometry: ImageGeometry) -> Result<ImageGeometry, ValidationError> {
    let ImageGeometry { width, height } = geometry;

    if width < MIN_DIMENSION || height < MIN_DIMENSION {
        return Err(ValidationError::ImageTooSmall {
            width,
            height,
            min: MIN_DIMENSION,
        });
    }

    let pixels = geometry.pixel_count();
    if pixels > MAX_PIXELS {
        return Err(ValidationError::ImageTooLarge {
            width,
            height,
            pixels,
            max: MAX_PIXELS,
        });
    }

    Ok(geometry)
}

/// Reads the geometry of a container without decoding a single pixel.
///
/// Opens the file, reads its first [`PNG_HEADER_LEN`] bytes and applies the
/// format and size gates to them. Nothing else is read, so the cost does not
/// depend on how large the file is.
///
/// # What this is for
///
/// Deciding whether a file is worth decoding. [`load_and_validate`] reads the
/// whole file into memory before it can answer the same question, which is
/// wasted work for every image that was never the right size — and on a folder
/// of photographs most of them are not. It is also the only way to refuse an
/// image that is too large to analyse *before* allocating anything for it.
///
/// A geometry this accepts is not a usable container. It has passed two gates
/// of five; the pixels still have to be decoded, screened for a JPEG grid,
/// hashed and measured for texture.
///
/// # Errors
///
/// Returns [`ValidationError::IoError`] if the file cannot be read,
/// [`ValidationError::JpegDetected`], [`ValidationError::WebpDetected`] or
/// [`ValidationError::NotPng`] if it is not a PNG, and
/// [`ValidationError::ImageTooSmall`] or [`ValidationError::ImageTooLarge`] if
/// its geometry is outside the accepted range.
pub fn probe_geometry(path: &Path) -> Result<ImageGeometry, ValidationError> {
    use std::io::Read;

    let mut file = std::fs::File::open(path)?;
    let mut header = [0u8; PNG_HEADER_LEN];

    // A short read is not an error here: a file of twenty bytes is simply not a
    // PNG, and `validate_magic_bytes` is what says so.
    let mut filled = 0usize;
    loop {
        match file.read(&mut header[filled..]) {
            Ok(0) => break,
            Ok(read) => filled += read,
            Err(err) if err.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(err) => return Err(ValidationError::IoError(err)),
        }

        if filled == PNG_HEADER_LEN {
            break;
        }
    }

    // The format gate runs on the same bytes and the same rules as the full
    // path, so a file the probe calls a JPEG is one the loader would too.
    validate_magic_bytes(RawBytes(header[..filled].to_vec()))?;

    if filled < PNG_HEADER_LEN {
        return Err(ValidationError::NotPng);
    }

    // The chunk header is checked before the two integers behind it are read.
    // Without this the probe would take whatever bytes happen to sit at that
    // offset as a geometry, and a file with an honest signature over a corrupt
    // stream would be reported as an absurdly large image rather than as the
    // broken file it is. The decoder is the authority on a malformed stream, so
    // anything that does not look like `IHDR` is handed straight to it.
    let declares_ihdr = header.get(8..16).is_some_and(|chunk| {
        chunk[..4] == IHDR_CHUNK_LENGTH.to_be_bytes() && &chunk[4..] == b"IHDR"
    });
    if !declares_ihdr {
        return Err(ValidationError::DecodingError(
            "the file begins with a PNG signature but no IHDR chunk follows it".to_owned(),
        ));
    }

    let Some(fields) = header.get(IHDR_WIDTH_OFFSET..IHDR_WIDTH_OFFSET + 8) else {
        return Err(ValidationError::NotPng);
    };

    // Both are big-endian `u32`, as every integer in a PNG chunk is. The slice
    // is exactly eight bytes by the check above, so neither conversion fails.
    let (width_bytes, height_bytes) = fields.split_at(4);
    let width = u32::from_be_bytes(width_bytes.try_into().unwrap_or([0; 4]));
    let height = u32::from_be_bytes(height_bytes.try_into().unwrap_or([0; 4]));

    check_dimensions(ImageGeometry { width, height })
}

/// Transition 2 — decodes the PNG and normalises its samples.
///
/// Dimensions and colour type are read from the decoder header before the
/// pixel data is expanded, so an image of the wrong size or with an unusable
/// layout is rejected without paying for a full decode.
fn decode_png(file: VerifiedPngFile) -> Result<DecodedPng, ValidationError> {
    let decoder = PngDecoder::new(Cursor::new(file.0))
        .map_err(|err| ValidationError::DecodingError(err.to_string()))?;

    let (width, height) = decoder.dimensions();
    check_dimensions(ImageGeometry { width, height })?;

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
    // The header first, on its own. Reading the file to decide whether it was
    // worth reading is the wrong order twice over: it is wasted work for a file
    // that was never the right size, and for one that is far too large it means
    // allocating gigabytes for an image that is about to be refused for being
    // that large. Twenty-four bytes answer both questions.
    probe_geometry(path)?;

    let raw = RawBytes(std::fs::read(path)?);
    let verified = validate_magic_bytes(raw)?;
    let decoded = decode_png(verified)?;
    validate_no_jpeg_artifacts(decoded)
}

#[cfg(test)]
mod tests {
    // The crate-wide bans on panicking helpers reach into `cfg(test)` code as
    // well. A test that cannot panic cannot fail, so they are lifted here and
    // only here.
    #![allow(clippy::expect_used)]
    #![allow(clippy::panic)]

    use super::*;

    use image::{GrayAlphaImage, GrayImage, ImageFormat, Rgb, RgbImage, RgbaImage};
    use tempfile::NamedTempFile;

    use crate::image_io::buffer::CoverSource;

    /// Side length of the throwaway containers built below.
    ///
    /// Exactly the minimum the size gate accepts, so a layout test never fails
    /// for the wrong reason.
    const SIDE: u32 = MIN_DIMENSION;

    /// Twelve bytes, so that [`validate_magic_bytes`] gets past its length
    /// guard and has to decide on the signature itself.
    fn header(prefix: &[u8]) -> RawBytes {
        let mut bytes = prefix.to_vec();
        bytes.resize(MIN_HEADER_LEN.max(prefix.len()), 0);

        RawBytes(bytes)
    }

    /// Writes a flat PNG of the given layout and hands back the file holding it.
    ///
    /// Flat rather than textured on purpose: this module's gates are about
    /// format, geometry and block structure, none of which need content, and a
    /// uniform image compresses to a few kilobytes instead of the tens of
    /// megabytes a noise field of this size would cost. It scores zero on the
    /// block detector, so it passes the final gate as well.
    fn flat_png(color_space: ColorSpace) -> NamedTempFile {
        let file = NamedTempFile::new().expect("temporary png file");

        let saved = match color_space {
            ColorSpace::Rgb8 => RgbImage::from_pixel(SIDE, SIDE, Rgb([90, 110, 130]))
                .save_with_format(file.path(), ImageFormat::Png),
            ColorSpace::Rgba8 => {
                RgbaImage::from_pixel(SIDE, SIDE, image::Rgba([90, 110, 130, 255]))
                    .save_with_format(file.path(), ImageFormat::Png)
            }
            ColorSpace::Luma8 => GrayImage::from_pixel(SIDE, SIDE, image::Luma([110]))
                .save_with_format(file.path(), ImageFormat::Png),
            ColorSpace::Rgb16 => image::ImageBuffer::<Rgb<u16>, Vec<u16>>::from_pixel(
                SIDE,
                SIDE,
                Rgb([23_000, 28_000, 33_000]),
            )
            .save_with_format(file.path(), ImageFormat::Png),
        };
        saved.expect("a flat png must be writable");

        file
    }

    /// A header too short to identify anything is not a PNG.
    #[test]
    fn a_truncated_header_is_not_a_png() {
        let error = validate_magic_bytes(RawBytes(vec![0x89, 0x50, 0x4E]))
            .map(|_| ())
            .expect_err("three bytes cannot identify a format");

        assert!(matches!(error, ValidationError::NotPng), "got: {error:?}");
    }

    /// The three formats the first gate names, and the one it accepts.
    #[test]
    fn the_magic_number_decides_the_format() {
        let jpeg = validate_magic_bytes(header(&[0xFF, 0xD8, 0xFF]))
            .map(|_| ())
            .expect_err("a jpeg must be named as such");
        assert!(
            matches!(jpeg, ValidationError::JpegDetected),
            "got: {jpeg:?}"
        );

        let mut webp = b"RIFF".to_vec();
        webp.extend_from_slice(&[0, 0, 0, 0]);
        webp.extend_from_slice(b"WEBP");
        let webp = validate_magic_bytes(RawBytes(webp))
            .map(|_| ())
            .expect_err("a webp must be named as such");
        assert!(
            matches!(webp, ValidationError::WebpDetected),
            "got: {webp:?}"
        );

        let unknown = validate_magic_bytes(header(b"GIF89a"))
            .map(|_| ())
            .expect_err("an unknown format must be refused");
        assert!(
            matches!(unknown, ValidationError::NotPng),
            "got: {unknown:?}"
        );

        assert!(validate_magic_bytes(header(&PNG_MAGIC)).is_ok());
    }

    /// A file that is not there is an I/O failure, and the cause is preserved.
    #[test]
    fn a_missing_file_is_an_io_error() {
        let error = load_and_validate(Path::new("no-such-container-image.png"))
            .map(|_| ())
            .expect_err("a path that does not exist must be refused");

        assert!(
            matches!(error, ValidationError::IoError(_)),
            "got: {error:?}"
        );

        // The `source` chain is what lets a front-end print why the read
        // failed without this layer having to flatten it into a string.
        assert!(std::error::Error::source(&error).is_some());
    }

    /// The header probe reads a geometry without decoding anything.
    #[test]
    fn the_probe_reads_the_geometry_from_the_header() {
        let file = flat_png(ColorSpace::Rgb8);

        match probe_geometry(file.path()) {
            Ok(geometry) => {
                assert_eq!(geometry.width, SIDE);
                assert_eq!(geometry.height, SIDE);
                assert_eq!(geometry.pixel_count(), u64::from(SIDE) * u64::from(SIDE));
            }
            Err(error) => panic!("a flat container must probe: {error}"),
        }
    }

    /// The probe applies the same format gate as the full path.
    #[test]
    fn the_probe_refuses_what_the_loader_refuses() {
        let scratch = NamedTempFile::new().expect("temporary file");

        std::fs::write(
            scratch.path(),
            [0xFF, 0xD8, 0xFF, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        )
        .expect("a jpeg header must be writable");
        assert!(matches!(
            probe_geometry(scratch.path()),
            Err(ValidationError::JpegDetected)
        ));

        std::fs::write(scratch.path(), b"not an image at all").expect("writable");
        assert!(matches!(
            probe_geometry(scratch.path()),
            Err(ValidationError::NotPng)
        ));

        // A file that stops before the geometry does. The signature is honest
        // and there is nothing behind it, which is not a PNG either.
        std::fs::write(scratch.path(), PNG_MAGIC).expect("writable");
        assert!(matches!(
            probe_geometry(scratch.path()),
            Err(ValidationError::NotPng)
        ));

        assert!(matches!(
            probe_geometry(Path::new("no-such-container.png")),
            Err(ValidationError::IoError(_))
        ));
    }

    /// Both size gates, applied to a geometry rather than to a file.
    ///
    /// The upper one cannot be reached through a real file in a test: the
    /// smallest PNG that would trip it is 128 megapixels, which costs more to
    /// write than the whole suite costs to run. The gate is a pure function of
    /// two integers, so it is exercised as one.
    #[test]
    fn the_size_gates_bound_the_geometry_from_both_ends() {
        let accepted = ImageGeometry {
            width: MIN_DIMENSION,
            height: MIN_DIMENSION,
        };
        assert!(check_dimensions(accepted).is_ok());

        assert!(matches!(
            check_dimensions(ImageGeometry {
                width: MIN_DIMENSION - 1,
                height: MIN_DIMENSION,
            }),
            Err(ValidationError::ImageTooSmall { .. })
        ));

        // 32767x32767, the geometry that made this gate necessary: a legal PNG
        // whose analysis asks for some sixteen gibibytes.
        let enormous = ImageGeometry {
            width: 32_767,
            height: 32_767,
        };
        match check_dimensions(enormous) {
            Err(ValidationError::ImageTooLarge { pixels, max, .. }) => {
                assert_eq!(pixels, 32_767 * 32_767);
                assert_eq!(max, MAX_PIXELS);
                assert!(pixels > max);
            }
            other => panic!("a billion-pixel container must be refused, got: {other:?}"),
        }

        // The exact boundary, from both sides. The limit is a pixel count and
        // not a side length, so the geometry that lands on it exactly is a
        // rectangle rather than a square.
        let (width, height) = (16_384u32, 8_192u32);
        assert_eq!(u64::from(width) * u64::from(height), MAX_PIXELS);
        assert!(check_dimensions(ImageGeometry { width, height }).is_ok());
        assert!(matches!(
            check_dimensions(ImageGeometry {
                width,
                height: height + 1,
            }),
            Err(ValidationError::ImageTooLarge { .. })
        ));
    }

    /// The pixel count is computed wide enough not to wrap.
    ///
    /// Two `u32` sides multiply to as much as `2^64`, and a product taken in
    /// `u32` would turn the largest images into the ones that look smallest —
    /// which would let exactly the file this limit exists for walk straight
    /// through it.
    #[test]
    fn the_pixel_count_does_not_wrap() {
        let geometry = ImageGeometry {
            width: u32::MAX,
            height: u32::MAX,
        };

        assert_eq!(
            geometry.pixel_count(),
            u64::from(u32::MAX) * u64::from(u32::MAX)
        );
        assert!(geometry.pixel_count() > MAX_PIXELS);
        assert!(matches!(
            check_dimensions(geometry),
            Err(ValidationError::ImageTooLarge { .. })
        ));
    }

    /// An honest PNG signature over bytes that are not a PNG stream.
    ///
    /// The complement of the magic-byte gate: the first transition passes and
    /// the decoder is the one that has to refuse.
    #[test]
    fn a_corrupt_png_stream_is_a_decoding_error() {
        let mut bytes = PNG_MAGIC.to_vec();
        bytes.extend_from_slice(&[0x13; 64]);

        let file = NamedTempFile::new().expect("temporary png file");
        std::fs::write(file.path(), &bytes).expect("the corrupt file must be writable");

        let error = load_and_validate(file.path())
            .map(|_| ())
            .expect_err("a malformed png stream must be refused");

        assert!(
            matches!(error, ValidationError::DecodingError(_)),
            "got: {error:?}"
        );
    }

    /// The size gate names the offending dimensions.
    #[test]
    fn an_undersized_container_is_refused() {
        let file = NamedTempFile::new().expect("temporary png file");
        RgbImage::from_pixel(100, 100, Rgb([10, 20, 30]))
            .save_with_format(file.path(), ImageFormat::Png)
            .expect("a small png must be writable");

        let error = load_and_validate(file.path())
            .map(|_| ())
            .expect_err("a 100x100 container must be refused");

        assert!(
            matches!(
                error,
                ValidationError::ImageTooSmall {
                    width: 100,
                    height: 100,
                    min: MIN_DIMENSION,
                }
            ),
            "got: {error:?}"
        );
    }

    /// Grayscale with an alpha channel is a layout the embedder cannot use.
    #[test]
    fn an_unsupported_layout_is_refused_by_name() {
        let file = NamedTempFile::new().expect("temporary png file");
        GrayAlphaImage::from_pixel(SIDE, SIDE, image::LumaA([110, 255]))
            .save_with_format(file.path(), ImageFormat::Png)
            .expect("a grayscale-alpha png must be writable");

        let error = load_and_validate(file.path())
            .map(|_| ())
            .expect_err("grayscale with alpha must be refused");

        match error {
            ValidationError::UnsupportedColorSpace { found } => {
                assert!(found.contains("La8"), "the layout must be named: {found}");
            }
            other => panic!("expected an unsupported layout, got: {other:?}"),
        }
    }

    /// Each of the four accepted layouts decodes to the buffer length its own
    /// `bytes_per_pixel` announces.
    ///
    /// The contract every layer above relies on: [`CoverSource::pixels`] must
    /// hold exactly `pixel_count * bytes_per_pixel` bytes, and the 16-bit path
    /// is the one where that is not obvious, because the decoder hands over
    /// native `u16` samples that this module re-lays as byte pairs.
    #[test]
    fn every_supported_layout_decodes_to_its_own_stride() {
        for expected in [
            ColorSpace::Rgb8,
            ColorSpace::Rgba8,
            ColorSpace::Luma8,
            ColorSpace::Rgb16,
        ] {
            let file = flat_png(expected);
            let image = match load_and_validate(file.path()) {
                Ok(image) => image,
                Err(error) => panic!("a flat {expected:?} container must load: {error}"),
            };

            assert_eq!(image.color_space(), expected);
            assert_eq!(image.dimensions(), (SIDE, SIDE));
            assert_eq!(
                image.pixels().len(),
                image.pixel_count() * expected.bytes_per_pixel()
            );
        }
    }

    /// Every rejection says what is wrong in words a user can act on.
    #[test]
    fn every_rejection_explains_itself() {
        let messages = [
            ValidationError::IoError(std::io::Error::other("disk on fire")).to_string(),
            ValidationError::JpegDetected.to_string(),
            ValidationError::WebpDetected.to_string(),
            ValidationError::NotPng.to_string(),
            ValidationError::UnsupportedColorSpace {
                found: "Rgba16".to_owned(),
            }
            .to_string(),
            ValidationError::ImageTooSmall {
                width: 10,
                height: 20,
                min: MIN_DIMENSION,
            }
            .to_string(),
            ValidationError::ImageTooLarge {
                width: 32_767,
                height: 32_767,
                pixels: 32_767 * 32_767,
                max: MAX_PIXELS,
            }
            .to_string(),
            ValidationError::DecodingError("truncated".to_owned()).to_string(),
            ValidationError::JpegArtifactsDetected { ratio: 3.25 }.to_string(),
        ];

        for message in &messages {
            assert!(!message.is_empty());
        }

        assert!(messages[1].contains("JPEG"));
        assert!(messages[2].contains("WebP"));
        assert!(messages[4].contains("Rgba16"));
        assert!(messages[5].contains("10x20"));
        // Megapixels rather than a raw count: "1024 megapixels" is a size a
        // person can compare against their own camera, "1073676289" is not.
        assert!(messages[6].contains("32767x32767"));
        // 32767 squared is one pixel short of 1024 megapixels, and the figure
        // is truncated rather than rounded — a limit that reported itself as
        // larger than it is would be the wrong way to be imprecise.
        assert!(messages[6].contains("1023 megapixels"));
        assert!(messages[6].contains("128 megapixels"));
        assert!(messages[8].contains("3.25"));

        // Only the I/O variant has an underlying cause to chain to.
        assert!(std::error::Error::source(&ValidationError::NotPng).is_none());
    }

    /// The `From` shortcut the loader relies on to use the `?` operator.
    #[test]
    fn an_io_error_converts_into_a_validation_error() {
        let converted =
            ValidationError::from(std::io::Error::new(std::io::ErrorKind::NotFound, "gone"));

        assert!(matches!(converted, ValidationError::IoError(_)));
    }
}
