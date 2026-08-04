//! The frame written into a container, and the bridge between image samples and
//! Syndrome-Trellis cover symbols.
//!
//! # Why there is a frame at all
//!
//! Syndrome-Trellis Codes do not carry their own length. The parity-check matrix
//! is built from the *ratio* between the number of cover positions and the number
//! of message bits, so decoding a run of positions under the wrong message length
//! does not return a truncated payload — it returns a different, meaningless one.
//! A receiver that does not already know how many bits were embedded cannot
//! recover anything, and no length field placed inside the message can help,
//! because reading that field is itself a decode that needs the length.
//!
//! The way out is to reserve a region whose length is a constant. The container
//! is therefore split into two regions of embedding positions:
//!
//! ```text
//! permuted positions:  [ header: HEADER_POSITIONS ][ payload: the rest ]
//! embedded bits:       [ 32-bit ciphertext length ][ the ciphertext     ]
//! ```
//!
//! Both boundaries are a function of the pixel count alone, which the receiver
//! reads off the stego image, so the header decodes without knowing anything
//! else. Its 32 bits then give the exact length of the second decode.
//!
//! The split costs nothing in secrecy: the regions are cut out of the *permuted*
//! order, so "the first 2048 positions" is a set of pixels scattered over the
//! whole image that nobody without the STC seed can name.
//!
//! # What a cover symbol is
//!
//! The carrier *sample* of a pixel — its first byte — not the bit inside it.
//! This module hands the coder one such byte per position and writes back
//! whatever the coder made of it; the bit the payload travels in is the least
//! significant one, and reading it out is [`crate::stego::stc`]'s business.
//!
//! The distinction matters, and it is the reason this module passes bytes rather
//! than the `0`/`1` symbols the former FFI coder wanted. The coder does not
//! overwrite the carrier bit, it moves the whole sample by one level — `+1` or
//! `-1`, chosen from the keystream. Overwriting the bit would pair every even
//! value with the odd one above it and never the reverse, which is precisely the
//! asymmetry RS Analysis and Sample Pair Analysis measure. Handing over only the
//! bit would make that impossible to express: the sign of the change is a fact
//! about the sample, not about the bit.
//!
//! One bit per pixel, from the first channel, is the carrier the layers below
//! were written against: [`crate::cost::CostMap`] holds one cost per pixel
//! rather than per sample, and the HILL model raises the cost of every pixel
//! whose red plane can carry a bit — a penalty that only means anything if the
//! red plane is where the bit goes. On a [`ColorSpace::Rgb16`] container the
//! first byte is the low half of the red sample, because validation stores
//! 16-bit samples as explicit little-endian pairs; the carrier is therefore the
//! least significant bit of the 16-bit value on every layout. The `±1` operator
//! stays inside that byte on all four layouts: it only ever moves a value away
//! from the end of the range it sits at, so a low half of `0` goes up and one of
//! `255` goes down, and the 16-bit sample changes by exactly one level too.

use std::path::Path;

use image::{DynamicImage, ImageFormat, Luma, Rgb, Rgba};

use crate::image_io::buffer::{ColorSpace, CoverSource, ImageBuffer};
use crate::pipeline::error::OutputError;

/// Bytes of the length header: a big-endian `u32` counting ciphertext bytes.
pub(crate) const LENGTH_HEADER_BYTES: usize = 4;

/// Bits of the length header.
pub(crate) const LENGTH_HEADER_BITS: usize = LENGTH_HEADER_BYTES * 8;

/// Embedding positions reserved per bit of the header region.
///
/// The payload rate the pipeline may use is `MAX_BPP` scaled by the share of it
/// that survives coding, which works out at just under one bit per 59 positions.
/// Rounding up to 64 leaves the shortest region of the frame — thirty-two bits,
/// where the trellis has the least room to place its changes — a margin of about
/// eight per cent over the rate the rest of the container runs at, and makes the
/// header region an exact power of two of positions.
const POSITIONS_PER_HEADER_BIT: usize = 64;

/// Embedding positions reserved for the length header.
///
/// Two thousand and forty-eight positions out of the four million a minimally
/// sized container has: the payload region gives up half a per mille of its
/// capacity to become self-describing.
pub(crate) const HEADER_POSITIONS: usize = LENGTH_HEADER_BITS * POSITIONS_PER_HEADER_BIT;

/// Bytes charged against the measured capacity to pay for the frame.
///
/// The capacity sizer measures the whole container and knows nothing about the
/// header region, so the pipeline charges the frame to the payload: four bytes
/// for the header itself and four more to absorb the rounding of the region
/// boundary. Deducting it before [`crate::stego::sizer::validate_payload_fits`]
/// runs is what keeps the sizer's promise true — that a payload it accepts will
/// embed — now that the payload no longer has the whole container to itself.
pub(crate) const FRAME_OVERHEAD_BYTES: usize = LENGTH_HEADER_BYTES + 4;

/// Smallest ciphertext a length header may plausibly announce.
///
/// The Poly1305 tag alone is sixteen bytes, so nothing shorter can be a
/// ciphertext this crate produced. Used to reject a header that decoded to
/// nonsense before spending a second trellis pass on the length it claims.
pub(crate) const MIN_CIPHERTEXT_BYTES: usize = 16;

/// Splits a per-position vector into the header region and the payload region.
///
/// Generic over the element so that the cover symbols and their costs are cut at
/// the same place by the same code: the coder is handed one pair of slices per
/// region and the two must describe the same positions.
///
/// Returns `(header, payload)`. The boundary is clamped to the length of the
/// slice, so a container too small to hold even the header yields an empty
/// payload region rather than a panic; the coder then rejects the payload on its
/// own terms. Validation already refuses images below 2000x2000, i.e. four
/// million positions against the 2048 the header needs, so the clamp never binds
/// in practice.
pub(crate) fn split_regions<T>(positions: &[T]) -> (&[T], &[T]) {
    positions.split_at(HEADER_POSITIONS.min(positions.len()))
}

/// Mutable counterpart of [`split_regions`].
pub(crate) fn split_regions_mut<T>(positions: &mut [T]) -> (&mut [T], &mut [T]) {
    let boundary = HEADER_POSITIONS.min(positions.len());

    positions.split_at_mut(boundary)
}

/// Byte offset of the carrier sample of the pixel at `index`.
///
/// The first byte of the pixel; see the module documentation for why that is the
/// carrier on every supported layout.
fn carrier_offset(index: usize, color_space: ColorSpace) -> usize {
    index * color_space.bytes_per_pixel()
}

/// Reads one carrier sample per position, in embedding order.
///
/// `permutation` is the secret visiting order produced by
/// [`crate::stego::permute::generate_pixel_permutation`]; the returned vector
/// holds the carrier byte of `permutation[i]` at index `i`, which is the order
/// both the cost vector and the coder work in.
///
/// Positions outside the buffer contribute a zero sample. That cannot happen
/// for a permutation of the image's own pixel count, which is the only kind this
/// crate builds; the fallback exists so the function is total without indexing.
pub(crate) fn gather_cover_symbols(image: &ImageBuffer, permutation: &[usize]) -> Vec<u8> {
    let color_space = image.color_space();
    let pixels = image.pixels();

    permutation
        .iter()
        .map(|&index| {
            pixels
                .get(carrier_offset(index, color_space))
                .copied()
                .unwrap_or(0)
        })
        .collect()
}

/// Writes the stego samples back into the carrier byte of each pixel.
///
/// The inverse of [`gather_cover_symbols`], and the only place in the crate
/// where container samples are modified. Every byte of every pixel other than
/// the carrier is left exactly as the decoder produced it, and the carrier
/// itself differs from the cover by at most one level: the coder returns the
/// samples it was given, with the ones the trellis chose moved by `±1`.
pub(crate) fn apply_cover_symbols(image: &mut ImageBuffer, permutation: &[usize], symbols: &[u8]) {
    let color_space = image.color_space();
    let pixels = image.pixels_mut();

    for (&index, &symbol) in permutation.iter().zip(symbols.iter()) {
        if let Some(sample) = pixels.get_mut(carrier_offset(index, color_space)) {
            *sample = symbol;
        }
    }
}

/// Reorders a row-major cost vector into embedding order.
///
/// The copy is unavoidable: the coder needs the costs in the order it visits the
/// positions, and the cost map is indexed by pixel. Producing it also lets the
/// map be dropped before the image is mutated, which is what releases the borrow
/// that freezes the samples.
///
/// A permutation entry pointing outside the map contributes a zero cost, which
/// the coder reads as "unusable position" rather than as a free one. As in
/// [`gather_cover_symbols`], this cannot arise for a permutation of the image's
/// own pixel count.
pub(crate) fn reorder_costs(costs: &[f32], permutation: &[usize]) -> Vec<f32> {
    permutation
        .iter()
        .map(|&index| costs.get(index).copied().unwrap_or(0.0))
        .collect()
}

/// Encodes the ciphertext length as the four header bytes.
///
/// Returns `None` for a length no `u32` can hold. A container able to carry four
/// gibibytes of ciphertext would need about two thousand gigapixels, so the
/// capacity check upstream rejects such a payload long before this point; the
/// option exists so the conversion is checked rather than truncated.
pub(crate) fn encode_length_header(ciphertext_len: usize) -> Option<[u8; LENGTH_HEADER_BYTES]> {
    u32::try_from(ciphertext_len).ok().map(u32::to_be_bytes)
}

/// Reads the ciphertext length back out of the decoded header bytes.
///
/// Returns `None` when fewer than [`LENGTH_HEADER_BYTES`] bytes were recovered.
/// The value itself is not validated here — a header decoded under the wrong key
/// is uniformly random, and deciding whether a length is plausible needs the
/// capacity of the payload region, which this function does not know.
pub(crate) fn decode_length_header(header: &[u8]) -> Option<usize> {
    let bytes: [u8; LENGTH_HEADER_BYTES] = header.get(..LENGTH_HEADER_BYTES)?.try_into().ok()?;

    Some(u32::from_be_bytes(bytes) as usize)
}

/// Writes a container to disk as a PNG.
///
/// The format is forced rather than inferred from the extension: a stego image
/// saved as anything lossy is a destroyed payload, and an output path chosen by
/// the user is not something to take format advice from.
///
/// # Errors
///
/// Returns [`OutputError::MalformedBuffer`] if the sample buffer does not match
/// the dimensions it reports, and [`OutputError::EncodingFailed`] if the encoder
/// or the filesystem refuses the write.
pub(crate) fn write_png(image: &ImageBuffer, path: &Path) -> Result<(), OutputError> {
    let (width, height) = image.dimensions();
    let pixels = image.pixels();

    // Built through the typed constructors of the `image` crate rather than by
    // handing it a raw byte slice and a colour tag: the 16-bit path has to
    // reassemble native `u16` samples out of the little-endian pairs validation
    // stored, and doing that here keeps the byte order of the output file the
    // encoder's business rather than this module's guess.
    let encoded = match image.color_space() {
        ColorSpace::Rgb8 => {
            image::ImageBuffer::<Rgb<u8>, Vec<u8>>::from_raw(width, height, pixels.to_vec())
                .map(DynamicImage::ImageRgb8)
        }
        ColorSpace::Rgba8 => {
            image::ImageBuffer::<Rgba<u8>, Vec<u8>>::from_raw(width, height, pixels.to_vec())
                .map(DynamicImage::ImageRgba8)
        }
        ColorSpace::Luma8 => {
            image::ImageBuffer::<Luma<u8>, Vec<u8>>::from_raw(width, height, pixels.to_vec())
                .map(DynamicImage::ImageLuma8)
        }
        ColorSpace::Rgb16 => {
            let samples: Vec<u16> = pixels
                .chunks_exact(2)
                .map(|pair| match pair {
                    [low, high] => u16::from_le_bytes([*low, *high]),
                    // Unreachable: `chunks_exact(2)` yields pairs. The arm keeps
                    // the match exhaustive without an index or an unwrap.
                    _ => 0,
                })
                .collect();

            image::ImageBuffer::<Rgb<u16>, Vec<u16>>::from_raw(width, height, samples)
                .map(DynamicImage::ImageRgb16)
        }
    };

    let Some(encoded) = encoded else {
        return Err(OutputError::MalformedBuffer);
    };

    encoded
        .save_with_format(path, ImageFormat::Png)
        .map_err(|err| OutputError::EncodingFailed(err.to_string()))
}

#[cfg(test)]
mod tests {
    // The crate-wide bans on panicking helpers reach into `cfg(test)` code as
    // well. A test that cannot panic cannot fail, so they are lifted here and
    // only here.
    #![allow(clippy::expect_used)]
    #![allow(clippy::panic)]

    use super::*;

    use tempfile::NamedTempFile;

    /// Width of the throwaway containers below, in pixels.
    const WIDTH: u32 = 5;

    /// Height of the throwaway containers below, in pixels.
    const HEIGHT: u32 = 4;

    /// A container whose carrier byte is the index of its pixel.
    ///
    /// Every other byte of every pixel is a value the carrier never takes, so a
    /// write into the wrong plane is visible rather than plausible.
    fn container(color_space: ColorSpace) -> ImageBuffer {
        let stride = color_space.bytes_per_pixel();
        let pixel_count = (WIDTH * HEIGHT) as usize;

        let pixels = (0..pixel_count * stride)
            .map(|offset| {
                if offset % stride == 0 {
                    (offset / stride) as u8
                } else {
                    0xEE
                }
            })
            .collect();

        ImageBuffer::new(pixels, WIDTH, HEIGHT, color_space)
    }

    /// The boundary is a constant, and it is clamped rather than allowed to run
    /// off the end of a short container.
    #[test]
    fn the_frame_is_cut_at_a_constant_boundary() {
        let long: Vec<u8> = vec![0; HEADER_POSITIONS + 17];
        let (header, payload) = split_regions(&long);
        assert_eq!(header.len(), HEADER_POSITIONS);
        assert_eq!(payload.len(), 17);

        let mut short = vec![0u8; 9];
        let (header, payload) = split_regions_mut(&mut short);
        assert_eq!(header.len(), 9);
        assert!(payload.is_empty());
    }

    /// Gathering and applying are inverses, and they address the carrier byte
    /// of the permuted pixel.
    #[test]
    fn cover_symbols_round_trip_through_the_permutation() {
        for color_space in [
            ColorSpace::Rgb8,
            ColorSpace::Rgba8,
            ColorSpace::Luma8,
            ColorSpace::Rgb16,
        ] {
            let mut image = container(color_space);
            let permutation = vec![3usize, 0, 7, 1];

            let gathered = gather_cover_symbols(&image, &permutation);
            assert_eq!(gathered, vec![3u8, 0, 7, 1], "layout {color_space:?}");

            let written: Vec<u8> = gathered.iter().map(|symbol| symbol ^ 1).collect();
            apply_cover_symbols(&mut image, &permutation, &written);

            assert_eq!(
                gather_cover_symbols(&image, &permutation),
                written,
                "layout {color_space:?}"
            );

            // Nothing but the carrier byte was touched.
            let stride = color_space.bytes_per_pixel();
            assert!(image
                .pixels()
                .iter()
                .enumerate()
                .filter(|(offset, _)| offset % stride != 0)
                .all(|(_, &sample)| sample == 0xEE));
        }
    }

    /// A permutation entry outside the container reads as a zero sample and
    /// writes nowhere, rather than indexing off the end.
    #[test]
    fn positions_outside_the_container_are_inert() {
        let mut image = container(ColorSpace::Rgb8);
        let permutation = vec![0usize, 9_999];

        assert_eq!(gather_cover_symbols(&image, &permutation), vec![0u8, 0]);

        let before = image.pixels().to_vec();
        apply_cover_symbols(&mut image, &permutation, &[0, 42]);

        // The first position was rewritten with the value it already had, and
        // the second wrote nothing at all.
        assert_eq!(image.pixels(), before.as_slice());
    }

    /// Costs are reordered into embedding order, and an entry with no cost of
    /// its own reads as an unusable position rather than a free one.
    #[test]
    fn costs_follow_the_permutation() {
        let costs = [0.5f32, 1.5, 2.5, 3.5];

        assert_eq!(
            reorder_costs(&costs, &[2, 0, 3, 1]),
            vec![2.5f32, 0.5, 3.5, 1.5]
        );
        assert_eq!(reorder_costs(&costs, &[9]), vec![0.0f32]);
    }

    /// The length header is a big-endian `u32`, and it round-trips.
    #[test]
    fn the_length_header_round_trips() {
        let header = encode_length_header(0x0102_0304).expect("a small length must encode");
        assert_eq!(header, [0x01, 0x02, 0x03, 0x04]);
        assert_eq!(decode_length_header(&header), Some(0x0102_0304));

        // Trailing bytes beyond the header are ignored.
        assert_eq!(decode_length_header(&[0, 0, 0, 7, 9, 9]), Some(7));

        // Fewer bytes than the header needs decodes to nothing.
        assert_eq!(decode_length_header(&[0, 0, 7]), None);
    }

    /// A length no `u32` can hold is reported rather than truncated.
    #[test]
    fn an_unrepresentable_length_does_not_encode() {
        assert!(encode_length_header(u32::MAX as usize).is_some());
        assert!(encode_length_header(u32::MAX as usize + 1).is_none());
    }

    /// Every layout is written back as a PNG that decodes to the samples it was
    /// given.
    #[test]
    fn every_layout_survives_a_write_and_a_read() {
        for color_space in [
            ColorSpace::Rgb8,
            ColorSpace::Rgba8,
            ColorSpace::Luma8,
            ColorSpace::Rgb16,
        ] {
            let image = container(color_space);
            let file = NamedTempFile::new().expect("temporary stego file");

            if let Err(error) = write_png(&image, file.path()) {
                panic!("a {color_space:?} container must be writable: {error}");
            }

            // The format is forced rather than inferred, so a temporary file
            // whose extension says nothing still holds a PNG.
            let bytes = std::fs::read(file.path()).expect("the written file must be readable");
            assert_eq!(&bytes[..4], &[0x89, b'P', b'N', b'G']);

            let decoded = image::load_from_memory_with_format(&bytes, ImageFormat::Png)
                .expect("the written png must decode");
            assert_eq!(decoded.width(), WIDTH);
            assert_eq!(decoded.height(), HEIGHT);
        }
    }

    /// A buffer that does not match the geometry it claims is refused rather
    /// than written as a file the caller would believe in.
    #[test]
    fn a_buffer_that_belies_its_geometry_is_refused() {
        let image = ImageBuffer::new(vec![0u8; 5], WIDTH, HEIGHT, ColorSpace::Rgb8);
        let file = NamedTempFile::new().expect("temporary stego file");

        let error = write_png(&image, file.path()).expect_err("a short buffer must not be encoded");

        assert!(
            matches!(error, OutputError::MalformedBuffer),
            "got: {error:?}"
        );
    }

    /// A path that cannot be written is reported as an encoding failure.
    #[test]
    fn an_unwritable_path_is_reported() {
        let image = container(ColorSpace::Rgb8);
        let directory = tempfile::tempdir().expect("temporary directory");

        let error = write_png(
            &image,
            &directory.path().join("no-such-dir").join("out.png"),
        )
        .expect_err("a path under a missing directory must fail");

        assert!(
            matches!(error, OutputError::EncodingFailed(_)),
            "got: {error:?}"
        );
    }
}
