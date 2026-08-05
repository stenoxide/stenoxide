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

use std::borrow::Cow;
use std::fmt;
use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::Path;

use png::{BitDepth, ColorType, Compression, Encoder, Filter};

use crate::image_io::buffer::{ColorSpace, CoverSource, ImageBuffer};
use crate::image_io::envelope;
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

/// The colour type and bit depth a layout is written as.
fn png_layout(color_space: ColorSpace) -> (ColorType, BitDepth) {
    match color_space {
        ColorSpace::Rgb8 => (ColorType::Rgb, BitDepth::Eight),
        ColorSpace::Rgb16 => (ColorType::Rgb, BitDepth::Sixteen),
        ColorSpace::Rgba8 => (ColorType::Rgba, BitDepth::Eight),
        ColorSpace::Luma8 => (ColorType::Grayscale, BitDepth::Eight),
    }
}

/// Wraps whatever the encoder or the filesystem said into an output failure.
fn encoding_failed<E: fmt::Display>(err: E) -> OutputError {
    OutputError::EncodingFailed(err.to_string())
}

/// An encoder configured the way every container this crate writes is encoded.
///
/// One function for both passes below — the compression pass and the file
/// itself — because the header of the second has to describe the stream the
/// first produced. Two configurations that drifted apart would write a file
/// whose `IHDR` and whose pixels disagree.
///
/// The deflate settings are the ones the high-level encoder this replaces used,
/// restated rather than left to a default. `Compression::Fast` is what
/// `image`'s `PngEncoder` defaults to — the `#[default]` of its own
/// `CompressionType` — and it selects the fdeflate compressor, which is
/// specialised for PNG rows and produces a stream that nothing else in this
/// crate is allowed to change: pairing that stream with the cover's is a
/// separate task. Everything else in this module changes only the layout of the
/// file, never the compressed bytes of its pixels.
fn configured_encoder<W: Write>(sink: W, image: &ImageBuffer) -> Encoder<'static, W> {
    let (width, height) = image.dimensions();
    let (color_type, bit_depth) = png_layout(image.color_space());

    let mut encoder = Encoder::new(sink, width, height);
    encoder.set_color(color_type);
    encoder.set_depth(bit_depth);
    encoder.set_compression(Compression::Fast);
    encoder.set_filter(Filter::Adaptive);

    encoder
}

/// The samples in the byte order the format demands.
///
/// PNG is big-endian and this crate stores 16-bit samples as explicit
/// little-endian pairs, so the 16-bit layout is the one place where the bytes
/// that go into the file are not the bytes held in memory. Getting this
/// backwards produces a file that decodes to a different image and no error at
/// all, which is why the three 8-bit layouts are borrowed straight through and
/// the fourth is spelled out.
fn big_endian_samples(image: &ImageBuffer) -> Cow<'_, [u8]> {
    let pixels = image.pixels();

    if image.color_space() != ColorSpace::Rgb16 {
        return Cow::Borrowed(pixels);
    }

    Cow::Owned(
        pixels
            .chunks_exact(2)
            .flat_map(|pair| match pair {
                [low, high] => [*high, *low],
                // Unreachable: `chunks_exact(2)` yields pairs. The arm keeps the
                // match exhaustive without an index or an unwrap.
                _ => [0, 0],
            })
            .collect::<Vec<u8>>(),
    )
}

/// Compresses the samples into the single zlib stream a PNG carries.
///
/// # Why the file is written twice
///
/// The encoder can either produce the stream in one piece or emit it through a
/// streaming writer that cuts it as it goes, and only the second lets the chunk
/// size be chosen. The streaming writer pays for that: it has to flush the
/// compressor at the end, which leaves a marker in the deflate stream and strands
/// its last few bytes in a chunk of their own — a six-byte `IDAT` at the end of
/// the file, which is a signature as particular as the one this is meant to
/// remove.
///
/// So the stream is produced whole, exactly as the one-shot encoder would have
/// written it, and cut up afterwards by the caller. The compressed bytes are
/// identical to what a plain save produces; only their packaging differs.
///
/// # Errors
///
/// Returns [`OutputError::EncodingFailed`] if the encoder refuses the geometry
/// or the samples.
fn compress_samples(image: &ImageBuffer, samples: &[u8]) -> Result<Vec<u8>, OutputError> {
    let mut encoded: Vec<u8> = Vec::new();

    {
        let encoder = configured_encoder(&mut encoded, image);
        let mut writer = encoder.write_header().map_err(encoding_failed)?;
        writer.write_image_data(samples).map_err(encoding_failed)?;
        writer.finish().map_err(encoding_failed)?;
    }

    // What comes back is a whole PNG; the pixel stream is the concatenation of
    // its `IDAT` payloads, which at these sizes is a single chunk.
    let mut stream = Vec::new();
    let mut offset = envelope::SIGNATURE_LEN;

    while let Some((code, data, next)) = envelope::read_chunk(&encoded, offset) {
        if &code == b"IDAT" {
            stream.extend_from_slice(data);
        }
        offset = next;
    }

    Ok(stream)
}

/// Writes a container to disk as a PNG, shaped like the file it came from.
///
/// The format is forced rather than inferred from the extension: a stego image
/// saved as anything lossy is a destroyed payload, and an output path chosen by
/// the user is not something to take format advice from.
///
/// # Why this does not use a one-line save
///
/// Handing the samples to a high-level encoder writes a file that is correct and
/// unlike any other: `IHDR`, one `IDAT` holding the whole compressed image, and
/// `IEND`. Ordinary photographic software writes several auxiliary chunks and
/// cuts the pixel stream into thousands of pieces, so a container with neither
/// property can be picked out of a folder with a hex viewer and no steganalysis
/// whatsoever. The envelope carried by the image — see
/// [`crate::image_io::envelope`] — is what both are taken from: the whitelisted
/// chunks of the original, in their original order, and its `IDAT` split. A
/// container this crate drew itself has no original to copy, and carries the
/// default profile instead, which is the same code path with different numbers.
///
/// The samples are untouched by any of it. This function decides how the file is
/// packed and never what is in it.
///
/// # Errors
///
/// Returns [`OutputError::MalformedBuffer`] if the sample buffer does not match
/// the dimensions it reports, and [`OutputError::EncodingFailed`] if the encoder
/// or the filesystem refuses the write.
pub(crate) fn write_png(image: &ImageBuffer, path: &Path) -> Result<(), OutputError> {
    let (width, height) = image.dimensions();
    let color_space = image.color_space();

    // Judged before anything is created, so a buffer that cannot be encoded
    // leaves no file behind for a caller to mistake for a container.
    let expected = (width as usize)
        .checked_mul(height as usize)
        .and_then(|pixels| pixels.checked_mul(color_space.bytes_per_pixel()));
    if expected != Some(image.pixels().len()) {
        return Err(OutputError::MalformedBuffer);
    }

    let stream = compress_samples(image, &big_endian_samples(image))?;

    let file = File::create(path).map_err(encoding_failed)?;
    let envelope = image.envelope();

    let mut writer = configured_encoder(BufWriter::new(file), image)
        .write_header()
        .map_err(encoding_failed)?;

    // Ahead of the pixel data, which is where every chunk on the whitelist
    // belongs and where the original carried them.
    for chunk in envelope.preserved_chunks() {
        writer
            .write_chunk(png::chunk::ChunkType(chunk.kind().type_code()), chunk.data())
            .map_err(encoding_failed)?;
    }

    // The one place the layout of the file is decided. Every chunk is full
    // except the last, which is the shape libpng produces and therefore the
    // shape of most of the PNGs in existence.
    for piece in stream.chunks(envelope.idat_chunk_size()) {
        writer
            .write_chunk(png::chunk::IDAT, piece)
            .map_err(encoding_failed)?;
    }

    // Writes `IEND` and flushes the buffered file. Dropping the writer would do
    // the first and swallow the failure of the second, which on a full disk is
    // the difference between an error and a truncated container.
    writer.finish().map_err(encoding_failed)
}

#[cfg(test)]
mod tests {
    // The crate-wide bans on panicking helpers reach into `cfg(test)` code as
    // well. A test that cannot panic cannot fail, so they are lifted here and
    // only here.
    #![allow(clippy::expect_used)]
    #![allow(clippy::panic)]

    use super::*;

    use image::ImageFormat;
    use tempfile::NamedTempFile;

    use crate::image_io::envelope::PngEnvelope;

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

    /// The chunk types of a PNG file, in the order they appear, with their
    /// payload lengths.
    ///
    /// A deliberately naive walk: four bytes of length, four of type, the data,
    /// four of CRC. It is what a hex viewer shows, which is the point of view
    /// this whole exercise is about.
    fn chunks(bytes: &[u8]) -> Vec<(String, usize)> {
        let mut found = Vec::new();
        let mut offset = 8usize;

        while offset + 8 <= bytes.len() {
            let length = u32::from_be_bytes(
                bytes[offset..offset + 4]
                    .try_into()
                    .expect("four bytes of length"),
            ) as usize;
            let code = String::from_utf8_lossy(&bytes[offset + 4..offset + 8]).into_owned();

            found.push((code, length));
            offset += 12 + length;
        }

        found
    }

    /// A container of `side` squared pixels filled with data that does not
    /// compress, so that the written file is large enough to be cut up.
    fn noisy_container(side: u32, color_space: ColorSpace) -> ImageBuffer {
        let len = side as usize * side as usize * color_space.bytes_per_pixel();

        // A linear congruential generator, inline: the fixture has to be
        // incompressible and reproducible, and nothing else about it matters.
        let mut state = 0x2545_F491_4F6C_DD1Du64;
        let pixels = (0..len)
            .map(|_| {
                state = state
                    .wrapping_mul(6_364_136_223_846_793_005)
                    .wrapping_add(1_442_695_040_888_963_407);
                (state >> 33) as u8
            })
            .collect();

        ImageBuffer::new(pixels, side, side, color_space)
    }

    /// Builds a PNG-shaped byte stream, so that an envelope can be read out of
    /// it and handed to the writer.
    fn envelope_of(chunks: &[(&[u8; 4], Vec<u8>)]) -> PngEnvelope {
        let mut bytes = vec![0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A];

        for (code, data) in chunks {
            bytes.extend_from_slice(&(data.len() as u32).to_be_bytes());
            bytes.extend_from_slice(*code);
            bytes.extend_from_slice(data);
            bytes.extend_from_slice(&[0, 0, 0, 0]);
        }

        PngEnvelope::read(&bytes)
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
    /// given, byte for byte.
    ///
    /// The 16-bit layout is the one that has to be checked rather than assumed:
    /// this crate holds those samples as little-endian pairs and PNG stores them
    /// big-endian, so a writer that passed the buffer straight through would
    /// produce a file that decodes to a different image without failing at any
    /// point.
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

            let recovered: Vec<u8> = match color_space {
                ColorSpace::Rgb8 => decoded.into_rgb8().into_raw(),
                ColorSpace::Rgba8 => decoded.into_rgba8().into_raw(),
                ColorSpace::Luma8 => decoded.into_luma8().into_raw(),
                ColorSpace::Rgb16 => decoded
                    .into_rgb16()
                    .into_raw()
                    .into_iter()
                    .flat_map(u16::to_le_bytes)
                    .collect(),
            };

            assert_eq!(
                recovered,
                image.pixels(),
                "a {color_space:?} container must decode to the samples it was written from"
            );
        }
    }

    /// The 16-bit samples land in the file in the order the format demands.
    ///
    /// The layer below the test above: it asserts that a decoder agrees with the
    /// writer, which two mirrored mistakes would also satisfy. This one reads the
    /// bytes of the file and checks that the high half of each sample comes
    /// first, which is a fact about the file rather than about the round trip.
    #[test]
    fn sixteen_bit_samples_are_written_big_endian() {
        // One pixel, and a value whose two halves cannot be confused.
        let image = ImageBuffer::new(
            vec![0x34, 0x12, 0x78, 0x56, 0xBC, 0x9A],
            1,
            1,
            ColorSpace::Rgb16,
        );

        assert_eq!(
            big_endian_samples(&image).as_ref(),
            &[0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC]
        );

        // Every other layout is written exactly as it is held.
        let flat = container(ColorSpace::Rgba8);
        assert_eq!(big_endian_samples(&flat).as_ref(), flat.pixels());
    }

    /// The whitelisted chunks of the original are written back, in order, ahead
    /// of the pixel data — and nothing else is.
    #[test]
    fn the_original_chunks_are_repeated_and_the_rest_are_not() {
        let envelope = envelope_of(&[
            (b"IHDR", vec![0; 13]),
            (b"sRGB", vec![0]),
            (b"gAMA", 45_455u32.to_be_bytes().to_vec()),
            (b"eXIf", vec![0x45; 120]),
            (b"tEXt", b"Software\0a camera".to_vec()),
            (b"pHYs", vec![0, 0, 0x0B, 0x13, 0, 0, 0x0B, 0x13, 1]),
            (b"IDAT", vec![0; 8192]),
            (b"IEND", Vec::new()),
        ]);

        let image = ImageBuffer::with_envelope(
            container(ColorSpace::Rgb8).pixels().to_vec(),
            WIDTH,
            HEIGHT,
            ColorSpace::Rgb8,
            envelope,
        );

        let file = NamedTempFile::new().expect("temporary stego file");
        write_png(&image, file.path()).expect("the container must be writable");

        let bytes = std::fs::read(file.path()).expect("the written file must be readable");
        let written: Vec<String> = chunks(&bytes)
            .into_iter()
            .map(|(code, _)| code)
            .filter(|code| code != "IDAT")
            .collect();

        assert_eq!(written, vec!["IHDR", "sRGB", "gAMA", "pHYs", "IEND"]);

        // The payload is repeated verbatim: 2835 pixels per metre on both axes.
        let physical = bytes
            .windows(4)
            .position(|window| window == b"pHYs")
            .expect("the chunk must be in the file");
        assert_eq!(
            &bytes[physical + 4..physical + 13],
            &[0, 0, 0x0B, 0x13, 0, 0, 0x0B, 0x13, 1]
        );
    }

    /// The pixel stream is cut into chunks of the size the original used.
    #[test]
    fn the_pixel_stream_is_cut_the_way_the_original_was() {
        let split = 4096usize;
        let envelope = envelope_of(&[
            (b"IHDR", vec![0; 13]),
            (b"IDAT", vec![0; split]),
            (b"IDAT", vec![0; split]),
            (b"IDAT", vec![0; 17]),
            (b"IEND", Vec::new()),
        ]);
        assert_eq!(envelope.idat_chunk_size(), split);

        let noisy = noisy_container(200, ColorSpace::Rgb8);
        let image = ImageBuffer::with_envelope(
            noisy.pixels().to_vec(),
            200,
            200,
            ColorSpace::Rgb8,
            envelope,
        );

        let file = NamedTempFile::new().expect("temporary stego file");
        write_png(&image, file.path()).expect("the container must be writable");

        let bytes = std::fs::read(file.path()).expect("the written file must be readable");
        let idat: Vec<usize> = chunks(&bytes)
            .into_iter()
            .filter(|(code, _)| code == "IDAT")
            .map(|(_, length)| length)
            .collect();

        // Incompressible samples: 120000 bytes of them cannot fit in one chunk
        // of four kilobytes, so the split is exercised rather than assumed.
        assert!(
            idat.len() > 20,
            "the stream must be cut into many chunks, got {}",
            idat.len()
        );

        // Every chunk but the last is full.
        let (last, full) = idat.split_last().expect("at least one chunk");
        assert!(full.iter().all(|&length| length == split), "{idat:?}");
        assert!(*last <= split, "{idat:?}");

        // And it still decodes to what it was given.
        let decoded = image::load_from_memory_with_format(&bytes, ImageFormat::Png)
            .expect("the written png must decode");
        assert_eq!(decoded.into_rgb8().into_raw(), noisy.pixels());
    }

    /// A container this crate drew itself is wrapped in the default profile.
    ///
    /// The path with no original to copy from, and the reason there is one
    /// writer rather than two: `generate` reaches this code through the same
    /// call as `embed` and differs only in the envelope its buffer carries.
    #[test]
    fn a_container_without_an_original_wears_the_default_profile() {
        let image = noisy_container(200, ColorSpace::Rgb8);
        let file = NamedTempFile::new().expect("temporary stego file");

        write_png(&image, file.path()).expect("the container must be writable");

        let bytes = std::fs::read(file.path()).expect("the written file must be readable");
        let written = chunks(&bytes);

        let names: Vec<&str> = written
            .iter()
            .map(|(code, _)| code.as_str())
            .filter(|code| *code != "IDAT")
            .collect();
        assert_eq!(names, vec!["IHDR", "gAMA", "cHRM", "sRGB", "pHYs", "IEND"]);

        let idat: Vec<usize> = written
            .iter()
            .filter(|(code, _)| code == "IDAT")
            .map(|(_, length)| *length)
            .collect();
        assert!(idat.len() > 4, "{idat:?}");

        let (last, full) = idat.split_last().expect("at least one chunk");
        assert!(full.iter().all(|&length| length == 8192), "{idat:?}");
        assert!(*last <= 8192, "{idat:?}");
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
