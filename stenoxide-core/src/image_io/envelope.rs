//! The file envelope of a container: what the wrapper says, as opposed to what
//! the pixels say.
//!
//! # Why the wrapper is part of the problem
//!
//! Everything else in this crate works to make the *samples* of a stego image
//! inseparable from those of a cover. None of it touches the file those samples
//! are packed into, and that file talks. A PNG is a signature followed by a
//! chain of chunks — four bytes of length, four of type, the data, four of
//! CRC — of which only `IDAT` carries pixels. The rest describe how to read
//! them, or describe where they came from, or are simply absent; and which of
//! the three is the case is itself a signature of the program that wrote the
//! file.
//!
//! Two properties give a re-encoded container away without any steganalysis at
//! all:
//!
//! - **The auxiliary chunks that are missing.** A PNG exported by an editor
//!   almost always carries `gAMA`, `sRGB` or `pHYs`, often an `iCCP` profile and
//!   some text. A file that carries none of them is already unusual.
//! - **How the pixel stream is cut up.** `IDAT` may be split into as many chunks
//!   as the encoder likes, and libpng — which sits under most of the world's
//!   photographic software — emits 8192-byte chunks. An encoder that writes the
//!   whole image as a single `IDAT` produces a file that can be told apart from
//!   almost everything else with a hex viewer.
//!
//! A [`PngEnvelope`] is what a container's own wrapper looked like, kept
//! alongside its samples so that the file written back out can be shaped like
//! the file that was read.
//!
//! # What is copied, and what is never copied
//!
//! The rule is a whitelist, and it is not configurable:
//!
//! - **Copied**: the chunks that say how to interpret the samples — `gAMA`,
//!   `sRGB`, `cHRM`, `pHYs`, `iCCP`, `sBIT`. None of them names a person, a
//!   place, a camera or a program.
//! - **Never copied**: everything that carries provenance or personal data —
//!   `eXIf`, `tEXt`, `iTXt`, `zTXt`, `tIME`. There is no flag that turns this
//!   on, because the stego image is the file that gets sent to somebody else,
//!   and the coordinates of the photographer's house have no business travelling
//!   with it.
//! - **Anything else is dropped.** An unrecognised chunk is not copied, so a
//!   chunk type that did not exist when this was written cannot smuggle anything
//!   out by default.
//!
//! That leaves an observable residue: an export whose text chunk has gone
//! missing is not quite an ordinary export. It is a trade accepted deliberately,
//! and it is documented in the README rather than hidden.
//!
//! # Reading is best effort, and never a gate
//!
//! Parsing happens on files supplied by whoever sent them, including on the
//! extraction path where the image may be hostile. Nothing here allocates on the
//! strength of a declared length: a chunk is only copied once its bytes have
//! been seen to exist, and one that is too large to be plausible is skipped
//! rather than reserved for.
//!
//! Failure is silent by construction. A file this module cannot make sense of
//! yields an empty envelope, never an error: the decoder is the authority on
//! whether a PNG is valid, and a second opinion here could only make a container
//! that used to be accepted stop being accepted.

use std::collections::HashMap;

/// Bytes of the PNG signature that precede the first chunk.
pub(crate) const SIGNATURE_LEN: usize = 8;

/// Bytes of a chunk header: the big-endian length, then the four type bytes.
const CHUNK_HEADER_LEN: usize = 8;

/// Bytes of the CRC that closes every chunk.
const CHUNK_CRC_LEN: usize = 4;

/// Largest technical chunk that is worth copying, in bytes.
///
/// Only `iCCP` can plausibly be large, and a colour profile runs to a few
/// kilobytes — the biggest ones published are a couple of megabytes. Four
/// mebibytes is well past every real profile and far short of what a file
/// crafted to make this crate hold a large buffer would declare. A chunk beyond
/// the limit is skipped, which costs fidelity on a file that was already
/// anomalous.
const MAX_PRESERVED_CHUNK_BYTES: usize = 4 * 1024 * 1024;

/// Smallest `IDAT` split this module will reproduce, in bytes.
///
/// A file whose pixel stream is cut into fragments smaller than this is either
/// broken or built to make the encoder emit hundreds of thousands of chunks. The
/// default profile is used instead.
const MIN_IDAT_CHUNK_SIZE: usize = 512;

/// Largest `IDAT` split this module will reproduce, in bytes.
///
/// The encoder holds one chunk in memory at a time, so this figure is an
/// allocation as much as it is a layout. Thirty-two mebibytes is four thousand
/// times what libpng writes and above every encoder that splits at all; past it
/// the shape being imitated is "one enormous `IDAT`", which is the anomaly this
/// module exists to stop producing.
const MAX_IDAT_CHUNK_SIZE: usize = 32 * 1024 * 1024;

/// `IDAT` split of the default profile, in bytes.
///
/// libpng's own, and therefore the most common layout in existence: it is what
/// sits under the photographic software most containers come out of.
const DEFAULT_IDAT_CHUNK_SIZE: usize = 8192;

/// A chunk that describes how to read the samples, and nothing else.
///
/// The whitelist as a closed type: a chunk that is not one of these has no
/// representation here, so no code path can copy one by accident.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TechnicalChunk {
    /// `gAMA` — the display gamma the samples were encoded against.
    Gamma,
    /// `sRGB` — a declaration that the samples are sRGB, and with what intent.
    Srgb,
    /// `cHRM` — the chromaticities of the primaries and of the white point.
    Chromaticities,
    /// `pHYs` — the physical size of a pixel.
    PhysicalDimensions,
    /// `iCCP` — an embedded ICC colour profile.
    ///
    /// The one whitelisted chunk that can be large, and the one whose contents
    /// are not a handful of integers. It is still a description of colour: a
    /// profile identifies a device class or a working space, not an owner.
    IccProfile,
    /// `sBIT` — how many bits of each sample the original actually used.
    ///
    /// Copied verbatim like the rest. Worth knowing that a container declaring
    /// fewer significant bits than its samples carry is a poor container for
    /// this purpose, because the payload lives in exactly the bits such a chunk
    /// claims are meaningless.
    SignificantBits,
}

impl TechnicalChunk {
    /// Every whitelisted chunk, in no significant order.
    const ALL: [TechnicalChunk; 6] = [
        TechnicalChunk::Gamma,
        TechnicalChunk::Srgb,
        TechnicalChunk::Chromaticities,
        TechnicalChunk::PhysicalDimensions,
        TechnicalChunk::IccProfile,
        TechnicalChunk::SignificantBits,
    ];

    /// The four type bytes this chunk is written with.
    pub fn type_code(self) -> [u8; 4] {
        match self {
            TechnicalChunk::Gamma => *b"gAMA",
            TechnicalChunk::Srgb => *b"sRGB",
            TechnicalChunk::Chromaticities => *b"cHRM",
            TechnicalChunk::PhysicalDimensions => *b"pHYs",
            TechnicalChunk::IccProfile => *b"iCCP",
            TechnicalChunk::SignificantBits => *b"sBIT",
        }
    }

    /// The chunk's name, for a report a person reads.
    pub fn name(self) -> &'static str {
        match self {
            TechnicalChunk::Gamma => "gAMA",
            TechnicalChunk::Srgb => "sRGB",
            TechnicalChunk::Chromaticities => "cHRM",
            TechnicalChunk::PhysicalDimensions => "pHYs",
            TechnicalChunk::IccProfile => "iCCP",
            TechnicalChunk::SignificantBits => "sBIT",
        }
    }

    /// Recognises a chunk type, or refuses it.
    ///
    /// The only way a chunk becomes copyable. Everything not on the list —
    /// `eXIf` and the text chunks included — returns `None` here and is dropped
    /// by the caller.
    fn from_type_code(code: [u8; 4]) -> Option<Self> {
        TechnicalChunk::ALL
            .into_iter()
            .find(|candidate| candidate.type_code() == code)
    }
}

/// One whitelisted chunk, with the bytes it carried.
#[derive(Debug, Clone)]
pub struct PreservedChunk {
    /// Which chunk this is.
    kind: TechnicalChunk,
    /// Its payload, without the length, the type or the CRC.
    data: Vec<u8>,
}

impl PreservedChunk {
    /// Which chunk this is.
    pub fn kind(&self) -> TechnicalChunk {
        self.kind
    }

    /// Bytes of payload, CRC and header excluded.
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Whether the chunk carries no payload at all.
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// The payload, for the encoder that writes it back out.
    pub(crate) fn data(&self) -> &[u8] {
        &self.data
    }
}

/// The shape of the file a container arrived in.
///
/// Travels with the samples it was read from — see
/// [`crate::image_io::buffer::ImageBuffer::envelope`] — so that the writing side
/// can reproduce it without any intermediate layer having to carry it.
#[derive(Debug, Clone)]
pub struct PngEnvelope {
    /// The whitelisted chunks, in the order the file listed them.
    chunks: Vec<PreservedChunk>,
    /// Bytes of compressed data per `IDAT` chunk.
    idat_chunk_size: usize,
    /// How many `IDAT` chunks the file was cut into.
    idat_chunk_count: usize,
    /// Ancillary chunks that were seen and will not be reproduced.
    discarded_chunks: usize,
}

impl PngEnvelope {
    /// The profile used for a container this crate drew itself.
    ///
    /// [`crate::generate`] has no original to copy from, so the wrapper is
    /// chosen rather than observed: the `IDAT` split libpng uses, and the
    /// technical chunks an ordinary export writes. The point is not to pass for
    /// any particular program — it is that two generated containers should stop
    /// sharing one peculiar signature that belongs to no other software.
    ///
    /// The values are the sRGB ones, which is what the samples are: an 8-bit
    /// RGB texture with no colour management of its own.
    pub(crate) fn synthesised() -> Self {
        // Gamma 1/2.2, written as the PNG fixed-point value: the figure libpng
        // pairs with an sRGB declaration.
        let gamma = 45_455u32.to_be_bytes().to_vec();

        // Rendering intent 0, perceptual. The value written by nearly every
        // exporter that emits this chunk at all.
        let srgb = vec![0u8];

        // The sRGB primaries and white point, in the order the format fixes:
        // white x/y, red x/y, green x/y, blue x/y, each scaled by 100000.
        let chromaticities = [
            31_270u32, 32_900, 64_000, 33_000, 30_000, 60_000, 15_000, 6_000,
        ]
        .iter()
        .flat_map(|value| value.to_be_bytes())
        .collect();

        // 2835 pixels per metre on both axes, which is 72 dpi, with the unit
        // byte set to metres.
        let mut physical = Vec::with_capacity(9);
        physical.extend_from_slice(&2835u32.to_be_bytes());
        physical.extend_from_slice(&2835u32.to_be_bytes());
        physical.push(1);

        Self {
            chunks: vec![
                PreservedChunk {
                    kind: TechnicalChunk::Gamma,
                    data: gamma,
                },
                PreservedChunk {
                    kind: TechnicalChunk::Chromaticities,
                    data: chromaticities,
                },
                PreservedChunk {
                    kind: TechnicalChunk::Srgb,
                    data: srgb,
                },
                PreservedChunk {
                    kind: TechnicalChunk::PhysicalDimensions,
                    data: physical,
                },
            ],
            idat_chunk_size: DEFAULT_IDAT_CHUNK_SIZE,
            idat_chunk_count: 0,
            discarded_chunks: 0,
        }
    }

    /// Reads the envelope of a PNG file from its bytes.
    ///
    /// Best effort throughout: a truncated file, a chunk whose declared length
    /// runs past the end of the buffer, or bytes that are not a PNG at all end
    /// the walk and yield whatever was understood up to that point. Nothing here
    /// can refuse a container — see the module documentation for why that
    /// matters.
    pub(crate) fn read(bytes: &[u8]) -> Self {
        let mut envelope = Self {
            chunks: Vec::new(),
            idat_chunk_size: DEFAULT_IDAT_CHUNK_SIZE,
            idat_chunk_count: 0,
            discarded_chunks: 0,
        };

        let mut idat_lengths: Vec<usize> = Vec::new();
        let mut offset = SIGNATURE_LEN;

        while let Some((code, data, next)) = read_chunk(bytes, offset) {
            offset = next;

            match &code {
                b"IEND" => break,
                b"IDAT" => idat_lengths.push(data.len()),
                _ => envelope.record(code, data, idat_lengths.is_empty()),
            }
        }

        envelope.idat_chunk_count = idat_lengths.len();
        if let Some(size) = dominant_length(&idat_lengths) {
            if (MIN_IDAT_CHUNK_SIZE..=MAX_IDAT_CHUNK_SIZE).contains(&size) {
                envelope.idat_chunk_size = size;
            } else if size > MAX_IDAT_CHUNK_SIZE {
                envelope.idat_chunk_size = MAX_IDAT_CHUNK_SIZE;
            }
        }

        envelope
    }

    /// Files one chunk that is neither `IDAT` nor `IEND`.
    ///
    /// `before_pixels` says whether the chunk was found ahead of the first
    /// `IDAT`. The whitelisted chunks all belong there, and one found in the
    /// tail of a file is either a decoration this crate does not reproduce or a
    /// malformed stream; either way it is counted and dropped.
    fn record(&mut self, code: [u8; 4], data: &[u8], before_pixels: bool) {
        let preservable = TechnicalChunk::from_type_code(code)
            .filter(|_| before_pixels)
            .filter(|_| data.len() <= MAX_PRESERVED_CHUNK_BYTES)
            // The format allows one of each, and a file with two `gAMA` chunks
            // is malformed. The first wins, so a duplicate cannot make this
            // crate write a file stranger than the one it read.
            .filter(|kind| !self.chunks.iter().any(|chunk| chunk.kind == *kind));

        match preservable {
            Some(kind) => self.chunks.push(PreservedChunk {
                kind,
                data: data.to_vec(),
            }),
            // Only ancillary chunks are counted as dropped. A critical one — a
            // palette, say — is not something this crate chose to discard; it is
            // something the layout it decoded to no longer has any use for.
            None => {
                if code[0].is_ascii_lowercase() {
                    self.discarded_chunks += 1;
                }
            }
        }
    }

    /// The whitelisted chunks, in the order they will be written.
    pub fn preserved_chunks(&self) -> &[PreservedChunk] {
        &self.chunks
    }

    /// Bytes of compressed pixel data per `IDAT` chunk.
    pub fn idat_chunk_size(&self) -> usize {
        self.idat_chunk_size
    }

    /// How many `IDAT` chunks the container was read from.
    ///
    /// Zero for an envelope that was chosen rather than observed, which is the
    /// case for every container this crate draws itself.
    pub fn idat_chunk_count(&self) -> usize {
        self.idat_chunk_count
    }

    /// Ancillary chunks that were present and will not be reproduced.
    ///
    /// The size of the residue, in the only unit that can be counted without
    /// keeping the chunks themselves: this is what a reader would notice missing
    /// from the file, and most of it is the metadata that is dropped on purpose.
    pub fn discarded_chunks(&self) -> usize {
        self.discarded_chunks
    }
}

/// Reads one chunk at `offset`, returning its type, payload and the offset of
/// the next chunk.
///
/// Returns `None` at the end of the file and at the first byte that cannot be
/// trusted: a header that does not fit, a length that no `usize` can hold, or a
/// payload that runs past the end of the buffer. The declared length is checked
/// against the bytes that actually exist *before* the payload is looked at, so a
/// chunk claiming four gibibytes costs nothing but the comparison.
///
/// Readable inside the crate rather than private to this module: the writing
/// side reads back the pixel stream it has just compressed, and one walk over a
/// chunk chain is enough for both directions.
pub(crate) fn read_chunk(bytes: &[u8], offset: usize) -> Option<([u8; 4], &[u8], usize)> {
    let header = bytes.get(offset..offset.checked_add(CHUNK_HEADER_LEN)?)?;

    let length = u32::from_be_bytes(header.get(..4)?.try_into().ok()?);
    let code: [u8; 4] = header.get(4..)?.try_into().ok()?;

    // The format caps a chunk at `i32::MAX`, and a 32-bit host caps it lower
    // still. Either way the conversion is checked rather than assumed.
    let length = usize::try_from(length).ok()?;

    let start = offset.checked_add(CHUNK_HEADER_LEN)?;
    let end = start.checked_add(length)?;
    let next = end.checked_add(CHUNK_CRC_LEN)?;

    // The CRC has to be there for the chunk to be complete, but it is not
    // verified: the decoder is the authority on a damaged stream, and a second
    // opinion here could only disagree with it.
    if next > bytes.len() {
        return None;
    }

    Some((code, bytes.get(start..end)?, next))
}

/// The length most `IDAT` chunks share.
///
/// An encoder that splits at all writes every chunk at its buffer size except
/// the last, so the mode is the size that was configured. The first chunk is not
/// a safe answer on its own — some encoders emit a slightly short one, because
/// the zlib header goes in ahead of the pixel data — and neither is the maximum,
/// which a single outsized chunk would decide by itself.
///
/// Ties go to the larger length, so that a file cut into exactly two chunks
/// reports the full one rather than the remainder.
fn dominant_length(lengths: &[usize]) -> Option<usize> {
    let mut counts: HashMap<usize, usize> = HashMap::new();
    for &length in lengths {
        *counts.entry(length).or_insert(0) += 1;
    }

    counts
        .into_iter()
        .max_by_key(|&(length, count)| (count, length))
        .map(|(length, _)| length)
}

#[cfg(test)]
mod tests {
    // The crate-wide bans on panicking helpers reach into `cfg(test)` code as
    // well. A test that cannot panic cannot fail, so they are lifted here and
    // only here.
    #![allow(clippy::expect_used)]
    #![allow(clippy::panic)]

    use super::*;

    /// Builds a PNG-shaped byte stream out of `(type, payload)` pairs.
    ///
    /// The CRC is filled with zeros: nothing in this module reads it, and a
    /// fixture that had to compute one would be testing the CRC rather than the
    /// walk.
    fn file(chunks: &[(&[u8; 4], Vec<u8>)]) -> Vec<u8> {
        let mut bytes = vec![0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A];

        for (code, data) in chunks {
            bytes.extend_from_slice(&(data.len() as u32).to_be_bytes());
            bytes.extend_from_slice(*code);
            bytes.extend_from_slice(data);
            bytes.extend_from_slice(&[0, 0, 0, 0]);
        }

        bytes
    }

    /// An `IHDR` payload of the length the format fixes. Its contents do not
    /// matter here: this module never reads them.
    fn ihdr() -> (&'static [u8; 4], Vec<u8>) {
        (b"IHDR", vec![0u8; 13])
    }

    /// The technical chunks are kept, in file order, and nothing else is.
    #[test]
    fn the_whitelist_is_copied_and_the_rest_is_dropped() {
        let bytes = file(&[
            ihdr(),
            (b"sRGB", vec![0]),
            (b"gAMA", 45_455u32.to_be_bytes().to_vec()),
            (b"eXIf", vec![9; 400]),
            (b"pHYs", vec![1; 9]),
            (b"tEXt", b"Software\0Adobe".to_vec()),
            (b"iTXt", vec![7; 20]),
            (b"tIME", vec![0; 7]),
            (b"zTXt", vec![3; 12]),
            (b"IDAT", vec![0; 8192]),
            (b"IDAT", vec![0; 100]),
            (b"IEND", Vec::new()),
        ]);

        let envelope = PngEnvelope::read(&bytes);
        let kinds: Vec<TechnicalChunk> = envelope
            .preserved_chunks()
            .iter()
            .map(PreservedChunk::kind)
            .collect();

        assert_eq!(
            kinds,
            vec![
                TechnicalChunk::Srgb,
                TechnicalChunk::Gamma,
                TechnicalChunk::PhysicalDimensions,
            ]
        );

        // The payload travels with the chunk, byte for byte.
        assert_eq!(
            envelope.preserved_chunks()[1].data(),
            &45_455u32.to_be_bytes()
        );
        assert_eq!(envelope.preserved_chunks()[0].len(), 1);
        assert!(!envelope.preserved_chunks()[0].is_empty());

        // Five ancillary chunks were seen and refused: eXIf, tEXt, iTXt, tIME
        // and zTXt. IHDR, IDAT and IEND are critical and are not counted.
        assert_eq!(envelope.discarded_chunks(), 5);
        assert_eq!(envelope.idat_chunk_count(), 2);
        assert_eq!(envelope.idat_chunk_size(), 8192);
    }

    /// Nothing that identifies a person or a program is representable at all.
    #[test]
    fn no_identifying_chunk_can_be_recognised() {
        for code in [b"eXIf", b"tEXt", b"iTXt", b"zTXt", b"tIME"] {
            assert_eq!(
                TechnicalChunk::from_type_code(*code),
                None,
                "{} must never be copyable",
                String::from_utf8_lossy(code)
            );
        }

        for kind in TechnicalChunk::ALL {
            assert_eq!(
                TechnicalChunk::from_type_code(kind.type_code()),
                Some(kind),
                "{} must round-trip through its type code",
                kind.name()
            );
            assert_eq!(kind.name().as_bytes(), kind.type_code());
        }
    }

    /// A chunk found after the pixel data is not reproduced, whatever it is.
    ///
    /// The layout of the file `In the Spotlight` and many other exports: the
    /// text chunk sits between the last `IDAT` and `IEND`.
    #[test]
    fn a_chunk_behind_the_pixels_is_not_copied() {
        let bytes = file(&[
            ihdr(),
            (b"IDAT", vec![0; 4096]),
            (b"pHYs", vec![1; 9]),
            (b"iTXt", vec![2; 30]),
            (b"IEND", Vec::new()),
        ]);

        let envelope = PngEnvelope::read(&bytes);

        assert!(envelope.preserved_chunks().is_empty());
        assert_eq!(envelope.discarded_chunks(), 2);
    }

    /// A repeated chunk is copied once, and the first occurrence is the one.
    #[test]
    fn a_duplicated_chunk_is_written_once() {
        let bytes = file(&[
            ihdr(),
            (b"gAMA", vec![1, 1, 1, 1]),
            (b"gAMA", vec![2, 2, 2, 2]),
            (b"IDAT", vec![0; 512]),
            (b"IEND", Vec::new()),
        ]);

        let envelope = PngEnvelope::read(&bytes);

        assert_eq!(envelope.preserved_chunks().len(), 1);
        assert_eq!(envelope.preserved_chunks()[0].data(), &[1, 1, 1, 1]);
        assert_eq!(envelope.discarded_chunks(), 1);
    }

    /// A colour profile larger than any real one is skipped rather than held.
    #[test]
    fn an_implausible_profile_is_not_kept() {
        let bytes = file(&[
            ihdr(),
            (b"iCCP", vec![0; MAX_PRESERVED_CHUNK_BYTES + 1]),
            (b"IDAT", vec![0; 1024]),
            (b"IEND", Vec::new()),
        ]);

        let envelope = PngEnvelope::read(&bytes);

        assert!(envelope.preserved_chunks().is_empty());
        assert_eq!(envelope.discarded_chunks(), 1);

        // One byte smaller and it is a profile like any other.
        let bytes = file(&[
            ihdr(),
            (b"iCCP", vec![0; MAX_PRESERVED_CHUNK_BYTES]),
            (b"IDAT", vec![0; 1024]),
            (b"IEND", Vec::new()),
        ]);
        assert_eq!(PngEnvelope::read(&bytes).preserved_chunks().len(), 1);
    }

    /// A declared length that runs past the end of the file reserves nothing.
    ///
    /// The case this parser exists to survive: on the extraction path the image
    /// is supplied by whoever sent it, and a chunk claiming four gibibytes must
    /// cost a comparison rather than an allocation.
    #[test]
    fn an_absurd_length_ends_the_walk() {
        let mut bytes = file(&[ihdr()]);
        bytes.extend_from_slice(&u32::MAX.to_be_bytes());
        bytes.extend_from_slice(b"iCCP");
        bytes.extend_from_slice(&[0; 16]);

        let envelope = PngEnvelope::read(&bytes);

        assert!(envelope.preserved_chunks().is_empty());
        assert_eq!(envelope.idat_chunk_count(), 0);
        assert_eq!(envelope.idat_chunk_size(), DEFAULT_IDAT_CHUNK_SIZE);
    }

    /// Bytes that are not a PNG, and a file that stops mid-chunk, both yield an
    /// envelope rather than a failure.
    #[test]
    fn an_unreadable_file_yields_the_default_profile() {
        for bytes in [
            Vec::new(),
            b"not a png at all".to_vec(),
            vec![0x89, b'P', b'N', b'G'],
            // A complete header promising a payload that is not there.
            {
                let mut truncated = file(&[ihdr(), (b"gAMA", vec![0; 4])]);
                truncated.truncate(truncated.len() - 5);
                truncated
            },
        ] {
            let envelope = PngEnvelope::read(&bytes);

            assert_eq!(envelope.idat_chunk_size(), DEFAULT_IDAT_CHUNK_SIZE);
            assert_eq!(envelope.idat_chunk_count(), 0);
        }
    }

    /// Everything behind `IEND` is outside the file.
    #[test]
    fn trailing_bytes_after_the_end_marker_are_ignored() {
        let bytes = file(&[
            ihdr(),
            (b"gAMA", vec![0; 4]),
            (b"IDAT", vec![0; 1024]),
            (b"IEND", Vec::new()),
            (b"pHYs", vec![1; 9]),
            (b"IDAT", vec![0; 1024]),
        ]);

        let envelope = PngEnvelope::read(&bytes);

        assert_eq!(envelope.preserved_chunks().len(), 1);
        assert_eq!(envelope.idat_chunk_count(), 1);
    }

    /// The split is the length most chunks share, not the first and not the
    /// largest.
    #[test]
    fn the_idat_split_is_the_length_the_chunks_agree_on() {
        // The layout of a real export: a short first chunk, a long run at the
        // configured size, and a remainder at the end.
        let mut chunks = vec![ihdr(), (b"IDAT", vec![0; 65_445])];
        chunks.extend((0..4).map(|_| (b"IDAT", vec![0; 65_524])));
        chunks.push((b"IDAT", vec![0; 62_588]));
        chunks.push((b"IEND", Vec::new()));

        let envelope = PngEnvelope::read(&file(&chunks));

        assert_eq!(envelope.idat_chunk_size(), 65_524);
        assert_eq!(envelope.idat_chunk_count(), 6);

        // Two chunks, one full and one remainder: the tie goes to the full one.
        assert_eq!(dominant_length(&[8192, 300]), Some(8192));
        assert_eq!(dominant_length(&[]), None);
    }

    /// Splits outside the range this crate will reproduce fall back or clamp.
    #[test]
    fn an_unreproducible_split_is_bounded() {
        let tiny = file(&[
            ihdr(),
            (b"IDAT", vec![0; 4]),
            (b"IDAT", vec![0; 4]),
            (b"IEND", Vec::new()),
        ]);
        assert_eq!(
            PngEnvelope::read(&tiny).idat_chunk_size(),
            DEFAULT_IDAT_CHUNK_SIZE
        );

        // A single enormous `IDAT` is the shape this module exists to stop
        // producing, so it is capped rather than repeated.
        let mut huge = file(&[ihdr()]);
        huge.extend_from_slice(&((MAX_IDAT_CHUNK_SIZE + 1) as u32).to_be_bytes());
        huge.extend_from_slice(b"IDAT");
        huge.resize(huge.len() + MAX_IDAT_CHUNK_SIZE + 1 + CHUNK_CRC_LEN, 0);

        let envelope = PngEnvelope::read(&huge);
        assert_eq!(envelope.idat_chunk_count(), 1);
        assert_eq!(envelope.idat_chunk_size(), MAX_IDAT_CHUNK_SIZE);
    }

    /// The chosen profile is the one a container drawn by this crate wears.
    #[test]
    fn the_default_profile_looks_like_an_ordinary_export() {
        let envelope = PngEnvelope::synthesised();
        let kinds: Vec<&str> = envelope
            .preserved_chunks()
            .iter()
            .map(|chunk| chunk.kind().name())
            .collect();

        assert_eq!(kinds, vec!["gAMA", "cHRM", "sRGB", "pHYs"]);
        assert_eq!(envelope.idat_chunk_size(), DEFAULT_IDAT_CHUNK_SIZE);
        assert_eq!(envelope.idat_chunk_count(), 0);
        assert_eq!(envelope.discarded_chunks(), 0);

        // Each chunk is exactly as long as the format says it must be.
        let lengths: Vec<usize> = envelope
            .preserved_chunks()
            .iter()
            .map(PreservedChunk::len)
            .collect();
        assert_eq!(lengths, vec![4, 32, 1, 9]);
    }
}
