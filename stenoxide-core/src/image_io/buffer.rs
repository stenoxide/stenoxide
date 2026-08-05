//! Owned image buffer and the pixel-access abstraction used by every layer
//! above image I/O.
//!
//! An [`ImageBuffer`] can only be produced by the validation type-state in
//! [`crate::image_io::validate`]: its constructor is `pub(crate)` and the
//! intermediate states of the automaton are private to that module. Downstream
//! layers therefore receive images that are guaranteed to have passed every
//! validation gate.

use zeroize::Zeroize;

use crate::image_io::envelope::PngEnvelope;

/// Pixel layout of a decoded container image.
///
/// Only layouts that expose an integer-valued, losslessly representable sample
/// per channel are supported. Floating point layouts are rejected during
/// validation because LSB embedding is not well defined on them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ColorSpace {
    /// Three 8-bit channels: red, green, blue.
    Rgb8,
    /// Three 16-bit channels stored as little-endian byte pairs.
    Rgb16,
    /// Four 8-bit channels: red, green, blue, alpha.
    Rgba8,
    /// A single 8-bit grayscale channel.
    Luma8,
}

impl ColorSpace {
    /// Number of bytes occupied by one pixel in this layout.
    ///
    /// For [`ColorSpace::Rgb16`] this counts the two bytes of each 16-bit
    /// sample, not the sample itself.
    pub fn bytes_per_pixel(&self) -> usize {
        match self {
            ColorSpace::Rgb8 => 3,
            ColorSpace::Rgb16 => 6,
            ColorSpace::Rgba8 => 4,
            ColorSpace::Luma8 => 1,
        }
    }

    /// Whether the layout carries a dedicated red channel.
    ///
    /// Grayscale images do not, which matters to the layers above: they cannot
    /// treat the single luma channel as if it were a colour component.
    pub fn has_explicit_red_channel(&self) -> bool {
        match self {
            ColorSpace::Rgb8 | ColorSpace::Rgb16 | ColorSpace::Rgba8 => true,
            ColorSpace::Luma8 => false,
        }
    }
}

/// Read/write access to the raw samples of a container image.
///
/// The trait exists so that the cost and embedding layers can operate on any
/// pixel source without owning the concrete buffer type. Implementors must
/// guarantee that [`CoverSource::pixels`] holds exactly
/// `pixel_count() * color_space().bytes_per_pixel()` elements, laid out in
/// row-major order with no padding between rows.
pub trait CoverSource {
    /// Image dimensions as `(width, height)`, in pixels.
    fn dimensions(&self) -> (u32, u32);

    /// Raw sample bytes in row-major order.
    fn pixels(&self) -> &[u8];

    /// Mutable view of the raw sample bytes, used by the embedding layer.
    fn pixels_mut(&mut self) -> &mut [u8];

    /// Pixel layout of the underlying samples.
    fn color_space(&self) -> ColorSpace;

    /// Total number of pixels in the image.
    fn pixel_count(&self) -> usize {
        let (width, height) = self.dimensions();
        width as usize * height as usize
    }

    /// Byte offset of the first sample of the pixel at `(x, y)`.
    ///
    /// The coordinates are not bounds-checked; callers must keep them inside
    /// the range reported by [`CoverSource::dimensions`].
    fn pixel_offset(&self, x: u32, y: u32) -> usize {
        let (width, _) = self.dimensions();
        (y as usize * width as usize + x as usize) * self.color_space().bytes_per_pixel()
    }
}

/// A decoded, fully validated container image owned as a flat byte buffer.
///
/// The type deliberately does not implement [`Clone`]. Container images are
/// several megabytes large, and an accidental copy would leave a second image
/// in memory that no layer is responsible for wiping.
#[derive(Debug)]
pub struct ImageBuffer {
    pixels: Vec<u8>,
    width: u32,
    height: u32,
    color_space: ColorSpace,
    envelope: PngEnvelope,
}

impl ImageBuffer {
    /// Builds a buffer from already validated components.
    ///
    /// Restricted to the crate on purpose: outside code must go through
    /// [`crate::image_io::validate::load_and_validate`], the only path that
    /// runs every validation gate.
    ///
    /// The image is given the envelope of a container this crate drew itself,
    /// which is the right one for every caller that has no file behind its
    /// samples. A buffer decoded from a real PNG is built by
    /// [`ImageBuffer::with_envelope`] instead, so that the file written back out
    /// can be shaped like the file that was read.
    pub(crate) fn new(pixels: Vec<u8>, width: u32, height: u32, color_space: ColorSpace) -> Self {
        Self::with_envelope(
            pixels,
            width,
            height,
            color_space,
            PngEnvelope::synthesised(),
        )
    }

    /// Builds a buffer that remembers the wrapper its samples arrived in.
    pub(crate) fn with_envelope(
        pixels: Vec<u8>,
        width: u32,
        height: u32,
        color_space: ColorSpace,
        envelope: PngEnvelope,
    ) -> Self {
        Self {
            pixels,
            width,
            height,
            color_space,
            envelope,
        }
    }

    /// The shape of the file these samples were read from.
    ///
    /// What the writing side reproduces, and the only description of the
    /// container that is about the file rather than about the pixels. See
    /// [`crate::image_io::envelope`] for what is copied out of it and what is
    /// deliberately left behind.
    pub fn envelope(&self) -> &PngEnvelope {
        &self.envelope
    }
}

impl CoverSource for ImageBuffer {
    fn dimensions(&self) -> (u32, u32) {
        (self.width, self.height)
    }

    fn pixels(&self) -> &[u8] {
        &self.pixels
    }

    fn pixels_mut(&mut self) -> &mut [u8] {
        &mut self.pixels
    }

    fn color_space(&self) -> ColorSpace {
        self.color_space
    }
}

impl Zeroize for ImageBuffer {
    /// Overwrites the sample buffer in place.
    ///
    /// Written by hand rather than derived: only `pixels` holds data worth
    /// wiping, whereas the derive would also reset the dimensions, which are
    /// metadata a caller may still need while inspecting the wiped buffer.
    fn zeroize(&mut self) {
        self.pixels.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every layout, with the stride it promises.
    const LAYOUTS: [(ColorSpace, usize); 4] = [
        (ColorSpace::Rgb8, 3),
        (ColorSpace::Rgb16, 6),
        (ColorSpace::Rgba8, 4),
        (ColorSpace::Luma8, 1),
    ];

    /// The stride of each layout, which the length contract of
    /// [`CoverSource::pixels`] is expressed in.
    #[test]
    fn each_layout_reports_its_own_stride() {
        for (layout, stride) in LAYOUTS {
            assert_eq!(layout.bytes_per_pixel(), stride, "layout {layout:?}");
        }
    }

    /// Only the colour layouts have a red plane for the cost layer to protect.
    #[test]
    fn only_colour_layouts_carry_a_red_channel() {
        for (layout, _) in LAYOUTS {
            assert_eq!(
                layout.has_explicit_red_channel(),
                layout != ColorSpace::Luma8,
                "layout {layout:?}"
            );
        }
    }

    /// The two provided methods of the trait, which no implementor overrides.
    #[test]
    fn offsets_follow_row_major_order() {
        let image = ImageBuffer::new(vec![0u8; 6 * 4 * 3], 6, 4, ColorSpace::Rgb8);

        assert_eq!(image.dimensions(), (6, 4));
        assert_eq!(image.pixel_count(), 24);
        assert_eq!(image.pixel_offset(0, 0), 0);
        assert_eq!(image.pixel_offset(1, 0), 3);
        // One row down and one column across: six pixels of stride, plus one.
        assert_eq!(image.pixel_offset(1, 1), 21);
    }

    /// Wiping a buffer clears the samples and leaves the geometry readable.
    #[test]
    fn zeroizing_clears_the_samples_and_keeps_the_geometry() {
        let mut image = ImageBuffer::new(vec![0xAAu8; 12], 4, 3, ColorSpace::Luma8);

        image.pixels_mut()[0] = 0xFF;
        assert!(image.pixels().iter().any(|&sample| sample != 0));

        image.zeroize();

        assert!(image.pixels().iter().all(|&sample| sample == 0));
        assert_eq!(image.dimensions(), (4, 3));
        assert_eq!(image.color_space(), ColorSpace::Luma8);
    }
}
