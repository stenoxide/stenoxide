//! Owned image buffer and the pixel-access abstraction used by every layer
//! above image I/O.
//!
//! An [`ImageBuffer`] can only be produced by the validation type-state in
//! [`crate::image_io::validate`]: its constructor is `pub(crate)` and the
//! intermediate states of the automaton are private to that module. Downstream
//! layers therefore receive images that are guaranteed to have passed every
//! validation gate.

use zeroize::Zeroize;

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
}

impl ImageBuffer {
    /// Builds a buffer from already validated components.
    ///
    /// Restricted to the crate on purpose: outside code must go through
    /// [`crate::image_io::validate::load_and_validate`], the only path that
    /// runs every validation gate.
    pub(crate) fn new(pixels: Vec<u8>, width: u32, height: u32, color_space: ColorSpace) -> Self {
        Self {
            pixels,
            width,
            height,
            color_space,
        }
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
