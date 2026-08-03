//! Layer 3 — adaptive cost analysis.
//!
//! Builds the HILL cost map used to steer embedding towards textured regions.
//! The `'img` lifetime carried by the cost map ties it to the borrow of the
//! validated image buffer, so the compiler — not convention — guarantees that
//! the pixels cannot be mutated while the map is alive.
//!
//! This module holds the vocabulary of the layer: the map itself and the trait
//! every cost model implements. The HILL model lives in [`hill`].

use std::fmt;
use std::marker::PhantomData;
use std::ops::Index;

use crate::image_io::buffer::{CoverSource, ImageBuffer};

pub mod hill;

/// Per-pixel embedding cost of a container image, in row-major order.
///
/// # What the lifetime buys
///
/// `'img` is the borrow of the [`ImageBuffer`] the map was computed from. The
/// map holds no reference to the image at run time — only a [`PhantomData`] —
/// but the borrow checker treats it as if it did, so for as long as a
/// `CostMap<'img>` is alive the compiler refuses every call to
/// [`CoverSource::pixels_mut`] on the source image.
///
/// That is the whole point. A cost map computed from one set of samples and
/// applied to another is silently wrong: the embedder would steer bits towards
/// regions that are no longer the textured ones, which is exactly the mistake a
/// steganalyst is looking for. Rather than keeping map and image in sync by
/// convention, the pipeline is forced to drop the map before it may touch the
/// pixels, and the invariant is checked at compile time.
pub struct CostMap<'img> {
    /// One cost per pixel, row-major, exactly `width * height` entries long.
    pub(crate) data: Vec<f32>,
    /// Width of the source image, in pixels.
    pub(crate) width: u32,
    /// Height of the source image, in pixels.
    pub(crate) height: u32,
    /// Carrier of the borrow described above; occupies no space.
    _phantom: PhantomData<&'img ImageBuffer>,
}

impl<'img> CostMap<'img> {
    /// Wraps a freshly computed cost vector as the map of `image`.
    ///
    /// The dimensions are read from `image` rather than passed in, so a map can
    /// never claim a geometry its source does not have. Callers must supply
    /// exactly `image.pixel_count()` costs, in row-major order; the constructor
    /// is `pub(crate)` because the only callers are the cost providers of this
    /// layer, which build the vector from that very count.
    pub(crate) fn new(image: &'img ImageBuffer, data: Vec<f32>) -> Self {
        let (width, height) = image.dimensions();

        Self {
            data,
            width,
            height,
            _phantom: PhantomData,
        }
    }

    /// Dimensions of the map as `(width, height)`, in pixels.
    ///
    /// Always the dimensions of the image the map was computed from.
    pub fn dimensions(&self) -> (u32, u32) {
        (self.width, self.height)
    }

    /// Number of pixels covered by the map.
    pub fn pixel_count(&self) -> usize {
        self.width as usize * self.height as usize
    }

    /// The costs as a flat row-major slice.
    ///
    /// The embedding layer consumes the map in permuted order, so it needs the
    /// raw vector rather than coordinate access.
    pub fn costs(&self) -> &[f32] {
        &self.data
    }

    /// Cost of the pixel at `(x, y)`, or `None` when the coordinates fall
    /// outside the map.
    ///
    /// The total counterpart of the [`Index`] implementation.
    pub fn get(&self, x: u32, y: u32) -> Option<f32> {
        if x >= self.width || y >= self.height {
            return None;
        }

        self.data.get(self.linear_index(x, y)).copied()
    }

    /// Offset of the pixel at `(x, y)` inside [`CostMap::data`].
    ///
    /// Not bounds-checked; both callers check the coordinates themselves.
    fn linear_index(&self, x: u32, y: u32) -> usize {
        y as usize * self.width as usize + x as usize
    }
}

impl Index<(u32, u32)> for CostMap<'_> {
    type Output = f32;

    /// Cost of the pixel at `(x, y)`.
    ///
    /// Follows the convention of every indexing implementation in the standard
    /// library and treats out-of-range coordinates as a programming error
    /// rather than as a runtime condition. Use [`CostMap::get`] wherever the
    /// coordinates come from outside the caller.
    fn index(&self, (x, y): (u32, u32)) -> &f32 {
        &self.data[self.linear_index(x, y)]
    }
}

impl fmt::Debug for CostMap<'_> {
    /// Prints the geometry of the map, never its contents.
    ///
    /// Written by hand rather than derived: a derived implementation would
    /// format several million floats, which is not what anyone putting a cost
    /// map behind `{:?}` is asking for.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CostMap")
            .field("width", &self.width)
            .field("height", &self.height)
            .field("costs", &self.data.len())
            .finish()
    }
}

/// A model that assigns an embedding cost to every pixel of a container image.
///
/// The trait exists so that the pipeline can be generic over the cost model:
/// [`hill::HillCostProvider`] is the only implementation today, but the layers
/// above never name it.
pub trait CostProvider {
    /// How this model reports an image it refuses to work with.
    type Error;

    /// Computes the cost map of `image`.
    ///
    /// The returned map borrows `image` for `'img`, which freezes its samples
    /// until the map is dropped; see [`CostMap`].
    ///
    /// # Errors
    ///
    /// Returns `Self::Error` when the image is unsuitable as a container. A
    /// cost model is entitled to refuse an image outright: producing a map for
    /// a container that cannot hide anything safely would only move the failure
    /// downstream, past the point where it can still be explained to the user.
    fn compute<'img>(&self, image: &'img ImageBuffer) -> Result<CostMap<'img>, Self::Error>;
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::image_io::buffer::ColorSpace;

    /// A 4x3 map whose cost is the linear index of the pixel.
    fn map(image: &ImageBuffer) -> CostMap<'_> {
        let costs = (0..image.pixel_count()).map(|index| index as f32).collect();

        CostMap::new(image, costs)
    }

    /// A container of the geometry the map above is built against.
    fn image() -> ImageBuffer {
        ImageBuffer::new(vec![0u8; 4 * 3], 4, 3, ColorSpace::Luma8)
    }

    /// The map takes its geometry from the image, never from its caller.
    #[test]
    fn the_map_reports_the_geometry_of_its_source() {
        let image = image();
        let map = map(&image);

        assert_eq!(map.dimensions(), image.dimensions());
        assert_eq!(map.pixel_count(), image.pixel_count());
        assert_eq!(map.costs().len(), image.pixel_count());
    }

    /// Coordinate access, in its total and its panicking form.
    #[test]
    fn coordinates_address_the_map_row_by_row() {
        let image = image();
        let map = map(&image);

        assert_eq!(map.get(0, 0), Some(0.0));
        assert_eq!(map.get(3, 0), Some(3.0));
        assert_eq!(map.get(1, 2), Some(9.0));
        assert_eq!(map[(1, 2)], 9.0);

        // Out of range on either axis is `None` rather than a wrapped lookup
        // into the next row.
        assert_eq!(map.get(4, 0), None);
        assert_eq!(map.get(0, 3), None);
    }

    /// The debug form prints the geometry and the size, never several million
    /// floats.
    #[test]
    fn the_debug_form_is_a_summary() {
        let image = image();
        let rendered = format!("{:?}", map(&image));

        assert!(rendered.contains("width: 4"), "got: {rendered}");
        assert!(rendered.contains("height: 3"), "got: {rendered}");
        assert!(rendered.contains("costs: 12"), "got: {rendered}");
        assert!(!rendered.contains("0.0"), "got: {rendered}");
    }
}
