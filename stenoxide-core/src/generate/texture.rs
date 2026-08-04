//! The texture a generated container is drawn from, and why it looks the way
//! it does.
//!
//! # The appearance is not a choice
//!
//! The generative construction is indifferent to what the container looks like:
//! its security rests on the amplitude of the grain and on nothing else. What
//! constrains the picture is the perceptual-hash gate, and that gate is far
//! more specific than "needs texture".
//!
//! [`compute_hash_bits`] takes DCT coefficients `1..=64` of a 32x32 thumbnail in
//! **row-major** order — the whole first row, which is the pure horizontal
//! frequencies up to the highest one the thumbnail can express, then all of the
//! second. It demands energy at the thumbnail's own scale, and one thumbnail
//! pixel of a 2000-pixel container is 62.5 image pixels.
//!
//! Sweeping the scale of a random field through that range, six seeds each,
//! puts the rule beyond doubt:
//!
//! | cell size | vs thumbnail pixel | accepted |
//! |---|---|---|
//! | 12 px | 0.19x | 1/6 |
//! | 40 px | 0.64x | 4/6 |
//! | **62.5 px** | **1.00x** | **6/6** |
//! | 125 px | 2.00x | 5/6 |
//! | 500 px | 8.00x | 0/6 |
//!
//! That also explains why fractal noise, marble and foliage were refused when
//! the families were surveyed: not for looking wrong, but for putting their
//! energy in the wrong octave. A `1/f` spectrum starves the high horizontal
//! coefficients the gate reads.
//!
//! # So the scale is going to be visible
//!
//! The instructive failure of that survey was a texture that tried to hide the
//! required field under fractal noise and came out looking like the mosaic it
//! was trying to escape. The scale the gate demands cannot be concealed, so the
//! texture has to make it its **motif** rather than fight it — stone, gravel,
//! terrazzo, weave, scales, all of which are things that vary at exactly that
//! scale in nature.
//!
//! [`pebbles`](Texture::base_levels) is the best of the ones that were
//! measured: Worley cells one thumbnail pixel across, each with its own level —
//! which is what feeds the high coefficients — plus the ridge between cells,
//! which is what makes it read as polished stone.
//!
//! # There is one family, and it is not a parameter
//!
//! Exposing the choice would be a setting that can only make the result worse,
//! for the same reason [`MAX_BPP`] is a compile-time constant rather than an
//! argument: a caller cannot be in a position to judge it, and every value
//! other than the measured one is a container the gates are more likely to
//! refuse.
//!
//! [`compute_hash_bits`]: crate::image_io::phash
//! [`MAX_BPP`]: crate::stego::stc::MAX_BPP

use super::CONTAINER_SIDE;

/// Standard deviation of the grain, in levels.
///
/// The security parameter of the whole mode, and the only one. The bias of the
/// least significant bit of `floor(base + N(0, sigma))` decays as
/// `exp(-2 pi^2 sigma^2)`, so at `2.0` it sits near `1e-34` against the `1.2e7`
/// samples a container holds. The minimum that keeps the bias a thousand times
/// under the sampling noise of a container is `0.89`; this is more than double
/// it, and the margin costs nothing.
pub(crate) const GRAIN_SIGMA: f32 = 2.0;

/// Cells across the container, which is the side of the hash thumbnail.
///
/// The whole design rule in one constant: one cell per thumbnail pixel.
const CELLS: u32 = 32;

/// Cell size, in image pixels. `62.5` for a 2000-pixel container.
const CELL_SIZE: f32 = CONTAINER_SIDE as f32 / CELLS as f32;

/// Cells held in the precomputed grid along one axis.
///
/// The ring of cells outside the image is part of the pattern: a pixel in the
/// first row is nearest to a feature point that may sit above it, and a Worley
/// field missing that ring would show a seam along all four edges.
const GRID: usize = CELLS as usize + 2;

/// Peak deviation of a cell's own level from mid grey, in levels.
///
/// The quantity the hash gate actually eats: cells with independent levels are
/// what put energy in the high horizontal coefficients.
const CELL_AMPLITUDE: f32 = 150.0;

/// How steeply the ridge between two cells rises, in levels per cell unit.
const RIDGE_GAIN: f32 = 90.0;

/// Where the ridge stops rising, in levels.
///
/// A cap rather than a smooth roll-off: the ridge is a decoration on top of the
/// cell levels and must not compete with them for range.
const RIDGE_CEILING: f32 = 30.0;

/// Mid grey, in levels.
const MID_LEVEL: f32 = 128.0;

/// Correction for the mean the ridge adds, in levels.
///
/// The ridge is one-sided, so without this the texture would sit noticeably
/// brighter than mid grey and give away range at the top of the scale.
const RIDGE_BIAS: f32 = 15.0;

/// Darkest and brightest base level the texture will produce.
///
/// Both ends are twelve standard deviations of grain clear of `0` and `255`.
/// That is what makes the rejection sampler terminate: at a base level pressed
/// against the clamp one parity could become unreachable, and here neither ever
/// is.
const LEVEL_FLOOR: f32 = 24.0;

/// Companion of [`LEVEL_FLOOR`] at the top of the range.
const LEVEL_CEILING: f32 = 231.0;

/// One cell of the Worley field.
///
/// Precomputed rather than hashed per pixel. The pattern is identical either
/// way — every attribute is a pure function of the cell's integer coordinates —
/// but a container is twelve million samples and the grid is a thousand cells,
/// so hashing inside the pixel loop would do the same work four thousand times
/// over.
#[derive(Clone, Copy)]
struct Cell {
    /// Feature point, in cell units.
    x: f32,
    /// Companion of [`Cell::x`].
    y: f32,
    /// The cell's own deviation from mid grey, in levels.
    level: f32,
}

/// The pseudorandom field one container is drawn from.
///
/// Deterministic in its seed, which is what lets the draft and the final
/// container share a texture while their grain is drawn separately.
pub(crate) struct Texture {
    /// The [`GRID`] by [`GRID`] cell grid, row-major, offset by one cell so
    /// that the ring outside the image is addressable.
    cells: Vec<Cell>,
}

impl Texture {
    /// Draws the field for `seed`.
    ///
    /// The seed comes from the system CSPRNG and is not persisted anywhere; see
    /// the module documentation of [`crate::generate`] for why it is treated as
    /// key material even though the picture it produces is public.
    pub(crate) fn new(seed: u64) -> Self {
        let mixed = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1;

        let mut cells = Vec::with_capacity(GRID * GRID);
        for row in 0..GRID {
            for column in 0..GRID {
                // The grid is offset by one so that index 0 addresses the ring
                // of cells at coordinate -1.
                let gx = column as i32 - 1;
                let gy = row as i32 - 1;

                cells.push(Cell {
                    x: gx as f32 + unit(mixed, gx, gy, 11),
                    y: gy as f32 + unit(mixed, gx, gy, 13),
                    level: (unit(mixed, gx, gy, 17) - 0.5) * CELL_AMPLITUDE,
                });
            }
        }

        Self { cells }
    }

    /// The three base levels of the pixel at `(x, y)`, before grain.
    ///
    /// The two nearest feature points decide both: the nearest one lends its
    /// level, and the gap between the two is the ridge. The channels are tinted
    /// slightly differently so the container is not three copies of one plane,
    /// which is an odd thing to hand any colour-aware analysis.
    pub(crate) fn base_levels(&self, x: u32, y: u32) -> [f32; 3] {
        let fx = x as f32 / CELL_SIZE;
        let fy = y as f32 / CELL_SIZE;
        let cx = fx.floor() as i32;
        let cy = fy.floor() as i32;

        let (mut first, mut second) = (f32::MAX, f32::MAX);
        let mut nearest_level = 0.0f32;

        for oy in -1..=1 {
            for ox in -1..=1 {
                let Some(cell) = self.cell(cx + ox, cy + oy) else {
                    continue;
                };

                let distance = (fx - cell.x).hypot(fy - cell.y);
                if distance < first {
                    second = first;
                    first = distance;
                    nearest_level = cell.level;
                } else if distance < second {
                    second = distance;
                }
            }
        }

        let ridge = ((second - first) * RIDGE_GAIN).min(RIDGE_CEILING);
        let level =
            (MID_LEVEL + nearest_level + ridge - RIDGE_BIAS).clamp(LEVEL_FLOOR, LEVEL_CEILING);

        [level, level * 0.98 + 3.0, level * 0.94 + 8.0]
    }

    /// The cell at integer coordinates, or `None` outside the stored ring.
    ///
    /// Nothing inside the image can ask for a cell outside it — the ring covers
    /// every neighbour of every pixel — so the `None` arm is unreachable and
    /// exists only to keep the lookup total.
    fn cell(&self, gx: i32, gy: i32) -> Option<Cell> {
        let column = usize::try_from(gx + 1).ok()?;
        let row = usize::try_from(gy + 1).ok()?;

        if column >= GRID || row >= GRID {
            return None;
        }

        self.cells.get(row * GRID + column).copied()
    }
}

/// A value in `[0, 1)` from the integer hash of a cell coordinate.
fn unit(seed: u64, x: i32, y: i32, channel: i32) -> f32 {
    // The top 24 bits, which is exactly the resolution of an `f32` mantissa;
    // taking more would only produce values that round to the same float.
    (hash(seed, x, y, channel) >> 40) as f32 / 16_777_216.0
}

/// Integer-hashed value noise, self-contained.
///
/// Written here rather than taken from a dependency because the field needs
/// nothing but a well-mixed function of three integers, and the texture has to
/// be reproducible from its seed alone for the draft and the final container to
/// agree.
fn hash(seed: u64, x: i32, y: i32, channel: i32) -> u64 {
    let mut mixed = seed
        ^ (x as i64 as u64).wrapping_mul(0xA24B_AED4_963E_E407)
        ^ (y as i64 as u64).wrapping_mul(0x9FB2_1C65_1E98_DF25)
        ^ (channel as i64 as u64).wrapping_mul(0xD6E8_FEB8_6659_FD93);

    mixed ^= mixed >> 32;
    mixed = mixed.wrapping_mul(0xD6E8_FEB8_6659_FD93);
    mixed ^= mixed >> 29;

    mixed
}

#[cfg(test)]
mod tests {
    // The crate-wide bans on panicking helpers reach into `cfg(test)` code as
    // well. A test that cannot panic cannot fail, so they are lifted here and
    // only here.
    #![allow(clippy::expect_used)]
    #![allow(clippy::panic)]

    use super::*;

    /// The cell scale is the thumbnail scale, which is the whole design rule.
    #[test]
    fn one_cell_is_one_thumbnail_pixel() {
        assert_eq!(CELL_SIZE, CONTAINER_SIDE as f32 / 32.0);
        assert_eq!(CELL_SIZE, 62.5);
    }

    /// Every base level stays far enough from both ends of the range for both
    /// parities to be reachable at every sample.
    ///
    /// The property the rejection sampler's termination rests on, checked over
    /// the corners and the interior of a whole container rather than argued
    /// for: a single level pressed against the clamp would be a loop that never
    /// ends.
    #[test]
    fn no_base_level_approaches_the_ends_of_the_range() {
        let texture = Texture::new(0x5EED);

        // Every 37th pixel of every 37th row: coprime with the cell size in
        // both axes, so the walk lands in every phase of the pattern rather
        // than sampling the same corner of each cell.
        for y in (0..CONTAINER_SIDE).step_by(37) {
            for x in (0..CONTAINER_SIDE).step_by(37) {
                for level in texture.base_levels(x, y) {
                    assert!(
                        (LEVEL_FLOOR..=LEVEL_CEILING).contains(&level),
                        "level {level} at ({x}, {y}) is outside the safe range"
                    );
                    // Ten standard deviations of grain from either end, which
                    // is the property the sampler needs stated in the units it
                    // is threatened by.
                    assert!(level > 10.0 * GRAIN_SIGMA);
                    assert!(level < 255.0 - 10.0 * GRAIN_SIGMA);
                }
            }
        }
    }

    /// The texture is a function of its seed and of nothing else.
    ///
    /// What makes the two renders of one candidate share a field: the draft
    /// fixes the perceptual hash, and the final container has to reproduce it.
    #[test]
    fn the_field_is_reproducible_from_its_seed() {
        let first = Texture::new(7);
        let again = Texture::new(7);
        let other = Texture::new(8);

        let mut differs = false;
        for (x, y) in [(0u32, 0u32), (1, 999), (1999, 1999), (500, 1200)] {
            assert_eq!(first.base_levels(x, y), again.base_levels(x, y));
            differs |= first.base_levels(x, y) != other.base_levels(x, y);
        }

        assert!(differs, "two seeds must not produce the same field");
    }

    /// The ring outside the image is addressable and the interior is complete.
    #[test]
    fn the_grid_covers_every_neighbour_of_every_pixel() {
        let texture = Texture::new(1);

        assert!(texture.cell(-1, -1).is_some());
        assert!(texture.cell(CELLS as i32, CELLS as i32).is_some());
        assert!(texture.cell(-2, 0).is_none());
        assert!(texture.cell(0, CELLS as i32 + 1).is_none());
    }

    /// The channels are tinted rather than copied.
    #[test]
    fn the_three_planes_are_not_one_plane_repeated() {
        let levels = Texture::new(3).base_levels(640, 480);

        assert!(levels[0] != levels[1] || levels[1] != levels[2]);
    }
}
