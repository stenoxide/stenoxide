//! Which families of synthetic texture does `stenoxide` actually accept?
//!
//! The generative construction is indifferent to what the container looks like
//! — its security comes from the grain's amplitude, not from the picture — so
//! the appearance is free to be chosen on other grounds. What is not free is
//! the perceptual-hash gate, which is far pickier than it first appears.
//!
//! # What the hash gate really demands
//!
//! `compute_stable_phash` reduces the container to a 32x32 thumbnail, takes its
//! DCT, and compares 64 AC coefficients against their own median, requiring all
//! but at most one to sit `5.0` clear of it. That is a demand for energy spread
//! **across the whole spectrum of the thumbnail**, and it rules out more than
//! smooth images: fractal noise, whose power falls as `1/f`, piles its energy
//! into the lowest coefficients and leaves the rest clustered around a near-zero
//! median — the same failure a clear sky produces, arrived at from the opposite
//! direction.
//!
//! So this harness generates several textures with deliberately different
//! spectra, runs each through the production gates, and reports which survive
//! and why the others do not.
//!
//! Run with:
//!
//! ```sh
//! cargo run --release --example container_families --features test-utils -- <out-dir>
//! ```

use std::f32::consts::TAU;
use std::path::{Path, PathBuf};

use image::{ImageFormat, RgbImage};
use rand::rngs::StdRng;
use rand::{RngExt, SeedableRng};
use stenoxide_core::cost::hill::HillCostProvider;
use stenoxide_core::cost::CostProvider;
use stenoxide_core::image_io::phash::compute_stable_phash;
use stenoxide_core::image_io::validate::load_and_validate;
use stenoxide_core::stego::sizer::{compute_capacity, EmbeddingMode};

/// Side length of every candidate, in pixels.
const SIDE: u32 = 2000;
/// Grain standard deviation, in levels. The security parameter of the
/// generative construction; held fixed so the families differ only in texture.
const GRAIN_SIGMA: f32 = 2.0;
/// Seeds tried per family before it is declared unusable.
const ATTEMPTS: u64 = 8;

/// A texture family: a name and a function from coordinates to a colour.
struct Family {
    name: &'static str,
    describe: &'static str,
    render: fn(&Noise, u32, u32) -> [f32; 3],
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let out_dir = PathBuf::from(args.get(1).map_or("families-out", String::as_str));
    std::fs::create_dir_all(&out_dir).expect("output directory should be creatable");

    let families = [
        Family {
            name: "mosaic",
            describe: "the current generator: two-valued cells, eased shoulders",
            render: mosaic,
        },
        Family {
            name: "fbm",
            describe: "fractal noise, 1/f spectrum — the obvious 'clouds' choice",
            render: fbm,
        },
        Family {
            name: "warped",
            describe: "fbm with domain warping — marble, organic contours",
            render: warped,
        },
        Family {
            name: "cellular",
            describe: "worley/voronoi cells — stone, skin, leather",
            render: cellular,
        },
        Family {
            name: "flat_spectrum",
            describe: "band-limited noise with a deliberately flat spectrum",
            render: flat_spectrum,
        },
        Family {
            name: "foliage",
            describe: "high-frequency detail over a coarse field — gravel, leaves",
            render: foliage,
        },
    ];

    println!("{:<16}{:<10}{:<44}capacity", "family", "verdict", "reason");
    println!("{}", "-".repeat(94));

    for family in &families {
        let mut verdict = String::from("no seed passed");
        let mut capacity = String::from("-");

        for seed in 0..ATTEMPTS {
            let noise = Noise::new(seed);
            let image = render_family(family, &noise, seed);
            let path = out_dir.join(format!("{}.png", family.name));

            match judge(&image, &path) {
                Ok(bytes) => {
                    verdict = "ACCEPTED".to_string();
                    capacity = format!("~{:.1} KB", bytes as f32 / 1024.0);
                    save_thumbnail(&image, &out_dir, family.name);
                    break;
                }
                Err(reason) => verdict = reason,
            }
        }

        let shown = if verdict == "ACCEPTED" { "ACCEPTED" } else { "refused" };
        let reason = if verdict == "ACCEPTED" { family.describe.to_string() } else { verdict };
        println!("{:<16}{:<10}{:<44}{}", family.name, shown, truncate(&reason, 43), capacity);
    }

    println!("\nContainers and 400x400 thumbnails in {}", out_dir.display());
}

/// Runs a candidate through the production gates, returning its capacity.
fn judge(image: &RgbImage, path: &Path) -> Result<usize, String> {
    image
        .save_with_format(path, ImageFormat::Png)
        .map_err(|err| format!("unwritable: {err}"))?;

    let buffer = load_and_validate(path).map_err(|err| shorten(&err.to_string()))?;
    compute_stable_phash(&buffer).map_err(|err| shorten(&err.to_string()))?;
    let cost_map = HillCostProvider::new()
        .compute(&buffer)
        .map_err(|err| shorten(&err.to_string()))?;

    Ok(compute_capacity(&cost_map, EmbeddingMode::Symmetric).available_bytes())
}

/// Keeps the reported reason to the width of the table.
fn shorten(message: &str) -> String {
    message.split(';').next().unwrap_or(message).trim().to_string()
}

fn truncate(text: &str, width: usize) -> String {
    if text.len() <= width {
        text.to_string()
    } else {
        format!("{}...", &text[..width.saturating_sub(3)])
    }
}

/// Renders one family, adding the grain every family shares.
fn render_family(family: &Family, noise: &Noise, seed: u64) -> RgbImage {
    let mut rng = StdRng::seed_from_u64(seed ^ 0x9E37_79B9);

    RgbImage::from_fn(SIDE, SIDE, |x, y| {
        let base = (family.render)(noise, x, y);
        let mut channels = [0u8; 3];

        for (channel, level) in channels.iter_mut().zip(base.iter()) {
            *channel = (level + gaussian(&mut rng, GRAIN_SIGMA)).clamp(4.0, 251.0) as u8;
        }

        image::Rgb(channels)
    })
}

/// Writes a 400x400 view so the families can be compared by eye.
fn save_thumbnail(image: &RgbImage, dir: &Path, name: &str) {
    image::imageops::resize(image, 400, 400, image::imageops::FilterType::Lanczos3)
        .save_with_format(dir.join(format!("{name}_thumb.png")), ImageFormat::Png)
        .expect("thumbnail should be writable");
}

// ---------------------------------------------------------------- textures

/// The generator in `test_support`: two-valued cells with eased shoulders.
fn mosaic(noise: &Noise, x: u32, y: u32) -> [f32; 3] {
    let cell = SIDE as f32 / 32.0;
    let mut out = [0.0; 3];

    for (channel, slot) in out.iter_mut().enumerate() {
        let gx = (x as f32 / cell).floor();
        let gy = (y as f32 / cell).floor();
        let tx = shoulder((x as f32 / cell).fract());
        let ty = shoulder((y as f32 / cell).fract());

        let at = |ix: f32, iy: f32| {
            if noise.hash(ix as i32, iy as i32, channel as i32) & 1 == 0 { 95.0 } else { -95.0 }
        };

        let top = at(gx, gy) * (1.0 - tx) + at(gx + 1.0, gy) * tx;
        let bottom = at(gx, gy + 1.0) * (1.0 - tx) + at(gx + 1.0, gy + 1.0) * tx;
        *slot = 128.0 + top * (1.0 - ty) + bottom * ty;
    }

    out
}

/// Fractal Brownian motion: the textbook "clouds", with a 1/f spectrum.
fn fbm(noise: &Noise, x: u32, y: u32) -> [f32; 3] {
    let mut out = [0.0; 3];

    for (channel, slot) in out.iter_mut().enumerate() {
        *slot = 128.0 + 70.0 * noise.fbm(x as f32 / 180.0, y as f32 / 180.0, channel as i32, 5, 0.5);
    }

    out
}

/// fBm sampled through an fBm-displaced coordinate field: marble, contours.
fn warped(noise: &Noise, x: u32, y: u32) -> [f32; 3] {
    let (fx, fy) = (x as f32 / 200.0, y as f32 / 200.0);
    let wx = fx + 2.4 * noise.fbm(fx, fy, 7, 4, 0.5);
    let wy = fy + 2.4 * noise.fbm(fx + 5.2, fy + 1.3, 7, 4, 0.5);

    let mut out = [0.0; 3];
    for (channel, slot) in out.iter_mut().enumerate() {
        *slot = 128.0 + 75.0 * noise.fbm(wx, wy, channel as i32, 4, 0.55);
    }

    out
}

/// Worley cells: distance to the nearest of a scattered set of feature points.
fn cellular(noise: &Noise, x: u32, y: u32) -> [f32; 3] {
    let scale = 55.0;
    let (fx, fy) = (x as f32 / scale, y as f32 / scale);
    let (cx, cy) = (fx.floor() as i32, fy.floor() as i32);
    let mut nearest = f32::MAX;

    for oy in -1..=1 {
        for ox in -1..=1 {
            let (gx, gy) = (cx + ox, cy + oy);
            let px = gx as f32 + noise.unit(gx, gy, 11);
            let py = gy as f32 + noise.unit(gx, gy, 13);
            nearest = nearest.min((fx - px).hypot(fy - py));
        }
    }

    let level = 128.0 + 150.0 * (nearest - 0.45);
    [level, level * 0.97 + 4.0, level * 0.92 + 9.0]
}

/// Band-limited noise whose octaves are weighted to flatten the spectrum.
///
/// The point of the family: `1/f` content fails the hash gate because the high
/// thumbnail coefficients starve. Weighting the octaves the other way feeds
/// them, at the cost of looking less like a natural scene.
fn flat_spectrum(noise: &Noise, x: u32, y: u32) -> [f32; 3] {
    let mut out = [0.0; 3];

    for (channel, slot) in out.iter_mut().enumerate() {
        // Gain above one: each finer octave contributes more, not less.
        *slot = 128.0
            + 60.0 * noise.fbm(x as f32 / 240.0, y as f32 / 240.0, channel as i32, 6, 1.35);
    }

    out
}

/// Coarse field with fine detail on top: gravel, foliage, fabric.
fn foliage(noise: &Noise, x: u32, y: u32) -> [f32; 3] {
    let mut out = [0.0; 3];

    for (channel, slot) in out.iter_mut().enumerate() {
        let coarse = noise.fbm(x as f32 / 260.0, y as f32 / 260.0, channel as i32, 3, 0.5);
        let fine = noise.fbm(x as f32 / 9.0, y as f32 / 9.0, channel as i32 + 3, 3, 0.6);
        *slot = 128.0 + 55.0 * coarse + 38.0 * fine;
    }

    out
}

/// The eased shoulder of the mosaic family.
fn shoulder(t: f32) -> f32 {
    let eased = ((t - 0.5) / 0.25 + 0.5).clamp(0.0, 1.0);
    eased * eased * (3.0 - 2.0 * eased)
}

// ------------------------------------------------------------------- noise

/// Integer-hashed value noise. Self-contained so the harness pulls in nothing.
struct Noise {
    seed: u64,
}

impl Noise {
    fn new(seed: u64) -> Self {
        Self { seed: seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1 }
    }

    /// A well-mixed integer hash of a lattice point.
    fn hash(&self, x: i32, y: i32, channel: i32) -> u64 {
        let mut h = self.seed
            ^ (x as i64 as u64).wrapping_mul(0xA24B_AED4_963E_E407)
            ^ (y as i64 as u64).wrapping_mul(0x9FB2_1C65_1E98_DF25)
            ^ (channel as i64 as u64).wrapping_mul(0xD6E8_FEB8_6659_FD93);
        h ^= h >> 32;
        h = h.wrapping_mul(0xD6E8_FEB8_6659_FD93);
        h ^= h >> 29;
        h
    }

    /// A lattice value in `[0, 1)`.
    fn unit(&self, x: i32, y: i32, channel: i32) -> f32 {
        (self.hash(x, y, channel) >> 40) as f32 / 16_777_216.0
    }

    /// A lattice value in `[-1, 1)`.
    fn signed(&self, x: i32, y: i32, channel: i32) -> f32 {
        self.unit(x, y, channel) * 2.0 - 1.0
    }

    /// Smoothly interpolated value noise at one frequency.
    fn value(&self, x: f32, y: f32, channel: i32) -> f32 {
        let (x0, y0) = (x.floor(), y.floor());
        let (tx, ty) = (smoothstep(x - x0), smoothstep(y - y0));
        let (ix, iy) = (x0 as i32, y0 as i32);

        let top = self.signed(ix, iy, channel) * (1.0 - tx)
            + self.signed(ix + 1, iy, channel) * tx;
        let bottom = self.signed(ix, iy + 1, channel) * (1.0 - tx)
            + self.signed(ix + 1, iy + 1, channel) * tx;

        top * (1.0 - ty) + bottom * ty
    }

    /// Octave sum. `gain` below one gives the natural `1/f` falloff; above one
    /// deliberately over-weights the fine detail.
    fn fbm(&self, x: f32, y: f32, channel: i32, octaves: u32, gain: f32) -> f32 {
        let (mut sum, mut amplitude, mut frequency, mut norm) = (0.0, 1.0, 1.0, 0.0);

        for octave in 0..octaves {
            sum += amplitude * self.value(x * frequency, y * frequency, channel + octave as i32 * 31);
            norm += amplitude;
            amplitude *= gain;
            frequency *= 2.0;
        }

        sum / norm
    }
}

/// The classic `3t^2 - 2t^3` ease.
fn smoothstep(t: f32) -> f32 {
    t * t * (3.0 - 2.0 * t)
}

/// One normal sample by Box-Muller, cosine half only.
fn gaussian(rng: &mut StdRng, sigma: f32) -> f32 {
    let uniform: f32 = rng.random_range(f32::EPSILON..1.0);
    let angle: f32 = rng.random_range(0.0..TAU);
    sigma * (-2.0 * uniform.ln()).sqrt() * angle.cos()
}
