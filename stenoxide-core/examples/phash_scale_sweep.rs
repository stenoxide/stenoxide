//! What does the perceptual-hash gate actually demand of a texture?
//!
//! The generative construction does not care what the container looks like —
//! its security rests on the grain's amplitude alone — so appearance is free to
//! be chosen for plausibility. The hash gate is what constrains it, and
//! `container_families` showed the constraint is sharp: fractal noise, marble
//! and foliage are all refused as perceptually unstable while a mosaic of cells
//! and a Worley pattern sail through. That is not a fact about how "natural"
//! they look.
//!
//! The gate hashes a 32x32 thumbnail and reads DCT coefficients 1..=64 in
//! *row-major* order — the entire first row, which is the pure horizontal
//! frequencies up to the highest the thumbnail can express, then the whole
//! second row. It needs all but one of those to sit 5.0 clear of their median.
//! So it is asking for energy at the thumbnail's own scale: for a 2000px
//! container, one thumbnail pixel is 62.5 image pixels.
//!
//! This sweeps the scale of a random field through that range and reports where
//! the gate accepts, over several seeds so the answer is a rate and not an
//! anecdote. Part two applies the resulting rule to textures chosen to look
//! like something.
//!
//! Run with:
//!
//! ```sh
//! cargo run --release --example phash_scale_sweep --features test-utils -- <out-dir>
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

/// A named texture: how to render it, and what it is meant to look like.
type Recipe = (&'static str, fn(&Noise, u32, u32) -> [f32; 3], &'static str);

/// Side length of every candidate, in pixels.
const SIDE: u32 = 2000;
/// Grain standard deviation, in levels; the security parameter, held fixed.
const GRAIN_SIGMA: f32 = 2.0;
/// Seeds judged per configuration, so the result is an acceptance rate.
const SEEDS: u64 = 6;
/// One thumbnail pixel, in image pixels. The scale the gate is tuned to.
const THUMBNAIL_PIXEL: f32 = SIDE as f32 / 32.0;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let out_dir = PathBuf::from(args.get(1).map_or("sweep-out", String::as_str));
    std::fs::create_dir_all(&out_dir).expect("output directory should be creatable");

    println!("One thumbnail pixel is {THUMBNAIL_PIXEL} image pixels.\n");
    println!("Part 1 — acceptance against the scale of the random field");
    println!("{:<14}{:<14}{:>12}{:>22}", "cell (px)", "vs thumbnail", "accepted", "typical refusal");
    println!("{}", "-".repeat(62));

    for &cell in &[12.0, 25.0, 40.0, 62.5, 90.0, 125.0, 200.0, 320.0, 500.0] {
        let mut passed = 0;
        let mut reason = String::new();

        for seed in 0..SEEDS {
            let image = render(SIDE, seed, |noise, x, y| field_at(noise, x, y, cell, 95.0));
            match judge(&image, &out_dir.join("sweep_tmp.png")) {
                Ok(()) => passed += 1,
                Err(text) => reason = text,
            }
        }

        let ratio = format!("{:.2}x", cell / THUMBNAIL_PIXEL);
        let shown = if passed == SEEDS { String::new() } else { truncate(&reason, 21) };
        println!("{cell:<14}{ratio:<14}{:>12}{shown:>22}", format!("{passed}/{SEEDS}"));
    }

    println!("\nPart 2 — textures built to look like something, at the accepted scale");
    println!("{:<20}{:>12}  what it is", "texture", "accepted");
    println!("{}", "-".repeat(74));

    let recipes: [Recipe; 4] = [
        ("pebbles", pebbles, "worley cells at 62px — gravel, stone, skin"),
        ("fabric", fabric, "woven threads, horizontal detail at 62px"),
        ("bark", bark, "vertical fibres broken by 62px horizontal banding"),
        ("lichen", lichen, "fbm for looks + a 62px random field for the gate"),
    ];

    for (name, render_fn, description) in recipes {
        let mut passed = 0;
        for seed in 0..SEEDS {
            let image = render(SIDE, seed, render_fn);
            let path = out_dir.join(format!("{name}.png"));
            if judge(&image, &path).is_ok() {
                passed += 1;
                save_thumbnail(&image, &out_dir, name);
            }
        }
        println!("{name:<20}{:>12}  {description}", format!("{passed}/{SEEDS}"));
    }

    let _ = std::fs::remove_file(out_dir.join("sweep_tmp.png"));
    println!("\nThumbnails in {}", out_dir.display());
}

/// Runs a candidate through the production gates.
fn judge(image: &RgbImage, path: &Path) -> Result<(), String> {
    image
        .save_with_format(path, ImageFormat::Png)
        .map_err(|err| format!("unwritable: {err}"))?;

    let buffer = load_and_validate(path).map_err(|err| shorten(&err.to_string()))?;
    compute_stable_phash(&buffer).map_err(|err| shorten(&err.to_string()))?;
    HillCostProvider::new()
        .compute(&buffer)
        .map_err(|err| shorten(&err.to_string()))?;

    Ok(())
}

fn shorten(message: &str) -> String {
    let head = message.split(';').next().unwrap_or(message).trim();
    head.replace("image is perceptually unstable: ", "unstable, ")
        .replace(" hash bits sit within 5", " bits")
}

fn truncate(text: &str, width: usize) -> String {
    if text.len() <= width { text.to_string() } else { text[..width].to_string() }
}

/// Renders a texture with the shared grain on top.
fn render<F>(side: u32, seed: u64, texture: F) -> RgbImage
where
    F: Fn(&Noise, u32, u32) -> [f32; 3],
{
    let noise = Noise::new(seed);
    let mut rng = StdRng::seed_from_u64(seed ^ 0x9E37_79B9);

    RgbImage::from_fn(side, side, |x, y| {
        let base = texture(&noise, x, y);
        let mut channels = [0u8; 3];
        for (channel, level) in channels.iter_mut().zip(base.iter()) {
            *channel = (level + gaussian(&mut rng, GRAIN_SIGMA)).clamp(4.0, 251.0) as u8;
        }
        image::Rgb(channels)
    })
}

fn save_thumbnail(image: &RgbImage, dir: &Path, name: &str) {
    image::imageops::resize(image, 400, 400, image::imageops::FilterType::Lanczos3)
        .save_with_format(dir.join(format!("{name}_thumb.png")), ImageFormat::Png)
        .expect("thumbnail should be writable");
}

// ------------------------------------------------------------------ part 1

/// A plateaued random field of the given cell size: the sweep's subject.
fn field_at(noise: &Noise, x: u32, y: u32, cell: f32, amplitude: f32) -> [f32; 3] {
    let mut out = [0.0; 3];

    for (channel, slot) in out.iter_mut().enumerate() {
        let (gx, gy) = ((x as f32 / cell).floor(), (y as f32 / cell).floor());
        let (tx, ty) = (shoulder((x as f32 / cell).fract()), shoulder((y as f32 / cell).fract()));

        let at = |ix: f32, iy: f32| {
            if noise.hash(ix as i32, iy as i32, channel as i32) & 1 == 0 { amplitude } else { -amplitude }
        };

        let top = at(gx, gy) * (1.0 - tx) + at(gx + 1.0, gy) * tx;
        let bottom = at(gx, gy + 1.0) * (1.0 - tx) + at(gx + 1.0, gy + 1.0) * tx;
        *slot = 128.0 + top * (1.0 - ty) + bottom * ty;
    }

    out
}

// ------------------------------------------------------------------ part 2

/// Worley cells sized to the thumbnail pixel, tinted like stone.
fn pebbles(noise: &Noise, x: u32, y: u32) -> [f32; 3] {
    let scale = THUMBNAIL_PIXEL;
    let (fx, fy) = (x as f32 / scale, y as f32 / scale);
    let (cx, cy) = (fx.floor() as i32, fy.floor() as i32);
    let (mut first, mut second) = (f32::MAX, f32::MAX);
    let mut nearest_id = 0u64;

    for oy in -1..=1 {
        for ox in -1..=1 {
            let (gx, gy) = (cx + ox, cy + oy);
            let px = gx as f32 + noise.unit(gx, gy, 11);
            let py = gy as f32 + noise.unit(gx, gy, 13);
            let distance = (fx - px).hypot(fy - py);
            if distance < first {
                second = first;
                first = distance;
                nearest_id = noise.hash(gx, gy, 17);
            } else if distance < second {
                second = distance;
            }
        }
    }

    // Each cell gets its own level, which is what feeds the high horizontal
    // coefficients; the ridge between cells is what makes it look like stone.
    let cell_level = ((nearest_id >> 40) as f32 / 16_777_216.0 - 0.5) * 150.0;
    let ridge = ((second - first) * 90.0).min(30.0);
    let level = 128.0 + cell_level + ridge - 15.0;

    [level, level * 0.98 + 3.0, level * 0.94 + 8.0]
}

/// A woven look: two thread systems, the horizontal one at the gate's scale.
fn fabric(noise: &Noise, x: u32, y: u32) -> [f32; 3] {
    let cell = THUMBNAIL_PIXEL;
    let warp = ((x as f32 / 7.0) * TAU).sin() * 9.0;
    let weft = ((y as f32 / 7.0) * TAU).sin() * 9.0;
    let block = field_at(noise, x, y, cell, 70.0);

    let mut out = [0.0; 3];
    for (channel, slot) in out.iter_mut().enumerate() {
        *slot = block[channel] + warp + weft;
    }
    out
}

/// Bark: vertical fibre detail, banded horizontally at the gate's scale.
fn bark(noise: &Noise, x: u32, y: u32) -> [f32; 3] {
    let fibre = noise.fbm(x as f32 / 6.0, y as f32 / 60.0, 3, 3, 0.55) * 26.0;
    let band = field_at(noise, x, y, THUMBNAIL_PIXEL, 62.0);

    [band[0] + fibre + 6.0, band[1] + fibre, band[2] + fibre - 10.0]
}

/// Fractal noise for the eye, plus the random field the gate insists on.
///
/// The interesting one: fbm alone is refused, and adding a field at the
/// thumbnail scale is enough to rescue it without changing the impression the
/// texture gives.
fn lichen(noise: &Noise, x: u32, y: u32) -> [f32; 3] {
    let field = field_at(noise, x, y, THUMBNAIL_PIXEL, 52.0);
    let mut out = [0.0; 3];

    for (channel, slot) in out.iter_mut().enumerate() {
        let organic = noise.fbm(x as f32 / 150.0, y as f32 / 150.0, channel as i32, 5, 0.5);
        *slot = field[channel] + 46.0 * organic;
    }

    out
}

fn shoulder(t: f32) -> f32 {
    let eased = ((t - 0.5) / 0.25 + 0.5).clamp(0.0, 1.0);
    eased * eased * (3.0 - 2.0 * eased)
}

// ------------------------------------------------------------------- noise

/// Integer-hashed value noise; self-contained so the harness pulls in nothing.
struct Noise {
    seed: u64,
}

impl Noise {
    fn new(seed: u64) -> Self {
        Self { seed: seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1 }
    }

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

    fn unit(&self, x: i32, y: i32, channel: i32) -> f32 {
        (self.hash(x, y, channel) >> 40) as f32 / 16_777_216.0
    }

    fn signed(&self, x: i32, y: i32, channel: i32) -> f32 {
        self.unit(x, y, channel) * 2.0 - 1.0
    }

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

fn smoothstep(t: f32) -> f32 {
    t * t * (3.0 - 2.0 * t)
}

fn gaussian(rng: &mut StdRng, sigma: f32) -> f32 {
    let uniform: f32 = rng.random_range(f32::EPSILON..1.0);
    let angle: f32 = rng.random_range(0.0..TAU);
    sigma * (-2.0 * uniform.ln()).sqrt() * angle.cos()
}
