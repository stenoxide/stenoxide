//! Prototype: a container that is *generated around* the payload rather than
//! modified to hold it, which makes detection provably impossible rather than
//! merely hard.
//!
//! # The idea
//!
//! Embedding into an existing image always changes it, and a change is a thing
//! a detector can hunt for. The reason it is hard to find is statistical, and
//! statistics can be improved on.
//!
//! When the container is generated, the sender knows the cover distribution
//! exactly, and can do something an embedder cannot: draw each sample *from
//! that distribution, conditioned on its least significant bit being the
//! ciphertext bit it must carry*. Rejection sampling does it in about two
//! draws. If the LSB of the unconditioned distribution is a fair coin, then
//!
//!     P(sample = v | bit) * P(bit) summed over bit  =  P(sample = v)
//!
//! exactly: the generated container and an ordinary one are draws from the same
//! distribution, so no detector -- neural, statistical, or one invented in fifty
//! years -- separates them better than a coin toss. Not "hard to detect": the
//! two hypotheses are identical, and there is nothing there to detect.
//!
//! The condition is the fairness of that coin. For the grain this generator
//! uses, `floor(c + N(0, 2))`, the bias of the LSB is around `1e-34` -- it
//! decays as `exp(-2 pi^2 sigma^2)` -- against a container holding some `1e7`
//! samples. The margin is twenty-seven orders of magnitude.
//!
//! # What this buys beyond undetectability
//!
//! The `0.02` bpp cap exists because a real photograph's distribution is
//! unknown, so every change risks being visible against a model the attacker
//! has and the sender does not. Here the sender *is* the distribution, and the
//! rate is irrelevant to security: every sample carries a bit. That is 1.5 MB
//! in a 2000x2000 container against roughly 7 KB today.
//!
//! # Resolving the circularity
//!
//! The key is derived from a hash of the container, and the container now
//! depends on the ciphertext, which depends on the key. The knot unties because
//! the perceptual hash is built to be blind to exactly this: it reads a 32x32
//! thumbnail, where four thousand grain samples average away, and layer 1
//! refuses any container whose coefficients sit within `5.0` of the median. So
//! a draft container fixes the hash, the hash fixes the key, and the final
//! container is verified to hash the same -- which it does, because the grain
//! cannot move a coefficient that far.
//!
//! Run with:
//!
//! ```sh
//! cargo run --release --example generative_stego --features test-utils -- <out-dir> <count>
//! ```
//!
//! Half the containers are generated around a payload and half around random
//! bits, named alike, so a detector can be pointed at the directory blind.

use std::f32::consts::TAU;
use std::path::{Path, PathBuf};

use image::{ImageFormat, RgbImage};
use rand::rngs::StdRng;
use rand::{RngExt, SeedableRng};
use stenoxide_core::crypto::aead::{compress_and_encrypt, decrypt_and_decompress,
                                   XChaCha20Poly1305Cipher};
use stenoxide_core::crypto::expand::expand_master_key;
use stenoxide_core::crypto::kdf::{Argon2Kdf, KeyDeriver};
use stenoxide_core::cost::hill::HillCostProvider;
use stenoxide_core::cost::CostProvider;
use stenoxide_core::image_io::phash::{compute_stable_phash, PHashSalt};
use stenoxide_core::image_io::validate::load_and_validate;
use stenoxide_core::test_support::incompressible_payload;

/// Side length of the containers, in pixels.
const SIDE: u32 = 2000;
/// Control-grid resolution of the low-frequency field.
const FIELD_GRID: usize = 32;
/// Peak deviation of the field from mid grey, in levels.
const FIELD_AMPLITUDE: f32 = 95.0;
/// Share of a cell spent easing between control values.
const FIELD_EDGE_WIDTH: f32 = 0.25;
/// Standard deviation of the grain, in levels. The security parameter: the
/// LSB bias decays as `exp(-2 pi^2 sigma^2)`, so this is what makes the coin
/// fair. Anything below about 1.5 starts to leak.
const GRAIN_SIGMA: f32 = 2.0;
/// Field seeds tried before giving up on the perceptual-hash gate.
const MAX_FIELD_CANDIDATES: u64 = 64;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let out_dir = PathBuf::from(args.get(1).map_or("generative-out", String::as_str));
    let count: u64 = args.get(2).and_then(|a| a.parse().ok()).unwrap_or(10);

    std::fs::create_dir_all(&out_dir).expect("output directory should be creatable");

    // Incompressible, and large enough to fill a serious share of the
    // container: a short message would leave 99.99% of the samples drawn
    // freely and make any indistinguishability test trivially easy to pass.
    let payload_bytes: usize = args.get(3).and_then(|a| a.parse().ok()).unwrap_or(1_000_000);
    let message = incompressible_payload(payload_bytes);
    let password = b"prototype-password-not-a-real-secret".to_vec();

    for index in 0..count {
        let seed = 7_000 + index * 128;
        let path = out_dir.join(format!("image_{index:02}.png"));

        // Half carry a message, half carry nothing but random bits. Both are
        // generated by the same code path, which is the point: the carrier
        // bits are ciphertext in one case and noise in the other, and
        // ciphertext is indistinguishable from noise.
        let loaded = index % 2 == 0;
        if loaded {
            let recovered = generate_and_verify(&path, seed, &message, &password);
            assert_eq!(recovered, message, "round trip must recover the message");
            println!("image_{index:02}.png  payload {} B  round trip OK", message.len());
        } else {
            generate_blank(&path, seed);
            println!("image_{index:02}.png  no payload");
        }
    }

    println!("\nwrote {count} containers to {}", out_dir.display());
    println!("even indices carry a message, odd ones do not");
}

/// Generates a container around `message` and reads it back out.
///
/// The receiver's side is run for real rather than asserted: the final image
/// goes to disk, comes back through `load_and_validate`, is hashed as it
/// arrived, and the payload has to authenticate under the key that hash
/// derives. That is also what verifies the circularity was resolved — a hash
/// that moved between draft and final would produce a different key, and the
/// Poly1305 tag would refuse.
fn generate_and_verify(path: &Path, seed: u64, message: &[u8], password: &[u8]) -> Vec<u8> {
    let cipher = XChaCha20Poly1305Cipher::new();
    let kdf = Argon2Kdf::low_cost_for_tests();

    for candidate in seed..seed + MAX_FIELD_CANDIDATES {
        let planes = field_planes(candidate);

        // Draft container: grain drawn freely. Its only job is to fix the hash.
        let draft = render(&planes, candidate, None);
        let Some(draft_salt) = gated_salt(&draft, path) else {
            continue;
        };

        let master = kdf.derive(password, &draft_salt).expect("derivation");
        let keys = expand_master_key(&master).expect("expansion");
        let ciphertext = compress_and_encrypt(message, keys.enc_key(), keys.nonce(), &cipher)
            .expect("encryption");

        // Final container: same field, grain conditioned on the ciphertext.
        let final_image = render(&planes, candidate, Some(&ciphertext));
        final_image
            .save_with_format(path, ImageFormat::Png)
            .expect("container should be writable");

        // From here on, only what a receiver holds: the file.
        let arrived = load_and_validate(path).expect("generated container should validate");
        let Ok(arrived_salt) = compute_stable_phash(&arrived) else {
            continue;
        };
        let arrived_master = kdf.derive(password, &arrived_salt).expect("derivation");
        let arrived_keys = expand_master_key(&arrived_master).expect("expansion");

        let carried = read_bits(&final_image, ciphertext.len());
        match decrypt_and_decompress(
            &carried,
            arrived_keys.enc_key(),
            arrived_keys.nonce(),
            &cipher,
        ) {
            Ok(plaintext) => return plaintext.to_vec(),
            // The grain moved a coefficient across the median, so the receiver
            // derived a different key. The stability gate makes this rare;
            // another field costs nothing.
            Err(_) => continue,
        }
    }

    panic!("no field passed the gates in {MAX_FIELD_CANDIDATES} candidates")
}

/// Generates a container carrying no payload, by the same code path.
fn generate_blank(path: &Path, seed: u64) {
    for candidate in seed..seed + MAX_FIELD_CANDIDATES {
        let image = render(&field_planes(candidate), candidate, None);
        if gated_salt(&image, path).is_some() {
            return;
        }
    }

    panic!("no field passed the gates in {MAX_FIELD_CANDIDATES} candidates")
}

/// Writes `image` to `path` and runs it through the real validation gates,
/// returning its salt when every gate accepts.
///
/// The image goes to disk because `load_and_validate` is the only public way
/// to obtain a validated buffer — which is the type-state pattern doing its
/// job, and it means these candidates are judged by the production path rather
/// than by a reimplementation of it.
fn gated_salt(image: &RgbImage, path: &Path) -> Option<PHashSalt> {
    image
        .save_with_format(path, ImageFormat::Png)
        .expect("container should be writable");

    let buffer = load_and_validate(path).ok()?;
    let salt = compute_stable_phash(&buffer).ok()?;
    HillCostProvider::new().compute(&buffer).ok()?;

    Some(salt)
}

/// Renders the container. With `carrier` present, every sample's least
/// significant bit is drawn to equal the corresponding ciphertext bit.
fn render(planes: &[Vec<f32>], seed: u64, carrier: Option<&[u8]>) -> RgbImage {
    let mut rng = StdRng::seed_from_u64(seed ^ 0xC0FFEE);
    let carrier_bits = carrier.map_or(0, |c| c.len() * 8);
    let mut position = 0usize;

    RgbImage::from_fn(SIDE, SIDE, |x, y| {
        let mut channels = [0u8; 3];
        for (channel, plane) in channels.iter_mut().zip(planes.iter()) {
            let base = 128.0 + sample_field(plane, x, y);

            *channel = match carrier {
                Some(bytes) if position < carrier_bits => {
                    let bit = (bytes[position / 8] >> (7 - position % 8)) & 1;
                    draw_with_lsb(&mut rng, base, bit)
                }
                _ => draw_free(&mut rng, base),
            };
            position += 1;
        }

        image::Rgb(channels)
    })
}

/// One sample of the cover distribution, unconstrained.
fn draw_free(rng: &mut StdRng, base: f32) -> u8 {
    (base + gaussian(rng, GRAIN_SIGMA)).clamp(0.0, 255.0) as u8
}

/// One sample of the cover distribution, conditioned on its LSB.
///
/// Rejection sampling, which is exact: the accepted samples are distributed as
/// the cover restricted to one parity class, and because the two classes carry
/// equal mass, mixing them over a uniform bit reproduces the cover distribution
/// itself. About two draws are needed on average.
///
/// The loop is bounded only in theory — each iteration accepts with
/// probability one half — so a cap guards against a base level pressed against
/// the clamp, where one parity could become unreachable. The field keeps every
/// base at 33 or 223, some sixteen standard deviations clear of both ends, so
/// the cap is never approached.
fn draw_with_lsb(rng: &mut StdRng, base: f32, bit: u8) -> u8 {
    for _ in 0..64 {
        let value = draw_free(rng, base);
        if value & 1 == bit {
            return value;
        }
    }

    panic!("rejection sampling failed to converge; base level is clamped")
}

/// Reads the carrier bits back out of a rendered container.
fn read_bits(image: &RgbImage, bytes: usize) -> Vec<u8> {
    let mut out = vec![0u8; bytes];

    for (position, sample) in image.as_raw().iter().enumerate().take(bytes * 8) {
        out[position / 8] |= (sample & 1) << (7 - position % 8);
    }

    out
}

/// Draws one control grid per channel.
fn field_planes(seed: u64) -> Vec<Vec<f32>> {
    let mut rng = StdRng::seed_from_u64(seed);
    (0..3).map(|_| control_grid(&mut rng)).collect()
}

/// Two-valued control grid; see `test_support` for why the extremes.
fn control_grid(rng: &mut StdRng) -> Vec<f32> {
    let side = FIELD_GRID + 1;
    (0..side * side)
        .map(|_| if rng.random_bool(0.5) { FIELD_AMPLITUDE } else { -FIELD_AMPLITUDE })
        .collect()
}

/// Interpolates the control grid: flat plateaus joined by eased shoulders.
fn sample_field(grid: &[f32], x: u32, y: u32) -> f32 {
    let scale = FIELD_GRID as f32 / SIDE as f32;
    let (fx, fy) = (x as f32 * scale, y as f32 * scale);
    let (x0, y0) = (fx as usize, fy as usize);
    let (tx, ty) = (shoulder(fx - x0 as f32), shoulder(fy - y0 as f32));

    let stride = FIELD_GRID + 1;
    let at = |gx: usize, gy: usize| grid.get(gy * stride + gx).copied().unwrap_or(0.0);

    let top = at(x0, y0) * (1.0 - tx) + at(x0 + 1, y0) * tx;
    let bottom = at(x0, y0 + 1) * (1.0 - tx) + at(x0 + 1, y0 + 1) * tx;
    top * (1.0 - ty) + bottom * ty
}

/// The eased shoulder: flat outside the middle `FIELD_EDGE_WIDTH` of a cell.
fn shoulder(t: f32) -> f32 {
    let eased = ((t - 0.5) / FIELD_EDGE_WIDTH + 0.5).clamp(0.0, 1.0);
    eased * eased * (3.0 - 2.0 * eased)
}

/// One normal sample by Box-Muller, cosine half only.
fn gaussian(rng: &mut StdRng, sigma: f32) -> f32 {
    let uniform: f32 = rng.random_range(f32::EPSILON..1.0);
    let angle: f32 = rng.random_range(0.0..TAU);
    sigma * (-2.0 * uniform.ln()).sqrt() * angle.cos()
}
