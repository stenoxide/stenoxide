//! Research harness: emits matched (cover, stego) pairs built from the
//! synthetic container generator, so that a detector which *knows* the
//! generator can be measured against them.
//!
//! Not part of the product. Run with:
//!
//! ```sh
//! cargo run --release --example synthetic_cover_probe --features test-utils -- <out-dir> <pairs>
//! ```

use std::path::{Path, PathBuf};

use stenoxide_core::crypto::aead::XChaCha20Poly1305Cipher;
use stenoxide_core::crypto::kdf::Argon2Kdf;
use stenoxide_core::cost::hill::HillCostProvider;
use stenoxide_core::pipeline::EmbedPipeline;
use stenoxide_core::test_support::{incompressible_payload, write_stable_cover};
use zeroize::Zeroizing;

/// Payload sizes tried, largest first, until one fits.
const PAYLOAD_CANDIDATES: [usize; 5] = [7000, 6000, 5000, 4000, 3000];

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let out_dir = PathBuf::from(args.get(1).map_or("probe-out", String::as_str));
    let pairs: u64 = args.get(2).and_then(|a| a.parse().ok()).unwrap_or(8);

    std::fs::create_dir_all(&out_dir).expect("output directory should be creatable");

    // The cheap deriver: this harness studies which pixels move, and the key
    // schedule has no bearing on that.
    let pipeline = EmbedPipeline::new(
        Argon2Kdf::low_cost_for_tests(),
        XChaCha20Poly1305Cipher::new(),
        HillCostProvider::new(),
    );

    for index in 0..pairs {
        // Seeds are spaced past the generator's own 64-candidate search so two
        // pairs can never land on the same container.
        let seed = 1_000 + index * 128;
        let cover = out_dir.join(format!("cover_{index:02}.png"));
        let stego = out_dir.join(format!("stego_{index:02}.png"));

        write_stable_cover(&cover, seed);
        let embedded = embed_largest(&pipeline, &cover, &stego);
        println!("pair {index:02}: seed {seed}, payload {embedded} B");
    }

    println!("wrote {pairs} pairs to {}", out_dir.display());
}

/// Embeds the largest candidate payload the container admits.
fn embed_largest(
    pipeline: &EmbedPipeline<Argon2Kdf, XChaCha20Poly1305Cipher, HillCostProvider>,
    cover: &Path,
    stego: &Path,
) -> usize {
    for size in PAYLOAD_CANDIDATES {
        let payload = Zeroizing::new(incompressible_payload(size));
        let password = Zeroizing::new(b"research-harness-not-a-real-secret".to_vec());

        match pipeline.embed(cover, payload, password, stego) {
            Ok(_) => return size,
            Err(err) => eprintln!("  {size} B refused: {err}"),
        }
    }

    panic!("no candidate payload fitted the container")
}
