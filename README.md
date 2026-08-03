# stenoxide

Adaptive LSB steganography with cryptographic-grade payload protection.

## What is stenoxide?

`stenoxide` hides an encrypted message inside a lossless PNG image. The message
is compressed, encrypted and authenticated before a single pixel is touched, and
the bits are then placed by a Syndrome-Trellis coder that is steered by a HILL
adaptive cost map, so the changes land in the textured regions where a detector
has the hardest time finding them. The keys come from the password and from the
image itself: nothing but the payload bits travels in the container — no header,
no salt, no nonce, no marker of any kind.

## How it works

1. **Container validation.** The image is loaded, checked for size and format,
   screened for the 8x8 grid a prior JPEG round trip leaves behind, and measured
   for perceptual stability. A type-state pattern makes the validated buffer the
   only thing downstream code can receive, so an unvalidated image cannot reach
   the embedding path even by mistake.
2. **Key derivation.** Argon2id stretches the password against a salt derived
   from a perceptual hash of the container, and HKDF-SHA3-512 expands the result
   into an encryption key, a nonce and the seed of the embedding permutation.
   The salt is never stored: the receiver recomputes it from the image.
3. **Payload protection.** The message is compressed with Zstandard at level 19
   and encrypted with XChaCha20-Poly1305. Extraction authenticates before it
   decompresses, so nothing unverified ever reaches the decoder.
4. **Adaptive cost map.** HILL assigns every pixel the cost of changing it: low
   in texture and noise, high in smooth gradients and flat areas. Images too
   smooth to carry a payload safely are rejected rather than used badly.
5. **STC embedding.** A Fisher-Yates permutation seeded from the derived key
   fixes a secret visiting order, and Syndrome-Trellis Codes embed the payload
   along it while minimising total distortion under the cost map. The embedding
   rate is capped at 0.02 bits per pixel, a compile-time constant rather than a
   parameter a caller can raise.

## Security model

**What it protects.** The payload is encrypted and authenticated, so an attacker
who suspects the image and cannot guess the password learns nothing about the
message and cannot alter it undetected. The embedding is designed for
statistical undetectability: adaptive costs, a low fixed rate and a secret
permutation are what keep the stego image close enough to the cover for a
detector to be unable to separate them.

**What it does not protect.** A compromised endpoint defeats everything here —
the message exists in plaintext on both ends. It hides nothing about the fact
that two parties exchanged an image: network metadata, timing and traffic
analysis are outside its scope. It also assumes the container is never published
elsewhere; an adversary holding the original cover can subtract the two images
and see every changed pixel, which no embedding scheme survives.

**Assumed adversary.** A forensic laboratory running convolutional steganalysis
(SRNet, YeNet and the like) against the stego image alone, without access to the
original cover, and without the password.

## Installation

### CLI

```sh
cargo install stenoxide-cli
```

### Library

```sh
cargo add stenoxide-core
```

## Usage

Both subcommands read the password from the terminal with echo disabled. Neither
the password nor the message is ever passed as an argument, so nothing sensitive
reaches the shell history or the process table.

### Embed

```sh
echo "secret message" | stenoxide embed --input photo.png --output stego.png
```

### Extract

```sh
stenoxide extract --input stego.png
```

Extraction writes the recovered message to standard output as raw bytes, and
reports every failure — wrong password, image carrying nothing, damaged payload
— with the same sentence. Telling them apart is the oracle an attacker holding
an intercepted image is looking for.

## Requirements

- PNG container image: minimum 2000x2000 pixels, with natural camera texture.
- No prior JPEG compression on the container image. A PNG saved from a JPEG
  still carries the 8x8 block grid and is refused.

## Crates

| Crate | Description |
|-------|-------------|
| [stenoxide-core](stenoxide-core/) | Core library: validation, cryptography, cost analysis and embedding |
| [stenoxide-cli](stenoxide-cli/) | Command-line interface, installed as `stenoxide` |

## License

Apache-2.0. See [LICENSE](LICENSE).
