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

When there is no usable photograph to hide a message in, `stenoxide generate`
builds a container around the message instead. It is a last resort with a
narrow guarantee, and it is described under [Generate](#generate).

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

> **Read [OPSEC.md](OPSEC.md) before using this for anything that matters.**
> The guarantees above hold under conditions this tool cannot enforce for you,
> and one of them is absolute: **never use the same image and the same password
> for two different messages.** The key and the nonce are both derived from that
> pair, so reusing it breaks the encryption outright. There is no warning and no
> recovery.

## Installation

### CLI

```sh
cargo install stenoxide-cli
```

Prebuilt binaries for Linux (`x86_64`), Windows (`x86_64`) and macOS (Apple
silicon) are attached to every [GitHub
release](https://github.com/stenoxide/stenoxide/releases) if you would rather
not compile.

### Library

```sh
cargo add stenoxide-core
```

## Usage

`embed` and `extract` read the password from the terminal with echo disabled.
Neither the password nor the message is ever passed as an argument, so nothing
sensitive reaches the shell history or the process table. Both validate the
container before asking for anything, so an unusable image is refused before you
type a passphrase — and so is a payload path that cannot be read, or an output
file that already exists.

### Scan

Whether a photo can be used as a container is not something you can tell by
looking at it, so ask:

```sh
stenoxide scan ./photos
```

The path may be a file, a directory or a glob pattern, and defaults to the
working directory. `--recursive` descends into subdirectories, `--all` also
lists the images that were rejected and why, and `--json` writes a document a
script can parse instead of a listing.

```text
Scanning ./photos ...

  ✓ photos/landscape.png         3840x2160   ~74.2 KB payload
  ✗ photos/portrait.jpg          UnsupportedFormat
  ✗ photos/logo.png              ImageTooSmall 400x400

  * Estimated payload capacity after encryption overhead
  Summary: 1 valid, 2 invalid (3 scanned)
```

The capacity shown is what the container admits after encryption. The message is
compressed first, so ordinary text usually fits at two or three times that
figure.

A recursive scan of a large folder shows a progress bar with a time estimate
while it works. The estimate is measured in megapixels rather than in files,
because that is what the analysis costs: a folder mixing snapshots with
hundred-megapixel exports would otherwise sit at 90% and then take longer than
the first 90% did. Progress is written to standard error and only when that is a
terminal, so `--json` and redirected output are never touched by it.

### Embed

The message is read from standard input, so it can be piped in:

```sh
echo "secret message" | stenoxide embed --input photo.png --output stego.png
```

Or typed, by running the command on its own. `embed` then says so and waits;
finish the message with a line containing a single dot:

```text
$ stenoxide embed --input photo.png --output stego.png
Password:
Message to hide. It may span as many lines as you need.
Finish with a line containing a single dot:  .
Meet me at six.
Bring the other half.
.
Read 38 bytes.
```

Typing it is the more private of the two: a message given to `echo` is a
command line like any other and stays in the shell's history, while nothing
typed here does. End of file — `Ctrl+D`, or `Ctrl+Z` then `Enter` on Windows —
also ends the message, but the dot is what the prompt offers because
PowerShell's line editor keeps `Ctrl+Z` for itself and never delivers it.

The payload does not have to be text. It never did — what is hidden is bytes,
and the pipeline has always compressed and encrypted whatever it was handed —
so `--payload` names a file of any kind and reads it instead of standard input:

```sh
stenoxide embed --input photo.png --output stego.png --payload secret.zip
```

Capacity is what stops this from being as useful as it sounds. A 3000x3000
container carries about 22 KB once encrypted, so a text file, a key, a small
document or a short archive fit comfortably; a photograph, an installer or
anything already compressed does not. Text shrinks a great deal before it is
measured and binary data usually does not, which is why the refusal quotes the
size of the *compressed* payload rather than the size of your file. Ask
`stenoxide scan` what a container can carry before choosing one.

When `--payload` is given, standard input is not read at all, and a path that
does not exist, names a folder, or is empty is refused before the passphrase is
asked for.

### Generate

Every requirement above assumes a photograph, and some people do not have one:
a camera that only writes JPEG, no comfortable way to move pictures across from
a phone. JPEG and HEIC are refused at the door — they are lossy and leave the
8x8 grid the detector looks for — and converting one to PNG does not remove it.
For that user, `generate` builds a container around the message rather than
hiding the message inside a container:

```sh
stenoxide generate --output container.png --input message.txt
```

It is a different construction, not a convenience. Each sample of the image is
drawn from the texture's own distribution *conditioned* on the ciphertext bit it
carries, so a container holding a message and one holding nothing are draws from
the same distribution: there is nothing for a detector to separate, whatever it
is trained on. That also lifts the rate cap, which exists only because a
photograph's statistics are unknown to the sender — here every sample carries a
bit:

| | embedding into a photograph | generating around the payload |
|---|---|---|
| capacity, 2000x2000 | ~8 KB | **1.45 MB** |
| samples changed | a few thousand | none — nothing is changed |
| optimal detector | hard to beat | **provably a coin toss** |

**It hides which, not whether.** What it equalises is "generated around a
message" against "generated around nothing". It says nothing about "generated"
against "photographed": the container looks like a synthetic texture, and a
folder full of them is conspicuous in a way no property of any single file is.
Against "which of these hundred carries the message?" it is a complete answer;
against "why do you have this folder?" it is no answer at all. Use a photograph
of your own that has never been published whenever you have one.

`extract` reads both kinds of container without being told which it was given,
and fails identically on both.

### Extract

```sh
stenoxide extract --input stego.png
stenoxide extract --input stego.png --payload-out secret.zip
```

Without `--payload-out`, extraction writes the recovered message to standard
output as raw bytes. With it, the payload goes to the file instead, nothing is
printed, and the exit code is the only thing to check.

The path is yours to choose in full: nothing about the original file name is
hidden with the payload, so the sender has no say in what lands on your disk.
Only the extension is recovered, from the leading bytes of the content against
a fixed table — so `--payload-out recovered` writes `recovered.zip` for an
archive and `recovered.txt` for text, and a directory receives a file named
`payload.<ext>` inside it. An extension you write yourself is always used
exactly as written.

An existing file is never overwritten; `--force` is what authorises it. Every
other failure — wrong password, image carrying nothing, damaged payload, a disk
that filled up mid-write — is reported with the same sentence. Telling them
apart is the oracle an attacker holding an intercepted image is looking for.

## Requirements

The container image has to satisfy four conditions, and `stenoxide scan` checks
all of them for you. Each one exists for a reason, and none of them is a
preference:

| Requirement | Why |
|-------------|-----|
| **PNG**, or any lossless format | The payload lives in the least significant bits of the samples. A lossy codec rewrites exactly those, so a container saved as JPEG or WebP is a destroyed payload rather than a weakened one. |
| **Never JPEG-compressed**, even if it is a PNG now | Decoding a JPEG and re-saving it as PNG keeps the pixels the codec produced, 8x8 block grid included. A steganalyst already knows the statistics of that grid, so anything added on top of it stands out against a signal they can model. |
| **Between 2000x2000 and 128 megapixels** | The embedding rate is capped at 0.02 bits per pixel, and that cap is what keeps the changes invisible. Capacity is therefore a direct function of pixel count: four megapixels buy about 8 KB. Below the minimum there is no useful payload left to carry without raising the rate, and the rate is not negotiable. The upper bound is memory: the analysis costs about sixteen bytes per pixel at its peak, so a larger image is refused rather than left to exhaust the machine. |
| **Natural texture**: foliage, fabric, stone, grass | A change can only hide where there is already detail to hide it in. Smooth regions — sky, walls, skin, plain backgrounds — offer nothing to hide behind, and an image that is smooth throughout also fails to hash reproducibly, which the key derivation depends on. |

One more condition the tool cannot check: **the container must not exist
anywhere else.** An adversary who finds the original subtracts the two images
and sees every changed pixel at once. See [OPSEC.md](OPSEC.md), which explains
each of these in full.

If nothing you own satisfies all of them, [Generate](#generate) is the way
through, with the limitation described there.

## Crates

| Crate | Description |
|-------|-------------|
| [stenoxide-core](stenoxide-core/) | Core library: validation, cryptography, cost analysis and embedding |
| [stenoxide-cli](stenoxide-cli/) | Command-line interface, installed as `stenoxide` |

## Development

```sh
# Run the test suite
cargo test --workspace

# Run tests with coverage
cargo llvm-cov --workspace --lcov --output-path lcov.info
cargo llvm-cov report --html
```

Coverage is a merge requirement: the line coverage of the workspace must stay at
or above 90%, and CI runs `cargo llvm-cov --workspace --fail-under-lines 90` on
every pull request. `cargo llvm-cov` is installed with
`cargo install cargo-llvm-cov --locked`.

## License

Apache-2.0. See [LICENSE](LICENSE).
