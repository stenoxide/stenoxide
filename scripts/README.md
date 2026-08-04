# scripts

## `validate_steganalysis.sh`

The test suite proves that a payload survives a round trip. It says nothing
about the property the project exists for: that someone holding the stego image
cannot tell it apart from an ordinary picture. Only a detector can answer that,
and this script asks one.

It builds a set of container images, embeds two payloads in every container
`stenoxide` accepts, cuts the results into crops of the size the detector was
trained on, runs the [Aletheia](https://github.com/daniellerch/aletheia)
steganalysis toolkit over them, and prints a verdict. Its exit status is `0`
when nothing was detected and `1` otherwise, so it can be wired into CI as it
stands.

Nothing it does touches the repository. Aletheia is cloned into a temporary
directory outside the working tree, its dependencies go into a virtual
environment beside that clone, and the images live in a third temporary
directory that is deleted on exit.

### Requirements

| Tool | Why |
|------|-----|
| Python 3.8 or later | Builds the containers and runs Aletheia. Found on `PATH` as `python3` or `python`. Needs `venv` and `pip`, which on Debian and Ubuntu are the `python3-venv` and `python3-pip` packages. |
| `git` | Fetches Aletheia. |
| GNU Octave | Aletheia runs its spatial-domain attacks through Octave. Without it the analysis produces no scores. |
| A `stenoxide` binary | `cargo build --release`. A debug build is accepted but spends minutes on the key derivation of every embedding. |

NumPy and Pillow are installed into the virtual environment on demand.

Aletheia pins TensorFlow 2.15, which needs Python 3.11 or older and ships no
native Windows wheel. On Windows, run the script from WSL; `--skip-analysis`
exercises everything up to the detector without it.

### Running it

```sh
cargo build --release
bash scripts/validate_steganalysis.sh
```

| Option | Effect |
|--------|--------|
| `--skip-analysis` | Build the containers and run the embeddings, then stop. Neither installs nor runs Aletheia. |
| `--keep-work-dir` | Keep the temporary directory holding the covers, the stego images and Aletheia's raw output. |
| `--accept-external-licenses` | Answer Aletheia's licence prompts. Its spatial detectors are Octave code it downloads on first use, and it downloads none of it until the licence has been accepted. Without this the prompts are shown and answered by hand, which a CI run cannot do. |

| Variable | Effect |
|----------|--------|
| `STENOXIDE_BIN` | Path to the binary. Defaults to the release build, then the debug build, under `target/`. |
| `ALETHEIA_DIR` | Where Aletheia lives. An existing checkout is reused, along with the virtual environment beside it, which skips the clone and the dependency install. The path is printed at the end of every run for exactly this purpose. |
| `STENOXIDE_PASSWORD` | Password used in automated runs. |

#### About the password

`stenoxide` reads its password from the terminal and its payload from standard
input, and never the other way round, so there is no pipe to feed the password
through. Where util-linux `script` is installed the run is fully automated: the
embedding is given a pseudo-terminal, the password is written to it, and the
transcript is scrubbed of the echo afterwards. Where it is not, the prompt
appears once per container image and has to be answered by hand. Any password
will do — the images are generated, analysed and deleted inside the run.

### The containers

Five, chosen so that the run exercises the validation gates as well as the
detector:

| Image | What it is | Expected |
|-------|------------|----------|
| `textured.png` | Synthetic: a coarse random field with photographic grain on top. | Accepted |
| `mixed.png` | Synthetic: the same field over 60% of the frame, a flat ramp over the rest. | Accepted |
| `smooth.png` | Synthetic: a smooth gradient, no texture anywhere. | Rejected — perceptually unstable, which is what a container without texture looks like to the hash |
| `photo.png` | A public-domain photograph from Wikimedia Commons, distributed as PNG and cropped to size. | Accepted |
| `photo_jpeg.png` | The same photograph put through a JPEG round trip and saved as PNG again. | Rejected — the 8x8 grid survives the conversion and the artifact detector finds it |

A rejection is a result, not a failure. Two of the five are refused before any
embedding happens, and that is the validation layer doing its job; the report
lists each one with the reason the refusing layer gave.

**The photograph is the one that makes the run mean anything.** Aletheia's
detectors were trained on photographs, and handed synthetic containers alone
they return a confident-looking score with an accuracy estimate of one half —
which is the model's way of saying it cannot tell. The synthetic covers are
there to exercise the gates; the photograph is there to be judged.

The synthetic containers are not arbitrary noise. `stenoxide` derives its
Argon2id salt from a perceptual hash of the container and refuses any image
whose hash would not survive the embedding, so the generator reproduces that
measurement and searches for a seed that clears it with room to spare. Grain on
a flat background does not clear it; the coarse field underneath the grain is
what does.

Containers are cropped to 2000x2000 and never tiled up to it. Repeating a small
image makes it periodic, and a periodic image has almost no energy outside the
harmonics of its own period, which leaves most of the 64 hash coefficients piled
up around the median and gets the container refused for a reason that came from
the tiling rather than from the picture.

### The two payloads

Every accepted container is embedded into twice, and the two results are
analysed as separate images:

| Case | Payload | Rate |
|------|---------|------|
| `reference` | Forty bytes of fixed text | About `0.0001` bpp |
| `loaded` | 80% of the capacity the container reports, as random bytes | Just under `0.02` bpp |

The `loaded` case is the one that answers the question. The hard limit is
`0.02` bits per pixel, and a forty-byte payload sits two orders of magnitude
below it — a detector handed that has essentially nothing to find, so a `PASS`
on it says very little. `reference` is kept as the control the loaded case is
read against: two rows that agree say the rate did not matter, and two that
disagree locate the rate at which it starts to.

The capacity is asked of the binary rather than computed here, with
`stenoxide scan --json`, so the script cannot drift from the sizer. The payload
is random because capacity is measured *after* compression: anything with
structure would be squeezed to a few dozen bytes and embedded at the reference
rate under a different name. Random bytes do not compress, so the run reaches
the real limit of the ciphertext — and grow slightly under Zstandard, which is
why a refusal at 80% is retried once at 70% instead of failing the run.

### The crops

Aletheia's neural models are trained on the 512x512 crops of ALASKA2 and
BOSSbase. A 2000x2000 container is outside the range they were fitted on, and a
model asked about one returns a confident-looking probability with an accuracy
estimate of exactly `0.50` — which is not a finding about the image but the
shape of a model being asked a question it was not trained to answer.

So every stego image is cut into a 3x3 grid of 512x512 crops before the detector
sees it, and the score reported per image is the **median of the nine**. The
crops are taken losslessly — no resampling, no lossy re-encoding, PNG on the way
out — because any of those would alter the least significant bits the whole
analysis is about. Their positions are spread across the frame rather than tiled
from a corner: the embedding is scattered over the whole container by a secret
permutation, so nine windows sampling the frame evenly is what makes their
median a statement about the image rather than about one part of it.

The median rather than the mean, because a single crop landing on a smooth part
of the frame should move the answer by one rank and not by its whole distance.

### Reading the report

```
  Results (HILL detector):
  ┌────────────────────────┬─────────────────┬───────────┬────────┬────────────┬─────────┬─────────────┐
  │ Container              │ Payload         │ Rate      │ Score  │ Confidence │ Crops   │ Status      │
  ├────────────────────────┼─────────────────┼───────────┼────────┼────────────┼─────────┼─────────────┤
  │ photo                  │ reference: 40 B │ 0.0001    │ 0.07   │ 0.85       │ 9/9     │ PASS        │
  │ photo                  │ loaded: 18.0 KB │ 0.0162    │ 0.22   │ 0.82       │ 9/9     │ PASS        │
  └────────────────────────┴─────────────────┴───────────┴────────┴────────────┴─────────┴─────────────┘
```

**Score** is the median of the nine crops' probabilities that the image carries
a payload, under the HILL detector — the one that matters here, because HILL is
the cost function `stenoxide` embeds under. **Confidence** is the median of
Aletheia's own estimates, by its DCI-SI method, of how well that model separates
cover from stego. **Crops** is how many of the nine cleared the confidence floor;
only those feed the two medians, because letting a crop the model has no opinion
about vote on the answer is exactly the failure the floor exists to prevent.

| | Status | Meaning |
|---|--------|---------|
| fewer than 5 confident crops | `UNRELIABLE` | The model cannot tell cover from stego on this material, so its scores carry no information whichever side of the threshold they land on. Not counted either way. |
| score below 0.30 | `PASS` | The detector cannot distinguish the image from a cover. |
| score 0.30 to 0.60 | `WARN` | Borderline. Usually a statement about the container rather than about the embedding. |
| score 0.60 and above | `FAIL` | Detected. |

The overall verdict is `PASS` only when at least one image was judged and none
failed. A single `FAIL` makes the run fail. `INCONCLUSIVE`, which also exits
non-zero, means no usable score came back — either Aletheia produced none at
all, in which case the tail of its output is printed underneath and the cause is
almost always a missing dependency (Octave, usually), or no image had five crops
clearing the confidence floor.

The verdict line quotes the rate the payload was actually embedded at, not the
`0.02` bpp hard limit. Even the loaded case lands a little under the limit, and
quoting the limit would credit the run with a test it did not perform.

### What a PASS does and does not mean

The report ends with these three lines whatever the verdict, and they are worth
repeating here:

- Neural detectors (HILL, UNIWARD, LSBM) are trained against a particular source
  of covers. A model trained on images from the same camera as the container
  would score it differently.
- Classical estimators (WS, RS, SPA) depend on no trained model, so their scores
  are valid whatever the container's provenance and whatever its size.
- A `PASS` means Aletheia cannot detect the embedding. It does not mean no
  detector can.
