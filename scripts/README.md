# scripts

## `validate_steganalysis.sh`

The test suite proves that a payload survives a round trip. It says nothing
about the property the project exists for: that someone holding the stego image
cannot tell it apart from an ordinary picture. Only a detector can answer that,
and this script asks one.

It builds a set of container images, embeds a short payload in every container
`stenoxide` accepts, runs the [Aletheia](https://github.com/daniellerch/aletheia)
steganalysis toolkit over the results, and prints a verdict. Its exit status is
`0` when nothing was detected and `1` otherwise, so it can be wired into CI as
it stands.

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

### Reading the report

```
  Results (HILL detector):
  ┌───────────────────────────┬───────┬────────────┬────────────┐
  │ Image                     │ Score │ Confidence │ Status     │
  ├───────────────────────────┼───────┼────────────┼────────────┤
  │ photo.png                 │ 0.10  │ 0.90       │ PASS       │
  └───────────────────────────┴───────┴────────────┴────────────┘
```

**Score** is Aletheia's probability that the image carries a payload, under the
HILL detector — the one that matters here, because HILL is the cost function
`stenoxide` embeds under. **Confidence** is Aletheia's own estimate, by its
DCI-SI method, of how well that model separates cover from stego on this
particular image.

| | Status | Meaning |
|---|--------|---------|
| confidence below 0.60 | `UNRELIABLE` | The model cannot tell cover from stego on this container, so its score carries no information whichever side of the threshold it lands on. Not counted either way. |
| score below 0.30 | `PASS` | The detector cannot distinguish the image from a cover. |
| score 0.30 to 0.60 | `WARN` | Borderline. Usually a statement about the container rather than about the embedding. |
| score 0.60 and above | `FAIL` | Detected. |

The overall verdict is `PASS` only when at least one image was judged and none
failed. A single `FAIL` makes the run fail. `INCONCLUSIVE`, which also exits
non-zero, means no usable score came back — either Aletheia produced none at
all, in which case the tail of its output is printed underneath and the cause is
almost always a missing dependency, or every score it did produce fell below the
confidence floor.

The verdict line quotes the rate the payload was actually embedded at, not the
`0.02` bpp hard limit. A short payload lands far below the limit, and quoting
the limit would credit the run with a test it did not perform.

### What this run does not answer yet

On the containers built above, every one of Aletheia's neural detectors —
LSBM, HILL and UNIWARD alike — comes back with a probability near one and a
DCI-SI accuracy of exactly `0.50`, on the photograph as much as on the
synthetic covers. An accuracy of one half across every method and every image
is not a finding about the images; it is the shape of a detector operating
outside its range. Aletheia's models are trained on the 512x512 crops of
ALASKA2 and BOSSbase, and the containers here are 2000x2000, which is the
smallest size `stenoxide` will accept.

The one classical estimator in the table is the exception, because it does not
depend on a trained model: the Weighted-Stego attack behind the `LSBR` column
estimates a payload of zero on all three stego images.

So the script reports `INCONCLUSIVE` rather than a pass, which is the honest
answer, and the confidence floor is what stops it reporting a `FAIL` it cannot
support. Two things would make the analysis decisive, and neither is in here
yet:

- **Embed near the limit.** The payload is forty bytes, some `0.0001` bpp
  against a ceiling of `0.02`. A payload two orders of magnitude larger would
  put the embedding where the limit actually is, and give a detector something
  to find.
- **Analyse at the detector's own resolution.** Feeding it the size it was
  trained on is the only way its score means what its documentation says.
