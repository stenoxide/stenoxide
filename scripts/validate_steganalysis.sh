#!/usr/bin/env bash
#
# End-to-end steganalysis validation for stenoxide.
#
# The unit and integration suites prove that what goes in comes out. They say
# nothing about the property this project actually exists for: that a third
# party holding the stego image cannot tell it apart from an ordinary picture.
# Only a detector can answer that, so this script builds a set of containers,
# embeds into every one stenoxide accepts, and hands the results to Aletheia —
# an external steganalysis toolkit that does not know anything about how the
# payload was placed.
#
# Two things make the answer worth reading, and both are about asking the
# detector a question it can answer:
#
#   - Every container is embedded into twice: once with a few dozen bytes, and
#     once with 80% of the capacity it reports. The hard limit is 0.02 bits per
#     pixel and the small payload sits two orders of magnitude below it, so a
#     detector handed only that has nothing to find and a pass on it means
#     little. The loaded case is the one under test; the small one is the
#     control it is read against.
#   - Every stego image is cut into a 3x3 grid of 512x512 crops before the
#     detector sees it, and the score reported is the median of the nine.
#     Aletheia's models are trained at that size, and a 2000x2000 container is
#     outside the range they were fitted on.
#
# Nothing here touches the repository. Aletheia is cloned into a temporary
# directory outside the working tree, the covers and the stego images live in a
# second temporary directory that is deleted on exit, and no Rust source, no
# parameter and no build artifact is modified.
#
# Exit status:
#   0  every analysed image scored below the detection threshold
#   1  a container was detected, the environment is incomplete, or the analysis
#      produced no usable result
#
set -euo pipefail

# --------------------------------------------------------------------------
# Constants
# --------------------------------------------------------------------------

# Verdict boundaries applied to the detector's probability of steganographic
# content. Below PASS_MAX the image is indistinguishable from a cover as far as
# the detector is concerned; from FAIL_MIN upwards the detector has made up its
# mind. The band in between is reported rather than judged: it usually says
# more about the container than about the embedding.
readonly PASS_MAX=0.3
readonly FAIL_MIN=0.6

# Smallest accuracy the detector may claim for its own verdict before that
# verdict is worth reading.
#
# Aletheia prints, beside every score, its estimate of how well the model
# separates cover from stego on this particular image. One half is the value
# that estimate takes when it separates nothing, and a confident score under an
# accuracy of one half is not a detection - it is the model reporting that it
# was shown something it has no opinion about. Synthetic containers land there
# routinely, which is exactly why one real photograph is in the set.
readonly CONFIDENCE_MIN=0.6

# The reference payload: a few dozen bytes, some 0.0001 bpp against a ceiling of
# 0.02. Far too little for a detector to have anything to find, which is exactly
# what makes it useful — it is the control the loaded case is read against.
readonly REFERENCE_PAYLOAD='test payload for steganalysis validation'

# Share of the container's measured capacity the loaded case fills.
#
# The question the run exists to answer is whether the embedding is visible at
# the rate the system actually permits, and the reference payload above answers
# a different, easier one. Eighty per cent puts the embedding just under the
# limit while leaving room for the frame the pipeline writes around the payload
# and for the couple of bytes Zstandard adds to material it cannot compress.
readonly CAPACITY_SHARE=0.80

# The share retried after a refusal.
#
# The capacity `scan` reports is what the container admits *after* encryption,
# and the loaded payload is random bytes, which Zstandard makes slightly larger
# rather than smaller. Eighty per cent leaves room for that in every case
# measured, but the margin is not something this script can compute exactly
# without reimplementing the sizer, so a refusal drops to seventy and tries once
# more instead of failing the run.
readonly CAPACITY_SHARE_RETRY=0.70

# Side of the crops handed to the detector, in pixels.
#
# Not a choice. Aletheia's neural models are trained on the 512x512 crops of
# ALASKA2 and BOSSbase, and a 2000x2000 image is outside the range they were
# fitted on: handed one they return a confident-looking probability with an
# accuracy estimate of exactly one half, on a photograph as readily as on a
# synthetic cover. That is not a finding about the image, it is the shape of a
# model being asked a question it was not trained to answer.
readonly CROP_SIDE=512

# Crops taken per stego image: a 3x3 grid.
readonly CROP_COUNT=9

# Crops that must clear the confidence floor before the aggregate is read.
#
# The score reported per image is the median of its nine crops, and a median is
# only worth quoting when most of the values behind it mean something. Five of
# nine is the smallest majority.
readonly MIN_CONFIDENT_CROPS=5

# Password used when the run is fully automated.
#
# Not a secret and not treated as one. It guards four throwaway images that are
# generated, analysed and deleted inside a single run of this script, and the
# key derived from it never leaves the temporary directory. It is a fixed
# string only so that the run needs no human at the keyboard; override it with
# STENOXIDE_PASSWORD if you would rather it were something else.
readonly THROWAWAY_PASSWORD='steganalysis-validation'

# The password actually used, resolved once: the automated path writes it to a
# pseudo-terminal and then scrubs it back out of the transcript, and those two
# have to be looking at the same string.
PASSWORD=${STENOXIDE_PASSWORD:-$THROWAWAY_PASSWORD}
readonly PASSWORD

readonly ALETHEIA_REPO='https://github.com/daniellerch/aletheia'

# Minimum container side stenoxide accepts. Mirrored here so that the generator
# can size the downloaded images before handing them over, rather than learning
# about the limit from a rejection.
readonly MIN_SIDE=2000

readonly SCRIPT_NAME=${0##*/}
REPO_ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
readonly REPO_ROOT

# --------------------------------------------------------------------------
# Output helpers
# --------------------------------------------------------------------------

info() { printf '%s\n' "$*"; }
step() { printf '\n== %s\n' "$*"; }
warn() { printf 'warning: %s\n' "$*" >&2; }

die() {
    printf 'error: %s\n' "$1" >&2
    shift
    for line in "$@"; do
        printf '       %s\n' "$line" >&2
    done
    exit 1
}

usage() {
    cat <<EOF
Usage: $SCRIPT_NAME [options]

Builds a set of container images, embeds two payloads into every one stenoxide
accepts — a few dozen bytes and 80% of the container's capacity — cuts the
results into 512x512 crops, and runs the Aletheia steganalysis toolkit over
them.

Options:
  --skip-analysis    Generate the covers and run the embeddings, but do not
                     crop, install or run Aletheia. Useful to check the first
                     half of the pipeline on a machine that cannot run the
                     detector.
  --keep-work-dir    Do not delete the temporary directory holding the covers
                     and the stego images.
  --accept-external-licenses
                     Answer Aletheia's licence prompts for you. Its spatial
                     detectors are Octave code it downloads on first use, and
                     it will not download any of it until the licence has been
                     accepted. Without this the prompts are shown and have to
                     be answered by hand, which a CI run cannot do.
  -h, --help         Show this message.

Environment:
  STENOXIDE_BIN      Path to the stenoxide binary. Defaults to the release
                     build, then the debug build, under target/.
  ALETHEIA_DIR       Where to install Aletheia. An existing checkout is
                     reused; otherwise a temporary directory is created.
  STENOXIDE_PASSWORD Password handed to stenoxide in automated runs.
EOF
}

# --------------------------------------------------------------------------
# Path conversion
#
# Under an MSYS2 shell on Windows the tools invoked below are native Windows
# programs that cannot read a POSIX path. Arguments are translated by the shell
# on the way out, which covers most of it, but a path that is built inside a
# heredoc or read back from a file is not, so every path handed to another
# program goes through this first. On a real POSIX system it is the identity.
# --------------------------------------------------------------------------

native_path() {
    if command -v cygpath >/dev/null 2>&1; then
        cygpath -w -- "$1"
    else
        printf '%s' "$1"
    fi
}

# --------------------------------------------------------------------------
# Argument parsing
# --------------------------------------------------------------------------

skip_analysis=false
keep_work_dir=false
accept_licenses=false

while [[ $# -gt 0 ]]; do
    case $1 in
        --skip-analysis) skip_analysis=true ;;
        --accept-external-licenses) accept_licenses=true ;;
        --keep-work-dir) keep_work_dir=true ;;
        -h|--help) usage; exit 0 ;;
        *) usage >&2; die "unknown option: $1" ;;
    esac
    shift
done

# --------------------------------------------------------------------------
# Step 1 — environment
# --------------------------------------------------------------------------

# Locates a Python interpreter of at least 3.8.
#
# `python3` is tried first and `python` second: on Windows the two frequently
# name different installations, and the one on PATH as `python3` is not
# necessarily the one carrying the scientific stack.
resolve_python() {
    local candidate
    for candidate in python3 python; do
        if command -v "$candidate" >/dev/null 2>&1 &&
            "$candidate" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 8) else 1)' \
                >/dev/null 2>&1; then
            printf '%s' "$candidate"
            return 0
        fi
    done
    return 1
}

# Locates the stenoxide binary, preferring the release build.
#
# A debug build works but spends minutes on the Argon2id derivation of every
# embedding, so it is accepted with a warning rather than silently.
resolve_stenoxide() {
    local candidate
    if [[ -n ${STENOXIDE_BIN:-} ]]; then
        [[ -x $STENOXIDE_BIN ]] || return 1
        printf '%s' "$STENOXIDE_BIN"
        return 0
    fi

    for candidate in \
        "$REPO_ROOT/target/release/stenoxide" \
        "$REPO_ROOT/target/release/stenoxide.exe" \
        "$REPO_ROOT/target/debug/stenoxide" \
        "$REPO_ROOT/target/debug/stenoxide.exe"; do
        if [[ -x $candidate ]]; then
            printf '%s' "$candidate"
            return 0
        fi
    done
    return 1
}

step 'Checking the environment'

PYTHON=$(resolve_python) || die \
    'no Python interpreter of version 3.8 or later was found on PATH.' \
    'Install Python 3.8+ from https://www.python.org/downloads/ and make sure' \
    'it is on PATH as python3 or python.'
readonly PYTHON
info "python:    $PYTHON ($("$PYTHON" -c 'import platform; print(platform.python_version())'))"

command -v git >/dev/null 2>&1 || die \
    'git is not on PATH, and it is needed to fetch Aletheia.' \
    'Install it from https://git-scm.com/downloads.'

STENOXIDE=$(resolve_stenoxide) || die \
    'the stenoxide binary was not found.' \
    'Build it first:  cargo build --release' \
    'or point STENOXIDE_BIN at an existing binary.'
readonly STENOXIDE
info "stenoxide: $STENOXIDE"

case $STENOXIDE in
    */debug/*) warn 'using a debug build; every embedding will take minutes. cargo build --release is much faster.' ;;
esac

# How the password reaches stenoxide.
#
# The binary reads it from the terminal with echo disabled and never from
# standard input, which is where the payload comes from. There is therefore no
# pipe to feed it through: the only way to answer the prompt without a human is
# to give the process a pseudo-terminal, which util-linux `script` does. Where
# that is unavailable the run stays interactive and the prompt appears once per
# container. Where neither is possible the script stops here rather than
# hanging on a prompt nobody can answer.
PTY_RUNNER=''
if command -v script >/dev/null 2>&1 && script --version 2>&1 | grep -qi 'util-linux'; then
    PTY_RUNNER='script'
    info 'password:  supplied automatically through a pseudo-terminal'
elif [[ -e /dev/tty ]] || [[ -t 1 ]]; then
    info 'password:  read from the terminal, once per container image'
else
    die 'stenoxide reads its password from a terminal, and this session has none.' \
        'Run the script from an interactive terminal, or install util-linux' \
        '"script" so the password can be supplied through a pseudo-terminal.'
fi
readonly PTY_RUNNER

if [[ $skip_analysis == false ]] && ! command -v octave >/dev/null 2>&1; then
    warn 'GNU Octave is not on PATH. Aletheia runs its spatial-domain attacks through Octave and will fail without it.'
fi

# --------------------------------------------------------------------------
# Step 2 — working directory
#
# Created before Aletheia so that the cleanup trap covers the expensive part of
# the run, and outside the repository so that nothing here can end up staged by
# accident.
# --------------------------------------------------------------------------

WORK_DIR=$(mktemp -d)
readonly WORK_DIR
mkdir -p "$WORK_DIR/covers" "$WORK_DIR/stego" "$WORK_DIR/report"

cleanup() {
    if [[ $keep_work_dir == true ]]; then
        info "work directory kept at: $WORK_DIR"
    else
        rm -rf "$WORK_DIR"
    fi
}
trap cleanup EXIT

readonly COVERS_DIR="$WORK_DIR/covers"
readonly STEGO_DIR="$WORK_DIR/stego"
readonly CROPS_DIR="$WORK_DIR/crops"
readonly REPORT_DIR="$WORK_DIR/report"
readonly NOTES_FILE="$REPORT_DIR/covers.tsv"
readonly OUTCOMES_FILE="$REPORT_DIR/outcomes.tsv"
readonly RAW_REPORT="$REPORT_DIR/aletheia_raw.txt"

mkdir -p "$CROPS_DIR"

: >"$NOTES_FILE"
: >"$OUTCOMES_FILE"

# --------------------------------------------------------------------------
# Step 3 — Aletheia and the interpreter that runs it
# --------------------------------------------------------------------------

# Prepares an interpreter of our own, beside the Aletheia checkout.
#
# Everything Python this script needs is installed into it rather than into the
# interpreter found on PATH. Two reasons, and either would be enough: current
# Debian and Ubuntu mark the system interpreter as externally managed and
# refuse `pip install` outright, and Aletheia pins versions of NumPy and
# TensorFlow that nobody should have dropped into the interpreter they use for
# everything else.
#
# It lives next to the checkout rather than inside it — a clone needs an empty
# directory — and is therefore reused by whatever reuses ALETHEIA_DIR.
setup_interpreter() {
    if [[ -z ${ALETHEIA_DIR:-} ]]; then
        ALETHEIA_DIR="$(mktemp -d)/aletheia"
    fi

    local venv="${ALETHEIA_DIR%/}.venv"

    if [[ ! -x "$venv/bin/python" && ! -x "$venv/Scripts/python.exe" ]]; then
        info "creating a virtual environment at $venv"
        if ! "$PYTHON" -m venv "$venv" >/dev/null 2>&1; then
            warn 'python -m venv failed; falling back to the interpreter on PATH.'
            warn 'On Debian and Ubuntu the missing piece is usually the python3-venv package.'
            VENV_PYTHON=$PYTHON
            return 0
        fi
    fi

    if [[ -x "$venv/bin/python" ]]; then
        VENV_PYTHON="$venv/bin/python"
    else
        VENV_PYTHON="$venv/Scripts/python.exe"
    fi
}

# Everything installed below goes through pip, so an interpreter without it is
# not usable. Checked here rather than against the interpreter on PATH: a
# virtual environment brings its own, and requiring one from the system as well
# would refuse a machine that is in fact perfectly able to run this.
require_pip() {
    if "$VENV_PYTHON" -m pip --version >/dev/null 2>&1; then
        info "pip:         $("$VENV_PYTHON" -m pip --version | cut -d' ' -f1-2)"
        return 0
    fi

    die "pip is not available for $VENV_PYTHON." \
        'On Debian and Ubuntu it comes with the python3-venv and python3-pip' \
        'packages; elsewhere, '"$PYTHON"' -m ensurepip --upgrade installs it.'
}

install_aletheia() {
    if [[ -f "$ALETHEIA_DIR/aletheia.py" ]]; then
        info "reusing the existing checkout at $ALETHEIA_DIR"
    else
        info "cloning $ALETHEIA_REPO"
        git clone --depth=1 "$ALETHEIA_REPO" "$ALETHEIA_DIR" >/dev/null 2>&1 || die \
            "could not clone $ALETHEIA_REPO into $ALETHEIA_DIR." \
            'Check the network connection and that the directory is writable.'
    fi

    info 'installing the Python requirements (this takes a while the first time)'
    if ! (cd "$ALETHEIA_DIR" && "$VENV_PYTHON" -m pip install -r requirements.txt --quiet --disable-pip-version-check); then
        die 'the Aletheia requirements could not be installed.' \
            'Aletheia pins TensorFlow, which ships no native Windows wheel; on' \
            'Windows run this script from WSL. See INSTALL.md in the checkout at' \
            "$ALETHEIA_DIR" \
            'Pass --skip-analysis to exercise the embedding half without it.'
    fi
}

# Points the next run at the interpreter and the checkout this one built. Both
# cost a download to rebuild, and neither is deleted on exit for that reason.
print_reuse_hint() {
    info ''
    info "Aletheia lives at:  $ALETHEIA_DIR"
    info "Its interpreter at: ${ALETHEIA_DIR%/}.venv"
    info "Reuse both with:    ALETHEIA_DIR='$ALETHEIA_DIR' $0"
}

step 'Preparing the Python environment'
setup_interpreter
readonly ALETHEIA_DIR
readonly VENV_PYTHON
info "interpreter: $VENV_PYTHON"
require_pip

if [[ $skip_analysis == false ]]; then
    step 'Installing Aletheia'
    install_aletheia
fi

# --------------------------------------------------------------------------
# Step 4 — container images
# --------------------------------------------------------------------------

step 'Generating the container images'

# Pillow and NumPy build the synthetic covers and normalise the downloaded
# ones. Installed on demand rather than declared as a prerequisite: the script
# is the only thing in the repository that needs them.
if ! "$VENV_PYTHON" -c 'import numpy, PIL' >/dev/null 2>&1; then
    info 'installing numpy and Pillow'
    "$VENV_PYTHON" -m pip install --quiet --disable-pip-version-check numpy Pillow || die \
        'numpy and Pillow could not be installed for '"$VENV_PYTHON"'.'
fi

# The generator writes the covers and one tab-separated note per image
# describing where it came from. Paths travel as arguments so that the shell
# translates them for a native interpreter.
"$VENV_PYTHON" - \
    "$(native_path "$COVERS_DIR")" \
    "$(native_path "$NOTES_FILE")" \
    "$MIN_SIDE" <<'PYTHON_GENERATOR'
"""Builds the container images the validation run embeds into.

Three are synthetic and two come from one photograph fetched from Wikimedia
Commons: the photograph itself, and a copy of it put through a JPEG round trip.

The synthetic ones are not arbitrary noise. stenoxide derives its Argon2id salt
from a perceptual hash of the container and refuses any image whose hash would
not survive the embedding, which is a real constraint on what a valid cover
looks like. The generator therefore reproduces that gate and searches for a seed
that clears it, rather than producing a plausible-looking image and discovering
at embedding time that it was never usable.
"""

import io
import math
import shutil
import subprocess
import sys
import urllib.error
import urllib.request

import numpy as np
from PIL import Image

COVERS_DIR, NOTES_PATH, MIN_SIDE = sys.argv[1], sys.argv[2], int(sys.argv[3])

# Geometry of the low-frequency field underneath the grain. One control point
# per perceptual-hash thumbnail sample, so that every coefficient the hash reads
# has energy in it; two thirds of each cell flat, so the thumbnail sees the
# control values rather than a smoothed version of them.
FIELD_GRID = 32
FIELD_AMPLITUDE = 95.0
FIELD_EDGE_WIDTH = 0.25
GRAIN_SIGMA = 2.0

# The stability margin stenoxide applies to the 64 hash bits, and the margin
# this generator insists on. The gap between them absorbs the difference
# between two resamplers: the verdict here is computed with Pillow and the one
# that matters is computed by the image crate, and they agree closely but not
# to the last bit.
DELTA_MIN = 5.0
TARGET_MARGIN = 12.0

# Seeds are cheap and most of them fail. The two central AC coefficients of the
# thumbnail sit symmetrically around their own median, so acceptance comes down
# to the gap between them being wide enough, which is close to a coin toss on
# any single seed. Roughly one seed in four clears the margin above, so the
# search almost always ends within the first handful.
MAX_SEEDS = 64

USER_AGENT = "stenoxide-steganalysis-validation/1.0"

# A real photograph, and the reason the run means anything.
#
# The detector was trained on photographs, and it says so itself: handed the
# synthetic covers alone it returns a confident-looking score with an accuracy
# estimate of one half, which is a way of reporting that it cannot tell. So one
# container has to be genuine photographic content — lossless, never
# JPEG-compressed, and large enough to be used without resampling.
#
# This one is a Library of Congress digitisation of a Prokudin-Gorsky colour
# photograph: public domain, distributed as PNG, and 3307x2859, so it is
# cropped to size rather than stretched to it.
PHOTO_URL = (
    "https://upload.wikimedia.org/wikipedia/commons/1/1f/Prokudin-Gorskii-19-v2.png"
)

# Quality the laundered copy of that photograph is compressed at.
#
# The JPEG case is built here rather than downloaded. A large modern JPEG off
# Wikimedia is compressed so lightly that the block detector — correctly — does
# not fire on it, which tests nothing; a controlled round trip at this quality
# puts the blocking ratio at about 1.5 against a threshold of 1.3, far enough
# from the boundary that the fixture does not depend on the exact encoder.
LAUNDER_QUALITY = 60

notes = []


def note(name, text):
    notes.append((name, text))
    print(f"  {name}: {text}")


def shoulder(t):
    """Maps a position within a field cell onto its eased transition."""
    eased = np.clip((t - 0.5) / FIELD_EDGE_WIDTH + 0.5, 0.0, 1.0)
    return eased * eased * (3.0 - 2.0 * eased)


def sample_field(grid, side):
    """Interpolates one control grid over a square image of the given side."""
    scale = FIELD_GRID / side
    coordinate = np.arange(side, dtype=np.float32) * scale
    index = coordinate.astype(np.int32)
    weight = shoulder(coordinate - index).astype(np.float32)

    top = grid[np.ix_(index, index)] * (1.0 - weight)[None, :] + \
        grid[np.ix_(index, index + 1)] * weight[None, :]
    bottom = grid[np.ix_(index + 1, index)] * (1.0 - weight)[None, :] + \
        grid[np.ix_(index + 1, index + 1)] * weight[None, :]

    return top * (1.0 - weight)[:, None] + bottom * weight[:, None]


def textured_image(seed, side):
    """A mottled low-frequency field with photographic grain on top."""
    rng = np.random.default_rng(seed)
    planes = []
    for _ in range(3):
        grid = np.where(
            rng.random((FIELD_GRID + 1, FIELD_GRID + 1)) < 0.5,
            FIELD_AMPLITUDE,
            -FIELD_AMPLITUDE,
        ).astype(np.float32)
        grain = rng.normal(0.0, GRAIN_SIGMA, (side, side)).astype(np.float32)
        planes.append(128.0 + sample_field(grid, side) + grain)

    return np.clip(np.stack(planes, axis=-1), 0.0, 255.0).astype(np.uint8)


def gradient_plane(side, rows=None):
    """A diagonal ramp: no texture anywhere, which is the point of it."""
    rows = side if rows is None else rows
    y = np.arange(rows, dtype=np.float32)[:, None]
    x = np.arange(side, dtype=np.float32)[None, :]
    return 96.0 + 64.0 * (x + y) / (2.0 * side)


def smooth_image(side):
    ramp = gradient_plane(side)
    return np.clip(np.stack([ramp, ramp * 0.98, ramp * 1.02], axis=-1), 0.0, 255.0).astype(
        np.uint8
    )


def mixed_image(seed, side, textured_fraction=0.6):
    """Texture over the first 60% of the rows, a flat ramp over the rest."""
    image = textured_image(seed, side)
    split = int(side * textured_fraction)
    ramp = gradient_plane(side, side - split)
    image[split:] = np.clip(
        np.stack([ramp, ramp * 0.98, ramp * 1.02], axis=-1), 0.0, 255.0
    ).astype(np.uint8)
    return image


def hash_margins(image):
    """Reproduces the perceptual-hash stability measurement of stenoxide.

    Luma, a 32x32 bilinear thumbnail, an unnormalised separable DCT-II, and the
    distance of each of the 64 AC coefficients from their median.
    """
    luma = (
        0.299 * image[..., 0].astype(np.float32)
        + 0.587 * image[..., 1].astype(np.float32)
        + 0.114 * image[..., 2].astype(np.float32)
    )
    luma = np.clip(luma, 0.0, 255.0).astype(np.uint8)

    thumbnail = np.asarray(
        Image.fromarray(luma, "L").resize((32, 32), Image.BILINEAR), dtype=np.float64
    )

    n = 32
    k = np.arange(n)[:, None]
    sample = np.arange(n)[None, :]
    basis = np.cos(math.pi / n * (sample + 0.5) * k)

    coefficients = (basis @ (thumbnail @ basis.T)).reshape(-1)
    ac = coefficients[1:65]
    ordered = np.sort(ac)
    median = (ordered[31] + ordered[32]) / 2.0

    return np.abs(ac - median)


def search_seed(build):
    """Returns the first seed whose image clears the stability margin.

    Candidates are built at full size rather than ranked on a smaller model of
    themselves. A reduced model is cheap but a poor predictor: the field cells
    fall on different pixel boundaries at a different side length, which moves
    the coefficients enough that a candidate accepted at one size is regularly
    refused at the other.
    """
    for seed in range(MAX_SEEDS):
        candidate = build(seed, MIN_SIDE)
        margin = float(hash_margins(candidate).min())
        if margin >= TARGET_MARGIN:
            return seed, margin, candidate
    return None, None, None


def save(name, array):
    Image.fromarray(array, "RGB").save(f"{COVERS_DIR}/{name}")


def centre_crop(array):
    """Takes the middle MIN_SIDE x MIN_SIDE of an image.

    Cropped and never tiled. Repeating a small image to reach the minimum size
    makes it periodic, and a periodic image has almost no energy outside the
    harmonics of its own period — which leaves most of the 64 perceptual-hash
    coefficients piled up around the median and gets the container refused for
    a reason that came from the tiling rather than from the picture.
    """
    height, width = array.shape[:2]
    top = (height - MIN_SIDE) // 2
    left = (width - MIN_SIDE) // 2
    return np.ascontiguousarray(array[top:top + MIN_SIDE, left:left + MIN_SIDE])


def fetch(url):
    """Retrieves a URL, falling back to whatever downloader is installed.

    urllib validates the server certificate against the interpreter's own
    trust store, which on a machine with an out-of-date or intercepted bundle
    rejects a site every other tool on the system reaches. curl and wget carry
    their own, so trying them in turn distinguishes a network that is down from
    a trust store that is stale.
    """
    # Wikimedia refuses the default urllib user agent outright, so every
    # request below carries one that says what is making it.
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(request, timeout=180) as response:
            return response.read()
    except (urllib.error.URLError, OSError) as error:
        first_failure = error

    for command in (
        ["curl", "--silent", "--show-error", "--location", "--fail",
         "--max-time", "180", "--user-agent", USER_AGENT, "--output", "-", url],
        ["wget", "--quiet", "--timeout=180", "--user-agent=" + USER_AGENT, "-O", "-", url],
    ):
        if shutil.which(command[0]) is None:
            continue
        result = subprocess.run(command, capture_output=True, check=False)
        if result.returncode == 0 and result.stdout:
            return result.stdout

    raise first_failure


def download_photograph():
    """Fetches the photographic container and derives the JPEG case from it."""
    original = Image.open(io.BytesIO(fetch(PHOTO_URL)))

    if original.mode in ("RGBA", "LA", "P"):
        # Dropping the alpha channel would leave whatever happens to sit under
        # a fully transparent pixel, which is usually nothing like the picture.
        original = original.convert("RGBA")
        backdrop = Image.new("RGBA", original.size, (255, 255, 255, 255))
        original = Image.alpha_composite(backdrop, original)

    array = np.asarray(original.convert("RGB"))
    height, width = array.shape[:2]
    if min(height, width) < MIN_SIDE:
        raise ValueError(f"{width}x{height} is below the {MIN_SIDE}x{MIN_SIDE} minimum")

    photo = centre_crop(array)
    save("photo.png", photo)
    note(
        "photo.png",
        f"public-domain photograph from Wikimedia Commons, centre-cropped "
        f"from {width}x{height}",
    )

    # The same pixels put through a lossy codec and handed back as a lossless
    # file: a container that looks like a PNG and carries a JPEG's fingerprint.
    buffer = io.BytesIO()
    Image.fromarray(photo, "RGB").save(buffer, "JPEG", quality=LAUNDER_QUALITY)
    buffer.seek(0)
    save("photo_jpeg.png", np.asarray(Image.open(buffer).convert("RGB")))
    note(
        "photo_jpeg.png",
        f"the same photograph through a quality {LAUNDER_QUALITY} JPEG round "
        f"trip, saved as PNG",
    )


seed, margin, image = search_seed(textured_image)
if image is None:
    sys.exit(f"no seed under {MAX_SEEDS} produced a perceptually stable textured cover")
save("textured.png", image)
note(
    "textured.png",
    f"synthetic, random field with grain, seed {seed}, hash margin {margin:.1f}",
)

save("smooth.png", smooth_image(MIN_SIDE))
note("smooth.png", "synthetic, smooth gradient, expected to be rejected")

seed, margin, image = search_seed(mixed_image)
if image is None:
    note("mixed.png", "skipped: no seed produced a perceptually stable 60/40 cover")
else:
    save("mixed.png", image)
    note(
        "mixed.png",
        f"synthetic, 60% textured and 40% flat, seed {seed}, hash margin {margin:.1f}",
    )

try:
    download_photograph()
except (urllib.error.URLError, OSError, ValueError) as error:
    note("photo.png", f"download failed and was skipped: {error}")

with open(NOTES_PATH, "w", encoding="utf-8") as handle:
    for name, text in notes:
        handle.write(f"{name}\t{text}\n")
PYTHON_GENERATOR

# --------------------------------------------------------------------------
# Step 5 — embedding
# --------------------------------------------------------------------------

# Payload bytes the container at $1 admits, or nothing when it admits none.
#
# Asked of the binary rather than computed here. The capacity is a function of
# the cost map, the coding efficiency and the tag, and a second implementation
# of that arithmetic in shell would be a second thing to keep in step with the
# sizer — `scan --json` is the answer the system itself gives.
container_capacity() {
    "$STENOXIDE" scan "$(native_path "$1")" --json 2>/dev/null |
        "$VENV_PYTHON" -c '
import json, sys

try:
    document = json.load(sys.stdin)
except json.JSONDecodeError:
    sys.exit(1)

for record in document.get("valid", []):
    print(int(record["capacity_kb"] * 1024))
    break
'
}

# Writes `$2` bytes of incompressible material to the file at `$1`.
#
# Random on purpose, and the point of the whole exercise. The capacity gate
# measures the payload *after* compression, so anything with structure would be
# squeezed to a few dozen bytes and embedded at a rate two orders of magnitude
# below the one being tested. Random bytes cannot be compressed, so the run
# reaches the real capacity limit of the ciphertext rather than the limit of a
# compressible plaintext.
write_random_payload() {
    "$VENV_PYTHON" -c '
import os, sys

with open(sys.argv[1], "wb") as handle:
    handle.write(os.urandom(int(sys.argv[2])))
' "$(native_path "$1")" "$2"
}

# Runs one embedding, returning stenoxide's own exit status.
#
# The payload always arrives on standard input, read from the file at `$4`. What
# changes between the two modes is only where the password comes from; in the
# automated one the whole command is handed to `script`, which runs it under a
# pseudo-terminal and forwards its own standard input to that terminal, so the
# password reaches the prompt while the payload keeps the pipe to itself.
embed_one() {
    local cover=$1 stego=$2 log=$3 payload_file=$4
    local status=0

    if [[ -n $PTY_RUNNER ]]; then
        local command
        printf -v command 'cat %q | %q embed --input %q --output %q' \
            "$(native_path "$payload_file")" "$STENOXIDE" \
            "$(native_path "$cover")" "$(native_path "$stego")"
        printf '%s\n' "$PASSWORD" |
            script -qec "$command" /dev/null >"$log" 2>&1 || status=$?
    else
        "$STENOXIDE" embed \
            --input "$(native_path "$cover")" \
            --output "$(native_path "$stego")" \
            <"$payload_file" >"$log" 2>&1 || status=$?
    fi

    # A pseudo-terminal echoes what is written to it until the reader turns
    # echo off, and the password is written before stenoxide gets that far, so
    # the transcript opens with the password in clear. It is removed here
    # rather than tolerated: the log is read back to explain a refusal, and
    # neither the report nor a kept working directory has any business
    # carrying it.
    if [[ -n $PTY_RUNNER ]]; then
        grep -vF -- "$PASSWORD" "$log" >"$log.scrubbed" 2>/dev/null || true
        mv -f "$log.scrubbed" "$log"
    fi

    return "$status"
}

step 'Embedding'

if [[ -z $PTY_RUNNER ]]; then
    info 'stenoxide will ask for a password once per container image below.'
    info 'Any password will do; it only has to be typed, not remembered.'
fi

# Extracts the refusal reason from an embedding transcript.
#
# Whatever the layer that refused wrote, kept verbatim: a rejection is a result
# of this run, not a failure of it, and rephrasing it here would hide which gate
# spoke.
#
# Matched on the prefix the front-end puts in front of every failure rather than
# taken by position. The password prompt ends without a newline, so under a
# pseudo-terminal the message shares a line with it, and the transcript carries
# several lines that are not the error.
refusal_reason() {
    local log=$1 reason

    reason=$(tr -d '\r' <"$log" | grep -o 'Error: .*' | head -n 1) || true
    reason=${reason#Error: }

    if [[ -z $reason ]]; then
        reason=$(tr -d '\r' <"$log" | grep -v '^$' | tail -n 1) || true
    fi

    printf '%s' "${reason:-no message}"
}

cover_count=0
rejected_count=0
embedded_count=0

for cover in "$COVERS_DIR"/*.png; do
    [[ -e $cover ]] || continue
    name=${cover##*/}
    base=${name%.png}
    cover_count=$((cover_count + 1))

    # The container is measured before anything is embedded, so the loaded case
    # knows what to fill. A capacity of nothing means a container the gates
    # refuse, and the reference case below is what turns that into the sentence
    # the refusing layer wrote.
    capacity=$(container_capacity "$cover") || true

    # Two embeddings per container, written as two stego images so that the
    # detector judges each on its own. The names carry the case, and the report
    # splits them apart again on the double underscore.
    for case_name in reference loaded; do
        stego="$STEGO_DIR/${base}__${case_name}.png"
        log="$REPORT_DIR/embed_${base}_${case_name}.log"
        payload_file="$WORK_DIR/payload_${base}_${case_name}.bin"

        if [[ $case_name == reference ]]; then
            printf '%s' "$REFERENCE_PAYLOAD" >"$payload_file"
            payload_bytes=${#REFERENCE_PAYLOAD}
        else
            # Nothing to load into a container that admits nothing. The
            # reference case has already recorded why.
            [[ -n $capacity && $capacity -gt 0 ]] || continue

            payload_bytes=$("$VENV_PYTHON" -c \
                "print(int($capacity * $CAPACITY_SHARE))")
            write_random_payload "$payload_file" "$payload_bytes"
        fi

        if ! embed_one "$cover" "$stego" "$log" "$payload_file"; then
            # The loaded case gets one retry at a smaller share. Random bytes
            # grow slightly under Zstandard, and how much is not something this
            # script can predict without reimplementing the sizer.
            if [[ $case_name == loaded ]]; then
                payload_bytes=$("$VENV_PYTHON" -c \
                    "print(int($capacity * $CAPACITY_SHARE_RETRY))")
                write_random_payload "$payload_file" "$payload_bytes"
                info "  $name ($case_name): retrying at $payload_bytes bytes"
            fi

            if ! embed_one "$cover" "$stego" "$log" "$payload_file"; then
                rejected_count=$((rejected_count + 1))
                reason=$(refusal_reason "$log")
                printf '%s\trejected\t%s\t%s\t%s\n' \
                    "${base}__${case_name}.png" "$reason" "$case_name" "$payload_bytes" \
                    >>"$OUTCOMES_FILE"
                info "  $name ($case_name): rejected — $reason"
                continue
            fi
        fi

        embedded_count=$((embedded_count + 1))
        rate=$(grep -E 'Effective rate' "$log" | tr -d '\r' | sed 's/^ *//')
        printf '%s\tembedded\t%s\t%s\t%s\n' \
            "${base}__${case_name}.png" "$rate" "$case_name" "$payload_bytes" \
            >>"$OUTCOMES_FILE"
        info "  $name ($case_name): embedded, $payload_bytes bytes"

        # The payload is deleted as soon as the embedding that used it has
        # returned. A kept working directory has no business carrying the
        # plaintext of what was hidden in the images beside it.
        rm -f "$payload_file"
    done
done

[[ $cover_count -gt 0 ]] || die 'no container images were generated; nothing to analyse.'

# --------------------------------------------------------------------------
# Step 6 — analysis
# --------------------------------------------------------------------------

if [[ $skip_analysis == true ]]; then
    step 'Analysis skipped'
    # Two embeddings per accepted container, so the counts below are of
    # embeddings and not of covers.
    info "covers:     $cover_count"
    info "embeddings: $embedded_count"
    info "rejected:   $rejected_count"
    info ''
    info 'Re-run without --skip-analysis to have Aletheia judge the stego images.'
    print_reuse_hint
    exit 0
fi

if [[ $embedded_count -eq 0 ]]; then
    step 'Nothing to analyse'
    info 'Every container was rejected, so no stego image was produced.'
    info 'That is a valid outcome for the validation gates, but it leaves the'
    info 'detection question unanswered.'
    exit 1
fi

step 'Cropping the stego images to the detector resolution'

info "Taking a 3x3 grid of ${CROP_SIDE}x${CROP_SIDE} crops from every stego image."
info 'Aletheia was trained on crops of that size; a whole 2000x2000 container is'
info 'outside the range its models were fitted on, and the number they return for'
info 'one carries no information.'

"$VENV_PYTHON" - \
    "$(native_path "$STEGO_DIR")" \
    "$(native_path "$CROPS_DIR")" \
    "$CROP_SIDE" <<'PYTHON_CROPPER'
"""Cuts every stego image into the 3x3 grid of crops the detector is judged on.

The crops are taken losslessly: no resampling, no re-encoding through a lossy
codec, and PNG on the way out. Any of those would alter the least significant
bits the whole analysis is about, and the detector would be reading the
resampler rather than the embedding.

Positions are spread across the frame rather than tiled from a corner. The
embedding is scattered over the whole container by a secret permutation, so nine
windows sampling the frame evenly is what makes the median of their scores a
statement about the image rather than about one part of it.
"""

import os
import sys

from PIL import Image

STEGO_DIR, CROPS_DIR, CROP_SIDE = sys.argv[1], sys.argv[2], int(sys.argv[3])

# Where each crop starts, as a fraction of the space left over once the crop
# itself is accounted for: hard against one edge, centred, hard against the
# other. Three of these along each axis is the 3x3 grid.
POSITIONS = (0.0, 0.5, 1.0)

os.makedirs(CROPS_DIR, exist_ok=True)

for name in sorted(os.listdir(STEGO_DIR)):
    if not name.lower().endswith(".png"):
        continue

    image = Image.open(os.path.join(STEGO_DIR, name))
    width, height = image.size

    if width < CROP_SIDE or height < CROP_SIDE:
        print(f"  {name}: {width}x{height} is smaller than one crop; skipped")
        continue

    stem = name[: -len(".png")]
    written = 0

    for row, vertical in enumerate(POSITIONS):
        for column, horizontal in enumerate(POSITIONS):
            left = int((width - CROP_SIDE) * horizontal)
            top = int((height - CROP_SIDE) * vertical)

            crop = image.crop((left, top, left + CROP_SIDE, top + CROP_SIDE))
            crop.save(os.path.join(CROPS_DIR, f"{stem}__crop{row}{column}.png"))
            written += 1

    print(f"  {name}: {written} crops")
PYTHON_CROPPER

step 'Running Aletheia'
info 'This runs on the CPU and is slow; several minutes per image is normal.'

# Aletheia's spatial detectors are Octave code it fetches on first use, and it
# prints the licence and waits for a yes before fetching any of it. The answers
# come from a file rather than a pipe so that neither side can be left holding
# a broken pipe; the count is generous because there is one prompt per detector
# and nothing goes wrong if some go unread.
readonly LICENSE_ANSWERS="$REPORT_DIR/license_answers.txt"

if [[ $accept_licenses == true ]]; then
    info 'Answering the licence prompts of the external Octave code with yes.'
    : >"$LICENSE_ANSWERS"
    for _ in $(seq 1 32); do printf 'y\n' >>"$LICENSE_ANSWERS"; done

    if ! (cd "$ALETHEIA_DIR" && "$VENV_PYTHON" aletheia.py auto "$(native_path "$CROPS_DIR")" \
        <"$LICENSE_ANSWERS") >"$RAW_REPORT" 2>&1; then
        warn 'Aletheia exited with an error; the report below is built from whatever it printed.'
    fi
else
    info 'Aletheia will ask you to accept the licence of the Octave code it needs'
    info 'before downloading it. Its output is shown as it runs so the prompts can'
    info 'be answered; --accept-external-licenses answers them for you.'

    if ! (cd "$ALETHEIA_DIR" && "$VENV_PYTHON" aletheia.py auto "$(native_path "$CROPS_DIR")") \
        2>&1 | tee "$RAW_REPORT"; then
        warn 'Aletheia exited with an error; the report below is built from whatever it printed.'
    fi
fi

# --------------------------------------------------------------------------
# Step 7 — report
# --------------------------------------------------------------------------

set +e
"$VENV_PYTHON" - \
    "$(native_path "$RAW_REPORT")" \
    "$(native_path "$NOTES_FILE")" \
    "$(native_path "$OUTCOMES_FILE")" \
    "$cover_count" \
    "$PASS_MAX" \
    "$FAIL_MIN" \
    "$CONFIDENCE_MIN" \
    "$CROP_SIDE" \
    "$CROP_COUNT" \
    "$MIN_CONFIDENT_CROPS" <<'PYTHON_REPORT'
"""Turns Aletheia's table into a verdict.

Aletheia prints one row per image with a column per detector; the column that
matters here is HILL, because that is the cost function stenoxide embeds under.
Everything else on the row is noise for this purpose.

The rows are crops, not containers. Every stego image was cut into a 3x3 grid
before the detector saw it, so the score reported per image is the median of the
nine — and the median rather than the mean because a single crop that happens to
land on a smooth part of the frame should move the answer by one rank and not by
its whole distance.
"""

import re
import statistics
import sys

# The table below is drawn with box characters, which a console left on a
# legacy code page cannot encode. Switching the stream to UTF-8 fixes the
# common case; where even that is refused the drawing falls back to ASCII,
# because a report that raises on its first line is worse than a plain one.
try:
    sys.stdout.reconfigure(encoding="utf-8")
except (AttributeError, OSError):
    pass


def encodable(sample):
    try:
        sample.encode(sys.stdout.encoding or "ascii")
    except (UnicodeEncodeError, LookupError, TypeError):
        return False
    return True


if encodable("═─│┌┬┐├┼┤└┴┘—"):
    BANNER, HORIZONTAL, VERTICAL, DASH = "═", "─", "│", "—"
    TOP, MIDDLE, BOTTOM = ("┌", "┬", "┐"), ("├", "┼", "┤"), ("└", "┴", "┘")
else:
    BANNER, HORIZONTAL, VERTICAL, DASH = "=", "-", "|", "--"
    TOP = MIDDLE = BOTTOM = ("+", "+", "+")

RAW_PATH, NOTES_PATH, OUTCOMES_PATH = sys.argv[1], sys.argv[2], sys.argv[3]
COVER_COUNT = int(sys.argv[4])
PASS_MAX, FAIL_MIN = float(sys.argv[5]), float(sys.argv[6])
CONFIDENCE_MIN = float(sys.argv[7])
CROP_SIDE, CROP_COUNT = int(sys.argv[8]), int(sys.argv[9])
MIN_CONFIDENT_CROPS = int(sys.argv[10])

# How a crop file names the stego image it came from and its position in the
# grid: `<container>__<case>__crop<row><column>.png`.
CROP_NAME = re.compile(r"^(?P<image>.+)__crop(?P<row>\d)(?P<column>\d)$")

# A cell is either a bare probability or a probability with the confidence of
# the model beside it, and a probability above the detector's own boundary is
# printed in brackets. All three forms collapse to the same two numbers.
CELL = re.compile(r"\[?(\d+(?:\.\d+)?)\]?(?:\s*\((\d+(?:\.\d+)?)\))?")


def read_pairs(path):
    try:
        with open(path, encoding="utf-8") as handle:
            rows = [line.rstrip("\n").split("\t") for line in handle if line.strip()]
    except OSError:
        return []
    return [row for row in rows if len(row) >= 2]


def parse_aletheia(text):
    """Extracts the HILL score and confidence of every row in the bitmap table.

    The header names the detectors in the order the columns appear, so the
    position of HILL is read from it rather than assumed: Aletheia has changed
    both the set of detectors and their order between releases.
    """
    lines = text.splitlines()
    header_index = None
    detectors = []

    for index, line in enumerate(lines):
        stripped = line.strip()
        if "HILL" in stripped and not stripped.startswith("-"):
            candidates = [
                token.strip("^*") for token in stripped.split() if token.strip("^*")
            ]
            if any(token.upper() == "HILL" for token in candidates):
                header_index = index
                detectors = candidates
                break

    if header_index is None:
        return {}

    hill_column = next(
        index for index, token in enumerate(detectors) if token.upper() == "HILL"
    )

    results = {}
    for line in lines[header_index + 1:]:
        stripped = line.strip()
        if not stripped or stripped.startswith("-"):
            continue
        if stripped.startswith("*") or stripped.startswith("("):
            break

        name = stripped.split()[0]
        cells = CELL.findall(stripped[len(name):])
        if len(cells) <= hill_column:
            continue

        score, confidence = cells[hill_column]
        results[name] = (float(score), float(confidence) if confidence else None)

    return results


def aggregate(rows):
    """Collapses the crops of one stego image into a single score.

    Returns the median score, the median confidence and how many of the crops
    stood behind their own number. Only the confident crops feed the medians:
    including a crop the model has no opinion about would let noise vote on the
    answer, which is the failure mode the floor exists to prevent.

    A container with no confident crop at all still reports the median of what
    came back, so that the table has a number to show beside the count that
    disqualifies it.
    """
    confident = [
        (score, confidence)
        for score, confidence in rows
        if confidence is not None and confidence >= CONFIDENCE_MIN
    ]

    if confident:
        scores = [score for score, _ in confident]
        confidences = [confidence for _, confidence in confident]
    else:
        scores = [score for score, _ in rows]
        confidences = [confidence for _, confidence in rows if confidence is not None]

    return (
        statistics.median(scores) if scores else None,
        statistics.median(confidences) if confidences else None,
        len(confident),
    )


def verdict(score, confident_crops):
    """Grades one stego image from its aggregate.

    The count of confident crops is checked first and on purpose. A model that
    cannot separate cover from stego on this container will still emit a number
    for every crop, and those numbers carry no information whichever side of the
    threshold they fall on: reading their median as a detection would be reading
    noise with extra steps.
    """
    if score is None or confident_crops < MIN_CONFIDENT_CROPS:
        return "UNRELIABLE"
    if score < PASS_MAX:
        return "PASS"
    if score < FAIL_MIN:
        return "WARN"
    return "FAIL"


def rule(corners, widths):
    left, middle, right = corners
    return left + middle.join(HORIZONTAL * (width + 2) for width in widths) + right


def row(cells, widths):
    body = f" {VERTICAL} ".join(cell.ljust(width) for cell, width in zip(cells, widths))
    return f"{VERTICAL} {body} {VERTICAL}"


with open(RAW_PATH, encoding="utf-8", errors="replace") as handle:
    raw = handle.read()

crop_scores = parse_aletheia(raw)
notes = dict(read_pairs(NOTES_PATH))
outcomes = read_pairs(OUTCOMES_PATH)


def crops_of(image):
    """Every crop row belonging to one stego image."""
    rows = []
    stem = image[: -len(".png")] if image.endswith(".png") else image

    for name, values in crop_scores.items():
        candidate = name[: -len(".png")] if name.endswith(".png") else name
        match = CROP_NAME.match(candidate)
        if match and match.group("image") == stem:
            rows.append(values)

    return rows


# One record per embedding: the stego image, which case it was, how many bytes
# went in, and the rate stenoxide reported.
embeddings = []
for name, state, *rest in outcomes:
    if state != "embedded":
        continue

    detail = rest[0] if rest else ""
    case = rest[1] if len(rest) > 1 else ""
    payload_bytes = int(rest[2]) if len(rest) > 2 and rest[2].isdigit() else None
    match = re.search(r"([0-9]*\.[0-9]+)\s*bpp", detail)

    embeddings.append(
        {
            "image": name,
            "case": case,
            "payload_bytes": payload_bytes,
            "bpp": float(match.group(1)) if match else None,
        }
    )

# The rate each embedding actually ran at, taken from what stenoxide reported.
# The verdict line quotes it rather than the 0.02 hard limit: the limit is what
# the coder will never exceed, and quoting it would credit the run with a test
# it did not perform.
rates = [record["bpp"] for record in embeddings if record["bpp"] is not None]

rejected = [
    (name, rest[0] if rest else "")
    for name, state, *rest in outcomes
    if state == "rejected"
]

def human_bytes(count):
    """A payload size a person can read at a glance."""
    if count is None:
        return "?"
    if count < 1024:
        return f"{count} B"
    return f"{count / 1024:.1f} KB"


banner = BANNER * 66
print()
print(banner)
print(" stenoxide steganalysis validation report")
print(banner)
print()
print(f"  Cover images tested:     {COVER_COUNT}")
print(f"  Rejected by stenoxide:   {len(rejected)}  (expected for smooth/jpeg images)")
print(f"  Stego images analyzed:   {len(embeddings)}")
print(f"  Analysis:                {CROP_COUNT} x {CROP_SIDE}x{CROP_SIDE} crops per image, median score")
print()

widths = [22, 15, 9, 6, 10, 7, 11]
detected = []
judged = []
unmatched = []

if crop_scores:
    print("  Results (HILL detector):")
    print("  " + rule(TOP, widths))
    print(
        "  "
        + row(
            ["Container", "Payload", "Rate", "Score", "Confidence", "Crops", "Status"],
            widths,
        )
    )
    print("  " + rule(MIDDLE, widths))

    for record in embeddings:
        rows = crops_of(record["image"])
        if not rows:
            unmatched.append(record["image"])
            continue

        score, confidence, confident_crops = aggregate(rows)
        status = verdict(score, confident_crops)

        if status == "FAIL":
            detected.append((record["image"], score))
        elif status != "UNRELIABLE":
            judged.append(record["image"])

        # The container and the case are one string in the file name and two
        # columns here: the case is what the row is about, and repeating the
        # container on both of its rows is what makes them comparable.
        container, _, case = record["image"].rpartition("__")
        container = container or record["image"]
        case = case[: -len(".png")] if case.endswith(".png") else case

        print(
            "  "
            + row(
                [
                    f"{container}"[: widths[0]],
                    f"{case}: {human_bytes(record['payload_bytes'])}"[: widths[1]],
                    "?" if record["bpp"] is None else f"{record['bpp']:.4f}",
                    "?" if score is None else f"{score:.2f}",
                    "n/a" if confidence is None else f"{confidence:.2f}",
                    f"{confident_crops}/{len(rows)}",
                    status,
                ],
                widths,
            )
        )

    print("  " + rule(BOTTOM, widths))
    print()
    print(f"  Crops: how many of the {CROP_COUNT} cleared the {CONFIDENCE_MIN:.2f} confidence")
    print(f"  floor. Fewer than {MIN_CONFIDENT_CROPS} makes the aggregate UNRELIABLE.")
    print()
else:
    print("  Aletheia produced no HILL scores. Tail of its output:")
    for line in raw.splitlines()[-12:]:
        print(f"    {line}")
    print()

if unmatched:
    print("  Embedded but absent from the detector's table:")
    for name in unmatched:
        print(f"  - {name}")
    print()

if rejected:
    print("  Rejected covers (stenoxide validation working correctly):")
    for name, reason in rejected:
        print(f"  - {name}: {reason}")
    print()

skipped = [(name, text) for name, text in notes.items() if "skipped" in text or "failed" in text]
if skipped:
    print("  Covers that never reached stenoxide:")
    for name, text in skipped:
        print(f"  - {name}: {text}")
    print()

if crop_scores and not judged and not detected:
    print(f"  No container had {MIN_CONFIDENT_CROPS} crops clearing the "
          f"{CONFIDENCE_MIN:.2f} confidence floor,")
    print("  which is the detector reporting that it cannot separate cover from")
    print("  stego on this material. Nothing here is evidence either way.")
    print()

# Always printed, whatever the verdict. A PASS is a narrower claim than it
# reads as, and the run that produced it is the right place to say so.
print("  Notes:")
print("  - Neural detectors (HILL, UNIWARD, LSBM) are trained against a")
print("    particular source of covers. A model trained on images from the same")
print("    camera as the container would score it differently.")
print("  - Classical estimators (WS, RS, SPA) depend on no trained model, so")
print("    their scores are valid whatever the container's provenance and")
print("    whatever its size.")
print("  - A PASS means Aletheia cannot detect the embedding. It does not mean")
print("    no detector can.")
print()

print(banner)
if not crop_scores:
    print(f" OVERALL: INCONCLUSIVE {DASH} the analysis produced no result")
    status = 1
elif not judged and not detected:
    print(f" OVERALL: INCONCLUSIVE {DASH} too few crops met the confidence floor")
    status = 1
elif detected:
    print(f" OVERALL: FAIL {DASH} detection above threshold, review cover image quality")
    status = 1
else:
    rate = f"{max(rates):.6f} bpp" if rates else "the rate embedded"
    print(f" OVERALL: PASS {DASH} stenoxide evades detection at {rate}")
    status = 0
print(banner)
print()

sys.exit(status)
PYTHON_REPORT
report_status=$?
set -e

# --------------------------------------------------------------------------
# Step 8 — cleanup
#
# The working directory goes with the trap above. The Aletheia checkout does
# not: it costs a clone and a dependency install to rebuild, and a second run
# can reuse it by exporting the path printed here.
# --------------------------------------------------------------------------

print_reuse_hint

exit "$report_status"
