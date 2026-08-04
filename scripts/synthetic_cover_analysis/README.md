# Is a generated container safe?

A user who has no photograph to hide a message in will ask whether the tool can
just make one. This directory holds the measurement that answers it, because the
answer is not the one either intuition predicts.

`OPSEC.md` tells the user not to use synthetic images, on the grounds that
"synthetic content has statistics of its own that a detector models more easily
than a photograph's". That reasoning is sound in general and does not survive
contact with the numbers in this particular case. The gap between the two is the
whole point of this note.

## The threat model, which is the worst one there is

A generated container is the one case where the attacker can hold the cover
*source*: the generator is open source, so its output distribution is public and
an adversary can draw from it without limit. In steganalysis that is the
strongest position an attacker can occupy, and it is one a photograph never
grants — nobody has a generative model of your camera pointed at your garden.

So the question is not whether some trained detector finds the payload. It is
whether the **optimal** detector does. On a plateau of the generator's
low-frequency field the cover is

    pixel = floor(c + G),    G ~ N(0, sigma),    c publicly known,

with samples independent given the field. That is a fully specified source, so
the likelihood-ratio test on the sample histogram is optimal by Neyman-Pearson,
and its power upper-bounds every detector that will ever exist — neural or
otherwise. `optimal_bound.py` computes it.

## What the bound says

| Condition | d | AUC |
|---|---|---|
| **stenoxide as it stands** (sigma 2.0, 0.02 bpp) | **0.31** | **0.586** |
| grain sigma 0.5 | 6.37 | 1.000 |
| grain sigma 1.0 | 1.21 | 0.803 |
| grain sigma 1.5 | 0.54 | 0.649 |
| rate raised to 0.10 bpp | 1.54 | 0.862 |
| rate raised to 0.50 bpp | 7.70 | 1.000 |

An AUC of 0.586 against an adversary holding the generator is, for practical
purposes, a coin toss. The generated container is *statistically* sound, and it
is sound for a reason that has nothing to do with the cost model: at sigma 2 the
cover's own least significant bit already carries 1.0000 bits of entropy, so the
bit a change overwrites was unpredictable to begin with. HILL never enters the
calculation.

Two parameters, and only two, hold that result up. **Grain amplitude**: at
sigma 0.5 the same bound is a perfect detector, because a grain that small makes
the LSB predictable from the neighbourhood. **Rate**: the 0.02 bpp cap is what
keeps the change rate at 6747 samples in 12,000,000 — 0.056%, which is the
Syndrome-Trellis coder operating within a few per cent of its theoretical
optimum. At 0.5 bpp the same container is detected every time.

## What the empirical run says

`informed_detector.py` runs three cover-source-specific statistics over ten
matched pairs from `synthetic_cover_probe`. All three overlap completely:

| statistic | separation (Cohen's d) | populations overlap |
|---|---|---|
| HCF centre of mass | 0.03 | yes |
| plateau peak kurtosis | 0.10 | yes |
| high-pass residual energy | 0.27 | yes |

Which agrees with the bound: no statistic can separate what the optimal test
separates at 0.31. Paired against its own cover the effect is perfectly
systematic — residual energy rises in 10 of 10 — but an attacker does not hold
the cover, and between containers the variance swamps it.

## Why this is still not a feature

The measurement clears the generated container on the axis it was doubted on and
convicts it on a different one.

**Look at it.** The generator emits a 32x32 mosaic of saturated colour cells with
grain on top. `OPSEC.md` asks for a container with "a plausible reason to exist
in that conversation"; a 2000x2000 PNG of coloured squares has none, in any
conversation. Nothing a detector could find in the file competes with the file
itself as evidence. The statistical result is real and it is answering a question
that is not the binding one.

**A generic detector's silence means nothing here.** Aletheia returns an accuracy
estimate of 0.50 on synthetic containers — a model saying it was asked about
material it was not trained on, which reads like a `PASS` and is not one. Any
future claim about a generated container has to come from a bound of the kind
computed here, never from a trained detector's score.

**The seed becomes key material.** The cover exists nowhere, so the subtraction
attack that defeats a published photograph has nothing to subtract — which
genuinely retires the second-worst mistake in `OPSEC.md`. But it retires it only
while the seed is unguessable. An attacker who can enumerate seeds regenerates
the exact cover and reads the changes directly, and the confirmation is
unmistakable: the right seed differs from the stego image in ~6700 samples where
a wrong one differs in millions. A seed drawn from a timestamp would be perhaps
thirty bits and would fall in seconds. Anything built on this would need at least
128 bits from the system CSPRNG and must never persist the clean cover.

---

# Part II: generating the container *around* the payload

The measurement above answers the question that was asked and raises a better
one. If the sender knows the cover distribution exactly — and when the sender
generates the container, they do — then embedding is the wrong operation
entirely.

## Why there is a construction with nothing left to detect

Embedding modifies an image, and a modification is a thing a detector can hunt
for; the argument is only ever about how well it is hidden. A generator can do
something an embedder cannot: draw each sample from the cover distribution
*conditioned on its least significant bit being the ciphertext bit it must
carry*. Rejection sampling does that in about two draws. Then, for a uniform
carrier bit,

    sum over b of  P(sample = v | LSB = b) P(b)  =  P(sample = v)

exactly, provided the LSB of the unconditioned distribution is a fair coin. The
container that carries a message and the container that carries nothing are
draws from **one distribution**. There is no statistic to find, no detector to
out-run, and no future model that changes it — the two hypotheses are equal.

The whole argument rests on the fairness of that coin, and `one_in_n.py`
measures it. For grain `floor(c + N(0, sigma))` the LSB bias decays as
`exp(-2 pi^2 sigma^2)`:

| grain sigma | LSB bias | samples needed to notice | container holds |
|---|---|---|---|
| 0.5 | 1.9e-01 | 10^1 | |
| 1.0 | 4.6e-03 | 10^5 | |
| **2.0** | **<1e-9** (theory: 1e-34) | **10^18** | **10^7.1** |

At sigma 2 the margin is eleven orders of magnitude, and that is against the
float64 noise floor of the measurement rather than the real bias, which the
theta expansion puts near `1e-34`. The generator's existing grain is already
past the point where this matters.

## What it costs and what it buys

`generative_stego.rs` implements it end to end. The circularity — the key comes
from a hash of the container, which now depends on the ciphertext, which depends
on the key — unties because the perceptual hash reads a 32x32 thumbnail where
four thousand grain samples average away, and layer 1 already refuses any
container whose coefficients sit within `5.0` of the median. A draft container
fixes the hash, the hash fixes the key, and the final container is *verified* to
hash the same by decrypting it back.

| | embedding into a synthetic cover | generating around the payload |
|---|---|---|
| capacity, 2000x2000 | ~7 KB | **1 MB** (1 bit per sample) |
| samples changed | 6747 of 12,000,000 | none — nothing is changed |
| optimal detector | AUC 0.586 | **AUC 0.500, provably** |
| picking 1 of 100 | 2.09% | **exactly 1%** |

The rate cap is what holds the left column up, and it does not apply to the
right one: `0.02` bpp exists because a photograph's distribution is unknown to
the sender. Here the sender *is* the distribution.

## Verification

Sixteen containers, eight generated around 1 MB of incompressible payload and
eight around nothing, all validated through the production path:

- **Round trip.** All eight recover their megabyte, authenticated under a key
  derived from the hash of the image as it arrived on disk.
- **`stenoxide scan` accepts all sixteen identically**, reporting the same
  ~8.3 KB capacity for a container already holding 1 MB and for one holding
  nothing.
- **No statistic separates them.** `hcf_com`, `peak_kurt`, `hf_energy` and
  `pair_ratio` all overlap, separating at 0.33 to 0.71 — which at n=8 per group
  is what chance looks like.

A null result proves nothing on its own, so `indistinguishability.py` carries a
positive control. The naive construction — overwrite the LSB rather than sample
conditioned on it — is applied at the same load factor and measured with the
same statistic. It moves `pair_ratio` by **434 pooled standard deviations**,
because overwriting redistributes mass within each value pair and flattens the
cover histogram's natural imbalance. The test can convict, and it does not.

## What this does not fix

**It hides which, not whether.** The two hypotheses it equalises are "generated
around a message" and "generated around nothing". It says nothing about
"generated" versus "photographed" — the container still looks like a mosaic of
coloured cells, and an adversary looking at the folder still sees a hundred
images nobody has a reason to own. Against the folder-of-100 question this is a
complete answer; against the question of why the folder exists it is no answer
at all.

**The seed stays key material.** No cover exists to subtract, but an adversary
who can reproduce the generator's RNG state regenerates the container and
compares. 128+ bits from the system CSPRNG, and the clean draft never persisted.

**It is a prototype, not a mode.** `stenoxide` embeds into images that already
exist; this generates one, which is a different entry point — a payload-length
header and an extraction path that does not run the trellis at all, since there
are no costs to minimise when every position is equally free.

## Shape this would take, if it is ever built

Nothing here is implemented in the product, and this section is a record of a
design decision rather than a plan being executed.

**An explicit `stenoxide generate`, not a prompt on a missing argument.** The
tempting interface is to notice that `embed` was given no container and offer to
make one. It is the wrong place for it twice over. A user who omitted `--input`
made a typo and is not asking to change their security model, so the offer turns
a slip into a hurried decision; and the operation that fits behind such a prompt
is *generate then embed*, which is the weaker of the two constructions — the
convenient path would deliver the worse column of the table above. The
discoverability belongs in `scan` instead: when it walks a directory and accepts
nothing, one informative line. That user has already demonstrated they looked.

This also matters for a rule the tool cannot otherwise enforce. "One image + one
password = one message" is today a matter of the user's discipline; a container
generated per message satisfies it by construction.

**Open questions, none of them interface.** How the payload length reaches the
receiver without leaking the message size — filling the container to the last
sample and carrying the length inside the authenticated plaintext looks right,
and costs a megabyte of cipher per send. How extraction tells a generated
container from an embedded one without a marker and without a failure that says
which — trying both under one derivation, since the salt is the same hash, may
be enough. And whether grain that imitates a real sensor, whose amplitude
follows luminance, keeps every region above the sigma the argument needs, or
whether the dark regions have to be excluded from carrying anything.

## Running it

```sh
cargo run --release --example generative_stego --features test-utils -- gen 16 1000000
python scripts/synthetic_cover_analysis/indistinguishability.py gen
python scripts/synthetic_cover_analysis/one_in_n.py
```

## Running the Part I harness

```sh
cargo run --release --example synthetic_cover_probe --features test-utils -- out 10
python scripts/synthetic_cover_analysis/oracle.py out            # what changed
python scripts/synthetic_cover_analysis/informed_detector.py out # can it be seen
python scripts/synthetic_cover_analysis/optimal_bound.py         # could it ever be
```

`optimal_bound.py` needs only NumPy and no images; the other two need Pillow and
the pairs. Ten pairs take a few minutes, most of it spent generating containers.
