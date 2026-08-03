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

## Running it

```sh
cargo run --release --example synthetic_cover_probe --features test-utils -- out 10
python scripts/synthetic_cover_analysis/oracle.py out            # what changed
python scripts/synthetic_cover_analysis/informed_detector.py out # can it be seen
python scripts/synthetic_cover_analysis/optimal_bound.py         # could it ever be
```

`optimal_bound.py` needs only NumPy and no images; the other two need Pillow and
the pairs. Ten pairs take a few minutes, most of it spent generating containers.
