"""Does a generated container leak whether it was generated around a payload?

Point this at the output of `generative_stego`, where even-numbered images were
generated around a message and odd-numbered ones around nothing. The two groups
should be draws from one distribution -- not similar, identical -- so every
statistic below should separate them at chance.

The interesting statistic is `pair_ratio`. Within a plateau the cover histogram
is floor(c + N(0, sigma)), whose adjacent bins are *unequal*: for each pair
(2k, 2k+1) the share landing on the even bin has a value the generator's own
parameters fix. Any construction that writes bits by pairing values -- LSB
replacement being the classic -- pulls that share towards one half, because it
redistributes mass inside a pair while preserving the pair's total. Rejection
sampling leaves it exactly where the cover put it. So this is the statistic that
would catch the mistake, which is why it is worth reporting even when it finds
nothing.

`hcf_com`, `peak_kurt` and `hf_energy` are carried over from
`informed_detector.py` so the numbers can be read against the embedding path's.
"""

import sys
import pathlib
import numpy as np
from PIL import Image

PEAKS = (33, 223)
HALF_WIDTH = 8


def load(path):
    return np.asarray(Image.open(path).convert("RGB"), dtype=np.int32)


def plateau_mask(channel):
    return (np.abs(channel - PEAKS[0]) <= 10) | (np.abs(channel - PEAKS[1]) <= 10)


def hcf_com(channel):
    hist = np.bincount(channel.ravel(), minlength=256).astype(np.float64)
    cf = np.abs(np.fft.fft(hist))
    k = np.arange(128)
    return float((k * cf[:128]).sum() / cf[:128].sum())


def peak_kurtosis(channel):
    values = channel[plateau_mask(channel)].astype(np.float64)
    low, high = values < 128, values >= 128
    centred = np.where(low, values - values[low].mean(), values - values[high].mean())
    return float((centred ** 4).mean() / centred.var() ** 2 - 3.0)


def hf_energy(channel):
    c = channel.astype(np.float64)
    lap = 4 * c[1:-1, 1:-1] - c[:-2, 1:-1] - c[2:, 1:-1] - c[1:-1, :-2] - c[1:-1, 2:]
    return float(lap[plateau_mask(channel)[1:-1, 1:-1]].var())


def pair_ratio(channel):
    """Mean share of each value pair sitting on the even member.

    Averaged over the pairs of both plateaus, weighted by pair occupancy. A
    construction that redistributes mass within pairs drives this to 0.5.
    """
    hist = np.bincount(channel.ravel(), minlength=256).astype(np.float64)
    ratios, weights = [], []

    for peak in PEAKS:
        for even in range(peak - HALF_WIDTH, peak + HALF_WIDTH, 2):
            even = even - (even % 2)
            total = hist[even] + hist[even + 1]
            if total > 1000:
                ratios.append(hist[even] / total)
                weights.append(total)

    ratios, weights = np.array(ratios), np.array(weights)
    # Distance from the balanced state, which is what a leak moves towards.
    return float(np.average(np.abs(ratios - 0.5), weights=weights))


STATISTICS = (("hcf_com", hcf_com), ("peak_kurt", peak_kurtosis),
              ("hf_energy", hf_energy), ("pair_ratio", pair_ratio))


def stats(path):
    img = load(path)
    return {name: float(np.mean([fn(img[:, :, c]) for c in range(3)]))
            for name, fn in STATISTICS}


def main():
    directory = pathlib.Path(sys.argv[1])
    images = sorted(directory.glob("image_*.png"))
    if not images:
        raise SystemExit(f"no images in {directory}")

    loaded, blank = [], []
    for path in images:
        index = int(path.stem.split("_")[1])
        (loaded if index % 2 == 0 else blank).append(stats(path))

    print(f"{len(loaded)} carrying a payload, {len(blank)} carrying nothing\n")
    print(f"{'statistic':<12}{'loaded mean':>14}{'blank mean':>14}"
          f"{'pooled sd':>12}{'separation':>12}{'overlap':>9}")
    print("-" * 73)

    for name, _ in STATISTICS:
        a = np.array([r[name] for r in loaded])
        b = np.array([r[name] for r in blank])
        sd = np.sqrt((a.var(ddof=1) + b.var(ddof=1)) / 2)
        d = abs(a.mean() - b.mean()) / sd if sd > 0 else 0.0
        overlap = "yes" if (max(a.min(), b.min()) <= min(a.max(), b.max())) else "NO"
        print(f"{name:<12}{a.mean():>14.6f}{b.mean():>14.6f}"
              f"{sd:>12.6f}{d:>12.2f}{overlap:>9}")

    positive_control(directory, images)


def positive_control(directory, images):
    """Show the test can find what it is looking for.

    A null result is worth nothing without knowing the test could have failed.
    So the naive construction -- overwrite the LSB instead of sampling
    conditioned on it -- is applied to a container that carries nothing, at the
    same load factor, and measured with the same statistic. That construction is
    the one a first implementation reaches for, and it is exactly what
    `pair_ratio` is built to catch: overwriting redistributes mass inside each
    value pair while leaving the pair's total alone, so the natural imbalance of
    the cover histogram is flattened towards zero.
    """
    blank_path = next(p for p in images if int(p.stem.split("_")[1]) % 2 == 1)
    img = load(blank_path)

    # Same share of samples the real payload occupied: 1 MB of ciphertext over
    # a 2000x2000 RGB container.
    load_factor = 1_000_000 * 8 / (2000 * 2000 * 3)
    rng = np.random.default_rng(0)

    naive = img.copy()
    flat = naive.reshape(-1, 3)
    chosen = rng.random(flat.shape[0]) < load_factor
    bits = rng.integers(0, 2, size=(chosen.sum(), 3))
    flat[chosen] = (flat[chosen] & ~1) | bits

    honest = float(np.mean([pair_ratio(img[:, :, c]) for c in range(3)]))
    broken = float(np.mean([pair_ratio(naive[:, :, c]) for c in range(3)]))

    print(f"\npositive control on {blank_path.name}, load factor {load_factor:.2f}")
    print(f"  pair_ratio, sampled conditionally (what we do): {honest:.6f}")
    print(f"  pair_ratio, LSB overwritten (the naive way):    {broken:.6f}")
    print(f"  the naive construction moves it by {abs(honest - broken) / 0.000132:.0f}"
          f" pooled standard deviations")
    print("\nSo the statistic has the power to convict, and does not.")


if __name__ == "__main__":
    main()
