"""Informed steganalysis of the synthetic container generator.

The threat model this measures: an adversary who has the source code, and can
therefore generate an unlimited supply of covers from the same distribution the
container came from. That is the situation an open-source generator creates and
a photograph never does.

Statistics computed per image, all of them cover-source specific:

  hcf_com   Harmsen-Pearlman centre of mass of the histogram characteristic
            function. LSB matching acts as a low-pass filter on the histogram,
            which pulls the COM down. The standard detector for +/-1 embedding.
  peak_kurt Excess kurtosis of the two plateau peaks. The generator puts ~75% of
            all pixels into two narrow (sigma=2) gaussians; smearing them is
            measurable directly.
  hf_energy Variance of a high-pass residual, restricted to plateau pixels where
            the cover's expected value is constant by construction.
"""

import sys
import pathlib
import numpy as np
from PIL import Image


def load(path):
    return np.asarray(Image.open(path).convert("RGB"), dtype=np.int32)


def hcf_com(channel):
    """Centre of mass of the histogram characteristic function."""
    hist = np.bincount(channel.ravel(), minlength=256).astype(np.float64)
    cf = np.abs(np.fft.fft(hist))
    k = np.arange(128)
    return float((k * cf[:128]).sum() / cf[:128].sum())


def plateau_mask(channel):
    """Pixels sitting on a flat control-grid plateau.

    The generator's field is piecewise constant with eased shoulders, so the
    plateaus are exactly where the cover's expected value is known to be flat.
    They are found by their level: a plateau is 128 +/- 95.
    """
    return (np.abs(channel - 33) <= 10) | (np.abs(channel - 223) <= 10)


def peak_kurtosis(channel):
    """Excess kurtosis of the pixels forming the two plateau peaks."""
    values = channel[plateau_mask(channel)].astype(np.float64)
    # Fold both peaks onto a common centre so they can be pooled.
    centred = np.where(values < 128, values - values[values < 128].mean(),
                       values - values[values >= 128].mean())
    var = centred.var()
    return float((centred ** 4).mean() / var ** 2 - 3.0)


def hf_energy(channel):
    """Variance of a Laplacian residual over plateau pixels."""
    c = channel.astype(np.float64)
    lap = 4 * c[1:-1, 1:-1] - c[:-2, 1:-1] - c[2:, 1:-1] - c[1:-1, :-2] - c[1:-1, 2:]
    mask = plateau_mask(channel)[1:-1, 1:-1]
    return float(lap[mask].var())


def stats(path):
    img = load(path)
    out = {}
    for name, fn in (("hcf_com", hcf_com), ("peak_kurt", peak_kurtosis),
                     ("hf_energy", hf_energy)):
        out[name] = float(np.mean([fn(img[:, :, c]) for c in range(3)]))
    return out


def main():
    directory = pathlib.Path(sys.argv[1])
    covers = sorted(directory.glob("cover_*.png"))
    stegos = sorted(directory.glob("stego_*.png"))
    if not covers:
        raise SystemExit(f"no cover images in {directory}")

    rows = {"cover": [stats(p) for p in covers],
            "stego": [stats(p) for p in stegos]}

    keys = list(rows["cover"][0])
    print(f"{len(covers)} covers, {len(stegos)} stegos\n")
    print(f"{'statistic':<12}{'cover mean':>14}{'stego mean':>14}"
          f"{'pooled sd':>12}{'separation':>12}{'overlap':>9}")
    print("-" * 73)

    for key in keys:
        a = np.array([r[key] for r in rows["cover"]])
        b = np.array([r[key] for r in rows["stego"]])
        sd = np.sqrt((a.var(ddof=1) + b.var(ddof=1)) / 2)
        d = abs(b.mean() - a.mean()) / sd if sd > 0 else float("inf")
        # Do the two populations overlap at all?
        overlap = "yes" if (max(a.min(), b.min()) <= min(a.max(), b.max())) else "NO"
        print(f"{key:<12}{a.mean():>14.6f}{b.mean():>14.6f}"
              f"{sd:>12.6f}{d:>12.2f}{overlap:>9}")

    print("\nper-image values")
    for key in keys:
        a = [r[key] for r in rows["cover"]]
        b = [r[key] for r in rows["stego"]]
        print(f"\n  {key}")
        print("    cover: " + " ".join(f"{v:.5f}" for v in a))
        print("    stego: " + " ".join(f"{v:.5f}" for v in b))
        # Paired comparison: same seed, so pairing removes container variance.
        if len(a) == len(b):
            diff = np.array(b) - np.array(a)
            wins = int((diff > 0).sum())
            print(f"    paired delta: mean {diff.mean():+.6f}, "
                  f"sd {diff.std(ddof=1):.6f}, stego higher in {wins}/{len(diff)}")


if __name__ == "__main__":
    main()
