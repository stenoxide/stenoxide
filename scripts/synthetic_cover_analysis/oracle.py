"""Characterises the embedding by differencing cover and stego directly.

Not a detector -- it uses the cover, which an attacker is assumed not to have.
It answers what the changes look like, so the detector results can be read.
"""

import sys
import pathlib
import numpy as np
from PIL import Image


def load(p):
    return np.asarray(Image.open(p).convert("RGB"), dtype=np.int32)


def plateau(ch):
    return (np.abs(ch - 33) <= 10) | (np.abs(ch - 223) <= 10)


def main():
    d = pathlib.Path(sys.argv[1])
    covers = sorted(d.glob("cover_*.png"))
    for cp in covers:
        sp = cp.with_name(cp.name.replace("cover_", "stego_"))
        if not sp.exists():
            continue
        c, s = load(cp), load(sp)
        diff = s - c
        changed = diff != 0
        n = int(changed.sum())
        total = diff.size
        on_plateau = int((changed & plateau(c)).sum())
        plateau_share = float(plateau(c).mean())
        print(f"{cp.name}: {n} samples changed of {total} "
              f"({n / total:.5%}), values {sorted(set(diff[changed].tolist()))}, "
              f"{on_plateau / max(n, 1):.1%} of changes on plateaus "
              f"(plateaus are {plateau_share:.1%} of the image)")


if __name__ == "__main__":
    main()
