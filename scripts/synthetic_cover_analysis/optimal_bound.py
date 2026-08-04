"""Power of the OPTIMAL detector against the synthetic container generator.

The generator produces, on a plateau of the low-frequency field,

    pixel = floor(c + G),   G ~ N(0, sigma),  c constant and publicly known

with the samples independent given the field. That is a fully specified cover
source: an attacker holding the source code knows p_k exactly, so the optimal
test is the likelihood ratio on the sample histogram and no detector -- neural
or otherwise -- can beat it. Its power is therefore an upper bound on ALL
detectors, which is what makes it worth computing.

Embedding is LSB matching at rate beta with the sign drawn uniformly, so

    q_k = (1 - beta) p_k + beta (p_{k-1} + p_{k+1}) / 2

The deflection coefficient d^2 = N * sum_k (q_k - p_k)^2 / p_k gives the
separation in standard deviations; AUC = Phi(d / sqrt(2)).
"""

import numpy as np
from math import erf, sqrt


def phi(x):
    return 0.5 * (1.0 + erf(x / sqrt(2.0)))


def quantised_gaussian(c, sigma, span=40):
    """Exact pmf of floor(c + N(0, sigma)) over integer bins."""
    lo, hi = int(c - span), int(c + span)
    k = np.arange(lo, hi + 1)
    cdf = np.array([phi((v - c) / sigma) for v in np.append(k, hi + 1)])
    p = np.diff(cdf)
    return p / p.sum()


def deflection(p, beta, n):
    shifted = 0.5 * (np.roll(p, 1) + np.roll(p, -1))
    q = (1 - beta) * p + beta * shifted
    mask = p > 1e-15
    d2 = n * np.sum((q[mask] - p[mask]) ** 2 / p[mask])
    return sqrt(d2)


def report(label, sigma, beta, n):
    p = quantised_gaussian(223.4, sigma)
    d = deflection(p, beta, n)
    auc = phi(d / sqrt(2.0))
    lsb_entropy = binary_entropy(p[::2].sum())
    print(f"{label:<34}{sigma:>7.2f}{beta:>12.2e}{n:>13.2e}"
          f"{d:>9.2f}{auc:>9.3f}{lsb_entropy:>10.4f}")


def binary_entropy(p):
    if p <= 0 or p >= 1:
        return 0.0
    return -(p * np.log2(p) + (1 - p) * np.log2(1 - p))


def main():
    # Measured from the harness: 6747 of 12,000,000 samples changed, of which
    # ~83% land on plateau pixels, which are ~83% of the image.
    n_plateau = 12_000_000 * 0.83
    beta_measured = 6747 * 0.83 / n_plateau

    print("Optimal (likelihood-ratio) detector against a fully known cover source")
    print("AUC 0.5 = coin toss; 1.0 = perfect. LSB H = entropy of the cover LSB.\n")
    print(f"{'scenario':<34}{'sigma':>7}{'beta':>12}{'N':>13}"
          f"{'d':>9}{'AUC':>9}{'LSB H':>10}")
    print("-" * 94)

    report("stenoxide as it stands", 2.0, beta_measured, n_plateau)

    print()
    for sigma in (0.25, 0.5, 1.0, 1.5, 2.0, 3.0, 5.0):
        report(f"  grain sigma = {sigma}", sigma, beta_measured, n_plateau)

    print()
    for mult, name in ((1, "0.02 bpp (the hard cap)"),
                       (5, "0.10 bpp"), (25, "0.50 bpp"), (50, "1.00 bpp")):
        report(f"  rate {name}", 2.0, beta_measured * mult, n_plateau)

    print()
    print("Reference: with sigma = 2 the cover's own LSB is already an almost")
    print("fair coin, so a flipped bit is hidden by the grain and not by the")
    print("cost model. That is why the bound does not depend on HILL at all.")


if __name__ == "__main__":
    main()
