"""Two questions, both answerable in closed form.

1. Given N generated images of which exactly one carries a payload, how often
   does the best possible attacker point at the right one? The attacker ranks
   all N by the likelihood ratio and picks the largest, so

       P(hit) = integral phi(x - d) Phi(x)^(N-1) dx

   where d is the deflection of the optimal detector, measured at 0.31 for the
   current design.

2. How uniform is the least significant bit of the generator's own grain? That
   number decides whether *perfect* indistinguishability is reachable at all:
   if P(LSB = 0) is exactly 1/2, a sample drawn conditioned on a ciphertext bit
   has precisely the cover distribution, and no detector can do better than
   chance -- not "hard", but information-theoretically impossible.
"""

import numpy as np
from math import erf, sqrt, log10


def phi_cdf(x):
    return 0.5 * (1.0 + erf(x / sqrt(2.0)))


def hit_rate(d, n, grid=4000, span=12.0):
    """P(the stego image is ranked first of n) for deflection d."""
    x = np.linspace(-span, span, grid)
    pdf = np.exp(-0.5 * (x - d) ** 2) / sqrt(2 * np.pi)
    cdf = np.array([phi_cdf(v) for v in x])
    return float(np.trapezoid(pdf * cdf ** (n - 1), x))


def lsb_bias(c, sigma, span=60):
    """|P(LSB = 0) - 1/2| for floor(c + N(0, sigma)), computed exactly."""
    lo, hi = int(np.floor(c - span)), int(np.ceil(c + span))
    k = np.arange(lo, hi + 1)
    cdf = np.array([phi_cdf((v - c) / sigma) for v in np.append(k, hi + 1)])
    p = np.diff(cdf)
    p = p / p.sum()
    even = p[(k % 2) == 0].sum()
    return abs(even - 0.5)


def theoretical_bias(sigma):
    """Leading term of the Jacobi theta expansion: the bias decays as
    2 exp(-2 pi^2 sigma^2), independently of where the centre sits."""
    return 2 * np.exp(-2 * np.pi ** 2 * sigma ** 2)


def main():
    print("1. Picking the stego image out of a folder of N")
    print("   d = 0.31 is the optimal detector's deflection for the current design.\n")
    print(f"{'N':>8}{'chance':>12}{'attacker':>12}{'times better':>15}")
    print("-" * 47)
    for n in (10, 100, 1000):
        p = hit_rate(0.31, n)
        print(f"{n:>8}{1 / n:>12.4f}{p:>12.4f}{p * n:>15.2f}")

    print("\n   For comparison, if the design were detectable at d = 3:")
    for n in (100,):
        p = hit_rate(3.0, n)
        print(f"{n:>8}{1 / n:>12.4f}{p:>12.4f}{p * n:>15.2f}")

    print("\n\n2. Uniformity of the cover's least significant bit")
    print("   If this is 0, sampling conditioned on a ciphertext bit reproduces")
    print("   the cover distribution exactly and detection becomes impossible.\n")
    print(f"{'sigma':>8}{'worst-case bias':>20}{'theory 2e^-2pi^2s^2':>24}"
          f"{'samples to notice':>20}")
    print("-" * 72)
    for sigma in (0.5, 0.8, 1.0, 1.5, 2.0, 2.5):
        # Worst case over the fractional part of the centre.
        bias = max(lsb_bias(100 + f, sigma) for f in np.linspace(0, 1, 21))
        theory = theoretical_bias(sigma)
        # A bias b needs about 1/b^2 samples before it is visible above noise.
        need = 1 / bias ** 2 if bias > 0 else float("inf")
        exp = log10(need) if np.isfinite(need) else float("inf")
        print(f"{sigma:>8.1f}{bias:>20.3e}{theory:>24.3e}{'10^%.0f' % exp:>20}")

    print("\n   A 2000x2000 RGB container holds 10^7.1 samples.")


if __name__ == "__main__":
    main()
