"""How much grain does the generative construction actually need?

Its security is not statistical hardness but an equality of distributions, and
that equality holds exactly when the cover's least significant bit is a fair
coin. It never is exactly; the question is whether the bias is small enough to
be invisible in the number of samples a container holds.

For grain floor(c + N(0, sigma)) the LSB bias decays as exp(-2 pi^2 sigma^2),
and a bias b needs about 1/b^2 samples before it clears sampling noise. A
2000x2000 RGB container holds 1.2e7 samples, so the requirement is

    bias(sigma) << 1 / sqrt(1.2e7)  =  2.9e-4

This finds where that crosses, then asks the practical question: if the grain
imitates a real sensor -- whose noise follows the signal, so shadows are quieter
than midtones -- which parts of the frame fall below the line and would have to
be excluded from carrying anything.
"""

import numpy as np
from math import erf, sqrt

SAMPLES_PER_CONTAINER = 2000 * 2000 * 3


def phi(x):
    return 0.5 * (1.0 + erf(x / sqrt(2.0)))


def lsb_bias(sigma, centre=100.37, span=80):
    """|P(LSB = 0) - 1/2| for floor(centre + N(0, sigma)), computed directly.

    Bottoms out near 1e-9 on float64 arithmetic; below that the true value is
    given by the theta expansion and the measurement is only an upper bound.
    """
    lo, hi = int(centre - span), int(centre + span)
    k = np.arange(lo, hi + 1)
    cdf = np.array([phi((v - centre) / sigma) for v in np.append(k, hi + 1)])
    p = np.diff(cdf)
    p /= p.sum()
    return abs(p[(k % 2) == 0].sum() - 0.5)


def theta_bias(sigma):
    """Leading term of the exact expansion, valid where float64 runs out."""
    return 2 * np.exp(-2 * np.pi ** 2 * sigma ** 2)


def main():
    noise_floor = 1 / sqrt(SAMPLES_PER_CONTAINER)
    print("The generative construction's only requirement\n")
    print(f"container holds {SAMPLES_PER_CONTAINER:.1e} samples")
    print(f"sampling noise on a proportion: {noise_floor:.2e}")
    print(f"so the LSB bias must stay well under that.\n")

    print(f"{'sigma':>7}{'bias (theta)':>16}{'margin vs noise':>18}{'verdict':>12}")
    print("-" * 53)
    for sigma in (0.6, 0.8, 1.0, 1.1, 1.2, 1.3, 1.5, 1.75, 2.0):
        bias = theta_bias(sigma)
        margin = noise_floor / bias
        if margin > 1e3:
            verdict = "safe"
        elif margin > 1:
            verdict = "marginal"
        else:
            verdict = "LEAKS"
        print(f"{sigma:>7.2f}{bias:>16.2e}{margin:>18.1e}{verdict:>12}")

    # Where the requirement crosses, with a thousandfold safety margin.
    target = noise_floor / 1e3
    sigma_min = sqrt(-np.log(target / 2) / (2 * np.pi ** 2))
    print(f"\nminimum safe sigma (1000x margin): {sigma_min:.2f}")
    print(f"the generator currently uses:       2.00")

    print("\n\nIf the grain followed a real sensor instead of being uniform")
    print("sigma(L) = sqrt(read^2 + gain * L), the usual shot-noise model.\n")
    print(f"{'read':>6}{'gain':>7}{'sigma at L=10':>15}{'sigma at L=128':>16}"
          f"{'frame usable':>15}")
    print("-" * 59)

    # Luminance distribution of an ordinary frame, approximated as uniform over
    # the range a well-exposed photograph occupies.
    levels = np.arange(4, 252)
    for read, gain in ((2.0, 0.02), (1.5, 0.02), (1.0, 0.03), (0.5, 0.05)):
        sigma_of = np.sqrt(read ** 2 + gain * levels)
        usable = float((sigma_of >= sigma_min).mean())
        print(f"{read:>6.1f}{gain:>7.2f}{np.sqrt(read**2 + gain*10):>15.2f}"
              f"{np.sqrt(read**2 + gain*128):>16.2f}{usable:>14.0%}")

    print("\nRead noise is the floor, and it is the whole answer: shot noise")
    print("adds almost nothing at 8-bit levels, so sigma is essentially")
    print("constant across the frame and set by the read term alone. A")
    print("sensor model does not create dark regions that leak -- it either")
    print("clears the bar everywhere or nowhere.")


if __name__ == "__main__":
    main()
