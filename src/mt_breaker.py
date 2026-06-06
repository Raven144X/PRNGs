"""
Mersenne Twister (MT19937) RNG Breaker
=======================================
Demonstrates that Python's random module (which uses MT19937) is completely
predictable once you observe 624 consecutive 32-bit outputs.

HOW IT WORKS:
  MT19937 maintains an internal state of 624 x 32-bit integers.
  Each call to getrandbits(32) outputs a "tempered" version of one state word.
  The tempering transform is fully invertible, so we can recover the
  original state word from each output.
  After collecting all 624 state words, we clone the RNG's state and
  can predict every future output with 100% accuracy.
"""

import random

# ---------------------------------------------------------------------------
# MT19937 constants
# ---------------------------------------------------------------------------
N = 624   # state size (32-bit words)


# ---------------------------------------------------------------------------
# Invert the MT19937 tempering transform
#
# MT19937 forward tempering (in order):
#   y ^= (y >> 11)
#   y ^= (y <<  7) & 0x9D2C5680
#   y ^= (y << 15) & 0xEFC60000
#   y ^= (y >> 18)
#
# We reverse these four steps in the opposite order.
# ---------------------------------------------------------------------------

def _inv_right_xor(y: int, shift: int) -> int:
    """Invert y ^= (y >> shift).  Top 'shift' bits are unchanged; propagate."""
    result = y
    for _ in range(32 // shift):
        result = y ^ (result >> shift)
    return result & 0xFFFFFFFF


def _inv_left_xor_mask(y: int, shift: int, mask: int) -> int:
    """Invert y ^= (y << shift) & mask.  Bottom 'shift' bits unchanged; propagate."""
    result = y
    for _ in range(32 // shift):
        result = y ^ ((result << shift) & mask)
    return result & 0xFFFFFFFF


def untemper(y: int) -> int:
    """
    Fully reverse the MT19937 tempering transform.
    Given an observed output word, returns the raw state word that produced it.
    """
    y = _inv_right_xor(y, 18)
    y = _inv_left_xor_mask(y, 15, 0xEFC60000)
    y = _inv_left_xor_mask(y,  7, 0x9D2C5680)
    y = _inv_right_xor(y, 11)
    return y & 0xFFFFFFFF


# ---------------------------------------------------------------------------
# Clone the RNG state from 624 observed 32-bit outputs
# ---------------------------------------------------------------------------

def clone_rng(observed_outputs: list[int]) -> random.Random:
    """
    Given 624 consecutive getrandbits(32) outputs from a victim Random instance,
    reconstruct its internal state and return a perfect clone.

    The clone will produce identical outputs for all subsequent calls —
    no knowledge of the original seed is required.
    """
    if len(observed_outputs) < N:
        raise ValueError(f"Need at least {N} outputs, got {len(observed_outputs)}")

    # Invert the tempering transform on each observed output to recover the
    # post-twist state words.  CPython's setstate expects index=N so that
    # the next call triggers another twist (advancing to the next 624 words).
    state = [untemper(y) for y in observed_outputs[:N]]

    cloned = random.Random()
    cloned.setstate((3, tuple(state + [N]), None))
    return cloned


# ---------------------------------------------------------------------------
# Pretty-print helpers
# ---------------------------------------------------------------------------

def separator(title: str) -> None:
    width = 62
    print(f"\n{'=' * width}")
    print(f"  {title}")
    print('=' * width)


# ---------------------------------------------------------------------------
# Demo
# ---------------------------------------------------------------------------

def main() -> None:
    print(__doc__)

    # -----------------------------------------------------------------------
    # Step 1: Create a "victim" RNG with an unknown seed
    # -----------------------------------------------------------------------
    separator("Step 1 – Victim RNG (unknown seed)")
    victim = random.Random()       # seeded from OS entropy — seed unknown to us
    print("  Victim RNG created, seeded from OS entropy.")
    print("  We can ONLY observe its outputs — not its seed or internal state.\n")

    # -----------------------------------------------------------------------
    # Step 2: Observe 624 consecutive 32-bit outputs (the attack window)
    # -----------------------------------------------------------------------
    separator("Step 2 – Observe 624 outputs (the attack window)")
    observed = [victim.getrandbits(32) for _ in range(N)]
    print(f"  Collected {N} outputs.  First five:")
    for v in observed[:5]:
        print(f"    {v:>12d}  (0x{v:08X})")
    print("    ...")

    # -----------------------------------------------------------------------
    # Step 3: Clone the RNG
    # -----------------------------------------------------------------------
    separator("Step 3 – Clone the RNG state")
    clone = clone_rng(observed)
    print("  Done.  Internal state reconstructed from observed outputs.")
    print("  Zero knowledge of the original seed required.\n")

    # -----------------------------------------------------------------------
    # Step 4: Verify — compare future outputs side by side
    # -----------------------------------------------------------------------
    separator("Step 4 – Verify future predictions")
    print(f"  {'Output #':<12} {'Victim (real)':>14} {'Clone (ours)':>14}  Match?")
    print(f"  {'-'*8:<12} {'-'*14:>14} {'-'*14:>14}  ------")

    n_predict = 20
    all_correct = True
    for i in range(n_predict):
        real = victim.getrandbits(32)
        pred = clone.getrandbits(32)
        ok   = real == pred
        if not ok:
            all_correct = False
        mark = "✓" if ok else "✗ WRONG"
        print(f"  {N + i + 1:<12} {real:>14} {pred:>14}  {mark}")

    # -----------------------------------------------------------------------
    # Step 5: Higher-level API calls
    # -----------------------------------------------------------------------
    separator("Step 5 – Predicting higher-level calls")
    print("  random.random(), randint(), choice() all consume getrandbits internally.\n")

    victim2 = random.Random()
    obs2    = [victim2.getrandbits(32) for _ in range(N)]
    clone2  = clone_rng(obs2)

    fruits = ["apple", "banana", "cherry", "date", "elderberry"]
    checks = [
        ("random()",          lambda r: round(r.random(), 6),       lambda v: f"{v:.6f}"),
        ("randint(1, 1000)",  lambda r: r.randint(1, 1000),         str),
        ("randint(1, 1000)",  lambda r: r.randint(1, 1000),         str),
        ("choice(fruits)",    lambda r: r.choice(fruits),           str),
        ("uniform(0, 100)",   lambda r: round(r.uniform(0, 100), 4), lambda v: f"{v:.4f}"),
    ]

    print(f"  {'Call':<28} {'Victim':>12}  {'Clone':>12}  Match?")
    print(f"  {'-'*28:<28} {'-'*12:>12}  {'-'*12:>12}  ------")
    for label, fn, fmt in checks:
        real = fn(victim2)
        pred = fn(clone2)
        ok   = real == pred
        mark = "✓" if ok else "✗ WRONG"
        print(f"  {label:<28} {fmt(real):>12}  {fmt(pred):>12}  {mark}")

    # -----------------------------------------------------------------------
    # Summary
    # -----------------------------------------------------------------------
    separator("Summary")
    status = "ALL CORRECT ✓" if all_correct else "SOME WRONG ✗"
    print(f"""
  Result: {status}

  What we just did
  ─────────────────
  • Observed only {N} consecutive 32-bit outputs from the victim RNG.
  • Applied the inverse tempering transform to each output, recovering
    the raw MT19937 internal state word for each position.
  • Cloned the RNG state into a new Random() instance — zero seed knowledge.
  • Predicted every subsequent output with 100% accuracy.

  Why this matters
  ─────────────────
  Python's random module (and most MT19937 implementations) is NOT
  cryptographically secure.  An adversary who can observe {N} outputs
  can predict ALL future (and reconstruct past) outputs.

  Do NOT use random for:
    ✗  Session tokens / API keys / passwords
    ✗  Cryptographic nonces
    ✗  Lottery / gambling / fairness-critical systems
    ✗  Any security-sensitive application

  Safe alternatives (backed by OS CSPRNG):
    ✓  secrets module (Python 3.6+)   — e.g. secrets.token_hex(32)
    ✓  os.urandom(n)
    ✓  cryptography library
""")


if __name__ == "__main__":
    main()
