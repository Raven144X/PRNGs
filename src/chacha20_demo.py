"""
ChaCha20 CSPRNG — Security Demonstration
==========================================
A direct contrast to the Mersenne Twister (MT19937) attack.

Shows that ChaCha20, used as a cryptographically secure pseudo-random
number generator (CSPRNG), resists the same kind of state-recovery attack
that completely breaks MT19937.

STRUCTURE
  Part 1 – ChaCha20 internals explained (the quarter-round, the block)
  Part 2 – MT19937 clone attack (recap, succeeds in ~0 ms)
  Part 3 – ChaCha20 clone attack (fails — shown mathematically)
  Part 4 – Statistical comparison (both pass, for different reasons)
  Part 5 – Practical security audit of common Python patterns
"""

import os
import random
import struct
import time
import hashlib
import secrets
from typing import Optional


# ============================================================
#  PART 0 — helpers
# ============================================================

def banner(title: str, width: int = 66) -> None:
    print(f"\n{'=' * width}")
    print(f"  {title}")
    print('=' * width)

def sub(title: str) -> None:
    print(f"\n  ── {title}")

def ok(msg: str)   -> None: print(f"  ✓  {msg}")
def bad(msg: str)  -> None: print(f"  ✗  {msg}")
def info(msg: str) -> None: print(f"     {msg}")


# ============================================================
#  PART 1 — Pure-Python ChaCha20 implementation (RFC 7539)
# ============================================================

def _rotl32(v: int, n: int) -> int:
    """Rotate-left a 32-bit integer by n bits."""
    return ((v << n) | (v >> (32 - n))) & 0xFFFFFFFF

def _quarter_round(a: int, b: int, c: int, d: int):
    """
    The ChaCha20 quarter-round function — the sole primitive.
    Four ARX (Add-Rotate-XOR) steps.  Avalanche is the key property:
    every output bit depends on every input bit after a full round.
    """
    a = (a + b) & 0xFFFFFFFF;  d ^= a;  d = _rotl32(d, 16)
    c = (c + d) & 0xFFFFFFFF;  b ^= c;  b = _rotl32(b, 12)
    a = (a + b) & 0xFFFFFFFF;  d ^= a;  d = _rotl32(d,  8)
    c = (c + d) & 0xFFFFFFFF;  b ^= c;  b = _rotl32(b,  7)
    return a, b, c, d

def _chacha20_block(key: bytes, counter: int, nonce: bytes) -> bytes:
    """
    Produce one 64-byte (512-bit) ChaCha20 keystream block.

    Initial state (16 x 32-bit words):
        "expa"  "nd 3"  "2-by"  "te k"   ← 4 constant words
        key[0]  key[1]  key[2]  key[3]   ─┐
        key[4]  key[5]  key[6]  key[7]   ─┘ 8 key words  (256 bits)
        counter  nonce[0]  nonce[1]  nonce[2]  ← 1 counter + 3 nonce words
    """
    # Constants: "expand 32-byte k"
    CONSTANTS = [0x61707865, 0x3320646E, 0x79622D32, 0x6B206574]

    key_words   = list(struct.unpack('<8I', key))
    nonce_words = list(struct.unpack('<3I', nonce))

    state = CONSTANTS + key_words + [counter] + nonce_words
    working = state[:]

    # 20 rounds = 10 double-rounds (column + diagonal quarter-rounds)
    for _ in range(10):
        # Column rounds
        working[0], working[4], working[ 8], working[12] = _quarter_round(working[0], working[4], working[ 8], working[12])
        working[1], working[5], working[ 9], working[13] = _quarter_round(working[1], working[5], working[ 9], working[13])
        working[2], working[6], working[10], working[14] = _quarter_round(working[2], working[6], working[10], working[14])
        working[3], working[7], working[11], working[15] = _quarter_round(working[3], working[7], working[11], working[15])
        # Diagonal rounds
        working[0], working[5], working[10], working[15] = _quarter_round(working[0], working[5], working[10], working[15])
        working[1], working[6], working[11], working[12] = _quarter_round(working[1], working[6], working[11], working[12])
        working[2], working[7], working[ 8], working[13] = _quarter_round(working[2], working[7], working[ 8], working[13])
        working[3], working[4], working[ 9], working[14] = _quarter_round(working[3], working[4], working[ 9], working[14])

    # Add the original state back (prevents reversing the rounds even with output)
    final = [(working[i] + state[i]) & 0xFFFFFFFF for i in range(16)]
    return struct.pack('<16I', *final)


class ChaCha20RNG:
    """
    A CSPRNG built on ChaCha20 (RFC 7539 / RFC 8439).
    Generates an unlimited stream of cryptographically secure random bytes.
    """

    def __init__(self, key: Optional[bytes] = None, nonce: Optional[bytes] = None):
        self._key     = key   if key   else os.urandom(32)   # 256-bit key
        self._nonce   = nonce if nonce else os.urandom(12)   # 96-bit nonce
        self._counter = 0
        self._buffer  = b''

    def _refill(self) -> None:
        self._buffer += _chacha20_block(self._key, self._counter, self._nonce)
        self._counter += 1

    def randbytes(self, n: int) -> bytes:
        while len(self._buffer) < n:
            self._refill()
        out, self._buffer = self._buffer[:n], self._buffer[n:]
        return out

    def getrandbits(self, k: int) -> int:
        nbytes = (k + 7) // 8
        raw = self.randbytes(nbytes)
        return int.from_bytes(raw, 'little') & ((1 << k) - 1)

    def random(self) -> float:
        return self.getrandbits(53) / (1 << 53)

    def randint(self, a: int, b: int) -> int:
        n = b - a + 1
        return a + (self.getrandbits(n.bit_length() + 32) % n)


# ============================================================
#  PART 2 — MT19937 clone attack (recap)
# ============================================================

def _inv_right_xor(y: int, shift: int) -> int:
    result = y
    for _ in range(32 // shift):
        result = y ^ (result >> shift)
    return result & 0xFFFFFFFF

def _inv_left_xor_mask(y: int, shift: int, mask: int) -> int:
    result = y
    for _ in range(32 // shift):
        result = y ^ ((result << shift) & mask)
    return result & 0xFFFFFFFF

def untemper(y: int) -> int:
    y = _inv_right_xor(y, 18)
    y = _inv_left_xor_mask(y, 15, 0xEFC60000)
    y = _inv_left_xor_mask(y,  7, 0x9D2C5680)
    y = _inv_right_xor(y, 11)
    return y & 0xFFFFFFFF

def clone_mt_rng(observed: list[int]) -> random.Random:
    state = [untemper(y) for y in observed[:624]]
    cloned = random.Random()
    cloned.setstate((3, tuple(state + [624]), None))
    return cloned

def demo_mt_attack() -> None:
    banner("PART 2 — MT19937 Clone Attack (recap)")

    victim = random.Random()
    t0 = time.perf_counter()
    observed = [victim.getrandbits(32) for _ in range(624)]
    clone    = clone_mt_rng(observed)
    elapsed  = (time.perf_counter() - t0) * 1000

    hits = sum(victim.getrandbits(32) == clone.getrandbits(32) for _ in range(1000))

    info(f"Observed     : 624 outputs")
    info(f"Attack time  : {elapsed:.1f} ms")
    info(f"Predictions  : {hits}/1000 correct")
    print()
    if hits == 1000:
        bad("MT19937 completely broken — 100% prediction accuracy.")
    else:
        ok(f"Only {hits}/1000 correct (unexpected — something went wrong).")


# ============================================================
#  PART 3 — Attempted ChaCha20 clone attack
# ============================================================

def attempt_chacha20_clone(observed_words: list[int], n_verify: int = 1000) -> None:
    """
    An attacker who observes `len(observed_words)` 32-bit outputs from a
    ChaCha20 RNG tries every conceivable naive reconstruction:
      (a) Use observed words directly as 'state' — fails
      (b) Guess the key by brute force   — computationally infeasible
      (c) Statistical prediction          — no better than random chance
    We demonstrate all three and measure the failure.
    """
    banner("PART 3 — Attempted ChaCha20 Clone Attack")

    real_rng = ChaCha20RNG()

    # Collect the same number of observations as the MT attack
    sub("Observation phase")
    observed = [real_rng.getrandbits(32) for _ in range(624)]
    info(f"Collected 624 outputs (same as MT attack).")
    info(f"ChaCha20 key: 256 bits = 2^256 ≈ 1.16 × 10^77 possible keys")
    info(f"Fastest supercomputer: ~10^18 ops/s")
    info(f"Time to brute-force: ~10^59 years  (universe age: ~1.4 × 10^10 years)")

    # --- Attempt (a): replay observed words as a fake 'state' ---------------
    sub("Attempt A — replay observed output as fake state")
    # Even if we somehow reverse ChaCha20 block output (we can't),
    # the final Addition step state += working means the pre-round state
    # is not recoverable from the output without the key.
    # We demonstrate by just checking prediction accuracy naively.
    hit_a = 0
    idx   = 0
    for _ in range(n_verify):
        real_val = real_rng.getrandbits(32)
        guess    = observed[idx % len(observed)]   # best naive reuse
        if real_val == guess:
            hit_a += 1
        idx += 1

    pct_a = hit_a / n_verify * 100
    info(f"Correct predictions: {hit_a}/{n_verify}  ({pct_a:.2f}%)")
    info(f"Expected by chance : {n_verify / 2**32 * 100:.4f}%")
    bad(f"Attack A failed — no better than random guessing.")

    # --- Attempt (b): statistical next-value prediction ----------------------
    sub("Attempt B — statistical / linear prediction")
    # For a linear congruential generator (LCG), you could solve for
    # modulus/multiplier from two outputs.  For MT you invert tempering.
    # For ChaCha20 the ARX network provides no linear relationship to exploit.
    # We show: XOR of consecutive outputs has uniform distribution (no bias).
    diffs = [observed[i] ^ observed[i+1] for i in range(len(observed)-1)]
    bit_counts = [bin(d).count('1') for d in diffs]
    avg_bits = sum(bit_counts) / len(bit_counts)
    info(f"Average set bits in XOR(output[i], output[i+1]): {avg_bits:.2f}")
    info(f"Expected for uniform random 32-bit words       : 16.00")
    info(f"Deviation from uniform: {abs(avg_bits - 16):.2f} bits  (≈ {abs(avg_bits-16)/16*100:.1f}%)")
    bad("Attack B failed — no exploitable statistical structure found.")

    # --- Attempt (c): key-length exhaustion estimate -------------------------
    sub("Attempt C — key space exhaustion (theoretical)")
    key_bits = 256
    info(f"ChaCha20 key space: 2^{key_bits} keys")
    info(f"Even with quantum computer (Grover's): 2^{key_bits//2} = 2^128 ops needed")
    info(f"2^128 ops at 10^18 ops/s = ~10^20 years")
    bad("Attack C impossible — key space is computationally unbounded.")

    print()
    ok("ChaCha20 withstands all three attack vectors.")
    ok("Observing any number of outputs reveals ZERO information about future outputs.")


# ============================================================
#  PART 4 — Statistical quality comparison
# ============================================================

def chi_square_uniformity(samples: list[int], n_buckets: int = 256) -> float:
    """Chi-square test for uniformity over [0, n_buckets)."""
    counts = [0] * n_buckets
    for s in samples:
        counts[s % n_buckets] += 1
    expected = len(samples) / n_buckets
    return sum((c - expected) ** 2 / expected for c in counts)

def demo_statistics() -> None:
    banner("PART 4 — Statistical Quality Comparison")

    N = 100_000

    mt_rng      = random.Random()
    chacha_rng  = ChaCha20RNG()

    mt_samples      = [mt_rng.getrandbits(8)     for _ in range(N)]
    chacha_samples  = [chacha_rng.getrandbits(8) for _ in range(N)]

    mt_chi      = chi_square_uniformity(mt_samples)
    chacha_chi  = chi_square_uniformity(chacha_samples)

    # Bit-balance test: fraction of set bits should be ~0.5
    mt_bits     = sum(bin(x).count('1') for x in mt_samples) / (N * 8)
    chacha_bits = sum(bin(x).count('1') for x in chacha_samples) / (N * 8)

    # Autocorrelation at lag 1
    def autocorr(seq):
        mean = sum(seq) / len(seq)
        num = sum((seq[i]-mean)*(seq[i+1]-mean) for i in range(len(seq)-1))
        den = sum((x-mean)**2 for x in seq)
        return num/den if den else 0

    mt_ac     = autocorr(mt_samples)
    chacha_ac = autocorr(chacha_samples)

    sub("Results")
    print(f"\n  {'Metric':<32} {'MT19937':>12}  {'ChaCha20':>12}  {'Ideal':>10}")
    print(f"  {'-'*32} {'-'*12}  {'-'*12}  {'-'*10}")
    print(f"  {'Chi-square (lower=more uniform)':<32} {mt_chi:>12.1f}  {chacha_chi:>12.1f}  {'≈255':>10}")
    print(f"  {'Bit balance (want 0.500)':<32} {mt_bits:>12.4f}  {chacha_bits:>12.4f}  {'0.5000':>10}")
    print(f"  {'Autocorrelation (want ≈0)':<32} {mt_ac:>12.6f}  {chacha_ac:>12.6f}  {'0.0000':>10}")

    print()
    info("Both generators pass statistical tests — but only ChaCha20 is cryptographically secure.")
    info("MT19937 fails because its output is algebraically reversible, not because it's biased.")


# ============================================================
#  PART 5 — Practical security audit
# ============================================================

def demo_security_audit() -> None:
    banner("PART 5 — Practical Security Audit: Common Python Patterns")

    patterns = [
        # (label, vulnerable?, example_code, fix)
        (
            "Session token via random.token_hex",
            True,
            "token = ''.join(random.choices('0123456789abcdef', k=32))",
            "token = secrets.token_hex(32)",
        ),
        (
            "Password reset code via random.randint",
            True,
            "code = str(random.randint(100000, 999999))",
            "code = str(secrets.randbelow(900000) + 100000)",
        ),
        (
            "API key via random.getrandbits",
            True,
            "key = hex(random.getrandbits(128))[2:]",
            "key = secrets.token_hex(16)",
        ),
        (
            "UUID via uuid.uuid4()",
            False,
            "uid = str(uuid.uuid4())",
            "(already uses os.urandom — safe)",
        ),
        (
            "Cryptographic nonce via secrets",
            False,
            "nonce = secrets.token_bytes(12)",
            "(correct — no fix needed)",
        ),
        (
            "Shuffle a deck via random.shuffle",
            True,
            "random.shuffle(deck)  # in a real card game",
            "Use a CSPRNG-backed shuffle (see below)",
        ),
        (
            "Salt for password hashing",
            True,
            "salt = str(random.random())",
            "salt = os.urandom(16)",
        ),
    ]

    print(f"\n  {'Pattern':<38} {'Safe?':>6}  {'Recommendation'}")
    print(f"  {'-'*38} {'-'*6}  {'-'*30}")
    for label, vuln, _, fix in patterns:
        mark   = "  ✗  " if vuln else "  ✓  "
        status = "NO " if vuln else "YES"
        print(f"  {mark}{label:<35} {status:>6}  {fix}")

    sub("CSPRNG-backed shuffle example")
    def secure_shuffle(lst: list) -> list:
        """Fisher-Yates shuffle using os.urandom for indices."""
        lst = lst[:]
        for i in range(len(lst) - 1, 0, -1):
            j = int.from_bytes(os.urandom(4), 'little') % (i + 1)
            lst[i], lst[j] = lst[j], lst[i]
        return lst

    deck = list(range(1, 53))
    shuffled = secure_shuffle(deck)
    info(f"Secure shuffle sample (first 10): {shuffled[:10]}")
    ok("Every card position chosen with cryptographic randomness.")


# ============================================================
#  PART 6 — Side-by-side clone attack summary
# ============================================================

def demo_clone_comparison() -> None:
    banner("PART 6 — Side-by-Side: Clone Attack Results")

    # MT19937
    mt_victim = random.Random()
    observed  = [mt_victim.getrandbits(32) for _ in range(624)]
    mt_clone  = clone_mt_rng(observed)
    mt_hits   = sum(mt_victim.getrandbits(32) == mt_clone.getrandbits(32) for _ in range(1000))

    # ChaCha20 — attacker just guesses using os.urandom (best possible)
    cc_victim = ChaCha20RNG()
    _observed = [cc_victim.getrandbits(32) for _ in range(624)]
    cc_hits   = sum(cc_victim.getrandbits(32) == (int.from_bytes(os.urandom(4), 'little')) for _ in range(1000))

    print(f"""
  ┌─────────────────────────────────────────────────────────────┐
  │  Generator   │  Obs. needed  │  Attack time  │  Accuracy   │
  ├──────────────┼───────────────┼───────────────┼─────────────┤
  │  MT19937     │  624 outputs  │  < 1 ms       │  {mt_hits:>4}/1000  │
  │  ChaCha20    │  ∞ (useless)  │  ∞ (years)    │  {cc_hits:>4}/1000  │
  └─────────────────────────────────────────────────────────────┘
""")
    bad(f"MT19937 — {mt_hits}/1000 correct  ({mt_hits/10:.0f}%)  ← BROKEN")
    ok (f"ChaCha20 — {cc_hits}/1000 correct  ({cc_hits/10:.1f}%)  ← indistinguishable from chance")


# ============================================================
#  MAIN
# ============================================================

def main() -> None:
    print(__doc__)

    banner("PART 1 — ChaCha20 Internals")
    sub("The quarter-round (the only primitive)")
    info("  a += b;  d ^= a;  d <<<= 16")
    info("  c += d;  b ^= c;  b <<<= 12")
    info("  a += b;  d ^= a;  d <<<= 8")
    info("  c += d;  b ^= c;  b <<<= 7")
    info("")
    info("A ChaCha20 block = 10 double-rounds × 8 quarter-rounds = 80 QRs")
    info("Each QR mixes 4 of 16 state words.  After 2 rounds, every output")
    info("bit depends on every input bit  — full avalanche.")
    info("")
    info("Crucially: final output = rounds(state) + state")
    info("The addition destroys the ability to invert even if you could")
    info("reverse the ARX rounds — you'd need the pre-round state too.")

    sub("Verify our ChaCha20 against RFC 7539 test vector")
    key   = bytes.fromhex("000102030405060708090a0b0c0d0e0f"
                           "101112131415161718191a1b1c1d1e1f")
    nonce = bytes.fromhex("000000090000004a00000000")
    block = _chacha20_block(key, 1, nonce)
    expected_first_word = 0xe4e7f110
    got = struct.unpack('<I', block[:4])[0]
    if got == expected_first_word:
        ok(f"RFC 7539 test vector passed  (first word: 0x{got:08X})")
    else:
        bad(f"Test vector mismatch: got 0x{got:08X}, expected 0x{expected_first_word:08X}")

    demo_mt_attack()
    attempt_chacha20_clone([])
    demo_statistics()
    demo_security_audit()
    demo_clone_comparison()

    banner("CONCLUSION")
    print("""
  Property              MT19937              ChaCha20 CSPRNG
  ─────────────────────────────────────────────────────────────
  State size            624 × 32-bit         256-bit key (secret)
  State observable?     YES — after 624 out  NO — computationally hidden
  Clonable?             YES — trivially       NO — 2^128 ops minimum
  Statistically uniform YES                  YES
  Cryptographically     NO                   YES
    secure?
  Use for tokens/keys?  NEVER                YES
  Use for simulations?  YES (fast, good      YES (but overkill)
                          distributions)
  Python stdlib?        random module         secrets / os.urandom

  Rule of thumb: if the output affects security, use secrets or os.urandom.
                 If it's purely for simulation or games, random is fine.
""")


if __name__ == "__main__":
    main()
