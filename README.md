# PRNGs

# From Statistical Vulnerability to Cryptographic Security:
## Evaluating PRNGs via Deep Learning and Algebraic Cryptanalysis

This repository accompanies the research paper:

**"From Statistical Vulnerability to Cryptographic Security: Evaluating PRNGs via Deep Learning and Algebraic Cryptanalysis"**

The project investigates whether modern machine learning models can predict outputs of common pseudo-random number generators (PRNGs), and compares these results against classical algebraic cryptanalysis techniques.

---

## Research Questions

This work explores three key questions:

1. Can an LSTM detect statistical weaknesses in traditional PRNGs?
2. Does failure of a neural network imply cryptographic security?
3. How do algebraic attacks compare to deep learning attacks?

---

## Generators Studied

### Linear Congruential Generator (LCG)

Classical first-order recurrence:

\[
X_{n+1} = (aX_n + c)\bmod m
\]

Used as a baseline generator due to known structural weaknesses.

---

### Mersenne Twister (MT19937)

A 623-dimensionally equidistributed generator with period:

\[
2^{19937}-1
\]

Widely used in simulations and programming languages.

---

### ChaCha20

Cryptographically Secure Pseudo-Random Number Generator (CSPRNG) based on the ARX (Add-Rotate-XOR) stream cipher architecture.

---

## Experimental Framework

Two independent attack methodologies are evaluated.

### 1. Deep Learning Sequence Prediction

A 64-unit LSTM network is trained under:

- Bitwise Classification
- Numerical Trajectory Regression

Metrics:

- Classification Accuracy
- Binary Cross Entropy
- Mean Squared Error (MSE)

---

### 2. Algebraic Cryptanalysis

For MT19937:

- Tempering inversion
- Untempering attack
- Internal state reconstruction
- Future stream prediction

---

## Main Findings

| Generator | LSTM Result | Algebraic Attack |
|------------|------------|------------|
| LCG LSB | 100% Predictable | Trivial |
| LCG Full Output | Appears Random | Structural Weakness Exists |
| MT19937 | Appears Random | Fully Clonable |
| ChaCha20 | Appears Random | Resistant |

---

## Key Insight

Statistical randomness does not imply cryptographic security.

MT19937 successfully defeats sequence-learning neural networks but remains completely vulnerable to deterministic state recovery.

ChaCha20 is the only evaluated generator that resists both machine learning prediction and algebraic inversion.

---

## Repository Structure

```text
src/
├── Regression_on_MT19937.py
├── chacha20_demo.py
├── classification_on_MT19937.py
├── lcg.py
├── mersenneTwister.py
├── mt_breaker.py
```

---

## Installation

Clone the repository:

```bash
git clone https://github.com/YOUR_USERNAME/prng-security-analysis.git

cd prng-security-analysis
```

Install dependencies:

```bash
pip install -r requirements.txt
```

---

## Running Experiments

### Train LSTM on LCG

```bash
python examples/train_lcg.py
```

### Train LSTM on MT19937

```bash
python examples/train_mt.py
```

### Clone MT19937 State

```bash
python examples/clone_mt.py
```

---

## Results

Observed results:

| Experiment | Result |
|------------|---------|
| LCG LSB Classification | 100.00% |
| MT19937 LSB Classification | 50.03% |
| MT19937 Regression MSE | 0.083512 |
| ChaCha20 Regression MSE | 0.083331 |
| MT19937 State Recovery | 100% |

---

## Paper

The complete manuscript is available in:

```text
paper/paper.pdf
```

---

## References

- Matsumoto & Nishimura (1998)
- NIST SP 800-22
- Bernstein (2008)
- Hochreiter & Schmidhuber (1997)

---

## License

MIT License
