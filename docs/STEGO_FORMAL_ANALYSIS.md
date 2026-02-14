# Steganography Formal Analysis Survey

**Author:** Formal Verification Team
**Date:** 2026-02-14
**Status:** Research complete · Formal model: DEFERRED with rationale
**Ref:** [todo-formal.md](../todo-formal.md) item 3b

---

## Purpose

Survey established formal and semi-formal steganographic security models to determine whether any framework is tractable for Meow Decoder's stego carrier modes. This assessment informs item 3c (whether to build a formal stego model).

---

## 1. Cachin's Information-Theoretic Model (1998, 2004)

### Definition

Cachin defines steganographic security relative to a covertext distribution $C$ and stegotext distribution $S$:

- **$\epsilon$-secure steganography:** A steganographic system is $\epsilon$-secure if the Kullback-Leibler divergence satisfies:

$$D_{KL}(P_C \| P_S) \leq \epsilon$$

- **Perfectly secure ($\epsilon = 0$):** Stegotext and covertext are identically distributed. The warden (adversary) has zero advantage, regardless of computational power.

- **$\epsilon$-secure ($\epsilon > 0$):** The adversary's advantage is bounded by $\epsilon$. Statistical tests cannot distinguish embedded from clean media beyond this bound.

### Key Results

1. **Perfectly secure stego requires:** The embedding function must sample from the exact covertext distribution $P_C$. This requires a perfect model of the cover medium.

2. **Capacity bound:** For $\epsilon$-secure stego with covertext entropy $H(C)$, the maximum embedding rate is bounded by $H(C) - D_{KL}(P_C \| P_S)$ bits per cover element.

3. **Detection theorem:** Any deviation from $P_C$ is in principle detectable given enough samples. The required sample size scales as $O(1/\epsilon^2)$.

### Reference

- C. Cachin, "An Information-Theoretic Model for Steganography," *Information and Computation*, vol. 192, no. 1, pp. 41–56, 2004. (Extended from IH 1998.)

---

## 2. Ker's Batch Steganography / Pooled Steganalysis (2006, 2007)

### Definition

Ker extends Cachin's model to the **batch** setting where an adversary observes $N$ objects, of which $M$ contain steganographic payloads:

- **Batch steganography:** The sender distributes a message across $M$ out of $N$ cover objects.
- **Pooled steganalysis:** The warden tests the entire batch jointly rather than individual objects.

### Key Results

1. **Square root law of steganography:** For a fixed total payload of $m$ bits distributed across $M$ carriers each with capacity $c$ bits, the per-object embedding rate is $m / (M \cdot c)$. The warden's detection power scales with:

$$\text{Detectability} \propto \frac{m}{\sqrt{M \cdot c}}$$

   Therefore, spreading the payload across more carriers reduces detectability, but only as $\sqrt{M}$, not linearly.

2. **Optimal batch strategy:** The sender minimizes detection risk by using all available carriers ($M = N$) with the minimum per-object embedding rate.

3. **Pooled detection advantage:** A warden who analyzes the batch jointly (summing per-object test statistics) has a detection advantage that grows as $\sqrt{N}$ — pooling always eventually succeeds given enough samples.

### Reference

- A. D. Ker, "Batch Steganography and Pooled Steganalysis," *IH 2006*, LNCS 4437, pp. 265–281, 2007.
- A. D. Ker, T. Pevný, "The Square Root Law Does Not Require a Linear Shift Invariant Distortion Measure," *IH 2012*.

---

## 3. Hopper-Langford-von Ahn (HLvA) Computational Model (2002, 2009)

### Definition

HLvA formalize steganographic security under computational assumptions:

- **Steganographic secrecy (SS-CHA):** No polynomial-time adversary can distinguish stegotext from covertext with non-negligible advantage.
- **Steganographic key concealment (SS-CCA):** As above, but adversary has access to a detection oracle.

### Key Insight

SS-CHA security against computationally bounded adversaries is achievable **if and only if** the sender has access to an efficient algorithm for sampling from the covertext distribution $P_C$.

### Implication for Meow Decoder

Constructing a provably SS-CHA stego system for GIF animations of cat photos would require an efficient, exact sampler for "natural cat GIF animations." This is not tractable with current generative models; even state-of-the-art GANs/diffusion models do not produce pixel-perfect distribution matching.

### Reference

- N. J. Hopper, J. Langford, L. von Ahn, "Provably Secure Steganography," *IEEE Trans. Computers*, vol. 58, no. 5, pp. 662–676, 2009. (Extended from CRYPTO 2002.)

---

## 4. Applicability Assessment for Meow Decoder

### Meow Decoder's Stego Properties

| Property | Value |
|----------|-------|
| Cover medium | Animated GIF (cat photos / logos) |
| Embedding method | QR code frames interleaved or LSB-embedded in carrier |
| Embedding rate | **Very high** (~entire frame is QR data) |
| Frames per GIF | 15–150 (depends on payload size) |
| Frame structure | Fountain code droplets → deterministic QR pattern per frame |
| Adversary model | Casual observer only (see THREAT_MODEL.md) |

### Why Formal Stego Models Are Intractable for Meow Decoder

#### 4.1 Embedding Rate Violation

Cachin's model requires $D_{KL}(P_C \| P_S) \leq \epsilon$ for small $\epsilon$. Meow Decoder's embedding rate approaches 100% of frame content (the QR code replaces or dominates the carrier image). The KL divergence between "animated cat GIF" and "QR-encoded data frames" is enormous — effectively infinite for statistical purposes.

**Conclusion:** Meow Decoder **cannot** achieve $\epsilon$-security for any useful $\epsilon$. This is by design; stego is cosmetic.

#### 4.2 Structural Distinguishability

Fountain code droplets produce deterministic QR patterns (black/white modules in a grid). Even with carrier overlay:
- QR finder patterns (3 corner squares) create a fixed spatial signature
- Frame-to-frame content changes are non-smooth (discrete jumps)
- QR error correction creates algebraic structure in pixel values

These properties are trivially distinguishable from natural imagery under any formal stego model.

#### 4.3 Batch Setting (Ker)

The square root law is irrelevant because Meow doesn't distribute payload across multiple files — it uses a single animated GIF with multiple frames. The "batch" is the frame sequence within one file, and each frame has near-100% embedding rate.

#### 4.4 Computational Model (HLvA)

SS-CHA security would require sampling cat-photo GIF frames from the exact natural distribution. This requires:
1. A perfect generative model of animated cat GIFs
2. Rejection-sampling to embed data while maintaining distributional match
3. Sufficient entropy in the cover to carry the payload

None of these are feasible with current technology for high-rate embedding.

### Tractability Verdict

| Framework | Tractable for Meow? | Reason |
|-----------|:-------------------:|--------|
| Cachin $\epsilon$-security | **No** | Embedding rate → $D_{KL} \gg 0$; fundamentally insecure |
| Ker batch/pooled | **No** | Single-file multi-frame; rate too high for square-root benefit |
| HLvA SS-CHA | **No** | Requires perfect GIF sampler; not achievable |
| Custom distortion-limited model | **Possible but vacuous** | Could formalize "undetectable by chi-squared at threshold $T$ given $<N$ frames" but would say nothing useful — the answer is "detectable" |

---

## 5. What Could Be Formalized (if scope changed)

If Meow Decoder's stego modes were redesigned around low-rate steganography (e.g., spreading small payloads across many cat GIFs using LSB flipping with distortion minimization), formal analysis would become meaningful:

1. **Cachin bound:** Compute $D_{KL}$ for specific embedding algorithms (e.g., ±1 LSBM with optimal matching) against first-order pixel statistics.
2. **Capacity certificate:** Prove max payload < $N \cdot H_{embed}$ for $\epsilon$-security target.
3. **Ker pooled bound:** Prove minimum number of GIFs needed to detect payload at given false-positive rate.

However, this would require a fundamentally different approach to data transfer — not QR-based animated GIFs for bulk file transfer.

---

## 6. Recommendation

**Formal stego model: DEFERRED.**

Rationale:
- The existing threat model (item 3a) correctly identifies stego as "cosmetic cover only"
- All three major formal frameworks (Cachin, Ker, HLvA) would trivially show Meow's stego is insecure — the exercise would confirm what's already documented without adding insight
- Building a formal model would consume 1-2 weeks for a result equivalent to "embedding rate too high; detectable"
- The honest conclusion is already in `docs/THREAT_MODEL.md`: stego modes defeat casual observers and automated content-type scanners, but not statistical analysts, ML classifiers, or forensic labs

**If stego security becomes a project requirement in the future**, the recommended path would be:
1. Redesign around low-rate embedding (not QR frames)
2. Model in ProVerif or custom framework using Cachin's KL-divergence bound
3. Compute explicit $\epsilon$ values for the chosen embedding method

---

## References

1. C. Cachin, "An Information-Theoretic Model for Steganography," *Information and Computation* 192(1):41–56, 2004.
2. A. D. Ker, "Batch Steganography and Pooled Steganalysis," *IH 2006*, LNCS 4437, pp. 265–281, 2007.
3. A. D. Ker, T. Pevný, "The Square Root Law Does Not Require a Linear Shift Invariant Distortion Measure," *IH 2012*.
4. N. J. Hopper, J. Langford, L. von Ahn, "Provably Secure Steganography," *IEEE Trans. Computers* 58(5):662–676, 2009.
5. T. Filler, J. Judas, J. Fridrich, "Minimizing Additive Distortion in Steganography Using Syndrome-Trellis Codes," *IEEE TIFS* 6(3):920–935, 2011.
6. M. Boroumand, M. Chen, J. Fridrich, "Deep Residual Network for Steganalysis of Digital Images," *IEEE TIFS* 14(5):1181–1193, 2019.
