//! Robust Soliton distribution — degree-selection PMF for the Luby
//! Transform encoder.
//!
//! Mirrors `meow_decoder.fountain.RobustSolitonDistribution`. The
//! Python implementation uses `numpy.log` / `numpy.sqrt`; the Rust port
//! uses `f64::ln` / `f64::sqrt`. Both ultimately call the platform
//! libm, which is bit-deterministic for `sqrt` (IEEE 754 mandates
//! correctly-rounded) but not for `ln` (last-bit differences across
//! libm implementations are allowed by the standard).
//!
//! The 16 golden vectors under `tests/golden/fountain/*.bin` are the
//! ground-truth — if a libm divergence ever surfaces, this module is
//! the place to switch to a portable `libm` crate or a fixed-point
//! lookup table per `k_blocks`.

/// Default Robust Soliton tuning: `c = 0.1`, `δ = 0.5`. Matches
/// `RobustSolitonDistribution.__init__` in fountain.py.
pub const DEFAULT_C: f64 = 0.1;
pub const DEFAULT_DELTA: f64 = 0.5;

/// Probability mass function over droplet degrees `0..=k`.
///
/// `pmf[0]` is always 0 (degree 0 has no semantic meaning — encoder
/// clamps to ≥ 1). `pmf[1..=k]` sums to 1.0 (modulo last-bit rounding
/// from the normalisation step).
///
/// The PMF is built once per `k` and used to drive sampling: the
/// encoder draws `r ∈ [0, 1)` from a seeded RNG, accumulates the PMF
/// into a CDF, and returns the smallest `i` such that `cumulative > r`.
#[derive(Debug, Clone, PartialEq)]
pub struct RobustSoliton {
    pub k: usize,
    pub c: f64,
    pub delta: f64,
    pub pmf: Vec<f64>,
}

impl RobustSoliton {
    /// Build the Robust Soliton PMF for `k` source blocks with the
    /// project default tuning (c=0.1, δ=0.5).
    pub fn new(k: usize) -> Self {
        Self::with_params(k, DEFAULT_C, DEFAULT_DELTA)
    }

    /// Build the Robust Soliton PMF with caller-supplied tuning. Mirrors
    /// `RobustSolitonDistribution.__init__(k, c, delta)`.
    ///
    /// Edge case: `k <= 1` returns `[0.0, 1.0]` — only degree 1 is
    /// meaningful when there's at most one source block.
    #[allow(clippy::needless_range_loop)]
    pub fn with_params(k: usize, c: f64, delta: f64) -> Self {
        if k <= 1 {
            return Self {
                k,
                c,
                delta,
                pmf: vec![0.0, 1.0],
            };
        }

        // ── Ideal Soliton ρ ──────────────────────────────────────────
        // ρ[1] = 1/k, ρ[i] = 1 / (i * (i-1)) for i ≥ 2.
        let mut rho = vec![0.0f64; k + 1];
        rho[1] = 1.0 / (k as f64);
        for i in 2..=k {
            rho[i] = 1.0 / ((i as f64) * ((i - 1) as f64));
        }

        // ── Robust correction τ ─────────────────────────────────────
        // R = c * ln(k/δ) * sqrt(k)
        // m = clamp(int(k / R), 1, k)
        // τ[i] = R / (i*k)        for 1 ≤ i < m
        // τ[m] = R * ln(R/δ) / k
        let r_factor = c * ((k as f64) / delta).ln() * (k as f64).sqrt();
        let mut tau = vec![0.0f64; k + 1];

        // The Python `int(k / R)` truncates toward zero. `R > 0` is
        // safe to assume for any sensible (k, c, δ) — `c.ln(...)` only
        // hits zero when k = δ, which the caller does not pass.
        let mut m = if r_factor > 0.0 {
            (k as f64 / r_factor) as usize
        } else {
            k
        };
        if m < 1 {
            m = 1;
        }
        if m > k {
            m = k;
        }
        for i in 1..m {
            tau[i] = r_factor / ((i as f64) * (k as f64));
        }
        tau[m] = r_factor * (r_factor / delta).ln() / (k as f64);

        // ── Combine and normalise ────────────────────────────────────
        let mut mu = vec![0.0f64; k + 1];
        for i in 0..=k {
            mu[i] = rho[i] + tau[i];
        }
        let total: f64 = mu.iter().sum();
        if total > 0.0 {
            for slot in mu.iter_mut() {
                *slot /= total;
            }
        } else {
            // Numerical fallback — same behaviour as fountain.py: drop
            // the robust correction and use the ideal soliton.
            mu = rho;
        }

        Self {
            k,
            c,
            delta,
            pmf: mu,
        }
    }

    /// Convert the PMF into its cumulative form. Caller uses this to
    /// sample by drawing `r ∈ [0, 1)` and finding the smallest `i`
    /// such that `cdf[i] > r` (mirrors `sample_degree` in
    /// fountain.py).
    pub fn cdf(&self) -> Vec<f64> {
        let mut out = Vec::with_capacity(self.pmf.len());
        let mut acc = 0.0f64;
        for p in &self.pmf {
            acc += p;
            out.push(acc);
        }
        out
    }

    /// Pick a degree given a uniform `r ∈ [0, 1)`. Mirrors
    /// `RobustSolitonDistribution.sample_degree` byte-for-byte:
    ///
    /// ```python
    /// cumulative = 0.0
    /// for degree, prob in enumerate(self.distribution):
    ///     cumulative += prob
    ///     if r < cumulative:
    ///         return max(1, degree)
    /// return 1
    /// ```
    ///
    /// Note the `max(1, degree)` clamp — degree 0 (the always-zero
    /// PMF slot) is never returned.
    pub fn sample_degree(&self, r: f64) -> usize {
        let mut cumulative = 0.0f64;
        for (degree, &prob) in self.pmf.iter().enumerate() {
            cumulative += prob;
            if r < cumulative {
                return degree.max(1);
            }
        }
        1
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn k_eq_1_special_case() {
        let d = RobustSoliton::new(1);
        assert_eq!(d.pmf, vec![0.0, 1.0]);
        assert_eq!(d.sample_degree(0.0), 1);
        assert_eq!(d.sample_degree(0.999), 1);
    }

    #[test]
    fn pmf_normalises_to_one() {
        for &k in &[2usize, 10, 100, 1000] {
            let d = RobustSoliton::new(k);
            let total: f64 = d.pmf.iter().sum();
            assert!(
                (total - 1.0).abs() < 1e-9,
                "k={k}: PMF sum = {total}, expected ~1.0"
            );
        }
    }

    #[test]
    fn cdf_is_monotonically_non_decreasing() {
        let d = RobustSoliton::new(100);
        let cdf = d.cdf();
        for window in cdf.windows(2) {
            assert!(window[0] <= window[1], "CDF non-monotonic: {:?}", window);
        }
        // Last entry is ~1.0
        assert!((cdf[cdf.len() - 1] - 1.0).abs() < 1e-9);
    }

    #[test]
    fn sample_degree_never_returns_zero() {
        let d = RobustSoliton::new(50);
        for r_step in 0..1000 {
            let r = r_step as f64 / 1000.0;
            assert!(d.sample_degree(r) >= 1, "r={r} returned 0");
        }
    }

    #[test]
    fn matches_python_for_k_2() {
        // Authoritative Python output for k=2, c=0.1, δ=0.5:
        //   pmf[0] = 0
        //   pmf[1] = 0.59431071856289918731
        //   pmf[2] = 0.40568928143710070167
        let d = RobustSoliton::with_params(2, 0.1, 0.5);
        assert_eq!(d.pmf.len(), 3);
        assert_eq!(d.pmf[0], 0.0);
        assert!(
            (d.pmf[1] - 0.594_310_718_562_899_2).abs() < 1e-12,
            "pmf[1] = {}",
            d.pmf[1]
        );
        assert!(
            (d.pmf[2] - 0.405_689_281_437_100_7).abs() < 1e-12,
            "pmf[2] = {}",
            d.pmf[2]
        );
    }

    /// Cross-check against the actual Python implementation. Catches
    /// any libm drift between CPython/NumPy and Rust on this platform.
    /// Threshold 1e-12 — anything beyond that is structural divergence.
    ///
    /// Authoritative values captured by:
    /// ```python
    /// from meow_decoder.fountain import RobustSolitonDistribution
    /// for k in [10, 100, 1000]:
    ///     d = RobustSolitonDistribution(k)
    ///     print(k, d.distribution[1], d.distribution[k])
    /// ```
    #[test]
    fn cross_platform_libm_drift_check() {
        let cases: &[(usize, f64, f64)] = &[
            // (k, expected_pmf[1], expected_pmf[k])
            (10, 0.146_577_367_050_264_45, 0.053_931_408_666_059_4),
            (100, 0.048_177_794_322_952_41, 7.726_577_731_462_398e-5),
            (1000, 0.020_934_564_233_055_39, 8.370_100_034_175_495e-7),
        ];
        for &(k, expected_p1, expected_pk) in cases {
            let d = RobustSoliton::new(k);
            let p1 = d.pmf[1];
            let pk = d.pmf[k];
            assert!(
                (p1 - expected_p1).abs() < 1e-12,
                "k={k}: pmf[1] = {p1}, expected {expected_p1} (libm drift?)"
            );
            assert!(
                (pk - expected_pk).abs() < 1e-12,
                "k={k}: pmf[{k}] = {pk}, expected {expected_pk} (libm drift?)"
            );
        }
    }
}
