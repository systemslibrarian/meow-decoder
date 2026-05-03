//! Faithful re-implementation of CPython's `random.Random` API surface
//! used by `meow_decoder/fountain.py`:
//!
//! * `random()` — uniform `[0.0, 1.0)` from two MT19937 outputs.
//! * `getrandbits(k)` — k bits of randomness (k ≤ 32 fast-path used
//!   by the encoder).
//! * `randbelow(n)` — uniform integer in `[0, n)` via reject-on-overflow.
//! * `sample(range(n), k)` — CPython's pool-path sample for `n ≤
//!   setsize`. The set path is implemented for completeness but not
//!   exercised by any of our 16 golden vectors (n ∈ {10, 100, 1000}
//!   all fit in the pool path's setsize threshold).
//!
//! Bit-for-bit cross-checks against CPython 3.11 live in this module's
//! `tests` block. The values were captured by:
//!
//! ```python
//! r = random.Random(seed)
//! ...
//! ```
//!
//! Cross-references:
//!
//! * `random()` and `getrandbits()` C source:
//!   `Modules/_randommodule.c` in the CPython 3.11 tree.
//! * `Random._randbelow_with_getrandbits` and `Random.sample` Python
//!   source: `Lib/random.py`.

use super::mt19937::Mt19937;

/// CPython's `random.Random` API surface (just enough for fountain).
pub struct CpRandom {
    mt: Mt19937,
}

impl CpRandom {
    /// Build a generator seeded from a single u32. CPython's
    /// `random.Random(seed: int)` for an integer `seed` that fits in
    /// 32 bits (the fountain encoder always passes a frame index, so
    /// the seed is small) is equivalent to this.
    ///
    /// Phase 1d note: a multi-limb seeder (for arbitrary `int` seeds
    /// larger than 32 bits) lives in MT19937's `seed_from_array` —
    /// we'll add a higher-level `seed_from_u128` or similar helper
    /// when an actual caller needs it.
    pub fn new(seed: u32) -> Self {
        Self {
            mt: Mt19937::seed_from_u32(seed),
        }
    }

    /// Build directly from an array of u32 limbs (CPython's
    /// `init_by_array(key, key_length)` path).
    pub fn from_seed_array(seed: &[u32]) -> Self {
        Self {
            mt: Mt19937::seed_from_array(seed),
        }
    }

    /// CPython `random.Random.random()` — uniform `[0.0, 1.0)`.
    ///
    /// C source (`_randommodule.c`):
    /// ```c
    /// uint32_t a = genrand_uint32(self) >> 5;   // 27 bits
    /// uint32_t b = genrand_uint32(self) >> 6;   // 26 bits
    /// return ((double)a * 67108864.0 + (double)b)  // a * 2^26 + b
    ///        * (1.0 / 9007199254740992.0);          // / 2^53
    /// ```
    ///
    /// IEEE 754 double exactness: `2^26` and `2^53` are powers of two
    /// and `a * 2^26 + b` fits in a 53-bit double mantissa exactly
    /// (since 27 + 26 = 53). So `random()` is bit-deterministic given
    /// the MT output stream — no libm involved.
    pub fn random(&mut self) -> f64 {
        let a = (self.mt.next_u32() >> 5) as f64; // 27 bits
        let b = (self.mt.next_u32() >> 6) as f64; // 26 bits
        (a * 67_108_864.0 + b) * (1.0 / 9_007_199_254_740_992.0)
    }

    /// CPython `random.Random.getrandbits(k)` — `k` random bits as a
    /// `u32`. Fast path: `k <= 32`.
    ///
    /// Returns the **top** `k` bits of a fresh MT output:
    /// ```c
    /// return genrand_uint32(self) >> (32 - k);
    /// ```
    ///
    /// `k > 32` would require multi-word assembly; the fountain
    /// encoder never calls it with k > 32, so we restrict the fast
    /// path here and panic on the slow-path call to surface any
    /// future regression.
    pub fn getrandbits_u32(&mut self, k: u32) -> u32 {
        assert!(k > 0, "getrandbits: k must be > 0");
        if k <= 32 {
            self.mt.next_u32() >> (32 - k)
        } else {
            panic!(
                "getrandbits: k > 32 not supported by the fountain \
                 encoder path (caller asked for {k} bits)"
            )
        }
    }

    /// CPython `Random._randbelow_with_getrandbits(n)` — uniform
    /// integer in `[0, n)`.
    ///
    /// Python source (`Lib/random.py`):
    /// ```python
    /// def _randbelow_with_getrandbits(self, n):
    ///     "Return a random int in the range [0,n).  Defined for n > 0."
    ///     getrandbits = self.getrandbits
    ///     k = n.bit_length()
    ///     r = getrandbits(k)         # 0 <= r < 2**k
    ///     while r >= n:
    ///         r = getrandbits(k)
    ///     return r
    /// ```
    ///
    /// `n.bit_length()` for n ≥ 1: position of the highest set bit
    /// + 1. We use `u32::leading_zeros` for the same answer.
    pub fn randbelow(&mut self, n: u32) -> u32 {
        assert!(n > 0, "randbelow: n must be > 0");
        let k = 32 - n.leading_zeros();
        loop {
            let r = self.getrandbits_u32(k);
            if r < n {
                return r;
            }
        }
    }

    /// CPython `Random.sample(range(n), k)` — pool path.
    ///
    /// Python source (`Lib/random.py`, `n <= setsize` branch):
    /// ```python
    /// pool = list(population)
    /// for i in range(k):
    ///     j = randbelow(n - i)
    ///     result[i] = pool[j]
    ///     pool[j] = pool[n - i - 1]   # move non-selected into vacancy
    /// ```
    ///
    /// Returns the `k` selected indices in selection order (NOT
    /// sorted). The fountain encoder sorts the result before
    /// serialising.
    ///
    /// CPython chooses pool vs set path based on a `setsize` heuristic:
    ///
    /// ```python
    /// setsize = 21
    /// if k > 5:
    ///     setsize += 4 ** _ceil(_log(k * 3, 4))
    /// if n <= setsize:
    ///     # pool path
    /// else:
    ///     # set path
    /// ```
    ///
    /// `sample_range` dispatches to the correct path so callers see a
    /// single API.
    pub fn sample_range(&mut self, n: u32, k: u32) -> Vec<u32> {
        assert!(k <= n, "sample: k > n");
        let setsize = setsize_for_k(k);
        if (n as u64) <= setsize {
            self.sample_range_pool(n, k)
        } else {
            self.sample_range_set(n, k)
        }
    }

    /// Pool path of `sample` — CPython's `n <= setsize` branch:
    ///
    /// ```python
    /// pool = list(population)
    /// for i in range(k):
    ///     j = randbelow(n - i)
    ///     result[i] = pool[j]
    ///     pool[j] = pool[n - i - 1]   # move non-selected into vacancy
    /// ```
    pub fn sample_range_pool(&mut self, n: u32, k: u32) -> Vec<u32> {
        assert!(k <= n, "sample: k > n");
        let mut pool: Vec<u32> = (0..n).collect();
        let mut result = Vec::with_capacity(k as usize);
        for i in 0..k {
            let j = self.randbelow(n - i) as usize;
            result.push(pool[j]);
            pool[j] = pool[(n - i - 1) as usize];
        }
        result
    }

    /// Set path of `sample` — CPython's `n > setsize` branch:
    ///
    /// ```python
    /// selected = set()
    /// for i in range(k):
    ///     j = randbelow(n)
    ///     while j in selected:
    ///         j = randbelow(n)
    ///     selected.add(j)
    ///     result[i] = population[j]
    /// ```
    ///
    /// Uses the same `randbelow(n)` (not `n - i`) as CPython, so the
    /// MT19937 consumption pattern matches byte-for-byte.
    pub fn sample_range_set(&mut self, n: u32, k: u32) -> Vec<u32> {
        assert!(k <= n, "sample: k > n");
        use std::collections::HashSet;
        let mut selected: HashSet<u32> = HashSet::with_capacity(k as usize);
        let mut result = Vec::with_capacity(k as usize);
        for _ in 0..k {
            let mut j = self.randbelow(n);
            while selected.contains(&j) {
                j = self.randbelow(n);
            }
            selected.insert(j);
            result.push(j);
        }
        result
    }
}

/// CPython `Random.sample`'s `setsize` heuristic (the threshold that
/// decides pool vs set path). Exposed so callers can decide which
/// path applies given (n, k).
///
/// ```python
/// setsize = 21
/// if k > 5:
///     setsize += 4 ** _ceil(_log(k * 3, 4))
/// ```
///
/// Implemented in pure integer arithmetic: `4 ** ceil(log_4(k*3))` is
/// the smallest power of 4 ≥ `k*3`. We compute it by doubling powers
/// of 4 until the threshold is met — exact, no float involved.
pub fn setsize_for_k(k: u32) -> u64 {
    let base: u64 = 21;
    if k <= 5 {
        return base;
    }
    let target: u64 = (k as u64) * 3;
    let mut pow4: u64 = 1;
    while pow4 < target {
        pow4 *= 4;
    }
    base + pow4
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `random.Random(0).random()` first three calls. Captured by:
    /// ```python
    /// r = random.Random(0)
    /// for _ in range(3): print(repr(r.random()))
    /// ```
    #[test]
    fn cpython_random_seed_0_first_three() {
        let mut r = CpRandom::new(0);
        let captured: [f64; 3] = [
            0.844_421_851_525_048_1,
            0.757_954_402_940_302_5,
            0.420_571_580_830_845,
        ];
        for (i, want) in captured.iter().enumerate() {
            let got = r.random();
            // bit-exact: random() is pure integer arithmetic + powers
            // of 2, so no libm tolerance is needed.
            assert_eq!(
                got, *want,
                "random() #{i} mismatch: got {got}, want {want}"
            );
        }
    }

    /// `getrandbits(32)` matches the raw MT output stream (which we
    /// already pinned in `mt19937` tests). Spot-check that the
    /// `getrandbits` wrapper agrees.
    #[test]
    fn getrandbits_32_equals_mt_output() {
        let mut r = CpRandom::new(0);
        // Same first MT output as `cpython_random_seed_0_first_10_outputs`
        // in mt19937.rs.
        assert_eq!(r.getrandbits_u32(32), 3_626_764_237);
    }

    /// `getrandbits(8)` — top 8 bits of the first MT output.
    /// First MT(0) output = 3626764237 = 0xD8224409.
    /// Top 8 bits = 0xD8 = 216.
    #[test]
    fn getrandbits_8_top_bits() {
        let mut r = CpRandom::new(0);
        assert_eq!(r.getrandbits_u32(8), 0xD8);
    }

    /// `_randbelow(n)` distribution sanity: for `n = 10` and many
    /// draws, every value 0..10 should appear and the loop should
    /// terminate quickly.
    #[test]
    fn randbelow_terminates_and_covers_range() {
        let mut r = CpRandom::new(42);
        let mut seen = [false; 10];
        for _ in 0..1000 {
            let v = r.randbelow(10);
            assert!(v < 10);
            seen[v as usize] = true;
        }
        for (i, &b) in seen.iter().enumerate() {
            assert!(b, "value {i} never seen in 1000 draws — distribution broken");
        }
    }

    /// CPython `Random.sample(range(n), k)` reference output. Captured by:
    /// ```python
    /// import random
    /// r = random.Random(42)
    /// r.sample(range(10), 3)
    /// ```
    /// = `[1, 0, 4]` (CPython 3.11)
    #[test]
    fn sample_range_pool_matches_python_seed_42() {
        let mut r = CpRandom::new(42);
        let out = r.sample_range_pool(10, 3);
        assert_eq!(out, vec![1, 0, 4]);
    }

    /// Same call, different seed: `Random(99).sample(range(20), 5)`
    /// = `[12, 19, 6, 5, 7]` (CPython 3.11).
    #[test]
    fn sample_range_pool_matches_python_seed_99() {
        let mut r = CpRandom::new(99);
        let out = r.sample_range_pool(20, 5);
        assert_eq!(out, vec![12, 19, 6, 5, 7]);
    }

    /// Set path: `Random(7).sample(range(100), 2)` → `[41, 19]`. With
    /// k=2 the setsize threshold is 21, n=100 forces set path.
    #[test]
    fn sample_range_set_matches_python_seed_7() {
        let mut r = CpRandom::new(7);
        let out = r.sample_range_set(100, 2);
        assert_eq!(out, vec![41, 19]);
    }

    /// Dispatch via `sample_range` picks pool path for n=10, k=2.
    #[test]
    fn sample_range_dispatches_to_pool_for_small_n() {
        let mut r = CpRandom::new(7);
        let out = r.sample_range(10, 2);
        assert_eq!(out, vec![5, 2]);
    }

    /// Dispatch via `sample_range` picks set path for n=100, k=2.
    #[test]
    fn sample_range_dispatches_to_set_for_large_n() {
        let mut r = CpRandom::new(7);
        let out = r.sample_range(100, 2);
        assert_eq!(out, vec![41, 19]);
    }

    /// `setsize_for_k` boundary checks. Pulled from CPython source:
    /// ```python
    /// setsize = 21
    /// if k > 5:
    ///     setsize += 4 ** _ceil(_log(k * 3, 4))
    /// ```
    #[test]
    fn setsize_threshold_matches_python() {
        assert_eq!(setsize_for_k(1), 21);
        assert_eq!(setsize_for_k(5), 21);
        // k=6: setsize += 4^ceil(log_4(18)) = 4^3 = 64 (since 4^2 = 16 < 18)
        assert_eq!(setsize_for_k(6), 21 + 64);
        // k=10: 4^ceil(log_4(30)) = 4^3 = 64
        assert_eq!(setsize_for_k(10), 21 + 64);
        // k=100: 4^ceil(log_4(300)) = 4^5 = 1024 (since 4^4 = 256 < 300)
        assert_eq!(setsize_for_k(100), 21 + 1024);
        // k=1000: 4^ceil(log_4(3000)) = 4^6 = 4096 (4^5 = 1024 < 3000)
        assert_eq!(setsize_for_k(1000), 21 + 4096);
    }
}
