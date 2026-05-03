//! Mersenne Twister 19937 (32-bit) — port of CPython's `random.Random`
//! core RNG.
//!
//! `meow_decoder/fountain.py` seeds a fresh `random.Random(seed)` per
//! droplet. To produce byte-identical droplets in Rust we have to
//! reproduce CPython's seeding *and* output stream bit-for-bit. That
//! decomposes into:
//!
//! 1. **MT19937 (this file).** Standard Matsumoto-Nishimura algorithm
//!    with state size 624 × `u32`. Drop-in compatible with the
//!    reference C implementation.
//! 2. **CPython init-by-array seeding.** CPython feeds the integer
//!    seed through a multi-step init-by-array routine derived from
//!    Matsumoto's `init_by_array`. We mirror that exactly so the post-
//!    seed state matches.
//! 3. **CPython random/getrandbits/sample (Phase 1d).** Built on top
//!    of the MT output stream defined here.
//!
//! References:
//!
//! * Matsumoto & Nishimura, *Mersenne Twister: A 623-dimensionally
//!   equidistributed uniform pseudorandom number generator*, ACM TOMS
//!   1998. <http://www.math.sci.hiroshima-u.ac.jp/m-mat/MT/emt.html>
//! * CPython's seeding algorithm:
//!   `Modules/_randommodule.c::random_seed_urandom_array` and
//!   `init_by_array`.
//!
//! Cross-check: the standard MT19937 reference vectors emitted by the
//! original C `mt19937ar.c` — see `tests::reference_vectors`.

const N: usize = 624;
const M: usize = 397;
const MATRIX_A: u32 = 0x9908_b0df;
const UPPER_MASK: u32 = 0x8000_0000;
const LOWER_MASK: u32 = 0x7fff_ffff;

/// Mersenne Twister 19937 (32-bit) state.
///
/// Implements the same `next_u32()` stream as the reference C
/// implementation. Use one of the `seed_*` constructors to enter a
/// known state — directly poking `state` is supported but discouraged.
pub struct Mt19937 {
    state: [u32; N],
    index: usize,
}

impl Mt19937 {
    /// Construct a generator seeded with the standard
    /// `init_by_array([seed])` routine, matching what CPython does
    /// for any non-negative integer seed that fits in a single
    /// 32-bit limb.
    ///
    /// CPython's `random.Random(seed)` for `seed: int` larger than
    /// 32 bits uses `init_by_array` over the seed's 32-bit limbs; we
    /// expose [`Mt19937::seed_from_array`] for that case.
    pub fn seed_from_u32(seed: u32) -> Self {
        Self::seed_from_array(&[seed])
    }

    /// Construct a generator seeded by feeding `key` through Matsumoto's
    /// `init_by_array` routine (CPython uses the same routine, with
    /// the seed integer's 32-bit little-endian limbs as the key).
    ///
    /// Quoting Matsumoto's reference C:
    ///
    /// ```c
    /// void init_by_array(unsigned long init_key[], int key_length) {
    ///     int i = 1, j = 0;
    ///     int k = (N > key_length ? N : key_length);
    ///     init_genrand(19650218UL);
    ///     for (; k; k--) {
    ///         mt[i] = (mt[i] ^ ((mt[i-1] ^ (mt[i-1] >> 30)) * 1664525UL))
    ///               + init_key[j] + j;
    ///         i++; j++;
    ///         if (i >= N) { mt[0] = mt[N-1]; i = 1; }
    ///         if (j >= key_length) j = 0;
    ///     }
    ///     for (k = N-1; k; k--) {
    ///         mt[i] = (mt[i] ^ ((mt[i-1] ^ (mt[i-1] >> 30)) * 1566083941UL))
    ///               - i;
    ///         i++;
    ///         if (i >= N) { mt[0] = mt[N-1]; i = 1; }
    ///     }
    ///     mt[0] = 0x80000000UL;
    /// }
    /// ```
    ///
    /// Wrapping arithmetic throughout — `u32` overflow wraps in Rust
    /// only when explicit, so we use `wrapping_*` everywhere.
    pub fn seed_from_array(key: &[u32]) -> Self {
        let mut g = Self::init_genrand(19_650_218);
        let key_length = key.len();
        let n_iter = N.max(key_length);
        let mut i: usize = 1;
        let mut j: usize = 0;
        // Reference C uses explicit parens to group the XOR before the
        // additions: `mt[i] = (mt[i] ^ (... * 1664525)) + init_key[j] + j`.
        for _ in 0..n_iter {
            let prev = g.state[i - 1];
            let mult = (prev ^ (prev >> 30)).wrapping_mul(1_664_525);
            g.state[i] = (g.state[i] ^ mult)
                .wrapping_add(key[j])
                .wrapping_add(j as u32);
            i += 1;
            j += 1;
            if i >= N {
                g.state[0] = g.state[N - 1];
                i = 1;
            }
            if j >= key_length {
                j = 0;
            }
        }
        // Second loop, same parenthesisation:
        //   mt[i] = (mt[i] ^ (... * 1566083941)) - i
        for _ in 0..(N - 1) {
            let prev = g.state[i - 1];
            let mult = (prev ^ (prev >> 30)).wrapping_mul(1_566_083_941);
            g.state[i] = (g.state[i] ^ mult).wrapping_sub(i as u32);
            i += 1;
            if i >= N {
                g.state[0] = g.state[N - 1];
                i = 1;
            }
        }
        g.state[0] = 0x8000_0000;
        g.index = N; // force a generate-cycle on first next_u32()
        g
    }

    /// Matsumoto's `init_genrand` (single-seed init):
    ///
    /// ```c
    /// void init_genrand(unsigned long s) {
    ///     mt[0] = s & 0xffffffffUL;
    ///     for (mti = 1; mti < N; mti++) {
    ///         mt[mti] = (1812433253UL * (mt[mti-1] ^ (mt[mti-1] >> 30)) + mti);
    ///     }
    /// }
    /// ```
    fn init_genrand(seed: u32) -> Self {
        let mut state = [0u32; N];
        state[0] = seed;
        for i in 1..N {
            let prev = state[i - 1];
            state[i] = 1_812_433_253u32
                .wrapping_mul(prev ^ (prev >> 30))
                .wrapping_add(i as u32);
        }
        Self { state, index: N }
    }

    /// Generate the next 32-bit output. Matches the reference C
    /// `genrand_int32`.
    pub fn next_u32(&mut self) -> u32 {
        if self.index >= N {
            self.regenerate();
        }
        let mut y = self.state[self.index];
        self.index += 1;
        // Tempering — must produce the standard MT19937 stream.
        y ^= y >> 11;
        y ^= (y << 7) & 0x9d2c_5680;
        y ^= (y << 15) & 0xefc6_0000;
        y ^= y >> 18;
        y
    }

    fn regenerate(&mut self) {
        let mag01 = [0u32, MATRIX_A];
        for kk in 0..(N - M) {
            let y = (self.state[kk] & UPPER_MASK) | (self.state[kk + 1] & LOWER_MASK);
            self.state[kk] = self.state[kk + M] ^ (y >> 1) ^ mag01[(y & 1) as usize];
        }
        for kk in (N - M)..(N - 1) {
            let y = (self.state[kk] & UPPER_MASK) | (self.state[kk + 1] & LOWER_MASK);
            self.state[kk] = self.state[kk + M - N] ^ (y >> 1) ^ mag01[(y & 1) as usize];
        }
        let y = (self.state[N - 1] & UPPER_MASK) | (self.state[0] & LOWER_MASK);
        self.state[N - 1] = self.state[M - 1] ^ (y >> 1) ^ mag01[(y & 1) as usize];
        self.index = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Authoritative CPython output for `init_by_array([0x123, 0x234,
    /// 0x345, 0x456])`. Captured by:
    /// ```python
    /// seed = 0x123 | (0x234 << 32) | (0x345 << 64) | (0x456 << 96)
    /// r = random.Random(seed)
    /// [r.getrandbits(32) for _ in range(10)]
    /// ```
    #[test]
    fn cpython_init_by_array_four_words() {
        let mut g = Mt19937::seed_from_array(&[0x123, 0x234, 0x345, 0x456]);
        let expected: [u32; 10] = [
            1_067_595_299,
            955_945_823,
            477_289_528,
            4_107_218_783,
            4_228_976_476,
            3_344_332_714,
            3_355_579_695,
            227_628_506,
            810_200_273,
            2_591_290_167,
        ];
        for (i, want) in expected.iter().enumerate() {
            let got = g.next_u32();
            assert_eq!(
                got, *want,
                "MT19937 init_by_array output {} mismatch: got {}, want {}",
                i, got, *want
            );
        }
    }

    /// CPython compatibility check: `random.Random(0).getrandbits(32)`
    /// stream. Captured by running:
    /// ```python
    /// r = random.Random(0)
    /// [r.getrandbits(32) for _ in range(10)]
    /// ```
    #[test]
    fn cpython_random_seed_0_first_10_outputs() {
        let mut g = Mt19937::seed_from_array(&[0]);
        let expected: [u32; 10] = [
            3_626_764_237,
            1_654_615_998,
            3_255_389_356,
            3_823_568_514,
            1_806_341_205,
            173_879_092,
            1_112_038_970,
            4_146_640_122,
            2_195_908_194,
            2_087_043_557,
        ];
        for (i, want) in expected.iter().enumerate() {
            let got = g.next_u32();
            assert_eq!(
                got, *want,
                "CPython random.Random(0) output {} mismatch: got {}, want {}",
                i, got, *want
            );
        }
    }

    /// CPython compatibility check: `random.Random(1).getrandbits(32)`
    /// stream — five outputs.
    #[test]
    fn cpython_random_seed_1_first_5_outputs() {
        let mut g = Mt19937::seed_from_array(&[1]);
        let expected: [u32; 5] = [
            577_090_037,
            2_444_712_010,
            3_639_700_191,
            3_445_702_192,
            3_280_387_012,
        ];
        for (i, want) in expected.iter().enumerate() {
            let got = g.next_u32();
            assert_eq!(
                got, *want,
                "seed=1 output {} mismatch: got {}, want {}",
                i, got, *want
            );
        }
    }

    #[test]
    fn many_outputs_dont_panic() {
        // Exercises the regenerate() path multiple times.
        let mut g = Mt19937::seed_from_u32(42);
        for _ in 0..(N * 4) {
            let _ = g.next_u32();
        }
    }
}
