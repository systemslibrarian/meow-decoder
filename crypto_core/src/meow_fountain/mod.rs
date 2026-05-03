//! Luby Transform fountain code — pure deterministic Rust.
//!
//! See `docs/FOUNTAIN_RUST_WASM_MIGRATION.md` for the unification plan
//! that motivates this module. The acceptance bar is **byte-identical
//! droplets** to the existing `meow_decoder/fountain.py` encoder for
//! the 16 golden vectors under `tests/golden/fountain/`.
//!
//! Module layout:
//!
//! * [`wire`] — droplet wire-format serialise/deserialise. Pure
//!   deterministic; no RNG involved. Phase 1a.
//! * [`distribution`] — Robust Soliton CDF math. Pure deterministic
//!   (uses only `f64` IEEE-754 ops that are bit-stable across CPython
//!   `numpy.float64`, JS V8, and Rust `libm`). Phase 1c.
//! * [`mt19937`] — Mersenne Twister 19937 (32-bit) — port of CPython's
//!   `random.Random` underlying RNG, required for byte-parity with
//!   the existing Python encoder. Phase 1b.
//! * `cpython_random` (TODO Phase 1d) — `random()`, `getrandbits()`,
//!   `sample()` faithful re-implementations on top of MT19937.
//! * `encoder` (TODO Phase 1e) — LT encoder. Wires distribution +
//!   cpython_random + wire to produce droplets.
//! * `decoder` (TODO Phase 1f) — LT decoder via belief propagation.
//!
//! The `encoder`/`decoder` modules are deliberately not yet declared
//! to keep each phase's diff focused. The phases land independently;
//! every committed phase leaves the crate compiling and tested.

pub mod cpython_random;
pub mod distribution;
pub mod mt19937;
pub mod wire;
// encoder, decoder land in follow-up commits — see module-level
// docstring above.
