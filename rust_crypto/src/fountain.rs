//! PyO3 bindings for the Rust fountain core in `crypto_core::meow_fountain`.
//!
//! Exposes three Python types that match the existing
//! `meow_decoder.fountain` public API surface:
//!
//! * `Droplet` — `{seed: int, block_indices: list[int], data: bytes}`.
//! * `FountainEncoder(data, k_blocks, block_size)` with `.droplet(seed)`.
//! * `FountainDecoder(k_blocks, block_size)` with `.add_droplet(d)`,
//!   `.is_complete()`, `.recovered_data()`, `.decoded_count`,
//!   `.pending_droplets` (read-only count).
//!
//! `meow_decoder/fountain.py` shrinks to a thin shim re-exporting
//! these from `meow_crypto_rs`, plus the Robust Soliton class
//! (delegated to `RobustSoliton::pmf` via a property).

use pyo3::exceptions::{PyRuntimeError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::PyBytes;

use crypto_core::meow_fountain::{
    decoder::DecoderError, decoder::FountainDecoder as RustDecoder, distribution::RobustSoliton,
    encoder::EncoderError,
    encoder::FountainEncoder as RustEncoder, wire::Droplet as RustDroplet, wire::WireError,
};

fn map_encoder_err(e: EncoderError) -> PyErr {
    match e {
        EncoderError::InvalidShape {
            k_blocks,
            block_size,
        } => PyValueError::new_err(format!(
            "fountain: invalid k_blocks={k_blocks} block_size={block_size}"
        )),
        EncoderError::TotalSizeExceeded { total, ceiling } => PyValueError::new_err(format!(
            "fountain: total_size {total} exceeds {ceiling}-byte sanity ceiling"
        )),
        EncoderError::KBlocksOverflowU16 { k_blocks } => PyValueError::new_err(format!(
            "fountain: k_blocks {k_blocks} exceeds u16::MAX wire-format limit (65535)"
        )),
    }
}

// SECURITY (H1): map the decoder's bounds-check errors to Python
// ValueError so an attacker-controlled `k_blocks`/`block_size` raises
// cleanly instead of forcing an unbounded allocation.
fn map_decoder_err(e: DecoderError) -> PyErr {
    match e {
        DecoderError::InvalidShape {
            k_blocks,
            block_size,
        } => PyValueError::new_err(format!(
            "invalid decoder shape: k_blocks={k_blocks}, block_size={block_size} (both must be > 0)"
        )),
        DecoderError::KBlocksOverflowU16 { k_blocks } => {
            PyValueError::new_err(format!("k_blocks={k_blocks} exceeds u16::MAX (65535)"))
        }
        DecoderError::TotalSizeExceeded { total, ceiling } => PyValueError::new_err(format!(
            "decoder total size {total} exceeds ceiling {ceiling}"
        )),
    }
}

fn map_wire_err(e: WireError) -> PyErr {
    match e {
        WireError::HeaderTooShort { got } => {
            PyValueError::new_err(format!("droplet wire too short: {got} bytes"))
        }
        WireError::IndicesOverflow {
            block_count,
            remaining_bytes,
        } => PyValueError::new_err(format!(
            "droplet block_count {block_count} overflows ({remaining_bytes} bytes left)"
        )),
        WireError::DataLengthMismatch { expected, got } => PyValueError::new_err(format!(
            "droplet data length {got} ≠ expected block_size {expected}"
        )),
        WireError::UnsortedOrDuplicateIndices => {
            PyValueError::new_err("droplet block_indices must be sorted ascending and unique")
        }
    }
}

/// Python-visible droplet. Mirrors `meow_decoder.fountain.Droplet`
/// (seed: int, block_indices: list[int], data: bytes).
// `from_py_object` opts in to the derived FromPyObject impl that pyo3 0.29
// made opt-in for Clone-able pyclasses; `add_droplet` takes PyDroplet by value.
#[pyclass(name = "Droplet", module = "meow_crypto_rs", from_py_object)]
#[derive(Clone)]
pub struct PyDroplet {
    inner: RustDroplet,
}

#[pymethods]
impl PyDroplet {
    /// Construct a droplet directly from its three fields. Mostly
    /// useful for tests; the encoder produces droplets directly.
    #[new]
    fn new(seed: u32, block_indices: Vec<u16>, data: Vec<u8>) -> Self {
        Self {
            inner: RustDroplet {
                seed,
                block_indices,
                data,
            },
        }
    }

    #[getter]
    fn seed(&self) -> u32 {
        self.inner.seed
    }

    #[getter]
    fn block_indices(&self) -> Vec<u16> {
        self.inner.block_indices.clone()
    }

    #[getter]
    fn data<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.inner.data)
    }

    /// Wire format bytes for this droplet.
    fn to_wire<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.inner.to_wire())
    }

    /// Parse a droplet from its wire bytes given the expected block_size.
    #[staticmethod]
    fn from_wire(buf: &[u8], block_size: usize) -> PyResult<Self> {
        RustDroplet::from_wire(buf, block_size)
            .map(|inner| Self { inner })
            .map_err(map_wire_err)
    }

    fn __repr__(&self) -> String {
        format!(
            "Droplet(seed={}, block_indices={:?}, data=<{} bytes>)",
            self.inner.seed,
            self.inner.block_indices,
            self.inner.data.len()
        )
    }

    fn __eq__(&self, other: &Self) -> bool {
        self.inner == other.inner
    }
}

/// Python-visible LT encoder.
#[pyclass(name = "FountainEncoder", module = "meow_crypto_rs")]
pub struct PyFountainEncoder {
    inner: RustEncoder,
}

#[pymethods]
impl PyFountainEncoder {
    #[new]
    fn new(data: &[u8], k_blocks: usize, block_size: usize) -> PyResult<Self> {
        RustEncoder::new(data, k_blocks, block_size)
            .map(|inner| Self { inner })
            .map_err(map_encoder_err)
    }

    #[getter]
    fn k_blocks(&self) -> usize {
        self.inner.k_blocks()
    }

    #[getter]
    fn block_size(&self) -> usize {
        self.inner.block_size()
    }

    /// Generate the droplet at the given seed.
    fn droplet(&self, seed: u32) -> PyDroplet {
        PyDroplet {
            inner: self.inner.droplet(seed),
        }
    }
}

/// Python-visible LT decoder.
#[pyclass(name = "FountainDecoder", module = "meow_crypto_rs")]
pub struct PyFountainDecoder {
    inner: RustDecoder,
}

#[pymethods]
impl PyFountainDecoder {
    #[new]
    fn new(k_blocks: usize, block_size: usize) -> PyResult<Self> {
        Ok(Self {
            inner: RustDecoder::new(k_blocks, block_size).map_err(map_decoder_err)?,
        })
    }

    #[getter]
    fn k_blocks(&self) -> usize {
        self.inner.k_blocks()
    }

    #[getter]
    fn block_size(&self) -> usize {
        self.inner.block_size()
    }

    #[getter]
    fn decoded_count(&self) -> usize {
        self.inner.decoded_count()
    }

    #[getter]
    fn pending_count(&self) -> usize {
        self.inner.pending_count()
    }

    fn is_complete(&self) -> bool {
        self.inner.is_complete()
    }

    /// Add a droplet. Returns true if the decoder is now complete.
    fn add_droplet(&mut self, droplet: PyDroplet) -> bool {
        self.inner.add_droplet(droplet.inner)
    }

    /// Recovered raw bytes, or None if decoding is incomplete.
    fn recovered_data<'py>(&self, py: Python<'py>) -> PyResult<Option<Bound<'py, PyBytes>>> {
        match self.inner.recovered_data() {
            Some(b) => Ok(Some(PyBytes::new(py, &b))),
            None => Ok(None),
        }
    }
}

/// Build the Robust Soliton PMF for a given k. Returned as a list of
/// f64 — Python computes the CDF / sample on the Python side if it
/// wants to drive the legacy `RobustSolitonDistribution` API. The
/// Rust encoder uses `RobustSoliton::sample_degree` internally; this
/// function is for the Python shim's compatibility.
#[pyfunction]
fn robust_soliton_pmf(k: usize) -> PyResult<Vec<f64>> {
    if k == 0 {
        return Err(PyRuntimeError::new_err("k must be > 0"));
    }
    let d = RobustSoliton::new(k);
    Ok(d.pmf)
}

/// Register the fountain types and helpers on the meow_crypto_rs
/// module.
pub fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<PyDroplet>()?;
    m.add_class::<PyFountainEncoder>()?;
    m.add_class::<PyFountainDecoder>()?;
    m.add_function(wrap_pyfunction!(robust_soliton_pmf, m)?)?;
    Ok(())
}
