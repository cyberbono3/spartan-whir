use super::WhirR1csInstance;
use crate::backends::BackendError;
use whir::crypto::fields::Field64;
use whir::poly_utils::coeffs::CoefficientList;

/// Wrapper around WHIR's coefficient list to make intent explicit.
pub struct WhirPolynomial(pub CoefficientList<Field64>);

/// Trait for translating a Spartan-origin R1CS into the multilinear polynomial WHIR expects.
pub trait WhirEncoder {
  fn encode(&self, instance: &WhirR1csInstance) -> Result<WhirPolynomial, BackendError>;
}

/// Default encoder that is not yet implemented.
pub struct DefaultEncoder;

impl WhirEncoder for DefaultEncoder {
  fn encode(&self, _instance: &WhirR1csInstance) -> Result<WhirPolynomial, BackendError> {
    Err(BackendError::Unsupported(
      "R1CS → WHIR multilinear encoding is not implemented (needs circuit-specific mapping)",
    ))
  }
}

/// A naive encoder that produces a zero polynomial over the hypercube.
/// This is mainly for experimentation; it does **not** encode the R1CS semantics.
pub struct NaiveZeroEncoder {
  /// Upper bound on variables to avoid allocating enormous vectors.
  pub max_vars: usize,
}

impl Default for NaiveZeroEncoder {
  fn default() -> Self {
    Self { max_vars: 20 } // 1<<20 evaluations cap (~1M elements)
  }
}

impl WhirEncoder for NaiveZeroEncoder {
  fn encode(&self, instance: &WhirR1csInstance) -> Result<WhirPolynomial, BackendError> {
    if instance.num_variables > self.max_vars {
      return Err(BackendError::Unsupported(
        "naive encoder refuses to allocate beyond configured max_vars",
      ));
    }
    let evals = vec![Field64::ZERO; 1 << instance.num_variables];
    Ok(WhirPolynomial(CoefficientList::new(evals)))
  }
}
