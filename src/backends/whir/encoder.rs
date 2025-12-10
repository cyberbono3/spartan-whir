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
