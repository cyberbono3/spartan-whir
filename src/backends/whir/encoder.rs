use super::WhirR1csInstance;
use crate::backends::BackendError;
use ark_ff::{AdditiveGroup, Field};
use whir::crypto::fields::Field64;
use whir::poly_utils::coeffs::CoefficientList;

/// Wrapper around WHIR's coefficient list to make intent explicit.
pub struct WhirPolynomial(pub CoefficientList<Field64>);

/// Trait for translating a Spartan-origin R1CS into the multilinear polynomial WHIR expects.
pub trait WhirEncoder {
  /// Translate the given R1CS instance into a multilinear polynomial over WHIR's field.
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

/// Encoder that computes R1CS residuals over the Goldilocks field and returns them as a multilinear
/// polynomial over the constraint index hypercube. Each evaluation corresponds to
/// `(A z)_i * (B z)_i - (C z)_i` for constraint row `i`.
pub struct ResidualEncoder;

impl WhirEncoder for ResidualEncoder {
  fn encode(&self, instance: &WhirR1csInstance) -> Result<WhirPolynomial, BackendError> {
    let num_cons = instance.num_constraints;
    let num_vars = instance.num_variables;
    let num_inputs = instance.num_inputs;
    let num_cols = num_vars + num_inputs + 1; // z = [vars, 1, inputs]

    // Build z vector in Goldilocks.
    if instance.assignment_vars.len() != num_vars {
      return Err(BackendError::Unsupported(
        "mismatched variable assignment length for Goldilocks encoding",
      ));
    }
    if instance.assignment_inputs.len() != num_inputs {
      return Err(BackendError::Unsupported(
        "mismatched input assignment length for Goldilocks encoding",
      ));
    }

    let mut z = vec![Field64::ZERO; num_cols];
    z[..num_vars].copy_from_slice(&instance.assignment_vars);
    z[num_vars] = Field64::ONE; // constant term
    z[num_vars + 1..].copy_from_slice(&instance.assignment_inputs);

    // Precompute row offsets for A, B, C.
    let mut residues = vec![Field64::ZERO; num_cons];
    for &(row, col, val) in &instance.matrices.A {
      residues[row] += val * z[col];
    }
    let mut Bz = vec![Field64::ZERO; num_cons];
    for &(row, col, val) in &instance.matrices.B {
      Bz[row] += val * z[col];
    }
    let mut Cz = vec![Field64::ZERO; num_cons];
    for &(row, col, val) in &instance.matrices.C {
      Cz[row] += val * z[col];
    }

    // Compute residuals.
    for i in 0..num_cons {
      residues[i] = residues[i] * Bz[i] - Cz[i];
    }

    Ok(WhirPolynomial(CoefficientList::new(residues)))
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
