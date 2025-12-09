//! Abstractions for pluggable polynomial commitment backends.
//!
//! This trait is a placeholder for future backends (e.g., WHIR) while keeping
//! the existing Pedersen-based PCS intact. It is not yet wired into the prover
//! or verifier pipeline.

/// A generic interface for polynomial commitment schemes.
pub trait PcsBackend {
  /// Base field element type used by the PCS.
  type Scalar;
  /// Commitment type produced by the PCS.
  type Commitment;
  /// Proof type returned by opening a commitment.
  type Proof;

  /// Commit to a polynomial represented by its coefficients or evaluations.
  fn commit(&self, poly: &[Self::Scalar]) -> Self::Commitment;

  /// Open a committed polynomial at a point, returning the value and an opening proof.
  fn open(&self, poly: &[Self::Scalar], point: &[Self::Scalar]) -> (Self::Scalar, Self::Proof);

  /// Verify that `value` is the evaluation of the committed polynomial at `point`.
  fn verify(
    &self,
    commitment: &Self::Commitment,
    point: &[Self::Scalar],
    value: &Self::Scalar,
    proof: &Self::Proof,
  ) -> bool;
}
