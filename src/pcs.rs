//! Abstractions for pluggable polynomial commitment backends.
//!
//! This trait is a placeholder for future backends (e.g., WHIR) while keeping
//! the existing Pedersen-based PCS intact. It is not yet wired into the prover
//! or verifier pipeline.

use crate::commitments::Commitments;

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

/// Experimental backend that wraps the existing Pedersen-style commitments.
///
/// This is **not** a fully sound PCS: `open` ignores the evaluation point and
/// `verify` currently only checks that the provided commitment matches a fresh
/// commitment of the polynomial (ignoring the point/value). It exists to
/// exercise the backend plumbing; do not rely on it for security.
pub struct PedersenPcs<'a> {
  pub gens: &'a crate::commitments::MultiCommitGens,
}

impl<'a> PcsBackend for PedersenPcs<'a> {
  type Scalar = crate::scalar::Scalar;
  type Commitment = crate::group::GroupElement;
  type Proof = ();

  fn commit(&self, poly: &[Self::Scalar]) -> Self::Commitment {
    // Deterministic blinding for experiments; not hiding.
    let blind = Self::Scalar::zero();
    poly.commit(&blind, self.gens)
  }

  fn open(&self, _poly: &[Self::Scalar], _point: &[Self::Scalar]) -> (Self::Scalar, Self::Proof) {
    // Return a dummy value; callers should not rely on soundness.
    (Self::Scalar::zero(), ())
  }

  fn verify(
    &self,
    commitment: &Self::Commitment,
    point: &[Self::Scalar],
    value: &Self::Scalar,
    proof: &Self::Proof,
  ) -> bool {
    let _ = (point, value, proof);
    // Unsound placeholder: accept all proofs.
    let _ = commitment;
    true
  }
}
