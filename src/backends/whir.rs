//! Feature-gated helpers for translating Spartan R1CS instances into WHIR-friendly inputs.
//!
//! This module only provides scaffolding today; actual PCS/sum-check wiring still needs to be
//! implemented. Keeping the code here (instead of behind cfg stubs) lets us stage the type
//! signatures that downstream examples/tests will rely on.

use super::{BackendError, BackendFlavor, ProofBackend, WhirBackend, WhirConfig};
use crate::{InputsAssignment, Instance, VarsAssignment};

/// Captures the minimal data we expect to shuttle into the WHIR prover.
#[derive(Debug)]
pub struct WhirR1csView<'a> {
  /// Number of constraints in the padded R1CS.
  pub num_constraints: usize,
  /// Number of variables in the padded R1CS.
  pub num_variables: usize,
  /// Number of public inputs.
  pub num_inputs: usize,
  /// Assignment to witness variables.
  pub assignment_vars: &'a VarsAssignment,
  /// Assignment to public inputs.
  pub assignment_inputs: &'a InputsAssignment,
}

impl<'a> WhirR1csView<'a> {
  /// Snapshot the shape of an `Instance` plus assignments that will be re-encoded for WHIR.
  pub fn new(
    inst: &'a Instance,
    vars: &'a VarsAssignment,
    inputs: &'a InputsAssignment,
  ) -> Result<Self, BackendError> {
    Ok(Self {
      num_constraints: inst.num_cons(),
      num_variables: inst.num_vars(),
      num_inputs: inst.num_inputs(),
      assignment_vars: vars,
      assignment_inputs: inputs,
    })
  }
}

/// Checks whether the supplied backend is WHIR and reachable.
pub fn ensure_whir_backend<B: ProofBackend>(backend: &B) -> Result<(), BackendError> {
  match backend.flavor() {
    BackendFlavor::Whir => backend.availability(),
    _ => Err(BackendError::Unsupported("expected WHIR backend")),
  }
}

/// Placeholder hook where the R1CS → WHIR translation and proof generation will live.
pub fn prove_r1cs_with_whir(
  backend: &WhirBackend,
  view: WhirR1csView<'_>,
) -> Result<(), BackendError> {
  let _config: &WhirConfig = backend.config();
  // TODO: translate the Spartan `Instance` matrices and assignments into WHIR's multilinear
  // polynomial representation, then drive the WHIR prover to produce a proof object we can
  // verify or wrap.
  Err(BackendError::NotImplemented(
    "R1CS → WHIR translation is not implemented yet",
  ))
}
