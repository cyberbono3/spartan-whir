//! Feature-gated helpers for translating Spartan R1CS instances into WHIR-friendly inputs.
//!
//! This module only provides scaffolding today; actual PCS/sum-check wiring still needs to be
//! implemented. Keeping the code here (instead of behind cfg stubs) lets us stage the type
//! signatures that downstream examples/tests will rely on.

use super::{BackendError, BackendFlavor, ProofBackend, WhirBackend, WhirConfig};
use crate::{ComputationCommitment, ComputationDecommitment, InputsAssignment, Instance, VarsAssignment};
use crate::SNARKGens;
use curve25519_dalek::scalar::Scalar;
use merlin::Transcript;
use whir::crypto::fields::Field64;

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

/// Convert a Spartan scalar into WHIR's Goldilocks-like field. This currently returns an
/// `Unsupported` error because the two fields are unrelated and a sound embedding strategy is
/// required (e.g., hashing to field or a different circuit encoding).
pub fn scalar_to_whir_field(_scalar: &Scalar) -> Result<Field64, BackendError> {
  Err(BackendError::Unsupported(
    "curve25519 Scalar → WHIR field conversion not implemented; choose an embedding or redesign the constraint encoding",
  ))
}

/// Translate variable and input assignments into WHIR's field representation.
pub fn translate_assignments_to_whir(
  vars: &VarsAssignment,
  inputs: &InputsAssignment,
) -> Result<(Vec<Field64>, Vec<Field64>), BackendError> {
  let mut whir_vars = Vec::with_capacity(vars.assignment.len());
  for s in &vars.assignment {
    whir_vars.push(scalar_to_whir_field(s)?);
  }

  let mut whir_inputs = Vec::with_capacity(inputs.assignment.len());
  for s in &inputs.assignment {
    whir_inputs.push(scalar_to_whir_field(s)?);
  }

  Ok((whir_vars, whir_inputs))
}

/// Placeholder for turning an R1CS instance into a WHIR statement (PCS/LDT inputs).
pub fn build_whir_statement(_view: &WhirR1csView<'_>) -> Result<(), BackendError> {
  Err(BackendError::NotImplemented(
    "R1CS → WHIR statement mapping is not implemented yet",
  ))
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
  build_whir_statement(&view)?;
  Err(BackendError::Unsupported(
    "WHIR proving path missing: field conversion and statement wiring incomplete",
  ))
}

/// Placeholder for a WHIR-backed SNARK proving path. Eventually this will translate Spartan's R1CS
/// objects into WHIR statements and drive the WHIR prover, then wrap the result in a Spartan
/// `SNARK` object (or a parallel structure).
pub fn prove_snark_with_whir(
  backend: &WhirBackend,
  inst: &Instance,
  _comm: &ComputationCommitment,
  _decomm: &ComputationDecommitment,
  vars: VarsAssignment,
  inputs: &InputsAssignment,
  _gens: &SNARKGens,
  _transcript: &mut Transcript,
) -> Result<crate::SNARK, BackendError> {
  // Snapshot the instance to feed into WHIR conversion logic.
  let view = WhirR1csView::new(inst, &vars, inputs)?;
  let (whir_vars, whir_inputs) = translate_assignments_to_whir(&vars, inputs)?;
  let _ = (whir_vars, whir_inputs);
  prove_r1cs_with_whir(backend, view)?;
  Err(BackendError::Unsupported(
    "WHIR-backed SNARK proof object is not yet constructed",
  ))
}
