//! Feature-gated helpers for translating Spartan R1CS instances into WHIR-friendly inputs.
//!
//! This module only provides scaffolding today; actual PCS/sum-check wiring still needs to be
//! implemented. Keeping the code here (instead of behind cfg stubs) lets us stage the type
//! signatures that downstream examples/tests will rely on.

use super::{BackendError, BackendFlavor, ProofBackend, WhirBackend, WhirConfig};
use crate::r1cs::R1CSShape;
use crate::sparse_mlpoly::SparseMatEntry;
use crate::{ComputationCommitment, ComputationDecommitment, InputsAssignment, Instance, VarsAssignment};
use crate::SNARKGens;
use curve25519_dalek::scalar::Scalar;
use merlin::Transcript;
use ark_ff::PrimeField;
use whir::crypto::fields::Field64;
use whir::whir::parameters::WhirConfig as InnerWhirConfig;
use whir::whir::parameters::{
  DeduplicationStrategy, FoldingFactor, MerkleProofStrategy, MultivariateParameters,
  ProtocolParameters, SoundnessType,
};

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

/// Convert a Spartan scalar into WHIR's Goldilocks-like field.
///
/// NOTE: this reduces the 255-bit Ristretto scalar modulo the Goldilocks prime. It is *not* an
/// injective homomorphism and may not be appropriate for real proof systems without additional
/// embedding design (e.g., hashing-to-field or circuit-level re-encoding). Use cautiously.
pub fn scalar_to_whir_field(_scalar: &Scalar) -> Result<Field64, BackendError> {
  // This maps a Ristretto scalar (little-endian bytes) into the Goldilocks-like field by reducing
  // modulo the target field prime. This is deterministic but **not** an injective homomorphism and
  // must be reviewed for soundness for your use-case.
  Ok(Field64::from_le_bytes_mod_order(&_scalar.to_bytes()))
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

/// Placeholder for building WHIR protocol parameters from the backend config.
///
/// TODO: Select concrete Merkle hash, PoW strategy, folding factor, and domain sizes using WHIR
/// types (`WhirConfig`, `ProtocolParameters`, `MultivariateParameters`), then return them to plug
/// into the prover/verifier. This currently returns `NotImplemented` to avoid guessing.
pub fn build_protocol_params_from_config(_backend: &WhirBackend) -> Result<(), BackendError> {
  Err(BackendError::NotImplemented(
    "WHIR protocol parameter mapping (Merkle/hash/PowStrategy) not implemented",
  ))
}

/// Sparse matrices re-encoded over WHIR's base field.
#[derive(Debug)]
pub struct WhirSparseMatrices {
  pub A: Vec<(usize, usize, Field64)>,
  pub B: Vec<(usize, usize, Field64)>,
  pub C: Vec<(usize, usize, Field64)>,
}

/// R1CS instance and assignments expressed in WHIR's field.
#[derive(Debug)]
pub struct WhirR1csInstance {
  pub num_constraints: usize,
  pub num_variables: usize,
  pub num_inputs: usize,
  pub matrices: WhirSparseMatrices,
  pub assignment_vars: Vec<Field64>,
  pub assignment_inputs: Vec<Field64>,
  /// Placeholder for protocol parameters once mapping is defined.
  pub protocol_params: Option<ProtocolParameters<(), ()>>,
  /// Placeholder for multivariate params (domain size) once mapping is defined.
  pub mv_params: Option<MultivariateParameters<Field64>>,
}

/// Turn a Spartan R1CS instance into WHIR-friendly sparse matrices. This does **not** yet build
/// the full WHIR statement or handle domain parameters.
pub fn build_whir_statement(
  _view: &WhirR1csView<'_>,
  shape: &R1CSShape,
) -> Result<WhirSparseMatrices, BackendError> {
  let (poly_a, poly_b, poly_c) = shape.sparse_matrices();

  let mut convert_entries =
    |entries: &[SparseMatEntry]| -> Result<Vec<(usize, usize, Field64)>, BackendError> {
      let mut out = Vec::with_capacity(entries.len());
      for entry in entries {
        let field_val = scalar_to_whir_field(entry.val())?;
        out.push((entry.row(), entry.col(), field_val));
      }
      Ok(out)
    };

  Ok(WhirSparseMatrices {
    A: convert_entries(poly_a.entries())?,
    B: convert_entries(poly_b.entries())?,
    C: convert_entries(poly_c.entries())?,
  })
}

/// Bundle the converted matrices and assignments into a WHIR-ready R1CS instance representation.
pub fn build_whir_instance(
  view: &WhirR1csView<'_>,
  shape: &R1CSShape,
  vars: &VarsAssignment,
  inputs: &InputsAssignment,
) -> Result<WhirR1csInstance, BackendError> {
  let matrices = build_whir_statement(view, shape)?;
  let (assignment_vars, assignment_inputs) = translate_assignments_to_whir(vars, inputs)?;
  // TODO: add domain/FFT parameters and Merkle/hash selections compatible with WHIR config.
  Ok(WhirR1csInstance {
    num_constraints: view.num_constraints,
    num_variables: view.num_variables,
    num_inputs: view.num_inputs,
    matrices,
    assignment_vars,
    assignment_inputs,
    protocol_params: None,
    mv_params: None,
  })
}

/// Placeholder hook where the R1CS → WHIR translation and proof generation will live.
pub fn prove_r1cs_with_whir(
  backend: &WhirBackend,
  view: WhirR1csView<'_>,
  shape: &R1CSShape,
) -> Result<(), BackendError> {
  let _config: &WhirConfig = backend.config();
  // TODO: translate the Spartan `Instance` matrices and assignments into WHIR's multilinear
  // polynomial representation, then drive the WHIR prover to produce a proof object we can
  // verify or wrap.
  let instance = build_whir_instance(&view, shape, view.assignment_vars, view.assignment_inputs)?;
  let _ = instance;
  Err(BackendError::Unsupported(
    "WHIR proving path missing: sum-check/PCS wiring not implemented",
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
  prove_r1cs_with_whir(backend, view, inst.shape())?;
  Err(BackendError::Unsupported(
    "WHIR-backed SNARK proof object is not yet constructed",
  ))
}
