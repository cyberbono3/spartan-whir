//! Feature-gated helpers for translating Spartan R1CS instances into WHIR-friendly inputs.
//!
//! This module only provides scaffolding today; actual PCS/sum-check wiring still needs to be
//! implemented. Keeping the code here (instead of behind cfg stubs) lets us stage the type
//! signatures that downstream examples/tests will rely on.

mod encoder;
pub use encoder::{DefaultEncoder, NaiveZeroEncoder, ResidualEncoder, WhirEncoder, WhirPolynomial};

use super::{BackendError, BackendFlavor, ProofBackend, WhirBackend, WhirConfig};
use crate::r1cs::R1CSShape;
use crate::sparse_mlpoly::SparseMatEntry;
use crate::{ComputationCommitment, ComputationDecommitment, InputsAssignment, Instance, VarsAssignment};
use crate::SNARKGens;
use curve25519_dalek::scalar::Scalar;
use encoder::{DefaultEncoder, WhirEncoder, WhirPolynomial};
use merlin::Transcript;
use rand::thread_rng;
use spongefish_pow::blake3::Blake3PoW;
use std::sync::Arc;
use whir::crypto::fields::{Field64, Field64_2};
use whir::crypto::merkle_tree::blake3::{Blake3Compress, Blake3LeafHash, Blake3MerkleTreeParams};
use whir::crypto::merkle_tree::parameters::default_config;
use whir::ntt::RSDefault;
use whir::poly_utils::evals::EvaluationsList;
use whir::poly_utils::multilinear::MultilinearPoint;
use whir::whir::committer::CommitmentWriter;
use whir::whir::parameters::{
  DeduplicationStrategy, FoldingFactor, MerkleProofStrategy, MultivariateParameters,
  ProtocolParameters, SoundnessType, WhirConfig as ArkWhirConfig,
};
use whir::whir::statement::{Statement as WhirStatement, Weights};
use whir::whir::{prover::Prover, verifier::Verifier};
use whir::whir::domainsep::WhirDomainSeparator;
use spongefish::DomainSeparator;
use whir::whir::statement::{Statement as WhirStatement, Weights};
use whir::poly_utils::evals::EvaluationsList;

/// Concrete types chosen for the WHIR adapter, inspired by the upstream WHIR defaults.
type MerkleConfig = Blake3MerkleTreeParams<Field64>;
type PowStrategy = Blake3PoW;
type WhirConfigType = ArkWhirConfig<Field64, MerkleConfig, PowStrategy>;
/// Avoids allocating gigantic linear weights; adjust as needed for experiments.
const MAX_STATEMENT_VARS: usize = 20;

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
  // For a sound encoding we require the value to already fit in Goldilocks; reject anything larger
  // instead of reducing modulo the field prime.
  let bytes = _scalar.to_bytes();
  if bytes[8..].iter().any(|&b| b != 0) {
    return Err(BackendError::Unsupported(
      "scalar not representable in Goldilocks; re-express the circuit over Goldilocks field",
    ));
  }
  let little = u64::from_le_bytes(bytes[..8].try_into().unwrap());
  Ok(Field64::from(little))
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

/// Build WHIR protocol and multivariate parameters from the backend config and instance size.
pub fn build_protocol_params_from_config(
  backend: &WhirBackend,
  num_variables: usize,
) -> Result<(WhirConfigType, MultivariateParameters<Field64>), BackendError> {
  let cfg = backend.config();

  // Only support Blake3 + Goldilocks for now, mirroring upstream defaults.
  if let Some(hash) = cfg.hash {
    if hash.to_lowercase() != "blake3" {
      return Err(BackendError::Unsupported("only Blake3 hash is supported in WHIR adapter"));
    }
  }
  if let Some(field) = cfg.field {
    if !field.to_lowercase().contains("goldilocks") {
      return Err(BackendError::Unsupported("only Goldilocks field is supported in WHIR adapter"));
    }
  }

  let soundness = match cfg.soundness {
    Some("UniqueDecoding") => SoundnessType::UniqueDecoding,
    Some("ProvableList") => SoundnessType::ProvableList,
    Some("ConjectureList") | None => SoundnessType::ConjectureList,
    Some(_) => {
      return Err(BackendError::Unsupported(
        "unsupported soundness type; use UniqueDecoding, ProvableList, or ConjectureList",
      ))
    }
  };

  let folding_factor = FoldingFactor::Constant(cfg.folding_factor.unwrap_or(4) as usize);
  let pow_bits = cfg.pow_bits.unwrap_or(0) as usize;
  let rate_log_inv = cfg.rate_log_inv.unwrap_or(1) as usize;

  let mut rng = thread_rng();
  let (leaf_hash_params, two_to_one_params) =
    default_config::<Field64_2, Blake3LeafHash<Field64_2>, Blake3Compress>(&mut rng);

  let mv_params = MultivariateParameters::new(num_variables);

  let protocol_params = ProtocolParameters::<MerkleConfig, PowStrategy> {
    initial_statement: true,
    security_level: cfg.security_level as usize,
    pow_bits,
    folding_factor,
    leaf_hash_params,
    two_to_one_params,
    soundness_type: soundness,
    _pow_parameters: Default::default(),
    starting_log_inv_rate: rate_log_inv,
    batch_size: 1,
    deduplication_strategy: DeduplicationStrategy::Enabled,
    merkle_proof_strategy: MerkleProofStrategy::Compressed,
  };

  let reed_solomon = Arc::new(RSDefault);
  let basefield_reed_solomon = reed_solomon.clone();

  let whir_config =
    ArkWhirConfig::new(reed_solomon, basefield_reed_solomon, mv_params.clone(), protocol_params);
  Ok((whir_config, mv_params))
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
  /// WHIR configuration with Merkle/hash/pow settings.
  pub whir_config: WhirConfigType,
  /// Multivariate parameters (domain sizing).
  pub mv_params: MultivariateParameters<Field64>,
}

/// Bundle of WHIR inputs ready for the prover once encoding is wired.
pub struct WhirProverContext {
  pub instance: WhirR1csInstance,
  pub polynomial: WhirPolynomial,
  pub statement: WhirStatement<Field64>,
}

impl WhirProverContext {
  pub fn new(
    instance: WhirR1csInstance,
    polynomial: WhirPolynomial,
    statement: WhirStatement<Field64>,
  ) -> Self {
    Self {
      instance,
      polynomial,
      statement,
    }
  }

  /// Placeholder hook to run the WHIR prover once R1CS → multilinear encoding is implemented.
  pub fn prove(self) -> Result<(), BackendError> {
    // Build prover and verifier configs.
    let prover = Prover::new(self.instance.whir_config.clone());
    let verifier = Verifier::new(&self.instance.whir_config);

    // Domain separator / transcript setup.
    let domainsep = DomainSeparator::new("whir_adapter")
      .commit_statement(&self.instance.whir_config)
      .add_whir_proof(&self.instance.whir_config);

    // Prover state / challenger.
    let mut prover_state = domainsep.to_prover_state();

    // Commit polynomial.
    let committer = CommitmentWriter::new(self.instance.whir_config.clone());
    let witness = committer
      .commit(&mut prover_state, &self.polynomial.0)
      .map_err(|_| BackendError::Unsupported("WHIR commitment failed"))?;

    // Prove.
    let (constraint_eval_point, deferred) = prover
      .prove(&mut prover_state, self.statement.clone(), witness)
      .map_err(|_| BackendError::Unsupported("WHIR prove failed"))?;

    // Verifier side.
    let mut verifier_state = domainsep.to_verifier_state(prover_state.narg_string());
    let commitment_reader = whir::whir::committer::CommitmentReader::new(&self.instance.whir_config);
    let parsed_commitment = commitment_reader
      .parse_commitment(&mut verifier_state)
      .map_err(|_| BackendError::Unsupported("WHIR commitment parse failed"))?;

    verifier
      .verify(
        &mut verifier_state,
        &parsed_commitment,
        &self.statement,
        constraint_eval_point,
        &deferred,
      )
      .map_err(|_| BackendError::Unsupported("WHIR verification failed"))?;

    Ok(())
  }
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
  whir_config: WhirConfigType,
  mv_params: MultivariateParameters<Field64>,
) -> Result<WhirR1csInstance, BackendError> {
  let matrices = build_whir_statement(view, shape)?;
  let (assignment_vars, assignment_inputs) = translate_assignments_to_whir(vars, inputs)?;
  Ok(WhirR1csInstance {
    num_constraints: view.num_constraints,
    num_variables: view.num_variables,
    num_inputs: view.num_inputs,
    matrices,
    assignment_vars,
    assignment_inputs,
    whir_config,
    mv_params,
  })
}

fn build_zero_sum_statement(poly: &WhirPolynomial) -> Result<WhirStatement<Field64>, BackendError> {
  let num_vars = poly.0.num_variables();
  if num_vars > MAX_STATEMENT_VARS {
    return Err(BackendError::Unsupported(
      "statement construction would allocate more than MAX_STATEMENT_VARS variables",
    ));
  }
  let weights = EvaluationsList::new(vec![Field64::ONE; 1 << num_vars]);
  let mut stmt = WhirStatement::new(num_vars);
  stmt.add_constraint(Weights::linear(weights), Field64::ZERO);
  Ok(stmt)
}

/// Build a small statement that samples a few corners to enforce the residual polynomial is zero.
/// This keeps constraints bounded (constant number) for efficiency; it is weaker than checking all
/// corners and should be replaced with a proper challenge-sampled scheme.
pub(crate) fn build_residual_statement(
  poly: &WhirPolynomial,
) -> Result<WhirStatement<Field64>, BackendError> {
  let num_vars = poly.0.num_variables();
  if num_vars > MAX_STATEMENT_VARS {
    return Err(BackendError::Unsupported(
      "residual statement would allocate more than MAX_STATEMENT_VARS variables",
    ));
  }
  let mut stmt = WhirStatement::new(num_vars);

  // Always check the all-zero corner.
  let zero_point = MultilinearPoint::new(vec![Field64::ZERO; num_vars]);
  stmt.add_constraint(Weights::evaluation(zero_point), Field64::ZERO);

  if num_vars > 0 {
    // Also check the all-one corner.
    let one_point = MultilinearPoint::new(vec![Field64::ONE; num_vars]);
    stmt.add_constraint(Weights::evaluation(one_point), Field64::ZERO);
  }

  Ok(stmt)
}

/// Placeholder hook where the R1CS → WHIR translation and proof generation will live. Uses the
/// residual encoder by default.
pub fn prove_r1cs_with_whir(
  backend: &WhirBackend,
  view: WhirR1csView<'_>,
  shape: &R1CSShape,
) -> Result<(), BackendError> {
  prove_r1cs_with_encoder(backend, view, shape, &ResidualEncoder)
}

/// Same as `prove_r1cs_with_whir` but lets callers supply a custom encoder implementation.
pub fn prove_r1cs_with_encoder(
  backend: &WhirBackend,
  view: WhirR1csView<'_>,
  shape: &R1CSShape,
  encoder: &impl WhirEncoder,
) -> Result<(), BackendError> {
  let _config: &WhirConfig = backend.config();
  let (whir_config, mv_params) = build_protocol_params_from_config(backend, view.num_variables)?;
  // TODO: translate the Spartan `Instance` matrices and assignments into WHIR's multilinear
  // polynomial representation, then drive the WHIR prover to produce a proof object we can
  // verify or wrap.
  let instance = build_whir_instance(
    &view,
    shape,
    view.assignment_vars,
    view.assignment_inputs,
    whir_config,
    mv_params,
  )?;
  // Encode the R1CS into WHIR's polynomial form.
  let polynomial = encoder.encode(&instance)?;
  let statement = build_residual_statement(&polynomial)?;
  let ctx = WhirProverContext::new(instance, polynomial, statement);
  ctx.prove()
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
  let (_whir_vars, _whir_inputs) = translate_assignments_to_whir(&vars, inputs)?;
  prove_r1cs_with_whir(backend, view, inst.shape())?;
  Err(BackendError::Unsupported(
    "WHIR-backed SNARK proof object is not yet constructed",
  ))
}
