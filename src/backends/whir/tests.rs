#![cfg(feature = "whir-backend")]

use super::{scalar_to_whir_field, translate_assignments_to_whir};
use crate::backends::whir::{build_protocol_params_from_config, build_whir_instance, WhirR1csView};
use crate::backends::whir::encoder::{NaiveZeroEncoder, ResidualEncoder};
use crate::backends::WhirBackend;
use crate::{Instance, InputsAssignment, VarsAssignment};
use curve25519_dalek::scalar::Scalar;
use crate::backends::whir::{build_residual_statement, verify_whir_proof_bundle};
use crate::backends::whir::prove_r1cs_with_whir;
use crate::backends::whir::{prove_whir_snark, verify_whir_snark};

#[test]
fn scalar_conversion_is_deterministic() {
  let s = Scalar::from(42u64);
  let a = scalar_to_whir_field(&s).unwrap();
  let b = scalar_to_whir_field(&s).unwrap();
  assert_eq!(a, b);
}

#[test]
fn scalar_conversion_rejects_large_values() {
  // Set high bytes to force rejection.
  let mut bytes = [0u8; 32];
  bytes[8] = 1;
  let s = Scalar::from_bytes_mod_order(bytes);
  let err = scalar_to_whir_field(&s).unwrap_err();
  assert!(matches!(err, crate::backends::BackendError::Unsupported(_)));
}

#[test]
fn translate_assignments_rounds_lengths() {
  let vars = VarsAssignment::new(&[Scalar::from(1u64).to_bytes(), Scalar::from(2u64).to_bytes()])
    .unwrap();
  let inputs =
    InputsAssignment::new(&[Scalar::from(3u64).to_bytes(), Scalar::from(4u64).to_bytes()]).unwrap();

  let (whir_vars, whir_inputs) = translate_assignments_to_whir(&vars, &inputs).unwrap();
  assert_eq!(whir_vars.len(), 2);
  assert_eq!(whir_inputs.len(), 2);
}

#[test]
fn naive_zero_encoder_rejects_large_instances() {
  // Build a tiny instance to satisfy types; the encoder only checks num_variables.
  let num_cons = 2usize;
  let num_vars = 1usize; // keep tiny
  let num_inputs = 0usize;
  let A: Vec<(usize, usize, [u8; 32])> = Vec::new();
  let B: Vec<(usize, usize, [u8; 32])> = Vec::new();
  let C: Vec<(usize, usize, [u8; 32])> = Vec::new();
  let inst = Instance::new(num_cons, num_vars, num_inputs, &A, &B, &C).unwrap();

  let vars = VarsAssignment::new(&[Scalar::ZERO.to_bytes()]).unwrap();
  let inputs = InputsAssignment::new(&[]).unwrap();

  let view = WhirR1csView::new(&inst, &vars, &inputs).unwrap();
  let backend = WhirBackend::default();
  let (whir_config, mv_params) =
    build_protocol_params_from_config(&backend, view.num_constraints.ilog2() as usize).unwrap();
  let whir_instance =
    build_whir_instance(&view, inst.shape(), &vars, &inputs, whir_config, mv_params).unwrap();

  let encoder = NaiveZeroEncoder { max_vars: 0 }; // force rejection
  let err = encoder.encode(&whir_instance).unwrap_err();
  assert!(matches!(err, crate::backends::BackendError::Unsupported(_)));
}

#[test]
fn residual_encoder_matches_empty_r1cs() {
  // Empty matrices imply zero residuals.
  let inst = Instance::new(2, 1, 0, &[], &[], &[]).unwrap();
  let vars = VarsAssignment::new(&[Scalar::ZERO.to_bytes()]).unwrap();
  let inputs = InputsAssignment::new(&[]).unwrap();

  let view = WhirR1csView::new(&inst, &vars, &inputs).unwrap();
  let backend = WhirBackend::default();
  let (whir_config, mv_params) =
    build_protocol_params_from_config(&backend, view.num_constraints.ilog2() as usize).unwrap();
  let whir_instance =
    build_whir_instance(&view, inst.shape(), &vars, &inputs, whir_config, mv_params).unwrap();

  let encoder = ResidualEncoder;
  let poly = encoder.encode(&whir_instance).unwrap();
  // all evaluations must be zero
  assert!(poly.0.clone().into_iter().all(|v| v.is_zero()));

  // Statement enforces zero at a bounded set of corners (all-zero/all-one plus samples).
  let stmt = build_residual_statement(&poly, &[0u8; 32]).unwrap();
  assert_eq!(stmt.num_variables(), 2);
  assert!(stmt.constraints.len() >= 2);
}

#[test]
fn whir_round_trip_tiny_r1cs() {
  // Constraint: z * z = z with z = 1 over Goldilocks.
  let num_cons = 1usize;
  let num_vars = 1usize;
  let num_inputs = 0usize;
  // A, B, C entries: single row/col with coefficient 1.
  let one = Scalar::ONE.to_bytes();
  let A = vec![(0usize, 0usize, one)];
  let B = vec![(0usize, 0usize, one)];
  let C = vec![(0usize, 0usize, one)];
  let inst = Instance::new(num_cons, num_vars, num_inputs, &A, &B, &C).unwrap();

  let vars = VarsAssignment::new(&[Scalar::ONE.to_bytes()]).unwrap();
  let inputs = InputsAssignment::new(&[]).unwrap();

  let backend = WhirBackend::default();
  let view = WhirR1csView::new(&inst, &vars, &inputs).unwrap();
  let res = prove_r1cs_with_whir(&backend, view, inst.shape());
  assert!(res.is_ok());

  // Proof bundle should contain a non-empty transcript.
  let proof = res.unwrap();
  assert!(!proof.narg.is_empty());
  verify_whir_proof_bundle(&proof).unwrap();
}

#[test]
fn whir_round_trip_two_constraints() {
  // Constraints:
  // 1) x * y = 6
  // 2) y * 1 = 3  (fixes y)
  let num_cons = 2usize;
  let num_vars = 2usize;
  let num_inputs = 0usize;
  let one = Scalar::ONE.to_bytes();
  let three = Scalar::from(3u64).to_bytes();
  let six = Scalar::from(6u64).to_bytes();
  // z = [x, y, 1]
  let A = vec![(0usize, 0usize, one), (1usize, 1usize, one)];
  let B = vec![(0usize, 1usize, one), (1usize, 2usize, one)]; // 1 is at col 2
  let C = vec![(0usize, 2usize, six), (1usize, 2usize, three)];

  let inst = Instance::new(num_cons, num_vars, num_inputs, &A, &B, &C).unwrap();

  let vars = VarsAssignment::new(&[Scalar::from(2u64).to_bytes(), Scalar::from(3u64).to_bytes()])
    .unwrap();
  let inputs = InputsAssignment::new(&[]).unwrap();

  let backend = WhirBackend::default();
  let view = WhirR1csView::new(&inst, &vars, &inputs).unwrap();
  let res = prove_r1cs_with_whir(&backend, view, inst.shape());
  let proof = res.unwrap();
  verify_whir_proof_bundle(&proof).unwrap();
}

#[test]
fn whir_round_trip_with_public_input() {
  // Constraint: x * input = 10, with input public and x witness = 2, input=5.
  let num_cons = 1usize;
  let num_vars = 1usize;
  let num_inputs = 1usize;
  let one = Scalar::ONE.to_bytes();
  let ten = Scalar::from(10u64).to_bytes();
  // z = [x, 1, input]
  let A = vec![(0usize, 0usize, one)];
  let B = vec![(0usize, 2usize, one)]; // public input column
  let C = vec![(0usize, 2usize, ten)];

  let inst = Instance::new(num_cons, num_vars, num_inputs, &A, &B, &C).unwrap();

  let vars = VarsAssignment::new(&[Scalar::from(2u64).to_bytes()]).unwrap();
  let inputs = InputsAssignment::new(&[Scalar::from(5u64).to_bytes()]).unwrap();

  let backend = WhirBackend::default();
  let view = WhirR1csView::new(&inst, &vars, &inputs).unwrap();
  let proof = prove_r1cs_with_whir(&backend, view, inst.shape()).unwrap();
  verify_whir_proof_bundle(&proof).unwrap();
}

#[test]
fn whir_snark_wrapper_round_trip() {
  // Reuse the two-constraint instance to exercise the WhirSnark wrapper.
  let num_cons = 2usize;
  let num_vars = 2usize;
  let num_inputs = 0usize;
  let one = Scalar::ONE.to_bytes();
  let three = Scalar::from(3u64).to_bytes();
  let six = Scalar::from(6u64).to_bytes();
  let A = vec![(0usize, 0usize, one), (1usize, 1usize, one)];
  let B = vec![(0usize, 1usize, one), (1usize, 2usize, one)];
  let C = vec![(0usize, 2usize, six), (1usize, 2usize, three)];
  let inst = Instance::new(num_cons, num_vars, num_inputs, &A, &B, &C).unwrap();
  let vars = VarsAssignment::new(&[Scalar::from(2u64).to_bytes(), Scalar::from(3u64).to_bytes()])
    .unwrap();
  let inputs = InputsAssignment::new(&[]).unwrap();

  let backend = WhirBackend::default();
  let snark = prove_whir_snark(&backend, &inst, vars, &inputs).unwrap();
  verify_whir_snark(&snark).unwrap();
}

#[test]
fn whir_residual_constraint_growth_is_bounded() {
  // Build a slightly larger instance (4 constraints, 3 vars) and ensure the statement constraint
  // count stays reasonable (fixed + samples + linear comb).
  let num_cons = 4usize;
  let num_vars = 3usize;
  let num_inputs = 0usize;
  let one = Scalar::ONE.to_bytes();
  let A = vec![(0usize, 0usize, one), (1usize, 1usize, one), (2usize, 2usize, one)];
  let B = vec![(0usize, 1usize, one), (1usize, 2usize, one), (2usize, 0usize, one)];
  let C = vec![(0usize, 2usize, one), (1usize, 0usize, one), (2usize, 1usize, one)];
  let inst = Instance::new(num_cons, num_vars, num_inputs, &A, &B, &C).unwrap();
  let vars = VarsAssignment::new(&[Scalar::from(2u64).to_bytes(); 3]).unwrap();
  let inputs = InputsAssignment::new(&[]).unwrap();

  let backend = WhirBackend::default();
  let view = WhirR1csView::new(&inst, &vars, &inputs).unwrap();
  let proof = prove_r1cs_with_whir(&backend, view, inst.shape()).unwrap();
  // Expect constraints: all-zero + all-one + samples + linear combination (plus potential dedup).
  assert!(proof.statement.constraints.len() <= 2 + 4 + 1 + 8);
  verify_whir_proof_bundle(&proof).unwrap();
}

#[test]
fn whir_rejects_blantantly_wrong_witness() {
  // Constraint: x * 1 = 0, but witness sets x = 1, so residual polynomial is constant 1.
  let num_cons = 1usize;
  let num_vars = 1usize;
  let num_inputs = 0usize;
  let one = Scalar::ONE.to_bytes();
  let zero = Scalar::ZERO.to_bytes();
  // z = [x, 1]
  let A = vec![(0usize, 0usize, one)];
  let B = vec![(0usize, 1usize, one)]; // constant column
  let C = vec![(0usize, 1usize, zero)];

  let inst = Instance::new(num_cons, num_vars, num_inputs, &A, &B, &C).unwrap();
  let vars = VarsAssignment::new(&[Scalar::ONE.to_bytes()]).unwrap(); // violates the constraint
  let inputs = InputsAssignment::new(&[]).unwrap();

  let backend = WhirBackend::default();
  let view = WhirR1csView::new(&inst, &vars, &inputs).unwrap();
  let res = prove_r1cs_with_whir(&backend, view, inst.shape());
  assert!(res.is_err(), "proof should fail for an invalid witness");
}
