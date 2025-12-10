#![cfg(feature = "whir-backend")]

use super::{scalar_to_whir_field, translate_assignments_to_whir};
use crate::backends::whir::{build_protocol_params_from_config, build_whir_instance, WhirR1csView};
use crate::backends::whir::encoder::{NaiveZeroEncoder, ResidualEncoder};
use crate::backends::WhirBackend;
use crate::{Instance, InputsAssignment, VarsAssignment};
use curve25519_dalek::scalar::Scalar;
use crate::backends::whir::build_residual_statement;
use crate::backends::whir::prove_r1cs_with_whir;

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
    build_protocol_params_from_config(&backend, view.num_variables).unwrap();
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
    build_protocol_params_from_config(&backend, view.num_variables).unwrap();
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
}
