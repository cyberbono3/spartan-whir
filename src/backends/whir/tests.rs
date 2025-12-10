#![cfg(feature = "whir-backend")]

use super::{scalar_to_whir_field, translate_assignments_to_whir};
use crate::backends::whir::{build_protocol_params_from_config, build_whir_instance, WhirR1csView};
use crate::backends::whir::encoder::NaiveZeroEncoder;
use crate::backends::WhirBackend;
use crate::{Instance, InputsAssignment, VarsAssignment};
use curve25519_dalek::scalar::Scalar;

#[test]
fn scalar_conversion_is_deterministic() {
  let s = Scalar::from(42u64);
  let a = scalar_to_whir_field(&s).unwrap();
  let b = scalar_to_whir_field(&s).unwrap();
  assert_eq!(a, b);
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
