#![cfg(feature = "whir-backend")]

use super::{scalar_to_whir_field, translate_assignments_to_whir};
use crate::{InputsAssignment, VarsAssignment};
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
