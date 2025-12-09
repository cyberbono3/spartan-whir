//! Demonstrates selecting a proof backend at runtime. Default is Spartan's native backend;
//! passing `--backend whir` will attempt to route to the WHIR adapter (currently unimplemented).
#![allow(clippy::assertions_on_result_states)]

use curve25519_dalek::scalar::Scalar;
use libspartan::backends::{BackendError, ProofBackend};
use libspartan::{backends::NativeBackend, InputsAssignment, Instance, SNARKGens, VarsAssignment, SNARK};
#[cfg(feature = "whir-backend")]
use libspartan::backends::WhirBackend;
use merlin::Transcript;
use rand::rngs::OsRng;

#[allow(non_snake_case)]
fn produce_r1cs() -> (
  usize,
  usize,
  usize,
  usize,
  Instance,
  VarsAssignment,
  InputsAssignment,
) {
  // parameters of the R1CS instance
  let num_cons = 4;
  let num_vars = 4;
  let num_inputs = 1;
  let num_non_zero_entries = 8;

  // We will encode the above constraints into three matrices, where
  // the coefficients in the matrix are in the little-endian byte order
  let mut A: Vec<(usize, usize, [u8; 32])> = Vec::new();
  let mut B: Vec<(usize, usize, [u8; 32])> = Vec::new();
  let mut C: Vec<(usize, usize, [u8; 32])> = Vec::new();

  let one = Scalar::ONE.to_bytes();

  // constraint 0 entries in (A,B,C)
  // constraint 0 is Z0 * Z0 - Z1 = 0.
  A.push((0, 0, one));
  B.push((0, 0, one));
  C.push((0, 1, one));

  // constraint 1 entries in (A,B,C)
  // constraint 1 is Z1 * Z0 - Z2 = 0.
  A.push((1, 1, one));
  B.push((1, 0, one));
  C.push((1, 2, one));

  // constraint 2 entries in (A,B,C)
  // constraint 2 is (Z2 + Z0) * 1 - Z3 = 0.
  A.push((2, 2, one));
  A.push((2, 0, one));
  B.push((2, num_vars, one));
  C.push((2, 3, one));

  // constraint 3 entries in (A,B,C)
  // constraint 3 is (Z3 + 5) * 1 - I0 = 0.
  A.push((3, 3, one));
  A.push((3, num_vars, Scalar::from(5u32).to_bytes()));
  B.push((3, num_vars, one));
  C.push((3, num_vars + 1, one));

  let inst = Instance::new(num_cons, num_vars, num_inputs, &A, &B, &C).unwrap();

  // compute a satisfying assignment
  let mut csprng: OsRng = OsRng;
  let z0 = Scalar::random(&mut csprng);
  let z1 = z0 * z0; // constraint 0
  let z2 = z1 * z0; // constraint 1
  let z3 = z2 + z0; // constraint 2
  let i0 = z3 + Scalar::from(5u32); // constraint 3

  // create a VarsAssignment
  let mut vars = vec![Scalar::ZERO.to_bytes(); num_vars];
  vars[0] = z0.to_bytes();
  vars[1] = z1.to_bytes();
  vars[2] = z2.to_bytes();
  vars[3] = z3.to_bytes();
  let assignment_vars = VarsAssignment::new(&vars).unwrap();

  // create an InputsAssignment
  let mut inputs = vec![Scalar::ZERO.to_bytes(); num_inputs];
  inputs[0] = i0.to_bytes();
  let assignment_inputs = InputsAssignment::new(&inputs).unwrap();

  // check if the instance we created is satisfiable
  let res = inst.is_sat(&assignment_vars, &assignment_inputs);
  assert!(res.unwrap(), "should be satisfied");

  (
    num_cons,
    num_vars,
    num_inputs,
    num_non_zero_entries,
    inst,
    assignment_vars,
    assignment_inputs,
  )
}

fn select_backend(args: &[String]) -> (String, Box<dyn ProofBackend>) {
  let wants_whir = args.iter().any(|arg| arg == "--backend=whir" || arg == "--whir");

  if wants_whir {
    #[cfg(feature = "whir-backend")]
    {
      return ("whir".to_string(), Box::new(WhirBackend::default()));
    }
    #[cfg(not(feature = "whir-backend"))]
    {
      eprintln!("WHIR backend requested, but `whir-backend` feature is not enabled; falling back to native");
    }
  }

  ("native".to_string(), Box::new(NativeBackend))
}

fn main() {
  let args: Vec<String> = std::env::args().collect();
  let (backend_label, backend) = select_backend(&args);

  // produce an R1CS instance
  let (
    num_cons,
    num_vars,
    num_inputs,
    num_non_zero_entries,
    inst,
    assignment_vars,
    assignment_inputs,
  ) = produce_r1cs();

  // produce public parameters
  let gens = SNARKGens::new(num_cons, num_vars, num_inputs, num_non_zero_entries);

  // create a commitment to the R1CS instance
  let (comm, decomm) = SNARK::encode(&inst, &gens);

  // produce a proof of satisfiability using the selected backend
  let mut prover_transcript = Transcript::new(b"backend_switch_example");
  match SNARK::prove_with_backend(
    &inst,
    &comm,
    &decomm,
    assignment_vars,
    &assignment_inputs,
    &gens,
    &mut prover_transcript,
    backend.as_ref(),
  ) {
    Ok(proof) => {
      println!("backend `{backend_label}` produced a proof");
      // verify the proof of satisfiability
      let mut verifier_transcript = Transcript::new(b"backend_switch_example");
      assert!(proof
        .verify(&comm, &assignment_inputs, &mut verifier_transcript, &gens)
        .is_ok());
      println!("proof verification successful!");
    }
    Err(BackendError::NotImplemented(msg)) => {
      eprintln!("backend `{backend_label}` is not implemented yet: {msg}");
    }
    Err(err) => {
      eprintln!("backend `{backend_label}` failed: {err}");
    }
  }
}
