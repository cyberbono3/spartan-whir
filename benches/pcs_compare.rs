#![cfg(feature = "whir-backend")]

//! PCS comparison bench: native (Pedersen/Bulletproofs) vs WHIR on Goldilocks-friendly R1CS.
//! Run with: `cargo run --release --bench pcs_compare --features whir-backend -- --nocapture`

use std::time::Instant;

use curve25519_dalek::scalar::Scalar;
use libspartan::backends::WhirBackend;
use libspartan::backends::whir::{prove_whir_snark, verify_whir_snark, WhirSnark};
use libspartan::{InputsAssignment, Instance, SNARK, SNARKGens, VarsAssignment};
use merlin::Transcript;

fn make_goldilocks_instance(size: usize) -> (Instance, VarsAssignment, InputsAssignment) {
    // Simple diagonal system: for each i, x_i * 1 = x_i (satisfied by any assignment).
    let num_cons = size;
    let num_vars = size;
    let num_inputs = 0usize;

    let mut a = Vec::with_capacity(num_cons);
    let mut b = Vec::with_capacity(num_cons);
    let mut c = Vec::with_capacity(num_cons);
    for i in 0..size {
        let one = Scalar::ONE.to_bytes();
        a.push((i, i, one)); // A selects x_i
        b.push((i, num_vars, one)); // B selects the constant 1
        c.push((i, i, one)); // C selects x_i
    }

    let mut vars = Vec::with_capacity(num_vars);
    for i in 0..size {
        vars.push(Scalar::from((i as u64) + 1).to_bytes());
    }

    let inst = Instance::new(num_cons, num_vars, num_inputs, &a, &b, &c).unwrap();
    let vars_assign = VarsAssignment::new(&vars).unwrap();
    let inputs = InputsAssignment::new(&[]).unwrap();
    (inst, vars_assign, inputs)
}

fn bench_pair(size: usize) {
    let (inst, vars, inputs) = make_goldilocks_instance(size);
    let num_cons = size;
    let num_vars = size;
    let num_inputs = 0usize;
    let num_nz_entries = size.next_power_of_two(); // max non-zero entries per matrix (padded)
    let gens = SNARKGens::new(num_cons, num_vars, num_inputs, num_nz_entries);

    // Native backend
    let (comm, decomm) = SNARK::encode(&inst, &gens);
    let mut prover_transcript = Transcript::new(b"pcs_compare_native");
    let start = Instant::now();
    let proof = SNARK::prove(
        &inst,
        &comm,
        &decomm,
        vars.clone(),
        &inputs,
        &gens,
        &mut prover_transcript,
    );
    let native_prove_ms = start.elapsed().as_millis();

    let mut verifier_transcript = Transcript::new(b"pcs_compare_native");
    let start = Instant::now();
    let native_ok = proof
        .verify(&comm, &inputs, &mut verifier_transcript, &gens)
        .is_ok();
    let native_verify_ms = start.elapsed().as_millis();

    // WHIR backend
    let whir_backend = WhirBackend::new(libspartan::backends::WhirConfig {
        folding_factor: Some(2),
        ..Default::default()
    });
    let start = Instant::now();
    let snark: WhirSnark = prove_whir_snark(&whir_backend, &inst, vars, &inputs).unwrap();
    let whir_prove_ms = start.elapsed().as_millis();

    let start = Instant::now();
    let whir_ok = verify_whir_snark(&snark).is_ok();
    let whir_verify_ms = start.elapsed().as_millis();

    println!(
        "size={size:4} native_prove_ms={native_prove_ms:4} native_verify_ms={native_verify_ms:4} whir_prove_ms={whir_prove_ms:4} whir_verify_ms={whir_verify_ms:4} native_ok={native_ok} whir_ok={whir_ok}"
    );
}

fn main() {
    // Keep sizes small to avoid long WHIR proving times in CI/sandboxed runs.
    let sizes = [4usize, 16, 64];
    for sz in sizes {
        bench_pair(sz);
    }
}
