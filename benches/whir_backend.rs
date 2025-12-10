#![cfg(feature = "whir-backend")]

use criterion::{criterion_group, criterion_main, Criterion};
use libspartan::backends::WhirBackend;
use libspartan::backends::whir::{prove_whir_snark, verify_whir_snark, WhirSnark};
use libspartan::{Instance, InputsAssignment, VarsAssignment};
use curve25519_dalek::scalar::Scalar;

fn make_instance(size: usize) -> (Instance, VarsAssignment, InputsAssignment) {
    // Build a diagonal-ish system: for each i, x_i * x_i = x_i + 1.
    let num_cons = size;
    let num_vars = size;
    let num_inputs = 0usize;

    let mut A = Vec::with_capacity(num_cons);
    let mut B = Vec::with_capacity(num_cons);
    let mut C = Vec::with_capacity(num_cons);
    for i in 0..size {
        let one = Scalar::ONE.to_bytes();
        A.push((i, i, one));
        B.push((i, i, one));
        let rhs = Scalar::from((i as u64) + 1).to_bytes();
        C.push((i, 2, rhs)); // constant column is index num_vars (here 2 for size>=2)
    }

    // Witness: x_i = i+1, which satisfies x_i^2 = x_i + 1.
    let mut vars = Vec::with_capacity(num_vars);
    for i in 0..size {
        vars.push(Scalar::from((i as u64) + 1).to_bytes());
    }

    let inst = Instance::new(num_cons, num_vars, num_inputs, &A, &B, &C).unwrap();
    let vars_assign = VarsAssignment::new(&vars).unwrap();
    let inputs = InputsAssignment::new(&[]).unwrap();
    (inst, vars_assign, inputs)
}

fn bench_whir(c: &mut Criterion) {
    let backend = WhirBackend::default();
    let sizes = [2usize, 4usize, 8usize];
    for &sz in &sizes {
        c.bench_function(&format!("whir_prove_verify_{}", sz), |b| {
            let (inst, vars, inputs) = make_instance(sz);
            b.iter(|| {
                let snark: WhirSnark = prove_whir_snark(&backend, &inst, vars.clone(), &inputs).unwrap();
                verify_whir_snark(&snark).unwrap();
            });
        });
    }
}

criterion_group!(benches, bench_whir);
criterion_main!(benches);
