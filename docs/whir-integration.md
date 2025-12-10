# WHIR integration status (experimental)

This repository includes a feature-gated WHIR backend (`whir-backend`) under `src/backends/whir`. The current code builds concrete WHIR protocol parameters (Goldilocks field, Blake3 Merkle/PoW, Reed–Solomon defaults) and converts Spartan assignments/matrices into WHIR field elements. The remaining work is:

- Implement a `WhirEncoder` that maps Spartan R1CS into a WHIR multilinear polynomial (and any associated constraints) instead of the placeholder encoders (`DefaultEncoder` errors; `NaiveZeroEncoder` produces an all-zero polynomial for experimentation only).
- Wire the PCS/sum-check proving path by invoking the WHIR prover with the encoded polynomial and constraints; `WhirProverContext::prove` is currently a stub.
- Validate the field-embedding choice: the current adapter now rejects Ristretto scalars that do not fit in Goldilocks. Circuits must be re-expressed over Goldilocks (or use an explicit encoding) to proceed.

Reference implementations:
- Upstream WHIR (arkworks-based): uses Goldilocks + Blake3 + spongefish PoW; see `whir::whir::mod`.
- `whir-p3` (Plonky3 port): shows full parameter derivation and Poseidon-based Merkle/challenger choices; see `tcoratger/whir-p3`.

Temporary hooks:
- `ResidualEncoder` computes per-constraint residuals in Goldilocks; statement wiring still defaults to a sum-to-zero check over a capped variable count.
- `NaiveZeroEncoder` can be used for plumbing tests but does **not** encode the R1CS semantics.
- `prove_r1cs_with_encoder` lets you plug a custom `WhirEncoder` for experimentation.
- You can inspect/build a `WhirProverContext` (exported from `backends::whir`) to run custom experiments once you have an encoder and a statement.
