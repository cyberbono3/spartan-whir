# WHIR R1CS encoding sketch

This is a starting point for wiring Spartan R1CS into WHIR. It is **not** a complete proof of soundness.

## Field assumption
- Circuits must be expressed over the Goldilocks field. The adapter now rejects Ristretto scalars that do not fit in Goldilocks instead of silently reducing modulo the field prime.
- If you need other fields, design a circuit-level encoding or change the WHIR field choice.

## Current encoder
- `ResidualEncoder` computes per-constraint residuals `(A z)_i * (B z)_i - (C z)_i` over Goldilocks and returns them as a multilinear polynomial over the constraint index hypercube.
- A `build_residual_statement` helper enforces the residual polynomial is zero at a small set of corners (all-zero, all-one, plus a few deterministic random samples) to keep constraints bounded; WHIR proving is wired to the WHIR prover using this still-weak constraint set.

## Current prover wiring
- `WhirProverContext::prove` now drives WHIR’s `CommitmentWriter`, `Prover`, and `Verifier` with the residual polynomial and the naive all-corners statement, using WHIR’s default domain separator.
- This is still not efficient or sound for large instances; it’s a baseline to swap out for a sampled-constraint system (see proposed plan below).

## Proposed constraint system (more efficient)
- Replace the fixed-corner checks with sampled evaluation constraints: derive `k` random points via the WHIR challenger and enforce `p(r_j) = 0`.
- Optionally add a random linear combination of residuals to bind the polynomial further.
- Keep `k` and `MAX_STATEMENT_VARS` bounded to control verifier cost; choose `k` using WHIR’s `queries`/`soundness_type` guidance.
Note: the encoding and constraint sampling must use the same transcript/seed on prover and verifier so constraints are consistent. Goldilocks-only inputs remain a hard requirement.

## To make it sound
1) Define the committed polynomial: should it be witness evaluations, constraint residuals, or a combination? Residuals alone + a sum-to-zero constraint are insufficient.
2) Build a WHIR `Statement` that enforces the R1CS relations with appropriate weights/challenges (e.g., random linear combination of residuals at random points).
3) Drive the WHIR prover with that statement, matching the verifier’s checks.

Upstream references: `whir::whir::mod` (arkworks) and `whir-p3` (Plonky3 port) show how to configure parameters and build statements for WHIR-specific protocols.
