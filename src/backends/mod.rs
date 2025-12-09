//! Abstractions and configuration for swapping Spartan's polynomial backend.
//!
//! The goal is to let consumers opt into an alternative prover stack (e.g. WHIR)
//! without disturbing the default implementation. The types in this module are
//! intentionally minimal and feature-gated so the existing code paths remain
//! unchanged until a full adapter is wired in.

use core::fmt;

/// Selects which backend should power Spartan's proof generation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BackendFlavor {
  /// Use Spartan's built-in PCS and sum-check implementation.
  Native,
  #[cfg(feature = "whir-backend")]
  /// Use the WHIR PCS/sum-check backend (feature-gated).
  Whir,
}

/// Shared configuration knobs for pluggable backends.
#[derive(Clone, Copy, Debug, Default)]
pub struct BackendConfig {
  /// Backend choice; defaults to `Native`.
  pub flavor: BackendFlavor,
  /// Security level in bits where applicable.
  pub security_bits: Option<u32>,
  /// Folding factor or similar batching knob.
  pub folding_factor: Option<usize>,
  /// Proof-of-work difficulty for the query phase (if supported).
  pub pow_bits: Option<u32>,
}

impl BackendConfig {
  /// A configuration that keeps Spartan's existing prover.
  pub const fn native() -> Self {
    Self {
      flavor: BackendFlavor::Native,
      security_bits: None,
      folding_factor: None,
      pow_bits: None,
    }
  }
}

/// Errors surfaced by backend adapters.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BackendError {
  /// The requested backend is not compiled in.
  FeatureNotEnabled(&'static str),
  /// The backend is known but the adapter is not wired yet.
  NotImplemented(&'static str),
  /// The backend cannot operate over the current field or instance shape.
  Unsupported(&'static str),
}

impl fmt::Display for BackendError {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    match self {
      BackendError::FeatureNotEnabled(reason) => {
        write!(f, "backend unavailable: {reason}")
      }
      BackendError::NotImplemented(reason) => {
        write!(f, "backend not implemented: {reason}")
      }
      BackendError::Unsupported(reason) => {
        write!(f, "backend unsupported for this instance: {reason}")
      }
    }
  }
}

#[cfg(feature = "std")]
impl std::error::Error for BackendError {}

/// Minimal interface each backend should satisfy to plug into Spartan.
pub trait ProofBackend {
  /// Identify the backend being used.
  fn flavor(&self) -> BackendFlavor;

  /// Lightweight readiness check before attempting to prove or verify.
  fn availability(&self) -> Result<(), BackendError>;
}

/// Marker type for the existing Spartan implementation.
#[derive(Clone, Copy, Debug, Default)]
pub struct NativeBackend;

impl ProofBackend for NativeBackend {
  fn flavor(&self) -> BackendFlavor {
    BackendFlavor::Native
  }

  fn availability(&self) -> Result<(), BackendError> {
    Ok(())
  }
}

#[cfg(feature = "whir-backend")]
/// WHIR-specific configuration mirroring the crate's CLI parameters.
#[derive(Clone, Debug)]
pub struct WhirConfig {
  /// Overall security parameter in bits.
  pub security_level: u32,
  /// Query-phase proof-of-work difficulty.
  pub pow_bits: Option<u32>,
  /// Number of variables in the WHIR instance (if overriding R1CS sizing).
  pub num_variables: Option<u32>,
  /// Number of evaluations to prove (PCS mode).
  pub num_evaluations: Option<u32>,
  /// Log inverse of the code rate.
  pub rate_log_inv: Option<u32>,
  /// Number of variables folded each iteration.
  pub folding_factor: Option<u32>,
  /// Verifier repetitions.
  pub repetitions: Option<u32>,
  /// Soundness variant to use.
  pub soundness: Option<&'static str>,
  /// Folding optimisation choice.
  pub fold_type: Option<&'static str>,
  /// Field selection (e.g., `Goldilocks2`).
  pub field: Option<&'static str>,
  /// Hash used for Merkle commitments.
  pub hash: Option<&'static str>,
}

#[cfg(feature = "whir-backend")]
impl Default for WhirConfig {
  fn default() -> Self {
    Self {
      security_level: 100,
      pow_bits: None,
      num_variables: None,
      num_evaluations: Some(1),
      rate_log_inv: Some(1),
      folding_factor: Some(4),
      repetitions: Some(1000),
      soundness: Some("ConjectureList"),
      fold_type: Some("ProverHelps"),
      field: Some("Goldilocks2"),
      hash: Some("Blake3"),
    }
  }
}

#[cfg(feature = "whir-backend")]
/// Placeholder adapter for the WHIR backend.
#[derive(Clone, Debug)]
pub struct WhirBackend {
  config: WhirConfig,
}

#[cfg(feature = "whir-backend")]
impl Default for WhirBackend {
  fn default() -> Self {
    Self::new(WhirConfig::default())
  }
}

#[cfg(feature = "whir-backend")]
impl WhirBackend {
  /// Create a WHIR backend with the provided configuration.
  pub const fn new(config: WhirConfig) -> Self {
    Self { config }
  }

  /// Returns a reference to the configured parameters.
  pub const fn config(&self) -> &WhirConfig {
    &self.config
  }
}

#[cfg(feature = "whir-backend")]
impl ProofBackend for WhirBackend {
  fn flavor(&self) -> BackendFlavor {
    BackendFlavor::Whir
  }

  fn availability(&self) -> Result<(), BackendError> {
    Ok(())
  }
}

/// WHIR integration helpers and adapters (feature gated).
#[cfg(feature = "whir-backend")]
pub mod whir;
