//! Evaluation domains and the FFT strategies behind them.
//!
//! The APK protocol itself is written against [`FftDomain`]; each curve configuration supplies a
//! concrete implementation. See [`types`] for why the two configurations cannot share one.

mod cooley_tukey;
mod naive;
mod radix2;
mod types;

pub use cooley_tukey::{admissible_sizes, CooleyTukeyDomain};
pub use naive::{subgroup_generator, NaiveDomain};
pub use radix2::Radix2Domain;
pub use types::{DomainError, DomainFactory, FftDomain, SupportsPackedScheme};
