//! Evaluation domains and the FFT strategies behind them.
//!
//! The APK protocol itself is written against [`FftDomain`]; each curve configuration supplies a
//! concrete implementation. See [`types`] for why the two configurations cannot share one.

mod radix2;
mod types;

pub use radix2::Radix2Domain;
pub use types::{DomainFactory, FftDomain};
