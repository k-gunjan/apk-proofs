//! Evaluation domains and the FFT strategies behind them.
//!
//! Three layers, from the inside out:
//!
//! - [`FftDomain`] is a single multiplicative subgroup with transforms over it. [`Radix2Domain`]
//!   delegates to arkworks; [`CooleyTukeyDomain`] handles the mixed-radix sizes BW6-767 forces;
//!   [`NaiveDomain`] is the O(n^2) reference the other two are tested against.
//! - [`DomainSet`] is the *triple* the protocol actually works over, chosen together because the
//!   three sizes constrain each other. [`Radix2DomainSet`] is `n, 2n, 4n`; [`SmoothDomainSet`] is
//!   `n, 2n, 6n` over [`APK381_DOMAIN_SIZES`].
//! - Everything above the domain layer takes one `D: DomainSet` parameter and never asks which
//!   curve it is on. See [`crate::config`].
//!
//! See [`types`] for why the two configurations cannot share one domain implementation.

mod cooley_tukey;
mod naive;
mod radix2;
mod set;
mod types;

pub use cooley_tukey::{admissible_sizes, CooleyTukeyDomain};
pub use naive::{subgroup_generator, NaiveDomain};
pub use radix2::Radix2Domain;
pub(crate) use set::nesting_index;
pub use set::{DomainSet, Radix2DomainSet, SmoothDomainSet, APK381_DOMAIN_SIZES};
pub use types::{DomainError, DomainFactory, FftDomain, SupportsPackedScheme};
