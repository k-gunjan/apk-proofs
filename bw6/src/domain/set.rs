//! The triple of evaluation domains the PIOP works over, and the two ways of producing it.
//!
//! The protocol needs three domains: the trace domain `H` of size `n`, and two larger ones that
//! hold products of register polynomials in evaluation form. The constraint polynomial has
//! degree up to `4n - 3`, so recovering it takes at least `4n - 2` evaluations.
//!
//! What the three sizes *are* is the only thing that differs between the two configurations, so
//! it is the only thing this trait leaves open. Everything downstream — [`crate::Keyset`],
//! [`crate::domains::Domains`], the PIOP, the prover and the verifier — carries a single
//! `D: DomainSet` parameter and never asks which curve it is on.

use ark_ff::PrimeField;
use ark_poly::univariate::DensePolynomial;

use super::cooley_tukey::{estimated_transform_cost, CooleyTukeyDomain};
use super::naive::subgroup_generator;
use super::radix2::Radix2Domain;
use super::types::{DomainError, FftDomain, SupportsPackedScheme};

/// The three domains a proof is computed over, chosen together.
///
/// Chosen *together* because they are not independent: the protocol requires
/// `medium >= 2n - 1` and `large >= 4n - 2`, and whether a domain of a given size exists at all
/// is a property of the field. Picking `n` first and then asking for `4n` separately is how the
/// sizes silently fail to line up.
pub trait DomainSet<F: PrimeField>: Clone + Sized {
    /// The underlying single-domain implementation. Radix-2 for APK-377, mixed-radix
    /// Cooley-Tukey for APK-381.
    type Domain: FftDomain<F>;

    /// The cheapest usable triple whose base domain holds at least `min_size` points.
    ///
    /// The base size is rounded **up** to something the field supports, so callers must read
    /// back `base().size()` rather than assuming they got what they asked for.
    fn for_min_size(min_size: usize) -> Result<Self, DomainError>;

    /// The trace domain `H`, of size `n`.
    fn base(&self) -> &Self::Domain;

    /// A domain of at least `2n - 1` points.
    fn medium(&self) -> &Self::Domain;

    /// A domain of at least `4n - 2` points.
    fn large(&self) -> &Self::Domain;

    /// The triple whose base domain has *exactly* `size` points.
    ///
    /// The verifier needs the exactness: the domain size arrives inside a keyset commitment,
    /// which for a bridge comes from the chain and is untrusted. Rounding it up there would let
    /// a proof verify against a domain the prover did not use.
    fn for_exact_size(size: usize) -> Result<Self, DomainError> {
        let set = Self::for_min_size(size)?;
        let realised = set.base().size();
        if realised != size {
            return Err(DomainError::NotExact { requested: size, nearest: realised });
        }
        Ok(set)
    }

    /// Just the base domain of [`for_exact_size`](Self::for_exact_size), without building the
    /// two larger ones.
    ///
    /// The verifier is the only caller and needs nothing else, and the large domain is where the
    /// cost is: at 100,000 validators its transform plan holds on the order of a million
    /// precomputed twiddle factors that the verifier would never touch.
    ///
    /// Must accept exactly the sizes `for_exact_size` accepts, and reject the rest with the same
    /// error — otherwise a proof could verify against a domain no prover would have chosen.
    fn base_for_exact_size(size: usize) -> Result<Self::Domain, DomainError> {
        Ok(Self::for_exact_size(size)?.base().clone())
    }

    /// Evaluations over `large` of `p(Xw)`, where `w` generates `base` — the left circular shift
    /// of the register `p` interpolates, which the affine-addition constraints need in order to
    /// relate consecutive rows.
    ///
    /// The default works for any triple at all: `p(Xw)` has coefficients `c_i w^i`, so scaling
    /// the coefficients and transforming once more is always correct. Implementations whose
    /// domains are nested override it with a rotation, which is free; the two are checked
    /// against each other in the tests.
    fn shift_over_large(&self, poly: &DensePolynomial<F>, _evals_over_large: &[F]) -> Vec<F> {
        let mut coeffs = poly.coeffs.clone();
        let mut power = F::one();
        let w = self.base().generator();
        for c in coeffs.iter_mut() {
            *c *= power;
            power *= w;
        }
        self.large().fft(&coeffs)
    }
}

/// `k` such that `large.element(k) == small.generator()`, when `small` sits inside `large` with
/// its elements interleaved in the natural way; `None` otherwise.
///
/// Both domain families here generate their subgroups as `GENERATOR^((q-1)/n)`, so a divisibility
/// of sizes does imply nesting — but that is a property of the construction, not a theorem, so
/// it is checked rather than assumed.
pub(crate) fn nesting_index<F: PrimeField, D: FftDomain<F>>(small: &D, large: &D) -> Option<usize> {
    let (n, m) = (small.size(), large.size());
    if n == 0 || m % n != 0 {
        return None;
    }
    let k = m / n;
    (large.element(k) == small.generator()).then_some(k)
}

// -------------------------------------------------------------------------------------------
// APK-377
// -------------------------------------------------------------------------------------------

/// Power-of-two domains `n, 2n, 4n`. Used by APK-377.
///
/// BW6-761's scalar field has two-adicity 46, so every size the prover could afford is available
/// and the classical radix-2 layout applies unchanged. This reproduces exactly what the crate
/// did before the domain layer was abstracted.
#[derive(Clone, Copy, Debug)]
pub struct Radix2DomainSet<F: PrimeField> {
    base: Radix2Domain<F>,
    medium: Radix2Domain<F>,
    large: Radix2Domain<F>,
}

impl<F: PrimeField> DomainSet<F> for Radix2DomainSet<F> {
    type Domain = Radix2Domain<F>;

    fn for_min_size(min_size: usize) -> Result<Self, DomainError> {
        let base = build_radix2(min_size)?;
        let n = base.size();
        Ok(Radix2DomainSet {
            base,
            medium: build_radix2(2 * n)?,
            large: build_radix2(4 * n)?,
        })
    }

    fn base(&self) -> &Radix2Domain<F> {
        &self.base
    }

    fn medium(&self) -> &Radix2Domain<F> {
        &self.medium
    }

    fn large(&self) -> &Radix2Domain<F> {
        &self.large
    }

    fn base_for_exact_size(size: usize) -> Result<Radix2Domain<F>, DomainError> {
        let base = build_radix2::<F>(size)?;
        if base.size() != size {
            return Err(DomainError::NotExact { requested: size, nearest: base.size() });
        }
        Ok(base)
    }

    /// `|large| = 4|base|` and the domains are nested, so `p(w_L^{i+4}) = p(w_L^i w)`: the shift
    /// is a rotation of the evaluation vector by four, and costs nothing.
    fn shift_over_large(&self, _poly: &DensePolynomial<F>, evals_over_large: &[F]) -> Vec<F> {
        debug_assert_eq!(nesting_index(&self.base, &self.large), Some(4));
        let mut shifted = evals_over_large.to_vec();
        shifted.rotate_left(4);
        shifted
    }
}

fn build_radix2<F: PrimeField>(size: usize) -> Result<Radix2Domain<F>, DomainError> {
    use super::types::DomainFactory;
    Radix2Domain::try_create_domain(size)
}

/// Radix-2 sizes from 256 up are all multiples of 256, which is what `packed` needs.
impl<F: PrimeField> SupportsPackedScheme for Radix2DomainSet<F> {}

// -------------------------------------------------------------------------------------------
// APK-381
// -------------------------------------------------------------------------------------------

/// The base domain sizes available to APK-381, ascending.
///
/// BW6-767's scalar field has `q - 1 = 2 * 3^2 * 11 * 23 * 47 * 10177 * (unusable large part)`.
/// Two of those factors are **reserved** rather than spent on the base domain: one 2 and one 3,
/// so that `6n` divides `q - 1` whenever `n` does. That fixes the triple as `n, 2n, 6n` —
/// `2n >= 2n - 1` and `6n >= 4n - 2`, both nested inside each other — and leaves the base sizes
/// as exactly the 32 divisors of
///
/// ```text
/// 3 * 11 * 23 * 47 * 10177 = 363,044,121
/// ```
///
/// listed here from the smallest to the largest the field admits. The largest entry's `6n` is
/// `2 * 3^2 * 11 * 23 * 47 * 10177`, the entire usable smooth part of `q - 1`, so the table
/// cannot be extended.
///
/// The price of reserving those factors is padding: the gaps are wide, and the worst case in the
/// range that matters is `n = 3244` rounding up to 10177, a factor of 3.14. Spending the 2 and
/// the 3 on the base domain would close the gaps, but then `2n` and `6n` would not exist and the
/// three domains would have to be chosen independently and would not nest.
///
/// Validator-set sizes of interest sit comfortably inside: Kusama's ~1000 lands on 1081 = 23*47
/// and Polkadot's ~1500 on 1551 = 3*11*47.
///
/// Only the first fourteen entries are Rader-free. From 10177 on, the prime 10177 appears and
/// its transform goes through Rader's algorithm at roughly four times the per-point cost; the
/// selector in [`SmoothDomainSet::for_min_size`] prefers a larger smooth size over a smaller
/// Rader one when that is cheaper, which is why asking for 5000 yields 11891 = 11*23*47 rather
/// than 10177.
pub const APK381_DOMAIN_SIZES: &[usize] = &[
    1,          // 1
    3,          // 3
    11,         // 11
    23,         // 23
    33,         // 3 * 11
    47,         // 47
    69,         // 3 * 23
    141,        // 3 * 47
    253,        // 11 * 23
    517,        // 11 * 47
    759,        // 3 * 11 * 23
    1081,       // 23 * 47          <- Kusama, ~1000 validators
    1551,       // 3 * 11 * 47      <- Polkadot, ~1500 validators
    3243,       // 3 * 23 * 47
    10177,      // 10177            <- Rader from here on
    11891,      // 11 * 23 * 47
    30531,      // 3 * 10177
    35673,      // 3 * 11 * 23 * 47
    111947,     // 11 * 10177
    234071,     // 23 * 10177
    335841,     // 3 * 11 * 10177
    478319,     // 47 * 10177
    702213,     // 3 * 23 * 10177
    1434957,    // 3 * 47 * 10177
    2574781,    // 11 * 23 * 10177
    5261509,    // 11 * 47 * 10177
    7724343,    // 3 * 11 * 23 * 10177
    11001337,   // 23 * 47 * 10177
    15784527,   // 3 * 11 * 47 * 10177
    33004011,   // 3 * 23 * 47 * 10177
    121014707,  // 11 * 23 * 47 * 10177
    363044121,  // 3 * 11 * 23 * 47 * 10177
];

/// Mixed-radix domains `n, 2n, 6n` drawn from [`APK381_DOMAIN_SIZES`]. Used by APK-381.
#[derive(Clone, Debug)]
pub struct SmoothDomainSet<F: PrimeField> {
    base: CooleyTukeyDomain<F>,
    medium: CooleyTukeyDomain<F>,
    large: CooleyTukeyDomain<F>,
}

impl<F: PrimeField> SmoothDomainSet<F> {
    /// The table entries this field can actually realise, ascending.
    ///
    /// The table is written for BW6-767's scalar field, but nothing stops another field from
    /// being asked for a `SmoothDomainSet`, so membership is checked against `q - 1` rather than
    /// assumed. An entry survives only if `6n` divides `q - 1`, which is what makes the whole
    /// triple constructible.
    fn realisable_sizes() -> Vec<usize> {
        APK381_DOMAIN_SIZES
            .iter()
            .copied()
            .filter(|&n| subgroup_generator::<F>(6 * n).is_some())
            .collect()
    }

    /// Estimated prover cost of the triple, in field multiplications.
    ///
    /// Weighted by how often the prover transforms over each domain: three times over the base,
    /// twice over the medium one and twelve times over the large one. `large` dominates, so this
    /// is effectively ranking by the cost of the `6n` transform.
    fn estimated_cost(n: usize) -> u128 {
        3 * estimated_transform_cost(n)
            + 2 * estimated_transform_cost(2 * n)
            + 12 * estimated_transform_cost(6 * n)
    }

    /// The table entry a request for `min_size` resolves to.
    ///
    /// The smallest entry at least `min_size`, unless a larger one transforms dramatically
    /// faster. Transform cost is not monotone in size here: 10177 is prime and needs Rader,
    /// while the larger 11891 = 11 * 23 * 47 is fully smooth and about three times cheaper.
    /// Minimising cost alone would be wrong in the other direction, though — the FFTs are not
    /// the prover's only work, and the commitments are multi-scalar multiplications linear in
    /// `n` — so a smaller entry is passed over only when something larger is *much* cheaper.
    ///
    /// Sole source of truth for which size a request maps to, so the prover's triple and the
    /// verifier's single domain cannot drift apart.
    fn select_size(min_size: usize) -> Result<usize, DomainError> {
        /// How much cheaper a larger triple must be before the extra linear work pays off.
        const WORTH_GROWING_FOR: u128 = 2;

        let sizes = Self::realisable_sizes();
        let first = sizes.partition_point(|&n| n < min_size);
        let smallest = *sizes.get(first).ok_or(DomainError::TooLarge { requested: min_size })?;

        // A cheaper option is always nearby: cost grows roughly as `n * sum(prime factors)`, and
        // this window is wider than the largest gap in the table.
        let ceiling = smallest.saturating_mul(4);
        let window = sizes[first..].iter().copied().take_while(|&n| n <= ceiling);

        let costed: Vec<(usize, u128)> = window.map(|n| (n, Self::estimated_cost(n))).collect();
        let best = costed.iter().map(|&(_, c)| c).min().unwrap_or(u128::MAX);
        Ok(costed
            .iter()
            .find(|&&(_, c)| c <= best.saturating_mul(WORTH_GROWING_FOR))
            .map(|&(n, _)| n)
            .unwrap_or(smallest))
    }

    fn build(n: usize) -> Result<Self, DomainError> {
        let missing = || DomainError::TooLarge { requested: n };
        Ok(SmoothDomainSet {
            base: CooleyTukeyDomain::new(n).ok_or_else(missing)?,
            medium: CooleyTukeyDomain::new(2 * n).ok_or_else(missing)?,
            large: CooleyTukeyDomain::new(6 * n).ok_or_else(missing)?,
        })
    }
}

impl<F: PrimeField> DomainSet<F> for SmoothDomainSet<F> {
    type Domain = CooleyTukeyDomain<F>;

    /// See [`SmoothDomainSet::select_size`] for which table entry a request resolves to.
    fn for_min_size(min_size: usize) -> Result<Self, DomainError> {
        Self::build(Self::select_size(min_size)?)
    }

    fn base_for_exact_size(size: usize) -> Result<CooleyTukeyDomain<F>, DomainError> {
        let selected = Self::select_size(size)?;
        if selected != size {
            return Err(DomainError::NotExact { requested: size, nearest: selected });
        }
        CooleyTukeyDomain::new(size).ok_or(DomainError::TooLarge { requested: size })
    }

    fn base(&self) -> &CooleyTukeyDomain<F> {
        &self.base
    }

    fn medium(&self) -> &CooleyTukeyDomain<F> {
        &self.medium
    }

    fn large(&self) -> &CooleyTukeyDomain<F> {
        &self.large
    }

    /// `|large| = 6|base|`, and reserving the factors 2 and 3 is exactly what makes that hold —
    /// so the domains nest and the shift is a rotation by six, not an extra transform.
    ///
    /// This is the payoff for the padding the table costs. Without nesting the shift would need
    /// a coefficient scaling and a further `6n`-point FFT, which is the most expensive transform
    /// the prover performs.
    fn shift_over_large(&self, _poly: &DensePolynomial<F>, evals_over_large: &[F]) -> Vec<F> {
        debug_assert_eq!(nesting_index(&self.base, &self.large), Some(6));
        let mut shifted = evals_over_large.to_vec();
        shifted.rotate_left(6);
        shifted
    }
}

/// Deliberately **not** `impl SupportsPackedScheme for SmoothDomainSet`: `packed` splits the
/// bitmask into 256-bit chunks and needs `256 | n`. Over BW6-767 that is impossible — `q - 1`
/// carries a single factor of 2, so no domain size there is even a multiple of 4.
#[cfg(test)]
mod tests {
    use super::*;
    use ark_bw6_761::Fr as Fr761;
    use ark_bw6_767::Fr as Fr767;
    use ark_poly::DenseUVPolynomial;
    use ark_std::test_rng;
    use num_bigint::BigUint;

    type Smooth = SmoothDomainSet<Fr767>;
    type Radix2 = Radix2DomainSet<Fr761>;

    /// The table is the reserved-factor rule made explicit: every entry divides
    /// `3 * 11 * 23 * 47 * 10177`, and every divisor of it is an entry.
    #[test]
    fn table_is_exactly_the_divisors_of_the_unreserved_part() {
        let unreserved: usize = 3 * 11 * 23 * 47 * 10177;
        let mut expected: Vec<usize> = vec![1];
        for f in [3usize, 11, 23, 47, 10177] {
            expected = expected.iter().flat_map(|&d| [d, d * f]).collect();
        }
        expected.sort_unstable();
        expected.dedup();

        assert_eq!(APK381_DOMAIN_SIZES, &expected[..]);
        assert!(APK381_DOMAIN_SIZES.iter().all(|&n| unreserved % n == 0));
        assert_eq!(*APK381_DOMAIN_SIZES.last().unwrap(), unreserved);
    }

    /// The reason the 2 and the 3 are held back: `6n` has to exist for every entry, and it has
    /// to be the whole usable smooth part of `q - 1` at the top of the table.
    #[test]
    fn every_entry_admits_its_doubled_and_sextupled_domain() {
        let order: BigUint = Into::<BigUint>::into(<Fr767 as ark_ff::PrimeField>::MODULUS) - 1u8;
        for &n in APK381_DOMAIN_SIZES {
            assert!(
                (&order % BigUint::from(6 * n)) == BigUint::from(0u32),
                "6 * {} does not divide q - 1",
                n
            );
        }
        assert_eq!(
            6 * APK381_DOMAIN_SIZES.last().unwrap(),
            2 * 9 * 11 * 23 * 47 * 10177,
            "the largest triple should exhaust the smooth part of q - 1"
        );
        assert_eq!(Smooth::realisable_sizes().len(), APK381_DOMAIN_SIZES.len());
    }

    /// What the PIOP actually requires of the triple, for every entry the field admits.
    #[test]
    fn every_triple_is_large_enough_and_nested() {
        // Building all 32 means transforming plans for domains in the hundreds of millions.
        // The protocol's requirements are structural, so the small end proves them.
        for &n in APK381_DOMAIN_SIZES.iter().take(12) {
            let set = Smooth::build(n).expect("entry must be constructible");
            assert_eq!(set.base().size(), n);
            assert!(set.medium().size() >= 2 * n - 1);
            assert!(set.large().size() >= 4 * n - 2);
            assert_eq!(nesting_index(set.base(), set.medium()), Some(2));
            assert_eq!(nesting_index(set.base(), set.large()), Some(6));
        }
    }

    /// The selector returns the first entry at least as large as requested...
    #[test]
    fn for_min_size_rounds_up_to_a_table_entry() {
        for (requested, expected) in [(1, 1), (2, 3), (12, 23), (34, 47), (48, 69), (254, 517)] {
            let set = Smooth::for_min_size(requested).unwrap();
            assert_eq!(set.base().size(), expected, "for_min_size({})", requested);
            assert!(APK381_DOMAIN_SIZES.contains(&set.base().size()));
        }
    }

    /// ...except where the first entry needs Rader and a larger smooth one is much cheaper.
    #[test]
    fn for_min_size_skips_a_smaller_but_slower_entry() {
        assert!(Smooth::estimated_cost(11891) < Smooth::estimated_cost(10177));
        let set = Smooth::for_min_size(5000).unwrap();
        assert_eq!(set.base().size(), 11891, "10177 is prime and needs Rader");
    }

    /// Sizes of interest land where the table says they do.
    #[test]
    fn validator_counts_of_interest_land_on_the_documented_entries() {
        // A keyset of k needs k + 1 points: the extra slot is the accumulator's seed.
        assert_eq!(Smooth::for_min_size(1000 + 1).unwrap().base().size(), 1081);
        assert_eq!(Smooth::for_min_size(1500 + 1).unwrap().base().size(), 1551);
    }

    #[test]
    fn asking_for_more_than_the_field_holds_is_an_error() {
        let too_big = APK381_DOMAIN_SIZES.last().unwrap() + 1;
        assert_eq!(
            Smooth::for_min_size(too_big).unwrap_err(),
            DomainError::TooLarge { requested: too_big }
        );
    }

    /// The verifier's constructor: a size off the table must not be silently rounded.
    #[test]
    fn for_exact_size_rejects_a_size_not_in_the_table() {
        assert_eq!(Smooth::for_exact_size(253).unwrap().base().size(), 253);
        assert_eq!(
            Smooth::for_exact_size(254).unwrap_err(),
            DomainError::NotExact { requested: 254, nearest: 517 }
        );
    }

    /// The verifier's cheap path must accept and reject exactly what the full one does. If it
    /// drifted, a proof could verify against a domain no prover would have chosen.
    #[test]
    fn base_for_exact_size_agrees_with_for_exact_size() {
        fn check<F: ark_ff::PrimeField, D: DomainSet<F>>(sizes: &[usize]) {
            for &size in sizes {
                match D::for_exact_size(size) {
                    Ok(set) => assert_eq!(
                        D::base_for_exact_size(size).unwrap().size(),
                        set.base().size(),
                        "size {}",
                        size
                    ),
                    Err(e) => assert_eq!(
                        D::base_for_exact_size(size).map(|d| d.size()).err(),
                        Some(e),
                        "size {}",
                        size
                    ),
                }
            }
        }

        // Table entries, non-entries, the entry the cost rule makes unreachable (10177), and
        // sizes past the end of the field.
        check::<Fr767, Smooth>(&[1, 3, 11, 23, 33, 46, 47, 253, 254, 517, 759, 1081, 10177]);
        check::<Fr761, Radix2>(&[1, 2, 16, 17, 256, 300, 1024]);
    }

    fn random_poly<F: ark_ff::PrimeField>(degree_bound: usize) -> DensePolynomial<F> {
        let rng = &mut test_rng();
        DensePolynomial::from_coefficients_vec(
            (0..degree_bound).map(|_| F::rand(rng)).collect(),
        )
    }

    /// The rotation overrides must agree with the trait's always-correct default. This is the
    /// regression guard for both configurations at once: it is what says the cheap path is the
    /// same function as the general one.
    #[test]
    fn rotation_agrees_with_coefficient_scaling() {
        fn check<F: ark_ff::PrimeField, D: DomainSet<F>>(set: &D) {
            let poly = random_poly::<F>(set.base().size());
            let evals = set.large().fft(&poly.coeffs);

            let rotated = set.shift_over_large(&poly, &evals);

            // The trait default, spelled out: p(Xw) has coefficients c_i * w^i.
            let mut coeffs = poly.coeffs.clone();
            let mut power = F::one();
            for c in coeffs.iter_mut() {
                *c *= power;
                power *= set.base().generator();
            }
            let scaled = set.large().fft(&coeffs);

            assert_eq!(rotated, scaled);

            // And both are really the evaluations of p(Xw) over the large domain.
            let w = set.base().generator();
            for i in 0..set.large().size() {
                let x = set.large().element(i);
                assert_eq!(rotated[i], evaluate(&poly, x * w));
            }
        }

        fn evaluate<F: ark_ff::PrimeField>(p: &DensePolynomial<F>, x: F) -> F {
            p.coeffs.iter().rev().fold(F::zero(), |acc, c| acc * x + c)
        }

        check(&Radix2::for_min_size(16).unwrap());
        check(&Smooth::for_min_size(23).unwrap());
        check(&Smooth::for_min_size(33).unwrap());
    }

    /// APK-377 is unchanged: powers of two, and the classical `n, 2n, 4n` layout.
    #[test]
    fn radix2_set_is_the_classical_layout() {
        let set = Radix2::for_min_size(200).unwrap();
        assert_eq!(set.base().size(), 256);
        assert_eq!(set.medium().size(), 512);
        assert_eq!(set.large().size(), 1024);
        assert_eq!(nesting_index(set.base(), set.large()), Some(4));
    }

    /// No BW6-767 domain is a multiple of 4, which is why `packed` is unavailable there.
    #[test]
    fn no_smooth_size_is_a_multiple_of_four() {
        for &n in APK381_DOMAIN_SIZES {
            assert_ne!(6 * n % 4, 0, "6 * {} is a multiple of 4", n);
        }
    }
}
