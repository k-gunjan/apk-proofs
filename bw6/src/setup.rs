use ark_ff::PrimeField;
use rand::Rng;
use w3f_pcs::pcs::{CommitterKey, PcsParams, PCS};

use crate::domain::{DomainFactory, FftDomain};

/// Generate PCS parameters for a keyset of the given size.
pub fn generate_for_keyset<R, F, S, D>(keyset_size: usize, rng: &mut R) -> S::Params
where
    R: Rng,
    F: PrimeField,
    S: PCS<F>,
    D: DomainFactory<F>,
{
    // The additional slot is occupied by the affine addition accumulator's initial value.
    generate_for_domain::<R, F, S, D>(keyset_size + 1, rng)
}

/// Generate PCS parameters sufficient for a domain of at least `min_domain_size`.
///
/// The domain, not the caller, decides the realized size: `create_domain` rounds up to the next
/// size the field supports, and the SRS is sized against that. Whether such a domain exists at
/// all is the domain implementation's business — for a radix-2 field that is a two-adicity
/// question, for BW6-767 it is a question of which divisors of `q - 1` are reachable — so the
/// failure surfaces from `create_domain` rather than from a two-adicity assertion here.
pub fn generate_for_domain<R, F, S, D>(min_domain_size: usize, rng: &mut R) -> S::Params
where
    R: Rng,
    F: PrimeField,
    S: PCS<F>,
    D: DomainFactory<F>,
{
    let domain_size = D::create_domain(min_domain_size).size();
    S::setup(highest_degree_to_commit(domain_size), rng)
}

/// The highest polynomial degree the prover needs to commit to.
///
/// That is the quotient `q = aggregate_constraint_polynomial / vanishing_polynomial`. The
/// highest constraint degree is `4n - 3`, so `deg(q) = 3n - 3`.
fn highest_degree_to_commit(domain_size: usize) -> usize {
    3 * domain_size - 3
}

/// Verify that PCS parameters are sufficient for a given domain size
pub fn params_fit<S, F>(params: &S::Params, domain_size: usize) -> bool
where
    F: PrimeField,
    S: PCS<F>,
{
    highest_degree_to_commit(domain_size) <= params.ck().max_degree()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Radix2Domain;
    use ark_bw6_761::{Fr, BW6_761};
    use ark_std::test_rng;
    use w3f_pcs::pcs::kzg::KZG;

    type TestKzg = KZG<BW6_761>;
    type TestDomain = Radix2Domain<Fr>;

    #[test]
    fn test_generate_for_domain() {
        let rng = &mut test_rng();
        let domain_size = 256;

        let params = generate_for_domain::<_, Fr, TestKzg, TestDomain>(domain_size, rng);

        assert!(params_fit::<TestKzg, Fr>(&params, domain_size));
    }

    /// The SRS must be sized against the domain the prover will actually build, not the size
    /// that was asked for.
    #[test]
    fn test_generate_for_domain_rounds_up() {
        let rng = &mut test_rng();

        let params = generate_for_domain::<_, Fr, TestKzg, TestDomain>(200, rng);

        // 200 is not a valid radix-2 size; the prover will get a domain of 256.
        assert!(params_fit::<TestKzg, Fr>(&params, 256));
    }

    #[test]
    fn test_generate_for_keyset() {
        let rng = &mut test_rng();
        let keyset_size = 100;

        let params = generate_for_keyset::<_, Fr, TestKzg, TestDomain>(keyset_size, rng);

        // keyset_size + 1 (for the accumulator), rounded up to a power of two.
        let required_domain_size = (keyset_size + 1).next_power_of_two();
        assert!(params_fit::<TestKzg, Fr>(&params, required_domain_size));
    }

    /// BW6-761's scalar field has two-adicity 46, so a domain of 2^50 does not exist. The
    /// failure now comes from the domain rather than from an assertion in this module.
    #[test]
    #[should_panic(expected = "two-adicity")]
    fn test_insufficient_adicity() {
        let rng = &mut test_rng();
        let _params = generate_for_domain::<_, Fr, TestKzg, TestDomain>(2usize.pow(50), rng);
    }
}
