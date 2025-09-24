use ark_ec::pairing::Pairing;
use ark_ff::FftField;
use fflonk::pcs::kzg::urs::URS;
use fflonk::pcs::kzg::KZG;
use fflonk::pcs::PCS;
use rand::Rng;

pub fn generate_for_keyset<R: Rng, OuterCurve: Pairing>(keyset_size: usize, rng: &mut R) -> URS<OuterCurve> {
    let required_domain_size = keyset_size + 1; // additional slot is occupied by affine addition accumulator initial value
    // as we use radix 2 domains
    let required_domain_size = required_domain_size.next_power_of_two();
    let log_domain_size = required_domain_size.trailing_zeros();
    generate_for_domain(log_domain_size, rng)
}

pub fn generate_for_domain<R: Rng, OuterCurve: Pairing>(log_domain_size: u32, rng: &mut R) -> URS<OuterCurve> {
    let domain_size = 2usize.pow(log_domain_size);
    // to operate with polynomials of degree up to 4 * domain_size, there should exist a domain of size 4 * domain_size
    assert!(log_domain_size + 2 <= OuterCurve::ScalarField::TWO_ADICITY, "not enough 2-adicity in in curve's scalar field");

    // the highest degree polynomial prover needs to commit is the quotient q=aggregate_constraint_polynomial/vanishing_polynomial
    // as the highest constraint degree is 4n-3, deg(q) = 3n-3
    let max_poly_degree = highest_degree_to_commit(domain_size);
    let kzg_params = KZG::<OuterCurve>::setup(max_poly_degree, rng);
    // assert!(kzg_params.fits(domain_size));
    kzg_params
}

fn highest_degree_to_commit(domain_size: usize) -> usize {
    3 * domain_size - 3
}

// impl kzg::Params<BW6_761> {
//     pub fn fits(&self, domain_size: usize) -> bool {
//         highest_degree_to_commit(domain_size) <= self.get_pk().max_degree()
//     }
// }