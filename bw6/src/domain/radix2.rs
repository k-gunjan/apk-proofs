use ark_ff::PrimeField;
use ark_poly::{EvaluationDomain, Radix2EvaluationDomain};

use super::types::{DomainFactory, FftDomain};

/// Radix-2 domain, backed by arkworks. Used by APK-377 (BW6-761 scalar field, two-adicity 46).
///
/// This is a thin delegating wrapper: it exists so the PIOP can be written against `FftDomain`
/// without changing anything about how BLS12-377/BW6-761 proofs are actually computed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Radix2Domain<F: PrimeField>(pub Radix2EvaluationDomain<F>);

impl<F: PrimeField> Radix2Domain<F> {
    /// Panics if the field lacks the two-adicity for a domain of this size.
    /// `DomainFactory::create_domain` is the same thing; both round `size` up to a power of two.
    pub fn new(size: usize) -> Self {
        Radix2Domain(
            Radix2EvaluationDomain::<F>::new(size)
                .expect("insufficient two-adicity for a radix-2 domain of this size"),
        )
    }
}

impl<F: PrimeField> FftDomain<F> for Radix2Domain<F> {
    fn size(&self) -> usize {
        self.0.size()
    }

    fn generator(&self) -> F {
        self.0.group_gen
    }

    fn generator_inv(&self) -> F {
        self.0.group_gen_inv
    }

    fn size_inv(&self) -> F {
        self.0.size_inv
    }

    fn fft(&self, coeffs: &[F]) -> Vec<F> {
        self.0.fft(coeffs)
    }

    fn interpolate(&self, evals: &[F]) -> Vec<F> {
        self.0.ifft(evals)
    }

    // The two below have correct default implementations, but arkworks has faster ones that
    // exploit the power-of-two structure, and APK-377 should keep using those.
    fn evaluate_vanishing_polynomial(&self, x: F) -> F {
        self.0.evaluate_vanishing_polynomial(x)
    }

    fn evaluate_all_lagrange_coefficients(&self, x: F) -> Vec<F> {
        self.0.evaluate_all_lagrange_coefficients(x)
    }
}

impl<F: PrimeField> DomainFactory<F> for Radix2Domain<F> {
    fn create_domain(size: usize) -> Self {
        Self::new(size)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bw6_761::Fr;
    use ark_ff::Field;
    use ark_poly::univariate::DensePolynomial;
    use ark_poly::DenseUVPolynomial;
    use ark_std::{test_rng, One, UniformRand, Zero};

    // These tests pin the trait's semantics to arkworks' own. They are what makes it safe to
    // rewrite the PIOP against `FftDomain`: as long as they hold, routing APK-377 through the
    // trait cannot change any proof it produces.

    #[test]
    fn fft_roundtrips() {
        let rng = &mut test_rng();
        let domain = Radix2Domain::<Fr>::new(32);
        let evals: Vec<Fr> = (0..domain.size()).map(|_| Fr::rand(rng)).collect();

        let coeffs = domain.interpolate(&evals);
        assert_eq!(domain.fft(&coeffs), evals);
    }

    #[test]
    fn size_is_rounded_up_to_a_power_of_two() {
        assert_eq!(Radix2Domain::<Fr>::new(33).size(), 64);
        assert_eq!(Radix2Domain::<Fr>::new(32).size(), 32);
    }

    #[test]
    fn generator_and_size_inv_match_arkworks() {
        let domain = Radix2Domain::<Fr>::new(32);
        let ark = Radix2EvaluationDomain::<Fr>::new(32).unwrap();

        assert_eq!(domain.generator(), ark.group_gen);
        assert_eq!(domain.generator_inv(), ark.group_gen_inv);
        assert_eq!(domain.size_inv(), ark.size_inv);
        assert_eq!(domain.generator() * domain.generator_inv(), Fr::one());
        // natural ordering: element(i) == w^i
        assert_eq!(domain.element(5), ark.group_gen.pow([5u64]));
    }

    #[test]
    fn vanishing_and_lagrange_match_arkworks() {
        let rng = &mut test_rng();
        let domain = Radix2Domain::<Fr>::new(16);
        let ark = Radix2EvaluationDomain::<Fr>::new(16).unwrap();
        let z = Fr::rand(rng);

        assert_eq!(
            domain.evaluate_vanishing_polynomial(z),
            ark.evaluate_vanishing_polynomial(z)
        );
        assert_eq!(
            domain.evaluate_all_lagrange_coefficients(z),
            ark.evaluate_all_lagrange_coefficients(z)
        );
    }

    /// The overridden `evaluate_vanishing_polynomial` must agree with the generic default;
    /// APK-381 will rely on the default, so a divergence here would be a silent fork.
    #[test]
    fn overrides_agree_with_generic_defaults() {
        let rng = &mut test_rng();
        let domain = Radix2Domain::<Fr>::new(16);
        let z = Fr::rand(rng);

        let generic_vanishing = z.pow([domain.size() as u64]) - Fr::one();
        assert_eq!(domain.evaluate_vanishing_polynomial(z), generic_vanishing);

        // Reproduce the trait default for the Lagrange coefficients.
        let n = domain.size();
        let scaled = generic_vanishing * domain.size_inv();
        let mut denoms: Vec<Fr> = (0..n).map(|i| z - domain.element(i)).collect();
        ark_ff::batch_inversion(&mut denoms);
        let generic: Vec<Fr> = denoms
            .iter()
            .enumerate()
            .map(|(i, d)| scaled * d * domain.element(i))
            .collect();
        assert_eq!(domain.evaluate_all_lagrange_coefficients(z), generic);
    }

    #[test]
    fn divide_by_vanishing_poly_is_exact_for_multiples() {
        let rng = &mut test_rng();
        let domain = Radix2Domain::<Fr>::new(8);

        // Build q * Z_H so the division must come out with zero remainder.
        let q = DensePolynomial::from_coefficients_vec((0..5).map(|_| Fr::rand(rng)).collect());
        let mut z_h = vec![Fr::zero(); domain.size() + 1];
        z_h[0] = -Fr::one();
        z_h[domain.size()] = Fr::one();
        let product = &q * &DensePolynomial::from_coefficients_vec(z_h);

        let (quotient, remainder) = domain.divide_by_vanishing_poly(&product);
        assert_eq!(remainder, DensePolynomial::zero());
        assert_eq!(quotient, q);
    }
}
