use ark_poly::{Evaluations, Radix2EvaluationDomain};
use ark_poly::polynomial::univariate::DensePolynomial;
use ark_ff::{One, Zero};
use ark_bw6_761::Fr;
use ark_bls12_377::G1Affine;

use crate::domains::Domains;
use crate::Bitmask;

/// Register polynomials in evaluation form amplified to support degree 4n constraints
pub(crate) struct Registers<'a> {
    domains: &'a Domains,
    bitmask: Evaluations<Fr, Radix2EvaluationDomain<Fr>>,
    // public keys' coordinates
    pks_x: Evaluations<Fr, Radix2EvaluationDomain<Fr>>,
    pks_y: Evaluations<Fr, Radix2EvaluationDomain<Fr>>,
    // aggregate public key rolling sum coordinates
    apk_acc_x: Evaluations<Fr, Radix2EvaluationDomain<Fr>>,
    apk_acc_y: Evaluations<Fr, Radix2EvaluationDomain<Fr>>,
    // TODO: not really registers
    apk_acc_x_shifted: Evaluations<Fr, Radix2EvaluationDomain<Fr>>,
    apk_acc_y_shifted: Evaluations<Fr, Radix2EvaluationDomain<Fr>>,
}

impl<'a> Registers<'a> {
    pub fn new(domains: &'a Domains,
               bitmask: &Bitmask,
               pks: Vec<G1Affine>,
               apk_acc: (Vec<Fr>, Vec<Fr>),
    ) -> Self {
        let mut bitmask = bitmask.to_bits_as_field_elements();
        bitmask.resize(domains.size, Fr::zero());

        let pks = pks.iter()
            .map(|p| (p.x, p.y))
            .unzip();

        let mut apk_acc_x_shifted = apk_acc.0.clone();
        let mut apk_acc_y_shifted = apk_acc.1.clone();
        apk_acc_x_shifted.rotate_left(1);
        apk_acc_y_shifted.rotate_left(1);

        Self::new_unchecked(
            domains,
            bitmask,
            pks,
            apk_acc,
            (apk_acc_x_shifted, apk_acc_y_shifted),
        )
    }

    fn new_unchecked(domains: &'a Domains,
                     bitmask: Vec<Fr>,
                     pks: (Vec<Fr>, Vec<Fr>),
                     apk_acc: (Vec<Fr>, Vec<Fr>),
                     apk_acc_shifted: (Vec<Fr>, Vec<Fr>),
    ) -> Self {
        Self {
            domains,
            bitmask: domains.amplify(bitmask),
            pks_x: domains.amplify(pks.0),
            pks_y: domains.amplify(pks.1),
            apk_acc_x: domains.amplify(apk_acc.0),
            apk_acc_y: domains.amplify(apk_acc.1),
            apk_acc_x_shifted: domains.amplify(apk_acc_shifted.0),
            apk_acc_y_shifted: domains.amplify(apk_acc_shifted.1),
        }
    }
}

pub(crate) struct Constraints {}

impl Constraints {
    pub fn compute_bitmask_booleanity_constraint_polynomial(registers: &Registers) -> DensePolynomial<Fr> {
        let b = &registers.bitmask;
        let mut one_minus_b = registers.domains.constant_4x(Fr::one());
        one_minus_b -= b;
        (b * &one_minus_b).interpolate()
    }

    pub fn evaluate_bitmask_booleanity_constraint(bitmask_at_zeta: Fr) -> Fr {
        bitmask_at_zeta * (Fr::one() - bitmask_at_zeta)
    }

    pub fn compute_conditional_affine_addition_constraint_polynomials(registers: &Registers) ->
    (DensePolynomial<Fr>, DensePolynomial<Fr>) {
        let b = &registers.bitmask;
        let mut one_minus_b = registers.domains.constant_4x(Fr::one());
        one_minus_b -= b;

        let x1 = &registers.apk_acc_x;
        let y1 = &registers.apk_acc_y;
        let x2 = &registers.pks_x;
        let y2 = &registers.pks_y;
        let x3 = &registers.apk_acc_x_shifted;
        let y3 = &registers.apk_acc_y_shifted;

        let c1 =
            &(
                b *
                    &(
                        &(
                            &(
                                &(x1 - x2) * &(x1 - x2)
                            ) *
                                &(
                                    &(x1 + x2) + x3
                                )
                        ) -
                            &(
                                &(y2 - y1) * &(y2 - y1)
                            )
                    )
            ) +
                &(
                    &one_minus_b * &(y3 - y1)
                );

        let c2 =
            &(
                b *
                    &(
                        &(
                            &(x1 - x2) * &(y3 + y1)
                        ) -
                            &(
                                &(y2 - y1) * &(x3 - x1)
                            )
                    )
            ) +
                &(
                    &one_minus_b * &(x3 - x1)
                );

        (c1.interpolate(), c2.interpolate())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_std::{test_rng, UniformRand};
    use ark_std::rand::{Rng, rngs::StdRng};
    use ark_poly::Polynomial;
    use ark_bls12_377::G1Projective;
    use ark_ec::ProjectiveCurve;
    use crate::tests::random_bits;

    // TODO: there's crate::tests::random_bits
    fn random_bitmask(rng: &mut StdRng, n: usize) -> Vec<Fr> {
        (0..n)
            .map(|_| rng.gen_bool(2.0 / 3.0))
            .map(|b| if b { Fr::one() } else { Fr::zero() })
            .collect()
    }

    fn random_pks(n: usize, rng: &mut StdRng) -> Vec<G1Affine> {
        (0..n)
            .map(|_| G1Projective::rand(rng))
            .map(|p| p.into_affine())
            .collect()
    }

    fn dummy_registers(n: usize) -> (Vec<Fr>, Vec<Fr>) {
        (vec![Fr::zero(); n], vec![Fr::zero(); n])
    }

    #[test]
    fn test_bitmask_booleanity_constraint() {
        let rng = &mut test_rng();
        let n = 64;
        let domains = Domains::new(n);


        let good_bitmask = Bitmask::from_bits(&random_bits(n, 0.5, rng));
        let registers = Registers::new(
            &domains,
            &good_bitmask,
            random_pks(n, rng),
            dummy_registers(n)
        );
        let constraint_poly =
            Constraints::compute_bitmask_booleanity_constraint_polynomial(&registers);
        assert_eq!(constraint_poly.degree(), 2 * (n - 1));
        assert!(domains.is_zero(&constraint_poly));


        let mut bad_bitmask = random_bitmask(rng, n);
        bad_bitmask[0] = Fr::rand(rng);
        let registers = Registers::new_unchecked(
            &domains,
            bad_bitmask,
            dummy_registers(n),
            dummy_registers(n),
            dummy_registers(n)
        );
        let constraint_poly =
            Constraints::compute_bitmask_booleanity_constraint_polynomial(&registers);
        assert_eq!(constraint_poly.degree(), 2 * (n - 1));
        assert!(!domains.is_zero(&constraint_poly));
    }
}