use std::ops::AddAssign;

use ark_bw6_761::{Fq, G1Projective};
use ark_ec::bls12::Bls12Config;
use ark_ec::Group;
use ark_ff::{BitIteratorBE, MontFp, Zero};

// See https://github.com/celo-org/zexe/blob/master/algebra/src/bw6_761/curves/g1.rs#L37-L71
// and also https://github.com/celo-org/zexe/blob/master/scripts/glv_lattice_basis/src/lib.rs

/// phi((x, y)) = (\omega x, y)
/// \omega = 0x531dc16c6ecd27aa846c61024e4cca6c1f31e53bd9603c2d17be416c5e44
/// 26ee4a737f73b6f952ab5e57926fa701848e0a235a0a398300c65759fc4518315
/// 1f2f082d4dcb5e37cb6290012d96f8819c547ba8a4000002f962140000000002a
const OMEGA: Fq = MontFp!(
    "196898582409020929727861073970057715139766638230382572845074161156680037021882725775086501\
        3421937292370006175842381275743914023380727582819905021229583192207421122272650305267822868\
        639090213645505120388400344940985710520836292650"
);

const U: &'static [u64] = ark_bls12_377::Config::X;

fn mul_by_u(p: &G1Projective) -> G1Projective {
    let mut res = G1Projective::zero();
    for i in BitIteratorBE::without_leading_zeros(U) {
        res.double_in_place();
        if i {
            res.add_assign(p)
        }
    }
    res
}

fn glv_endomorphism_proj(p: &G1Projective) -> G1Projective {
    G1Projective::new_unchecked(p.x * OMEGA, p.y, p.z)
}

// See https://eprint.iacr.org/2020/351.pdf, section 3.1
pub fn subgroup_check(p: &G1Projective) -> bool {
    let up = mul_by_u(p);
    let u2p = mul_by_u(&up);
    let u3p = mul_by_u(&u2p);

    (up + p + glv_endomorphism_proj(&(u3p - u2p + p))).is_zero()
}

#[cfg(test)]
mod tests {
    use ark_bw6_761::{Fr, G1Affine};
    use ark_ec::{AffineRepr, CurveGroup};
    use ark_ff::{Field, One};
    use ark_std::{test_rng, UniformRand};

    use super::*;

    /// lambda in Z s.t. phi(P) = lambda*P for all P
    /// \lambda = 0x9b3af05dd14f6ec619aaf7d34594aabc5ed1347970dec00452217cc900000008508c00000000001
    const LAMBDA: Fr = MontFp!(
        "809496482649127194085583631406374772648452947207104994781372872627125359383014618798134594\
        10945"
    );

    fn glv_endomorphism_in_place(p: &mut G1Affine) {
        let x = &mut p.x;
        *x *= &OMEGA;
    }

    fn glv_endomorphism(p: &G1Affine) -> G1Affine {
        let mut p = p.clone();
        glv_endomorphism_in_place(&mut p);
        p
    }

    #[test]
    pub fn test_omega() {
        assert!(OMEGA.pow([3]).is_one());
    }

    #[test]
    pub fn test_endo() {
        let rng = &mut test_rng();

        let p1 = ark_bw6_761::G1Projective::rand(rng).into_affine();
        let mut p2 = p1.clone();

        assert_eq!(glv_endomorphism(&p1), p1 * LAMBDA);
        glv_endomorphism_in_place(&mut p2);
        assert_eq!(p2, p1 * LAMBDA);
    }

    #[test]
    pub fn test_endo_proj() {
        let rng = &mut test_rng();

        let p = ark_bw6_761::G1Projective::rand(rng);

        assert_eq!(glv_endomorphism_proj(&p), p * LAMBDA);
    }

    #[test]
    pub fn test_subgroup_check() {
        let rng = &mut test_rng();

        let p = ark_bw6_761::G1Projective::rand(rng);

        assert!(subgroup_check(&p));

        let point_not_in_g1 = loop {
            let x = Fq::rand(rng);
            let p = G1Affine::get_point_from_x_unchecked(x, false);
            if p.is_some() && !p.unwrap().is_in_correct_subgroup_assuming_on_curve() {
                break p.unwrap();
            }
        };

        assert!(point_not_in_g1.is_on_curve());
        assert!(!point_not_in_g1.is_in_correct_subgroup_assuming_on_curve());
        assert!(!subgroup_check(&point_not_in_g1.into_group()));
    }
}
