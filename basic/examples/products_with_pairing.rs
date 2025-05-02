use icicle_bn254::curve::CurveCfg;
use icicle_core::curve;
use icicle_core::{curve::{Affine,Curve,Projective}, traits::FieldImpl};
use icicle_core::pairing::Pairing;
use icicle_bn254::{curve::{G1Affine as G1, G1Projective, G2Affine as G2, ScalarField as Fr, 
CurveCfg as G1Cfg, G2CurveCfg as G2Cfg}, 
pairing::PairingTargetField as Fq12};



pub fn main() {
    let a = Fr::from_u32(rand::random::<u32>());
    let b = Fr::from_u32(rand::random::<u32>());
    let c = a*b;
    let one = Fr::one();
    let g1 = icicle_bn254::curve::CurveCfg::generate_random_projective_points(1)[0];
    let g2 = icicle_bn254::curve::G2CurveCfg::generate_random_projective_points(1)[0];

    let gL1 = g1 * a;
    let gL2 = g2 * b;
    let gR1 = g1 * c;
    let gR2 = g2 * one;

    let gL1_affine = Affine::<G1Cfg>::from(gL1);
    let gL2_affine = Affine::<G2Cfg>::from(gL2);

    let gR1_affine = Affine::<G1Cfg>::from(gR1);
    let gR2_affine = Affine::<G2Cfg>::from(gR2);

    let pairing:Fq12 = <G1Cfg as Pairing<G1Cfg,G2Cfg,Fq12>>::pairing(&gL1_affine, &gL2_affine).unwrap();
    let pairing_right:Fq12 = <G1Cfg as Pairing<G1Cfg,G2Cfg,Fq12>>::pairing(&gR1_affine, &gR2_affine).unwrap();

    assert_eq!(pairing, pairing_right);
    println!(" verified by pairing c=a*b mod p for bn254");
}
