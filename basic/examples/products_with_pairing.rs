

use icicle_core::{bignum::BigNum, ecntt::Projective, pairing::{self, Pairing}, traits::{Arithmetic,GenerateRandom}};
use icicle_bn254::{curve::{G1Affine as G1, G1Projective, G2Affine as G2, G2Projective, ScalarField as Fr},pairing::{PairingTargetField as Fq12}};



pub fn main() {
    let a = Fr::from(rand::random::<u32>());
    let b = Fr::from(rand::random::<u32>());
    let c = a*b;
    let one = Fr::one();
    let g1 = G1Projective::generate_random(1)[0];
    let g2 = G2Projective::generate_random(1)[0];

    let gL1 = g1 * a;
    let gL2 = g2 * b;
    let gR1 = g1 * c;
    let gR2 = g2 * one;

    let gL1_affine: G1 = G1Projective::to_affine(gL1);
    let gL2_affine: G2 = G2Projective::to_affine(gL2);
    let gR1_affine: G1 = G1Projective::to_affine(gR1);
    let gR2_affine: G2 = G2Projective::to_affine(gR2);
    let pairingL: Fq12 = pairing::pairing::<G1Projective, G2Projective, Fq12>(&gL1_affine, &gL2_affine).unwrap();
    let pairingR: Fq12 = pairing::pairing::<G1Projective, G2Projective, Fq12>(&gR1_affine, &gR2_affine).unwrap();

    assert_eq!(pairingL,pairingR);
    println!(" verified by pairing c=a*b mod p for bn254");
}
