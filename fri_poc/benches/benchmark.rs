use criterion::{criterion_group, criterion_main, Criterion};
use fri_poc::{utils::*,data_structures::*,transcript::*};

use icicle_core::
    {field::Field, hash::{self, HashConfig, Hasher, HasherHandle}, merkle::{MerkleProof,MerkleTree,MerkleTreeConfig,PaddingPolicy}, 
    ntt::{get_root_of_unity, initialize_domain, ntt, ntt_inplace, NTTConfig, NTTInitDomainConfig,NTTDir}, 
    polynomials::UnivariatePolynomial, 
    traits::{Arithmetic,FieldConfig,FieldImpl,GenerateRandom,MontgomeryConvertible}, vec_ops::*
    };
use icicle_hash::{blake2s::Blake2s, keccak::Keccak256};
use icicle_runtime::memory::HostSlice;

use icicle_babybear::{
    field::{ExtensionField as Fr4, ScalarCfg, ScalarField as Fr},
    polynomials::DensePolynomial, vec_ops};

const SAMPLES: usize = 131072; // 2^17


pub fn bench_fold2(c:&mut Criterion){
try_load_and_set_backend_gpu();
let mut group = c.benchmark_group("Fold2");
let test_vec = generate_random_vector::<Fr>(SAMPLES);
let challenge = Fr::from_u32(rand::random::<u32>());
let logsize=SAMPLES.ilog2();
// this cannot compute cosets
init_ntt_domain::<Fr>(1 << logsize);
let rou: Fr = get_root_of_unity::<Fr>(SAMPLES.try_into().unwrap());
let mut frilayer =  Current_layer::<Fr> {
    current_code_word: test_vec.clone(),

};

let mut poly = DensePolynomial::from_rou_evals(HostSlice::from_slice(&test_vec), test_vec.len());
let mut cfg = NTTConfig::<Fr>::default();
fn fold_poly(
    poly: DensePolynomial,
    beta: Fr,// this should be in extension field for FRI security. currently unsupported
) -> DensePolynomial {
    let o: DensePolynomial = poly.odd();
    let e: DensePolynomial = poly.even();
    &e + &(&o*&beta)
}
let mut new_domain_evals = vec![Fr::zero();  SAMPLES];
let new_domain_eval_size = HostSlice::from_mut_slice(&mut new_domain_evals[..]);
group.bench_function("Fold in two vec", |b| b.iter(
    ||{
        let _res = frilayer.fold_evals(rou, Fr::one(), challenge);
    })
);

group.bench_function("fold in two poly", |b|b.iter(
    || {
        let res = fold_poly(poly.clone(), challenge);
        ntt(poly.coeffs_mut_slice(), NTTDir::kForward, &cfg, new_domain_eval_size).unwrap();
    })
);
group.finish();

}
criterion_group!(benches,bench_fold2);
criterion_main!(benches);