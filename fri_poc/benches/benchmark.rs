use criterion::{criterion_group, criterion_main, Criterion};
use fri_poc::{utils::*,data_structures::*};

use icicle_core::{
    ntt::{get_root_of_unity,ntt, NTTConfig,NTTDir}, 
    polynomials::UnivariatePolynomial, 
    traits::{Arithmetic, FieldImpl}};
use icicle_runtime::memory::HostSlice;

use icicle_babybear::{
    field::ScalarField as Fr,
    polynomials::DensePolynomial};
use merlin::Transcript;
use fri_poc::prover::prove;

const SAMPLES: usize = 131072; // 2^17


pub fn bench_fold(c:&mut Criterion){
try_load_and_set_backend_gpu();
let mut group = c.benchmark_group("Fold2");
let test_vec = generate_random_vector::<Fr>(SAMPLES);
let challenge = Fr::from_u32(rand::random::<u32>());
let logsize=SAMPLES.ilog2();
// this cannot compute cosets
init_ntt_domain::<Fr>(1 << logsize);
let mut frilayer =  Current_layer::<Fr> {
    current_code_word: test_vec.clone(),

};

let mut poly = DensePolynomial::from_rou_evals(HostSlice::from_slice(&test_vec), test_vec.len());
let cfg = NTTConfig::<Fr>::default();
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
let rou: Fr = get_root_of_unity::<Fr>(SAMPLES.try_into().unwrap());
let rou_inv: Fr = rou.inv();
let two_inv:Fr = Fr::from_u32(2).inv();
let mut inv_domain: Vec<Fr> = Vec::with_capacity(SAMPLES / 2);
let mut current = Fr::one(); // can define coset gen inv here if we want

//precompute domain and access in strides
for _ in 0..(SAMPLES/ 2) {
    inv_domain.push(current);
    current = current*rou_inv; 
}

group.bench_function("Fold in two vec", |b| b.iter(
    ||{
        let _res = frilayer.fold_evals( Fr::one(), challenge);
    })
);

group.bench_function("fold in two precompute domain", |b|b.iter(
    ||{
        let _res = frilayer.fold_evals_precompute_domain(&mut inv_domain, &two_inv, challenge);
    }));

group.bench_function("fold in two poly", |b|b.iter(
    || {
        let res = fold_poly(poly.clone(), challenge);
        ntt(poly.coeffs_mut_slice(), NTTDir::kForward, &cfg, new_domain_eval_size).unwrap();
    })
);
group.finish();

}
criterion_group!(benches,bench_fold);
criterion_main!(benches);