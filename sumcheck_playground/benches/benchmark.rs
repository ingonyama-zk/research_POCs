use criterion::{criterion_group, criterion_main, Criterion};
use icicle_bn254::curve::ScalarField as Fr;
use icicle_bn254::program::bn254::FieldReturningValueProgram;
use icicle_core::traits::{FieldImpl,GenerateRandom};
use icicle_hash::blake3::Blake3;
use icicle_runtime::memory::HostSlice;
use icicle_core::sumcheck::{Sumcheck,SumcheckConfig,SumcheckTranscriptConfig,SumcheckProofOps};
use icicle_core::program::{PreDefinedProgram, ReturningValueProgram};
use sumcheck_playground::utils::*;

const SAMPLES: usize = 1<<12;

pub fn bench_sumcheck(c:&mut Criterion){
try_load_and_set_backend_gpu();
let mut group = c.benchmark_group("Sumcheck_bench");

let poly_a = generate_random_vector::<Fr>(SAMPLES);
let poly_b = generate_random_vector::<Fr>(SAMPLES);
let poly_c = generate_random_vector::<Fr>(SAMPLES);
let poly_e = generate_random_vector::<Fr>(SAMPLES);

    //compute claimed sum
let temp:Vec<Fr> = poly_a
    .iter()
    .zip(poly_b.iter())
    .zip(poly_c.iter())
    .zip(poly_e.iter())
    .map(|(((a, b), c), e)| *a * *b * *e - *c * *e)
    .collect();  
    let claimed_sum = temp.iter().fold(Fr::zero(), |acc, &a| acc + a);


    let leaf_size = (Fr::one()).to_bytes_le().len().try_into().unwrap();
    let hasher = Blake3::new(leaf_size).unwrap();

    //define sumcheck config
    let sumcheck_config = SumcheckConfig::default();

    let mle_poly_hosts = vec![HostSlice::<Fr>::from_slice(&poly_a),
    HostSlice::<Fr>::from_slice(&poly_b),HostSlice::<Fr>::from_slice(&poly_c),HostSlice::<Fr>::from_slice(&poly_e)];
    let sumcheck = <icicle_bn254::sumcheck::SumcheckWrapper as Sumcheck>::new().unwrap();

group.bench_function("sumcheck_prover", |b |b.iter(
    ||{
        let seed_rng = generate_random_vector::<Fr>(1)[0];
        let transcript_config = SumcheckTranscriptConfig::new(
            &hasher, 
            b"start_sumcheck".to_vec(), 
            b"round_poly".to_vec(), 
            b"round_challenge".to_vec(), 
            true, 
            seed_rng);
        let combine_function = <FieldReturningValueProgram as ReturningValueProgram>::new_predefined(PreDefinedProgram::EQtimesABminusC).unwrap();
       let _proof= sumcheck.prove(
        &mle_poly_hosts, 
        SAMPLES.try_into().unwrap(), 
        claimed_sum, 
        combine_function, 
        &transcript_config, 
        &sumcheck_config); 
    }));
}

criterion_group!(benches,bench_sumcheck);
criterion_main!(benches);