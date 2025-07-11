use icicle_bn254::sumcheck::SumcheckWrapper as SW;
use icicle_bn254::curve::ScalarField as Fr;
use icicle_bn254::program::bn254::ReturningValueProgram as P;
use icicle_core::bignum::BigNum;
use icicle_core::program::{PreDefinedProgram, ReturningValueProgramImpl};
use icicle_core::sumcheck::{Sumcheck, SumcheckConfig, SumcheckProofOps, SumcheckTranscriptConfig};
use icicle_core::traits::{Arithmetic, GenerateRandom, Invertible};
use icicle_hash::keccak::Keccak256;
use icicle_runtime::memory::HostSlice;

pub fn main() {
    //setup
    let log_mle_poly_size = 10u64;
    let mle_poly_size = 1 << log_mle_poly_size;
    //number of MLE polys
    let nof_mle_poly = 4;
    let mut mle_polys = Vec::with_capacity(nof_mle_poly);
    //create polys
    for _ in 0..nof_mle_poly {
        let mle_poly_random = Fr::generate_random(mle_poly_size);
        mle_polys.push(mle_poly_random);
    }
    //compute claimed sum
    let mut claimed_sum = Fr::zero();
    for i in 0..mle_poly_size {
        let a = mle_polys[0][i];
        let b = mle_polys[1][i];
        let c = mle_polys[2][i];
        let eq = mle_polys[3][i];
        claimed_sum = claimed_sum + (a * b - c) * eq;
    }
    //create polynomial host slices
    let mle_poly_hosts = mle_polys
        .iter()
        .map(|poly| HostSlice::from_slice(poly))
        .collect::<Vec<&HostSlice<<SW as Sumcheck>::Field>>>();
    //define transcript config
    let leaf_size: u64 = (<SW as Sumcheck>::Field::one())
        .to_bytes_le()
        .len()
        .try_into()
        .unwrap();
    let hasher = Keccak256::new(0).unwrap();
    let seed_rng = Fr::generate_random(1)[0];
    let transcript_config = SumcheckTranscriptConfig::from_string_labels(
        &hasher,
        "DomainLabel",
        "PolyLabel",
        "ChallengeLabel",
        true, // little endian
        seed_rng,
    );
    //define sumcheck config
    let sumcheck_config = SumcheckConfig::default();
    let sumcheck = <SW as Sumcheck>::new().unwrap();
    //define combine function
    let combine_function = <P as ReturningValueProgramImpl>::new_predefined(PreDefinedProgram::EQtimesABminusC).unwrap();
    let proof = sumcheck.prove(
        &mle_poly_hosts,
        mle_poly_size.try_into().unwrap(),
        claimed_sum,
        combine_function,
        &transcript_config,
        &sumcheck_config,
    ).unwrap();
    //serialize round polynomials from proof
    let proof_round_polys = <<SW as Sumcheck>::Proof as SumcheckProofOps<
        <SW as Sumcheck>::Field,
    >>::get_round_polys(&proof)
    .unwrap();
    //verifier reconstruct proof from round polynomials
    let proof_as_sumcheck_proof: <SW as Sumcheck>::Proof =
        <SW as Sumcheck>::Proof::from(proof_round_polys);
    //verify proof
    let proof_validty = sumcheck.verify(&proof_as_sumcheck_proof, claimed_sum, &transcript_config);
    println!(
        "Sumcheck proof verified, is valid: {}",
        proof_validty.unwrap()
    );
}
