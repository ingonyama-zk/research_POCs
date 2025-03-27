use icicle_bn254::sumcheck::SumcheckWrapper as SW;
use icicle_bn254::program::bn254::FieldReturningValueProgram as P;
use icicle_core::program::ReturningValueProgram;
use icicle_core::sumcheck::{Sumcheck, SumcheckConfig, SumcheckProofOps, SumcheckTranscriptConfig};
use icicle_core::traits::{FieldImpl, GenerateRandom};
use icicle_hash::keccak::Keccak256;
use icicle_runtime::memory::HostSlice;

pub fn main() {
    //setup begin
    let log_mle_poly_size = 10u64;
    let mle_poly_size = 1 << log_mle_poly_size;
    //number of MLE polys
    let nof_mle_poly = 5;
    let mut mle_polys = Vec::with_capacity(nof_mle_poly);
    //define slack vector
    let mut slack_poly = vec![<<SW as Sumcheck>::Field as FieldImpl>::zero(); mle_poly_size];
    //create polys except slack poly
    for _ in 0..nof_mle_poly-1 {
        let mle_poly_random = <<SW as Sumcheck>::FieldConfig>::generate_random(mle_poly_size);
        mle_polys.push(mle_poly_random);
    }
    //compute claimed sum
    let mut claimed_sum = <<SW as Sumcheck>::Field as FieldImpl>::zero();
    for i in 0..mle_poly_size {
        let a = mle_polys[0][i];
        let b = mle_polys[1][i];
        let c = mle_polys[2][i];
        let eq = mle_polys[3][i];
        let slack =  c - a * b;
        slack_poly[i]=slack;
        claimed_sum = claimed_sum + (a * b - c +slack) * eq;
    };
    mle_polys.push(slack_poly); // add slack poly to mle_polys
    //check that claimed sum is zero
    assert_eq!(claimed_sum, <<SW as Sumcheck>::Field as FieldImpl>::zero());
   //setup emd
   //define relaxed r1cs
    let relaxed_r1cs = |vars: &mut Vec<<P as ReturningValueProgram>::ProgSymbol>|-> <P as ReturningValueProgram>::ProgSymbol {
        let a = vars[0]; // Shallow copies pointing to the same memory in the backend
        let b = vars[1];
        let c = vars[2];
        let eq = vars[3];
        let slack =vars[4];
        return eq* (a * b - c + slack);
    };
    //create polynomial host slices
    let mle_poly_hosts = mle_polys
        .iter()
        .map(|poly| HostSlice::from_slice(poly))
        .collect::<Vec<&HostSlice<<SW as Sumcheck>::Field>>>();
    //define transcript config
    let hasher = Keccak256::new(0).unwrap();
    let seed_rng = <<SW as Sumcheck>::FieldConfig>::generate_random(1)[0];
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
    let combine_function = P::new(relaxed_r1cs, 5).unwrap();
    let proof = sumcheck.prove(
        &mle_poly_hosts,
        mle_poly_size.try_into().unwrap(),
        claimed_sum,
        combine_function,
        &transcript_config,
        &sumcheck_config,
    );
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