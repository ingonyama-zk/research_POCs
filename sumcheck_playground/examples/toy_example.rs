use icicle_bn254::curve::ScalarField as Fr;
use icicle_core::bignum::BigNum;
use icicle_core::program::{PreDefinedProgram, ReturningValueProgramImpl};
use icicle_bn254::program::bn254::ReturningValueProgram as P;
use icicle_core::sumcheck::{Sumcheck, SumcheckConfig, SumcheckTranscriptConfig};
use icicle_core::traits::{Arithmetic, GenerateRandom, Invertible};
use icicle_hash::blake3::Blake3;
use icicle_runtime::memory::HostSlice;
use merlin::Transcript;
use sumcheck_playground::transcript::*;

pub fn main() {
    let size = 1 << 3;
    //simulate previous state
    let mut prover_previous_transcript = Transcript::new(b"my_sumcheck");

    //define specific polys
    let poly_a = vec![
        Fr::from(1u32),
        Fr::from(2u32),
        Fr::from(3u32),
        Fr::from(4u32),
        Fr::from(5u32),
        Fr::from(6u32),
        Fr::from(7u32),
        Fr::from(8u32),
    ];
    let poly_b = vec![
        Fr::from(11u32),
        Fr::from(12u32),
        Fr::from(13u32),
        Fr::from(14u32),
        Fr::from(15u32),
        Fr::from(16u32),
        Fr::from(17u32),
        Fr::from(18u32),
    ];
    let poly_c = vec![
        Fr::from(21u32),
        Fr::from(22u32),
        Fr::from(23u32),
        Fr::from(24u32),
        Fr::from(25u32),
        Fr::from(26u32),
        Fr::from(27u32),
        Fr::from(28u32),
    ];
    let poly_e = vec![
        Fr::from(2u32),
        Fr::from(10u32),
        Fr::from(1u32),
        Fr::from(6u32),
        Fr::from(9u32),
        Fr::from(3u32),
        Fr::from(8u32),
        Fr::from(7u32),
    ];

    //compute claimed sum
    let temp: Vec<Fr> = poly_a
        .iter()
        .zip(poly_b.iter())
        .zip(poly_c.iter())
        .zip(poly_e.iter())
        .map(|(((a, b), c), e)| *a * *b * *e - *c * *e)
        .collect();
    let claimed_sum = temp.iter().fold(Fr::zero(), |acc, &a| acc + a);

    //add claimed sum to transcript to simulate previous state
    <Transcript as TranscriptProtocol<Fr>>::append_data(
        &mut prover_previous_transcript,
        b"public",
        &claimed_sum,
    );
    //get seed based on previous state
    let seed_rng = <Transcript as TranscriptProtocol<Fr>>::challenge_scalar(
        &mut prover_previous_transcript,
        b"seeded",
    );

    //define FS config
    let leaf_size = (Fr::one()).to_bytes_le().len().try_into().unwrap();
    let hasher = Blake3::new(leaf_size).unwrap();
    let transcript_config = SumcheckTranscriptConfig::new(
        &hasher,
        b"start_sumcheck".to_vec(),
        b"round_poly".to_vec(),
        b"round_challenge".to_vec(),
        true,
        seed_rng,
    );
    //define sumcheck config
    let sumcheck_config = SumcheckConfig::default();

    //define sumcheck instance
    let sumcheck = <icicle_bn254::sumcheck::SumcheckWrapper as Sumcheck>::new().unwrap();

    // map data to host slice
    let mle_poly_hosts = vec![
        HostSlice::<Fr>::from_slice(&poly_a),
        HostSlice::<Fr>::from_slice(&poly_b),
        HostSlice::<Fr>::from_slice(&poly_c),
        HostSlice::<Fr>::from_slice(&poly_e),
    ];

    // define combine function
    let combine_function = <P as ReturningValueProgramImpl>::new_predefined(PreDefinedProgram::EQtimesABminusC).unwrap();
    let proof = sumcheck.prove(
        &mle_poly_hosts,
        size,
        claimed_sum,
        combine_function,
        &transcript_config,
        &sumcheck_config,
    ).unwrap();
    drop(transcript_config);
    drop(prover_previous_transcript);
    drop(poly_a);
    drop(poly_b);
    drop(poly_c);
    drop(poly_e);
    //------------------------end_prover------------------------------

    // simulate verifier
    let mut verifier_previous_transcript = Transcript::new(b"my_sumcheck");
    <Transcript as TranscriptProtocol<Fr>>::append_data(
        &mut verifier_previous_transcript,
        b"public",
        &claimed_sum,
    );
    //get seed based on previous state
    let verifier_seed_rng = <Transcript as TranscriptProtocol<Fr>>::challenge_scalar(
        &mut verifier_previous_transcript,
        b"seeded",
    );

    //define verifier FS config
    let leaf_size = (Fr::one()).to_bytes_le().len().try_into().unwrap();
    let hasher = Blake3::new(leaf_size).unwrap();
    let verifier_transcript_config = SumcheckTranscriptConfig::new(
        &hasher,
        b"start_sumcheck".to_vec(),
        b"round_poly".to_vec(),
        b"round_challenge".to_vec(),
        true,
        verifier_seed_rng,
    );

    let proof_validty = sumcheck.verify(&proof, claimed_sum, &verifier_transcript_config);

    match proof_validty {
        Ok(true) => eprintln!("Valid proof!"), // Verification succeeded
        Ok(false) => {
            eprintln!("Sumcheck proof not valid",);
        }
        Err(err) => {
            eprintln!("Error in verification");
        }
    }
}
