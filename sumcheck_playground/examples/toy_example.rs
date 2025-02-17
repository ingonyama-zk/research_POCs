use icicle_core::traits::FieldImpl;
use icicle_core::sumcheck::{Sumcheck,SumcheckConfig,SumcheckTranscriptConfig};
use icicle_core::program::{PreDefinedProgram, ReturningValueProgram};
use icicle_bn254::curve::ScalarField as Fr;
use icicle_hash::blake3::Blake3;
use icicle_runtime::memory::HostSlice;
use merlin::Transcript;
use sumcheck_playground::transcript::*;

pub fn main() {
    let size = 1<<3;
    //simulate previous state
    let mut prover_previous_transcript = Transcript::new(b"my_sumcheck");
    
    //define specific polys
    let poly_a = vec![Fr::from_u32(1),Fr::from_u32(2),Fr::from_u32(3),Fr::from_u32(4),Fr::from_u32(5),Fr::from_u32(6),Fr::from_u32(7),Fr::from_u32(8)];
    let poly_b = vec![Fr::from_u32(11),Fr::from_u32(12),Fr::from_u32(13),Fr::from_u32(14),Fr::from_u32(15),Fr::from_u32(16),Fr::from_u32(17),Fr::from_u32(18)];
    let poly_c = vec![Fr::from_u32(21),Fr::from_u32(22),Fr::from_u32(23),Fr::from_u32(24),Fr::from_u32(25),Fr::from_u32(26),Fr::from_u32(27),Fr::from_u32(28)];
    let poly_e = vec![Fr::from_u32(2),Fr::from_u32(10),Fr::from_u32(1),Fr::from_u32(6),Fr::from_u32(9),Fr::from_u32(3),Fr::from_u32(8),Fr::from_u32(7)];

    //compute claimed sum
    let temp:Vec<Fr> = poly_a
    .iter()
    .zip(poly_b.iter())
    .zip(poly_c.iter())
    .zip(poly_e.iter())
    .map(|(((a, b), c), e)| *a * *b * *e - *c * *e)
    .collect();  
    let claimed_sum = temp.iter().fold(Fr::zero(), |acc, &a| acc + a);

    //add claimed sum to transcript to simulate previous state
    <Transcript as TranscriptProtocol::<Fr>>::append_data(&mut prover_previous_transcript, b"public", &claimed_sum);
    //get seed based on previous state
    let seed_rng = <Transcript as TranscriptProtocol::<Fr>>::challenge_scalar(&mut prover_previous_transcript, b"seeded");

    //define FS config
    let leaf_size = (Fr::one()).to_bytes_le().len().try_into().unwrap();
    let hasher = Blake3::new(leaf_size).unwrap();
    let transcript_config = SumcheckTranscriptConfig::new(
        &hasher, 
        b"start_sumcheck".to_vec(), 
        b"round_poly".to_vec(), 
        b"round_challenge".to_vec(), 
        true, 
        seed_rng);
    //define sumcheck config
    let sumcheck_config = SumcheckConfig::default();

    //define sumcheck instance
    let sumcheck = <icicle_bn254::sumcheck::SumcheckWrapper as Sumcheck>::new().unwrap();
    
    // map data to host slice
    let mle_poly_hosts = vec![HostSlice::<Fr>::from_slice(&poly_a),
    HostSlice::<Fr>::from_slice(&poly_b),HostSlice::<Fr>::from_slice(&poly_c),HostSlice::<Fr>::from_slice(&poly_e)];

    // define combine function
    let combine_function = <icicle_bn254::program::FieldReturningValueProgram as ReturningValueProgram>::new_predefined(PreDefinedProgram::EQtimesABminusC).unwrap();
    let proof =    sumcheck.prove(
        &mle_poly_hosts, 
        size, 
        claimed_sum, 
        combine_function, 
        &transcript_config, 
        &sumcheck_config);
    drop(transcript_config);
    drop(prover_previous_transcript);
    drop(poly_a);
    drop(poly_b);
    drop(poly_c);
    drop(poly_e);
//------------------------end_prover------------------------------

    // simulate verifier
    let mut verifier_previous_transcript =  Transcript::new(b"my_sumcheck");
    <Transcript as TranscriptProtocol::<Fr>>::append_data(&mut verifier_previous_transcript, b"public", &claimed_sum);
    //get seed based on previous state
    let verifier_seed_rng = <Transcript as TranscriptProtocol::<Fr>>::challenge_scalar(&mut verifier_previous_transcript, b"seeded");
    
    //define verifier FS config
    let leaf_size = (Fr::one()).to_bytes_le().len().try_into().unwrap();
    let hasher = Blake3::new(leaf_size).unwrap();
    let verifier_transcript_config = SumcheckTranscriptConfig::new(
          &hasher, 
          b"start_sumcheck".to_vec(), 
          b"round_poly".to_vec(), 
          b"round_challenge".to_vec(), 
          true, 
          verifier_seed_rng);

    
    let proof_validty = sumcheck.verify(&proof, claimed_sum, &verifier_transcript_config);

match proof_validty {
        Ok(true) => eprintln!("Valid proof!"), // Verification succeeded
        Ok(false) => {
            eprintln!(
                "Sumcheck proof not valid",
            );
        }
        Err(err) => {
            eprintln!("Error in verification");
        }
    }
    
}