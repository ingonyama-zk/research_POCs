use core::hash;

use icicle_hash::keccak::Keccak256;
use icicle_core::hash::{Hasher, HashConfig};
use icicle_core::traits::{FieldImpl, GenerateRandom};
use icicle_runtime::memory::HostSlice;
use sha3::{Digest, Keccak256 as gen_Keccak256, Shake128Reader};
use sumcheck_playground::jolt_transcript::*;
use icicle_bn254::sumcheck::SumcheckWrapper as SW;
use icicle_bn254::curve::ScalarField as Fr;
use icicle_bn254::program::bn254::FieldReturningValueProgram as P;
use icicle_core::program::{PreDefinedProgram, ReturningValueProgram};
use icicle_core::sumcheck::{Sumcheck, SumcheckConfig, SumcheckProofOps, SumcheckTranscriptConfig};

fn check_icicle_vs_jolt_hash(){
    let test_b = b"Schroedinger's cat is both alive and dead";
    let mut hasher = gen_Keccak256::new();
    hasher.update(test_b);
    let result = hasher.finalize();
    let mut output = vec![0u8; 32];
    let input = HostSlice::from_slice(test_b);
    let hasher_icicle = Keccak256::new(0).unwrap();
    hasher_icicle.hash(input, &HashConfig::default(), HostSlice::from_mut_slice(&mut output)).unwrap();
    assert_eq!(*output,*result, "Hash mismatch");
}

fn icicle_transcript(){

let log_mle_poly_size: u32 = 3;
let mle_poly_size: u32 = 1 << log_mle_poly_size;
 //number of MLE polys
 let nof_mle_poly: u32 = 1;
  let poly_a = vec![
    <<SW as Sumcheck>::Field as FieldImpl>::from_u32(1),
    <<SW as Sumcheck>::Field as FieldImpl>::from_u32(4),
    <<SW as Sumcheck>::Field as FieldImpl>::from_u32(2),
    <<SW as Sumcheck>::Field as FieldImpl>::from_u32(8),
    <<SW as Sumcheck>::Field as FieldImpl>::from_u32(11),
    <<SW as Sumcheck>::Field as FieldImpl>::from_u32(91),
    <<SW as Sumcheck>::Field as FieldImpl>::from_u32(20),
    <<SW as Sumcheck>::Field as FieldImpl>::from_u32(5),
];
 //compute claimed sum
 let mut claimed_sum = <<SW as Sumcheck>::Field as FieldImpl>::zero();
 for i in 0..poly_a.len() {
     claimed_sum = claimed_sum + poly_a[i];
 };
 let test = |vars: &mut Vec<<P as ReturningValueProgram>::ProgSymbol>|-> <P as ReturningValueProgram>::ProgSymbol {
     let a = vars[0]; // Shallow copies pointing to the same memory in the backend
     return a;
 };
 //create polynomial host slices
 let host_a  = HostSlice::<<SW as Sumcheck>::Field>::from_slice(&poly_a);

//define transcript config
 let hasher = Keccak256::new(0).unwrap();
 let seed_rng =<<SW as Sumcheck>::Field as FieldImpl>::zero();
 let mut transcript_config = SumcheckTranscriptConfig::from_string_labels(
     &hasher,
     "new",
     "begin_append_vector",
     "challenge",
     true, // little endian
     seed_rng,
 );
 //define sumcheck config
 let sumcheck_config = SumcheckConfig::default();
 let sumcheck = <SW as Sumcheck>::new().unwrap();
 //define combine function
 let combine_function = P::new(test, 1).unwrap();
 let proof = sumcheck.prove(
     &[host_a],
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
proof.print();
 println!("Proof round polys: {:?}", proof_round_polys.clone());
 //verifier reconstruct proof from round polynomials
 let proof_as_sumcheck_proof: <SW as Sumcheck>::Proof =
     <SW as Sumcheck>::Proof::from(proof_round_polys.clone());
 //verify proof
 let proof_validty = sumcheck.verify(&proof_as_sumcheck_proof, claimed_sum, &transcript_config);
 println!(
     "Sumcheck proof verified, is valid: {}",
     proof_validty.unwrap()); 




//Simulate verifier explicit


let r0 = proof_round_polys[0].clone();
let r1 = proof_round_polys[1].clone();
let r2 = proof_round_polys[2].clone();
let poly_evals = poly_a.clone();

assert_eq!(r0[0], poly_a[0]+poly_a[2]+poly_a[4]+poly_a[6], "rp 0 mismatch");
assert_eq!(r0[1], poly_a[1]+poly_a[3]+poly_a[5]+poly_a[7], "rp 0 mismatch");

// a(1-x) +b x = a + (b-a)x
let r0poly= vec![r0[0],r0[1]-r0[0]]; 
let r1poly= vec![r1[0],r1[1]-r1[0]]; 
let r2poly= vec![r2[0],r2[1]-r2[0]]; 

//basic check
assert_eq!(r0[0]+r0[1],claimed_sum, "Claimed sum mismatch");// this passes of course, so the proof is in the correct order.


//icicle transcript
//entry_DS = [domain_separator_label || proof.mle_polynomial_size || proof.degree || public (hardcoded?) ||
//claimed_sum]
//alpha_0 = Hash(entry_DS || seed_rng || round_challenge_label || entry_0).to_field()
//config data
//generate alpha0
let mut hash_input_0: Vec<u8> =transcript_config.domain_separator_label.clone();
hash_input_0.append(mle_poly_size.to_le_bytes().to_vec().as_mut());//ok
hash_input_0.append(nof_mle_poly.to_le_bytes().to_vec().as_mut());//ok combine degree
hash_input_0.append(claimed_sum.to_bytes_le().to_vec().as_mut());
//challenge prev data
hash_input_0.append(seed_rng.to_bytes_le().to_vec().as_mut());
//challenge meta data
hash_input_0.append(&mut transcript_config.round_challenge_label);
//meta data of actual data
hash_input_0.append(&mut transcript_config.round_poly_label);
//actual data
hash_input_0.append(r0.len().to_le_bytes().to_vec().as_mut());
hash_input_0.append(0u32.to_le_bytes().to_vec().as_mut());
hash_input_0.append(r0[0].to_bytes_le().to_vec().as_mut());
hash_input_0.append(r0[1].to_bytes_le().to_vec().as_mut());


let mut output = vec![0u8; 32];
let hasher_icicle = Keccak256::new(0).unwrap();
hasher_icicle.hash(HostSlice::from_slice(&hash_input_0), &HashConfig::default(), HostSlice::from_mut_slice(&mut output)).unwrap();
println!("icicle transcript initial state {:?}", output);
let alpha0icicle = Fr::from_bytes_le(&output);
println!("alpha0 ICICLE: {:?}", alpha0icicle);

//r1[0]+r1[1] = r0[alpha0] = r0poly[0] + alpha0 * ropoly[1]
assert_eq!(r1poly[0]+r1poly[1],r0poly[0]+r0poly[1]*alpha0icicle, "r1 mismatch");

// //entry_i = [round_poly_label || r_i[x].len() || k=i || r_i[x]]
// //alpha_i = Hash(entry_0 || alpha_(i-1) || round_challenge_label || entry_i).to_field()
// let mut entry1: Vec<u8>=vec![];
// entry1.append(&mut transcript_config.round_poly_label);
// entry1.append(r1.len().to_le_bytes().to_vec().as_mut());
// entry1.append(1u32.to_le_bytes().to_vec().as_mut());
// entry1.append(r1[0].to_bytes_le().to_vec().as_mut());
// entry1.append(r1[1].to_bytes_le().to_vec().as_mut());

// let mut hash_input1 :Vec<u8> = vec![];
// hash_input1.append(entry0.as_mut());
// hash_input1.append(alpha0icicle.to_bytes_le().to_vec().as_mut());
// hash_input1.append(&mut transcript_config.round_challenge_label);
// hash_input1.append(entry1.as_mut());


// let mut output = vec![0u8; 32];
// let hasher_icicle = Keccak256::new(0).unwrap();
// hasher_icicle.hash(HostSlice::from_slice(&hash_input1), &HashConfig::default(), HostSlice::from_mut_slice(&mut output)).unwrap();
// let alpha1icicle = Fr::from_bytes_le(&output);
// println!("alpha1 ICICLE: {:?}", alpha1icicle);

// //entry_i = [round_poly_label || r_i[x].len() || k=i || r_i[x]]
// //alpha_i = Hash(entry_0 || alpha_(i-1) || round_challenge_label || entry_i).to_field()
// let mut entry2: Vec<u8>=vec![];
// entry2.append(&mut transcript_config.round_poly_label);
// entry2.append(r2.len().to_le_bytes().to_vec().as_mut());
// entry2.append(2u32.to_le_bytes().to_vec().as_mut());
// entry2.append(r2[0].to_bytes_le().to_vec().as_mut());
// entry2.append(r2[1].to_bytes_le().to_vec().as_mut());

// let mut hash_input2 :Vec<u8> = vec![];
// hash_input2.append(entry0.as_mut());
// hash_input2.append(alpha1icicle.to_bytes_le().to_vec().as_mut());
// hash_input2.append(&mut transcript_config.round_challenge_label);
// hash_input2.append(entry2.as_mut());


// let mut output = vec![0u8; 32];
// let hasher_icicle = Keccak256::new(0).unwrap();
// hasher_icicle.hash(HostSlice::from_slice(&hash_input2), &HashConfig::default(), HostSlice::from_mut_slice(&mut output)).unwrap();
// let alpha2icicle = Fr::from_bytes_le(&output);
// println!("alpha1 ICICLE: {:?}", alpha2icicle);



//r2[0]+r2[1] = r1[alpha0] = r1poly[0] + alpha1 * r1poly[1]
// assert_eq!(r2poly[0]+r2poly[1],r1poly[0]+r1poly[1]*alpha1icicle, "r2 mismatch");



    // let mut entry0: Vec<u8> =vec![];
    // entry0.append(b"begin_append_vector".to_vec().as_mut());
    // entry0.append(proof_round_polys_jolt[0].len().to_le_bytes().to_vec().as_mut());
    // entry0.append(0u32.to_le_bytes().to_vec().as_mut());
    // entry0.append(proof_round_polys_jolt[0][0].to_bytes_le().to_vec().as_mut());
    // entry0.append(proof_round_polys_jolt[0][1].to_bytes_le().to_vec().as_mut());
// let mut jolt_transcript = KeccakTranscript::new(b"new",mle_poly_size.try_into().unwrap(), nof_mle_poly.try_into().unwrap(), claimed_sum,seed_rng,entry0);
// println!("jolt transcript initial state{:?}", jolt_transcript.state);
// //get alpha 0
// let alpha0 = jolt_transcript.challenge_scalar::<Fr>();
// println!("alpha0: {:?}", alpha0);
}



pub fn main() {
check_icicle_vs_jolt_hash();
icicle_transcript();
}

//icicle iop pattern
// void build_hash_input_round_0(std::vector<std::byte>& hash_input, const std::vector<S>& round_poly)
//   {
//     const std::vector<std::byte>& round_poly_label = m_transcript_config.get_round_poly_label();
//     // append entry_DS = [domain_separator_label || proof.mle_polynomial_size || proof.degree || public (hardcoded?) ||
//     // claimed_sum]
//     append_data(hash_input, m_transcript_config.get_domain_separator_label());
//     append_u32(hash_input, m_mle_polynomial_size);
//     append_u32(hash_input, m_combine_function_poly_degree);
//     append_field(hash_input, m_claimed_sum);

//     // append seed_rng
//     append_field(hash_input, m_transcript_config.get_seed_rng());

//     // append round_challenge_label
//     append_data(hash_input, m_transcript_config.get_round_challenge_label());

//     // build entry_0 = [round_poly_label || r_0[x].len() || k=0 || r_0[x]]
//     append_data(m_entry_0, round_poly_label);
//     append_u32(m_entry_0, round_poly.size());
//     append_u32(m_entry_0, m_round_idx);
//     for (const S& r_i : round_poly) {
//       append_field(hash_input, r_i);
//     }

//     // append entry_0
//     append_data(hash_input, m_entry_0);
//   }

//   // round !=0 hash input
//   void build_hash_input_round_i(std::vector<std::byte>& hash_input, const std::vector<S>& round_poly)
//   {
//     const std::vector<std::byte>& round_poly_label = m_transcript_config.get_round_poly_label();
//     // entry_i = [round_poly_label || r_i[x].len() || k=i || r_i[x]]
//     // alpha_i = Hash(entry_0 || alpha_(i-1) || round_challenge_label || entry_i).to_field()
//     append_data(hash_input, m_entry_0);
//     append_field(hash_input, m_prev_alpha);
//     append_data(hash_input, m_transcript_config.get_round_challenge_label());

//     append_data(hash_input, round_poly_label);
//     append_u32(hash_input, round_poly.size());
//     append_u32(hash_input, m_round_idx);
//   }