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
 let transcript_config = SumcheckTranscriptConfig::from_string_labels(
     &hasher,
     "",
     "begin_append_vector",
     "",
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


let proof_round_polys_jolt = proof_round_polys.clone();
let poly_a_jolt = poly_a.clone();

let one = Fr::one();
assert_eq!(proof_round_polys_jolt[0][0]+proof_round_polys_jolt[0][1],claimed_sum, "Claimed sum mismatch");

let mut entry0: Vec<u8> =vec![];
entry0.append(b"begin_append_vector".to_vec().as_mut());
entry0.append(proof_round_polys_jolt[0].len().to_le_bytes().to_vec().as_mut());
entry0.append(0u32.to_le_bytes().to_vec().as_mut());
entry0.append(proof_round_polys_jolt[0][0].to_bytes_le().to_vec().as_mut());
entry0.append(proof_round_polys_jolt[0][1].to_bytes_le().to_vec().as_mut());
// append entry_DS = [domain_separator_label || proof.mle_polynomial_size || proof.degree || public (hardcoded?) ||
// claimed_sum]
//entry_0 = [entryDS|| round_poly_label || r_0[x].len() || k=0 || r_0[x]]
//in the first round hash all meta data and round poly data in one go, it saves multiple hash invocations.
let mut jolt_transcript = KeccakTranscript::new(b"new",mle_poly_size.try_into().unwrap(), nof_mle_poly.try_into().unwrap(), claimed_sum,seed_rng,entry0);
println!("jolt transcript initial state{:?}", jolt_transcript.state);
//get alpha 0
let alpha0 = jolt_transcript.challenge_scalar::<Fr>();
println!("alpha0: {:?}", alpha0);
//icicle transcript
// append entry_DS = [domain_separator_label || proof.mle_polynomial_size || proof.degree || public (hardcoded?) ||
// claimed_sum]
let mut ds: Vec<u8> =b"new".to_vec();
ds.append(mle_poly_size.to_le_bytes().to_vec().as_mut());
ds.append(nof_mle_poly.to_le_bytes().to_vec().as_mut());
ds.append(claimed_sum.to_bytes_le().to_vec().as_mut());
ds.append(seed_rng.to_bytes_le().to_vec().as_mut());
// build entry_0 = [entryDS|| round_poly_label || r_0[x].len() || k=0 || r_0[x]]
ds.append(b"begin_append_vector".to_vec().as_mut());
ds.append(proof_round_polys_jolt[0].len().to_le_bytes().to_vec().as_mut());
ds.append(0u32.to_le_bytes().to_vec().as_mut());
ds.append(proof_round_polys_jolt[0][0].to_bytes_le().to_vec().as_mut());
ds.append(proof_round_polys_jolt[0][1].to_bytes_le().to_vec().as_mut());

let mut output = vec![0u8; 32];
let hasher_icicle = Keccak256::new(0).unwrap();
hasher_icicle.hash(HostSlice::from_slice(&ds), &HashConfig::default(), HostSlice::from_mut_slice(&mut output)).unwrap();
println!("icicle transcript initial state {:?}", output);
let alpha0icicle = Fr::from_bytes_le(&output);
println!("alpha0 ICICLE: {:?}", alpha0icicle);


assert_eq!(proof_round_polys_jolt[1][0]+proof_round_polys_jolt[1][1],
    proof_round_polys_jolt[0][0]+ (proof_round_polys_jolt[0][1]-proof_round_polys_jolt[0][0])*alpha0icicle, "First round poly mismatch");

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