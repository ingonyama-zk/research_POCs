use std::u64;

#[cfg(test)] 
use fri_poc::transcript::TranscriptProtocol;
use fri_poc::utils::{hash_fuse, num_leading_zeros, proof_of_work, try_load_and_set_backend_gpu};
use icicle_babybear::field::ScalarField as Fr;
use icicle_runtime::memory::HostSlice;
use merlin::{Transcript,TranscriptRngBuilder};
use icicle_core::{
    hash::{HashConfig, Hasher}, 
    merkle::{MerkleTree, MerkleTreeConfig,MerkleProof,PaddingPolicy}, 
    traits::FieldImpl,
};
use icicle_hash::keccak::Keccak256;
use hex::encode;



#[test] 
 
 fn test_FS_merlin_encoding() {

   let mut new_transcript = Transcript::new(b"test");
   let public = Fr::from_u32(99).to_bytes_le();
   TranscriptProtocol::<Fr>::fri_domain_sep(&mut new_transcript, b"friv1", 2u64, 1u64,public.clone());
   
   let t = Fr::from_u32(3);
   TranscriptProtocol::<Fr>::append_root(&mut new_transcript,b"scalar",&t);
   let challenge = TranscriptProtocol::<Fr>::challenge_scalar(&mut new_transcript, b"challenge");
   println!("transcript challenge from strobe128: {:?}",challenge);

//    ---- test_FS stdout ----
//    Initialize STROBE-128(4d65726c696e2076312e30)   # b"Merlin v1.0"
//    meta-AD : 646f6d2d736570 || LE32(4)     # b"dom-sep"
//         AD : 74657374      # b"test"
//    meta-AD :  || LE32(5)   # b""
//         AD : 6672697631    # b"friv1"
//    meta-AD : 496e69745f446f6d61696e5f53697a65 || LE32(8)   # b"Init_Domain_Size"
//         AD : 0200000000000000      # b""
//    meta-AD : 7075626c6963 || LE32(4)       # b"public"
//         AD : 63000000      # b"c"
//    meta-AD : 7363616c6172 || LE32(4)       # b"scalar"
//         AD : 03000000      # b""
//    meta-AD : 6368616c6c656e6765 || LE32(64)        # b"challenge"
//         PRF: a63e776d4f41308defb12d496a4f9467ab571dc5cbe65e133bb636a0ca57c5d6729c4e2f381ba09f8ded56ce4c396dff1dff5c967283854f5f2fdf03a76c6367
//    transcript challenge: 0x6d773ea6
// to reproduce above: in cargo enable debug mode in merlin, comment out hex in test start
//or comment out code below
   println!("mimic merlin with keccak\n");
   let mut buf = vec![0u8;64];
   let mut input =  vec![];
   input.push(encode(b"Merlin v1.0"));
   println!("input[0]: {:?}", input[0]);
   input.push(encode(b"dom-sep"));
   input.push(encode((b"test".len() as u32).to_le_bytes()));
   println!("input[1..=2]: {:?}", &input[1..=2].to_vec());
   input.push(encode(b"test"));
   println!("input[3]: {:?}", &input[3]);
   input.push(encode((b"friv1".len() as u32).to_le_bytes()));
   println!("input[4]: {:?}", &input[4]);
   input.push(encode(b"friv1"));
   println!("input[5]: {:?}", input[5]);
   input.push(encode(b"Init_Domain_Size"));
   input.push(encode((2u64.to_le_bytes().len() as u32).to_le_bytes()));
   println!("input[6..=7]: {:?}", &input[6..=7].to_vec());
   input.push(encode(2u64.to_le_bytes()));
   println!("input[8]: {:?}", input[8]);
   input.push(encode(b"public"));
   input.push(encode((public.clone().len() as u32).to_le_bytes()));
   println!("input[9..=10]: {:?}", &input[9..=10].to_vec());
   input.push(encode(public.clone()));
   println!("input[11]: {:?}", input[11]);
   input.push(encode(b"scalar"));
   input.push(encode((t.clone().to_bytes_le().len() as u32).to_le_bytes()));
   println!("input[12..=13]: {:?}", &input[12..=13].to_vec());
   input.push(encode(t.clone().to_bytes_le()));
   println!("input[14]: {:?}", input[14]);
   input.push(encode(b"challenge"));

   

   let bind = input.concat();
   let hash_in = bind.as_bytes();
   let hasher:Hasher = Keccak256::new(0).unwrap();
   let cfg: HashConfig = HashConfig::default();
   
   hasher.hash(HostSlice::from_slice(hash_in),
                &cfg, 
                HostSlice::from_mut_slice(&mut buf)).unwrap();
    input.push(encode((buf.clone().len() as u32).to_le_bytes()));
    println!("input[15..=16]: {:?}", input[15..=16].to_vec());
    println!("keccak prf:{:?}",encode(buf.clone()));
    println!("challenge prf: {:?}", Fr::from_bytes_le(&buf));



 }   

#[test]
//Shitty proof of work
fn test_pow() {
   try_load_and_set_backend_gpu();
   let mut new_transcript = Transcript::new(b"test");
   let public = Fr::from_u32(99).to_bytes_le();
   TranscriptProtocol::<Fr>::fri_domain_sep(&mut new_transcript, b"friv1", 2u64, 1u64, public.clone());
   
   let t = Fr::from_u32(3);
   TranscriptProtocol::<Fr>::append_root(&mut new_transcript,b"scalar",&t);
   let challenge = TranscriptProtocol::<Fr>::challenge_scalar(&mut new_transcript, b"challenge");
   println!("transcript challenge: {:?}",challenge);

   let pow_bits:usize = 24;
   let nonce = proof_of_work(pow_bits, challenge);
   println!("nonce {:?} ",nonce );
   let out: Vec<u8> = hash_fuse(challenge.to_bytes_le(), nonce.to_le_bytes().to_vec());
   let out_lead_zeros: usize = num_leading_zeros(out);
   assert_eq!(out_lead_zeros,pow_bits);
   
}