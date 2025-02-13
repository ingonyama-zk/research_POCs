use std::time::Instant;

use icicle_core::
    {merkle::{MerkleProof,MerkleTree},
    traits::{Arithmetic,FieldImpl},
    ntt::{NTTDomain,NTT,get_root_of_unity},
    vec_ops::*,
    };
use merlin::Transcript;
use log::{debug,info};
use crate::{data_structures::*,transcript::*,utils::*};

// Prover can input a vector of coefficients, or a vector of evaluations (codeword).
// However, the verifier only knows about the codeword.
// The verifier will convince themselves with a collinearity check and Merkle path authentication.
pub fn prove<F>(
    fri_config: Friconfig,
    transcript: &mut Transcript,
    code_word: Vec<F>, //evals with blow up factor included
) -> Friproof<F> 
where
    F: FieldImpl+Arithmetic,
    F::Config: VecOps<F> + NTTDomain<F> + NTT<F, F>,
{
//let protocol_security = 
let size: usize = code_word.len();
debug!("prover_size {:?}",size);

let precompute_domain = Instant::now();
//Begin precompute domain, if NTT domain was exposed could read it directly
let rou: F = get_root_of_unity::<F>(size.try_into().unwrap());
let rou_inv: F = rou.inv();

let mut inv_domain: Vec<F> = Vec::with_capacity(size / 2);
let mut current = F::one(); // can define coset gen inv here if we want
for _ in 0..(size / 2) {
    inv_domain.push(current);
    current = current*rou_inv; 
}
let two_inv = F::from_u32(2).inv();
//end precompute domain

let num_rounds = size.ilog2()-fri_config.stopping_size.ilog2();
debug!("num_rounds {:?}",num_rounds);

//init transcript
<Transcript as TranscriptProtocol<F>>::fri_domain_sep(
    transcript, b"my_Shitty_FRI", 
    size.try_into().unwrap(),
    b"public".to_vec()
);

let mut frilayerdata: Frilayerdata<F> = Frilayerdata::<F>::new();

let mut friproof: Friproof<F> = Friproof::<F>::new();

let mut current_layer: Current_layer<F> = Current_layer::new();
current_layer.current_code_word= code_word.clone();

info!("prove: Precompute domain inverse {:?}",precompute_domain.elapsed());
let commit_phase = Instant::now();
//commit phase
for j in 0..num_rounds {
    debug!("round: {:?}, current_code_word: {:?}",j, current_layer.current_code_word.clone());
    
    //add current code word to prover list
    frilayerdata.layer_code_words.push(current_layer.current_code_word.clone());
    
    //compute merkle commit
    let current_tree: MerkleTree = current_layer.commit();
    
    //extract root for FS challenge
    let current_root: F  = current_tree.get_root::<F>().unwrap()[0];
    
    //add tree to prover list
    debug!("round: {:?}, Current_root: {:?}", j, current_root);
    frilayerdata.layer_trees.push(current_tree);
    
    //generate fiat shamir challenge
    <Transcript as TranscriptProtocol<F>>::append_root(transcript, b"commit", &current_root);
    let current_challenge:F = <Transcript as TranscriptProtocol<F>>::challenge_scalar(transcript, b"challenge");
    debug!("round: {:?},Current_challenge {:?}",j ,current_challenge);

    //fold without precompute
    //current_layer.current_code_word=current_layer.fold_evals( F::one(), current_challenge);
    let mut inv_domain_layer:Vec<F> = inv_domain.iter().step_by(2_usize.pow(j)).cloned().collect();
    current_layer.current_code_word = current_layer.fold_evals_precompute_domain(&mut inv_domain_layer, &two_inv, current_challenge);
    if current_layer.current_code_word.len() == fri_config.stopping_size {
        friproof.final_poly=current_layer.current_code_word.clone();
        debug!("Final poly {:?}",friproof.final_poly);
        break;
    }
}
info!("prove: Commit phase {:?}",commit_phase.elapsed());
set_backend_cpu();
let pow_time = Instant::now();
//proof of work is not parallelized yet so better do query and pow in cpu
let current_challenge:F = <Transcript as TranscriptProtocol<F>>::challenge_scalar(transcript, b"challenge");
debug!("POW_challenge {:?}",current_challenge);
let nonce: u64 = proof_of_work::<F>(fri_config.pow_bits, current_challenge);
debug!("nonce {:?}",nonce);
info!("prove: pow_phase {:?}",pow_time.elapsed());

//add nonce to transcript
<Transcript as TranscriptProtocol<F>>::add_nonce(transcript, nonce);
//add nonce to proof struct
friproof.pow_nonce =nonce;

//sample queries for foldiing by 2
let seed = <Transcript as TranscriptProtocol<F>>::challenge_scalar(transcript, b"sample").to_bytes_le();
debug!("prover_seed for sampling based on transcript {:?}",seed);
let query_indices: Vec<usize> = generate_samples_in_range(seed, fri_config.num_queries, size/fri_config.folding_factor);
debug!("top layer query_indices {:?}",query_indices);

//query phase
let query_time = Instant::now();
//iterate over indices in query vector
for query_index in query_indices.iter() {
    //for each query index go over all the fri layers,
    for (layer_code_word, layer_tree) in frilayerdata.layer_code_words.iter().zip(frilayerdata.layer_trees.iter()) {
        current_layer.current_code_word = layer_code_word.clone();
        let layer_size = layer_code_word.len();
        let index:u64 = (query_index % layer_size).try_into().unwrap();
        let index_sym:u64 = ((query_index + layer_size / 2) % layer_size).try_into().unwrap();
        let index_proof: MerkleProof = current_layer.layer_query(index, layer_tree);
        let index_sym_proof: MerkleProof = current_layer.layer_query(index_sym, layer_tree);
        friproof.query_proofs.push(vec![index_proof,index_sym_proof]);
    }
    }
info!("prove: query phase {:?}",query_time.elapsed());
drop(frilayerdata);
friproof
}