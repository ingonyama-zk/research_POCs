use core::num;

use icicle_core::
    {field::Field,
    hash::{HashConfig,Hasher},
    merkle::{MerkleProof,MerkleTree,MerkleTreeConfig,PaddingPolicy},
    polynomials::UnivariatePolynomial,
    traits::{Arithmetic,FieldConfig,FieldImpl,GenerateRandom,MontgomeryConvertible},
    ntt::{get_root_of_unity, initialize_domain, ntt, ntt_inplace, NTTConfig, NTTInitDomainConfig,NTTDir,NTTDomain,NTT},
    };

use icicle_runtime::memory::HostSlice;
use merlin::Transcript;
use crate::{data_structures::*,transcript::*,utils::*};

/// Prover can input a vector of coefficients, or a vector of evaluations (codeword).
/// However, the verifier only knows about the codeword.
/// The verifier will convince themselves with a collinearity check and Merkle path authentication.
pub fn prove<F:FieldImpl>(
    fri_config: Friconfig,
    fri_layer_data: Frilayerdata<F>,// struct for prover to keep track for queries
    transcript: &mut Transcript,
    input_data: Vec<F>,// can be in coeffs or evals
    is_coeff: bool,
) -> Friproof<F> 
where
        F: FieldImpl,
        <F as FieldImpl>::Config: NTTDomain<F> +NTT<F,F>,
{
//to do
//let protocol_security = 
let size: usize = input_data.len()*fri_config.blow_up_factor;

let mut code_word: Vec<F> = if is_coeff {
    //degree =2^k-1, i,e size = 2^k
    //if input is in coeff form and codeword required is 2^k*blowup
    coeff_to_eval_blowup::<F>(input_data.clone(), size)
} else { 
    //eval = 2^k and we need size = 2^k*blowup
    eval_to_eval_blowup::<F>(input_data.clone(), size)
};
let num_rounds = size.ilog2()-fri_config.stopping_size.ilog2();

//init transcript
TranscriptProtocol::<F>::fri_domain_sep(
    transcript, b"Shitty_FRI", 
    size.try_into().unwrap(),
    num_rounds.try_into().unwrap(),
    b"public".to_vec()
);
 //prover stores data here for query retrieval
let mut frilayerdata :Frilayerdata<F>   = Frilayerdata {
    layer_code_words: Vec::<Vec<F>>::new(),
    layer_trees: Vec::<MerkleTree>::new(),
};

let friproof: Friproof<F> = Friproof {
    query_proofs: Vec::<MerkleProof>::new(),
    final_poly: Vec::<F>::new(),
    pow_nonce: 0u64,
};

let mut current_layer: Current_layer<F> = Current_layer {
    current_code_word: code_word.clone(),
};
//commit phase
for round in 0..num_rounds-1 {
    frilayerdata.layer_code_words.push(code_word.clone());

}  
Friproof {
            query_proofs: todo!(), 
            final_poly: todo!(), 
            pow_nonce: todo!() }
}