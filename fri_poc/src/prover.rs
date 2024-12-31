use icicle_core::
    {field::Field,
    hash::{HashConfig,Hasher},
    merkle::{MerkleProof,MerkleTree,MerkleTreeConfig,PaddingPolicy},
    polynomials::UnivariatePolynomial,
    traits::{Arithmetic,FieldConfig,FieldImpl,GenerateRandom,MontgomeryConvertible},
    };

use merlin::Transcript;
use crate::{data_structures::*,transcript::*, };


pub fn prove<F:FieldImpl>(
    fri_config: Friconfig,
    commit_config: commit_config<F>,
    fri_layer_data: Frilayerdata<F>,
    transcript: &mut Transcript,
    input_data: Vec<F>,// can be in coeffs or evals
    is_coeff: bool,
) -> Friproof<F> {

    //init transcript
TranscriptProtocol::<F>::fri_domain_sep(
    transcript, b"Shitty_FRI", 
    (input_data.len()*fri_config.blow_up_factor).try_into().unwrap(),
    b"public".to_vec()
);
if is_coeff {
    
}

  
Friproof { commit_phase_commits: todo!(), 
            query_leafs: todo!(), 
            query_proofs: todo!(), 
            final_poly: todo!(), 
            pow_nonce: todo!() }
}