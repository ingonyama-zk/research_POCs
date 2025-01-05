use icicle_core::
    {field::Field,
    hash::{HashConfig,Hasher},
    merkle::{MerkleProof,MerkleTree,MerkleTreeConfig,PaddingPolicy},
    polynomials::UnivariatePolynomial,
    traits::{Arithmetic,FieldConfig,FieldImpl,GenerateRandom,MontgomeryConvertible},
    };

use merlin::Transcript;
use crate::{data_structures::*,transcript::*, };
use icicle_hash::blake2s::Blake2s;


impl<F: FieldImpl> Friproof<F> {
    //checks the path of the query proof
    pub fn verify_path (
        &mut self,
        proof_index: usize,
        tree_height: usize,
    ) -> bool {
    //to replace this with generics and merkle config
    let leaf_size:u64 = (F::one()).to_bytes_le().len().try_into().unwrap();//4 for 32 bit fields
    let hasher = Blake2s::new(leaf_size).unwrap();
    let compress = Blake2s::new(hasher.output_size()*2).unwrap();
    let layer_hashes: Vec<&Hasher> = std::iter::once(&hasher)
        .chain(std::iter::repeat(&compress).take(tree_height))
        .collect();       
    let verifier_tree = MerkleTree::new(&layer_hashes, leaf_size, 0).unwrap();
    verifier_tree.verify(&self.query_proofs[proof_index]).unwrap()
    }
}

pub fn verify <F:FieldImpl>(
    fri_config: Friconfig,
    friproof: Friproof<F>,
    transcript: &mut Transcript,

) -> Result<bool, &'static str>{

// let init_domain_size: usize = 
// let stopping_size: usize = fri_config.stopping_size;

// //init transcript
// TranscriptProtocol::<F>::fri_domain_sep(
//     transcript, b"Shitty_FRI", 
//     init_domain_size.try_into().unwrap(),
//     b"public".to_vec()
// );

// let num_rounds = (init_domain_size.ilog2()-stopping_size.ilog2());
    


    Ok(true)
}