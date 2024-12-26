use icicle_core::
    {field::Field,
    hash::{HashConfig,Hasher},
    merkle::{MerkleProof,MerkleTree,MerkleTreeConfig,PaddingPolicy},
    polynomials::UnivariatePolynomial,
    traits::{Arithmetic,FieldConfig,FieldImpl,GenerateRandom,MontgomeryConvertible},
    };

pub struct fri_config{
    pub(crate) blow_up_factor: usize,
    pub (crate) folding_factor: usize,
    pub(crate) pow_bits: usize,
    pub(crate) num_queries: usize,
    pub(crate) stopping_degree: usize,
    //pub (crate) Commitment_scheme: Merkle/MMCS,
}
pub struct Friproof<F:FieldImpl> {
    pub commit_phase_commits: Vec<F>,
    pub query_leafs: Vec<Vec<F>>, // [q1 :[leaf,leafsym], q2: [leaf,leafsym], q3: [leaf,leafsym]...]
    pub query_proofs: Vec<MerkleProof>,
    pub final_poly: F,
    pub pow_nonce: u64,
}

pub struct Frilayer <F:FieldImpl> {
    layer_code_words: Vec<Vec<F>>,
    layer_commitments: Vec<MerkleTree>,
}