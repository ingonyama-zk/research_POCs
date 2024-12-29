use std::iter;

use icicle_core::
    {field::Field, hash::{self, HashConfig, Hasher, HasherHandle}, merkle::{MerkleProof,MerkleTree,MerkleTreeConfig,PaddingPolicy}, polynomials::UnivariatePolynomial, traits::{Arithmetic,FieldConfig,FieldImpl,GenerateRandom,MontgomeryConvertible}, vec_ops::*
    };
use icicle_hash::blake2s::Blake2s;
use icicle_runtime::memory::HostSlice;

pub struct Friconfig{
    pub(crate) blow_up_factor: usize,
    pub (crate) folding_factor: usize,
    pub(crate) pow_bits: usize,
    pub(crate) num_queries: usize,
    pub(crate) stopping_degree: usize,
    //pub (crate) Commitment_scheme: Merkle/MMCS,
}

pub struct commit_config <F:FieldImpl>{
    pub(crate) hasher: HasherHandle,
    pub (crate) hasher_DT: F,
    pub(crate) compression: HasherHandle,
    pub (crate) compression_DT: F,
    pub(crate) arity: usize,
    pub (crate) padding_policy: PaddingPolicy,

}
pub struct Friproof<F:FieldImpl> {
    pub commit_phase_commits: Vec<F>,
    pub query_leafs: Vec<Vec<F>>, // [q1 :[leaf,leafsym], q2: [leaf,leafsym], q3: [leaf,leafsym]...]
    pub query_proofs: Vec<MerkleProof>,
    pub final_poly: F,
    pub pow_nonce: u64,
}

// impl<F: FieldImpl> Friproof<F> {
//     pub fn verify_path (
//         leaf: F,
//         query_proof: MerkleProof,
//         root: F,
//     ) -> bool {
//         //[sibling1, sibling 2]
//         let path = query_proof.get_path::<F>();
//         let path_slice = HostSlice::from_slice(path);
//         let leaf_size = 4;//for 32 bit fields
//         let hasher = Blake2s::new(leaf_size).unwrap();
//         let mut output = vec![F::zero(); hasher.output_size().try_into().unwrap()];

//         let compress = Blake2s::new(hasher.output_size()*2).unwrap();
//         let mut output_compress = vec![F::zero();compress.output_size().try_into().unwrap()];
        
//         let binding = [leaf];
//         let leaf_slice = HostSlice::from_slice(&binding);
//         let mut output_slice = HostSlice::from_mut_slice(&mut output);
//         let leaf_hash = hasher.hash(leaf_slice, &HashConfig::default(), output_slice).unwrap();
//         let l = path.len();
//         for i in 0..l-1 {
//             let path_element_slice = HostSlice::from_slice(std::slice::from_ref(&path_slice[i]));
//             let mut compressor = compress.hash(path_element_slice, &HashConfig::default(), );

//         }
//         false
//     }
// }

pub struct Frilayerdata <F:FieldImpl> {
    layer_code_words: Vec<Vec<F>>,
    layer_trees: Vec<MerkleTree>,
}

pub struct current_layer <F:FieldImpl>{
    pub current_code_word: Vec<F>,
}

impl <F: FieldImpl+ Arithmetic> current_layer<F>
where
    F::Config: VecOps<F>,
{

    pub fn fold_evals(
    &mut self,
    rou: F,
    coset_gen: F,
    alpha: F,
    ) -> Vec<F>
    {    
        let rou_inv = rou.inv();    
        let len:usize = self.current_code_word.len();
        let lenu64:u64 = len.try_into().unwrap();
        let gen = F::one();
        
        //(1,w^{-1},w^{-2},...)
        let mut rou_inv_vec: Vec<F> = iter::successors(Some(gen), |p| Some(*p * rou_inv))
            .take(len/2)
            .collect();
    
        let mut rou_inv_slicebc =HostSlice::from_mut_slice(&mut rou_inv_vec[..]);
        let v_slice = HostSlice::from_mut_slice(&mut self.current_code_word[..]);
       //init arrays
        let mut v1 = vec![F::zero(); len / 2];
        let mut v2 = vec![F::zero(); len / 2];
        let mut odd = vec![F::zero(); len / 2];
        let mut even = vec![F::zero(); len / 2];
        let mut even1 = vec![F::zero(); len / 2];
        let mut even2 = vec![F::zero(); len / 2];
        let mut res = vec![F::zero(); len / 2];
        let mut resf = vec![F::zero(); len / 2];
        let mut rouf=  vec![F::zero(); len / 2];  
        let mut odd_slice = HostSlice::from_mut_slice(&mut odd[..]);
        let mut even_slice =  HostSlice::from_mut_slice(&mut even[..]);
        let mut even1_slice =  HostSlice::from_mut_slice(&mut even1[..]);
        let mut even2_slice =  HostSlice::from_mut_slice(&mut even2[..]);
        let mut res_slice =  HostSlice::from_mut_slice(&mut res[..]);
        let mut resf_slice =  HostSlice::from_mut_slice(&mut resf[..]);
        let v1_slice = HostSlice::from_mut_slice(&mut v1[..]);
        let v2_slice = HostSlice::from_mut_slice(&mut v2[..]);
    
        let mut rou_inv_slice = HostSlice::from_mut_slice(&mut rouf[..]);
        let cfg = VecOpsConfig::default();
        // g^{-1}(1,w^{-1},w^{-2},...)
        scalar_mul(HostSlice::from_slice(&mut [coset_gen.inv()]), rou_inv_slicebc, rou_inv_slice, &cfg).unwrap();
        //get odd and even slice
        let _ = slice(v_slice, 0, 1, lenu64, lenu64/2, &cfg, v1_slice);
        let _ = slice(v_slice, lenu64/2, 1, lenu64, lenu64/2, &cfg, v2_slice);
        //o=v1(x)+v2(-x)
        add_scalars(v1_slice, v2_slice,odd_slice, &cfg).unwrap();
        //e=v1(x)-v2(-x)
        sub_scalars(v1_slice, v2_slice, even_slice, &cfg).unwrap();
        //e1= e* w^{-i}
        mul_scalars(rou_inv_slice, even_slice, even1_slice, &cfg).unwrap();
        //e2=e* w^{-i}*alpha
        scalar_mul(HostSlice::from_slice(&mut [alpha]), even1_slice, even2_slice, &cfg).unwrap();
        //o+e2
        add_scalars(odd_slice, even2_slice, res_slice, &cfg).unwrap();
        let two_inv:F= F::from_u32(2).inv();
        scalar_mul(HostSlice::from_mut_slice(&mut [two_inv]), res_slice, resf_slice, &cfg).unwrap();
        let res: Vec<F> = resf_slice.as_slice().to_vec();
        res
    }

    pub fn commit(
        &mut self
    ) -> MerkleTree
    { 
        let leaf_size:u64 = 4;//for 32 bit fields
        //to replace this with generics and merkle config
        let hasher = Blake2s::new(leaf_size).unwrap();
        let compress = Blake2s::new(hasher.output_size()*2).unwrap();
        let tree_height = self.current_code_word.len().ilog2() as usize;
    
        let layer_hashes: Vec<&Hasher> = std::iter::once(&hasher)
            .chain(std::iter::repeat(&compress).take(tree_height))
            .collect();
        //binary tree
        let config = MerkleTreeConfig::default();
        
        let poly_slice = self.current_code_word.as_mut_slice();
        let merkle_tree = MerkleTree::new(&layer_hashes, leaf_size, 0).unwrap();
        merkle_tree
            .build(HostSlice::from_slice(poly_slice), &config).unwrap();
        merkle_tree
    }
    pub fn test_query(
        &mut self,
        query_index: u64,
        layer_tree: &MerkleTree,
    ) -> MerkleProof {
        let config = MerkleTreeConfig::default();
        let code_slice = HostSlice::<F>::from_slice(&self.current_code_word);
        layer_tree.get_proof(code_slice, query_index, false, &config).unwrap() 
}
}


// s