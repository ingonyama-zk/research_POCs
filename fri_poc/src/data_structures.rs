use std::iter;

use icicle_core::{
    bignum::BigNum, hash::Hasher, merkle::{MerkleProof, MerkleTree, MerkleTreeConfig}, ntt::{get_root_of_unity, NTTDomain}, polynomials::UnivariatePolynomial, ring::IntegerRing, traits::{Arithmetic, Invertible}, vec_ops::*
};
use icicle_hash::blake2s::Blake2s;
use icicle_runtime::memory::{HostOrDeviceSlice, HostSlice};
use rand::distr::uniform::UniformSampler;

#[derive(Clone, Copy, Debug)]
pub struct Friconfig {
    pub blow_up_factor: usize,
    pub folding_factor: usize,
    pub pow_bits: usize,
    pub num_queries: usize,
    pub stopping_size: usize, //should be power of two
                              //pub (crate) Commitment_scheme: Merkle/MMCS,
}

//for future
// pub struct commit_config {
//     pub hasher: Hasher,
//     pub hasher_dt: &'static [u8],
//     pub compression: Hasher,
//     pub compression_dt: &'static [u8],
//     pub arity: usize,
//     pub merkle_conf: MerkleTreeConfig,
// }
pub struct Friproof<T> {
    pub query_proofs: Vec<Vec<MerkleProof>>, // contains path, root, leaf.
    pub final_poly: Vec<T>,
    pub pow_nonce: u64,
}

impl<F: Arithmetic+BigNum+Invertible> Default for Friproof<F> {
    fn default() -> Self {
        Self::new()
    }
}

impl<F: Arithmetic+BigNum+Invertible> Friproof<F> {
    pub fn new() -> Self {
        Friproof {
            query_proofs: Vec::<Vec<MerkleProof>>::new(),
            final_poly: Vec::<F>::new(),
            pow_nonce: 0u64,
        }
    }
}

pub struct Frilayerdata<T> {
    pub layer_code_words: Vec<Vec<T>>,
    pub layer_trees: Vec<MerkleTree>,
}

impl<F: Arithmetic+BigNum+Invertible> Default for Frilayerdata<F> {
    fn default() -> Self {
        Self::new()
    }
}

impl<F: Arithmetic+BigNum+Invertible> Frilayerdata<F> {
    pub fn new() -> Self {
        Frilayerdata {
            layer_code_words: Vec::<Vec<F>>::new(),
            layer_trees: Vec::<MerkleTree>::new(),
        }
    }
    pub fn total_layers(&self) -> usize {
        self.layer_code_words.len()
    }
}

pub struct Current_layer<T> {
    pub current_code_word: Vec<T>,
}

impl<F> Default for Current_layer<F>
where
    F: Arithmetic + IntegerRing + VecOps<F> + NTTDomain<F>+Invertible,
{
    fn default() -> Self {
        Self::new()
    }
}

impl<F> Current_layer<F>
where
F: Arithmetic + IntegerRing + VecOps<F> + NTTDomain<F>+Invertible,
{
    pub fn new() -> Self {
        Current_layer {
            current_code_word: Vec::<F>::new(),
        }
    }
    pub fn fold_evals_precompute_domain(
        &mut self,
        inv_domain: &mut Vec<F>,
        &two_inv: &F,
        alpha: F,
    ) -> Vec<F> {
        let len: usize = self.current_code_word.len();
        let lenu64: u64 = len.try_into().unwrap();
        let mut rou_inv_slice = HostSlice::from_mut_slice(&mut inv_domain[..]);
        let v_slice = HostSlice::from_mut_slice(&mut self.current_code_word[..]);
        //init arrays
        let mut v1 = vec![F::zero(); len / 2];
        let mut v2 = vec![F::zero(); len / 2];
        let mut odd = vec![F::zero(); len / 2];
        let mut even = vec![F::zero(); len / 2];
        let mut odd1 = vec![F::zero(); len / 2];
        let mut odd2 = vec![F::zero(); len / 2];
        let mut res = vec![F::zero(); len / 2];
        let mut resf = vec![F::zero(); len / 2];
        let mut rouf = vec![F::zero(); len / 2];

        let mut odd_slice = HostSlice::from_mut_slice(&mut odd[..]);
        let mut even_slice = HostSlice::from_mut_slice(&mut even[..]);
        let mut odd1_slice = HostSlice::from_mut_slice(&mut odd1[..]);
        let mut odd2_slice = HostSlice::from_mut_slice(&mut odd2[..]);
        let mut res_slice = HostSlice::from_mut_slice(&mut res[..]);
        let mut resf_slice = HostSlice::from_mut_slice(&mut resf[..]);
        let v1_slice = HostSlice::from_mut_slice(&mut v1[..]);
        let v2_slice = HostSlice::from_mut_slice(&mut v2[..]);

        let cfg = VecOpsConfig::default();
        //get odd and even slice
        let _ = slice(v_slice, 0, 1, lenu64, lenu64 / 2, &cfg, v1_slice);
        let _ = slice(v_slice, lenu64 / 2, 1, lenu64, lenu64 / 2, &cfg, v2_slice);
        //e=v1(x)+v2(-x)
        add_scalars(v1_slice, v2_slice, even_slice, &cfg).unwrap();
        //o=v1(x)-v2(-x)
        sub_scalars(v1_slice, v2_slice, odd_slice, &cfg).unwrap();
        let mut teven = vec![F::zero(); len / 2];
        let mut teven_slice = HostSlice::from_mut_slice(&mut teven[..]);
        let mut todd = vec![F::zero(); len / 2];
        let mut todd_slice = HostSlice::from_mut_slice(&mut todd[..]);
        let mut todd1 = vec![F::zero(); len / 2];
        let mut todd_slice1 = HostSlice::from_mut_slice(&mut todd1[..]);
        let mut todd2 = vec![F::zero(); len / 2];
        let mut todd_slice2 = HostSlice::from_mut_slice(&mut todd2[..]);
        let two_inv: F = (F::from_u32(2)).inv();
        scalar_mul(
            HostSlice::from_slice(&mut [two_inv]),
            even_slice,
            teven_slice,
            &cfg,
        )
        .unwrap();
        scalar_mul(
            HostSlice::from_slice(&mut [two_inv]),
            odd_slice,
            todd_slice,
            &cfg,
        )
        .unwrap();
        mul_scalars(rou_inv_slice, todd_slice, todd_slice1, &cfg).unwrap();
        scalar_mul(
            HostSlice::from_slice(&mut [alpha]),
            todd_slice1,
            todd_slice2,
            &cfg,
        )
        .unwrap();
        add_scalars(teven_slice, todd_slice2, res_slice, &cfg).unwrap();
        let res: Vec<F> = res_slice.as_slice().to_vec();
        res
    }

    //this is real shit fold
    pub fn fold_evals(&mut self, coset_gen: F, alpha: F) -> Vec<F> {
        let len: usize = self.current_code_word.len();
        let mut rou: F = get_root_of_unity::<F>(len.try_into().unwrap()).unwrap();
        let mut rou_inv = rou.inv();
        let lenu64: u64 = len.try_into().unwrap();
        let gen = F::one();

        //(1,w^{-1},w^{-2},...)
        let mut rou_inv_vec: Vec<F> = iter::successors(Some(gen), |p| Some(*p * rou_inv))
            .take(len / 2)
            .collect();
        //        println!("rou_inv_vec {:?}",rou_inv_vec.clone());
        let mut rou_inv_slicebc = HostSlice::from_mut_slice(&mut rou_inv_vec[..]);
        let v_slice = HostSlice::from_mut_slice(&mut self.current_code_word[..]);
        //init arrays
        let mut v1 = vec![F::zero(); len / 2];
        let mut v2 = vec![F::zero(); len / 2];
        let mut odd = vec![F::zero(); len / 2];
        let mut even = vec![F::zero(); len / 2];
        let mut odd1 = vec![F::zero(); len / 2];
        let mut odd2 = vec![F::zero(); len / 2];
        let mut res = vec![F::zero(); len / 2];
        let mut resf = vec![F::zero(); len / 2];
        let mut rouf = vec![F::zero(); len / 2];
        let mut odd_slice = HostSlice::from_mut_slice(&mut odd[..]);
        let mut even_slice = HostSlice::from_mut_slice(&mut even[..]);
        let mut odd1_slice = HostSlice::from_mut_slice(&mut odd1[..]);
        let mut odd2_slice = HostSlice::from_mut_slice(&mut odd2[..]);
        let mut res_slice = HostSlice::from_mut_slice(&mut res[..]);
        let mut resf_slice = HostSlice::from_mut_slice(&mut resf[..]);
        let v1_slice = HostSlice::from_mut_slice(&mut v1[..]);
        let v2_slice = HostSlice::from_mut_slice(&mut v2[..]);

        let mut rou_inv_slice = HostSlice::from_mut_slice(&mut rouf[..]);
        let cfg = VecOpsConfig::default();
        // g^{-1}(1,w^{-1},w^{-2},...)
        scalar_mul(
            HostSlice::from_slice(&mut [coset_gen.inv()]),
            rou_inv_slicebc,
            rou_inv_slice,
            &cfg,
        )
        .unwrap();
        //get odd and even slice
        let _ = slice(v_slice, 0, 1, lenu64, lenu64 / 2, &cfg, v1_slice);
        let _ = slice(v_slice, lenu64 / 2, 1, lenu64, lenu64 / 2, &cfg, v2_slice);
        //e=v1(x)+v2(-x)
        add_scalars(v1_slice, v2_slice, even_slice, &cfg).unwrap();
        //o=v1(x)-v2(-x)
        sub_scalars(v1_slice, v2_slice, odd_slice, &cfg).unwrap();
        //o1= o* w^{-i}
        /////
        let mut teven = vec![F::zero(); len / 2];
        let mut teven_slice = HostSlice::from_mut_slice(&mut teven[..]);
        let mut todd = vec![F::zero(); len / 2];
        let mut todd_slice = HostSlice::from_mut_slice(&mut todd[..]);
        let mut todd1 = vec![F::zero(); len / 2];
        let mut todd_slice1 = HostSlice::from_mut_slice(&mut todd1[..]);
        let mut todd2 = vec![F::zero(); len / 2];
        let mut todd_slice2 = HostSlice::from_mut_slice(&mut todd2[..]);
        let two_inv: F = (F::from_u32(2)).inv();
        scalar_mul(
            HostSlice::from_slice(&mut [two_inv]),
            even_slice,
            teven_slice,
            &cfg,
        )
        .unwrap();
        scalar_mul(
            HostSlice::from_slice(&mut [two_inv]),
            odd_slice,
            todd_slice,
            &cfg,
        )
        .unwrap();
        mul_scalars(rou_inv_slice, todd_slice, todd_slice1, &cfg).unwrap();
        scalar_mul(
            HostSlice::from_slice(&mut [alpha]),
            todd_slice1,
            todd_slice2,
            &cfg,
        )
        .unwrap();
        add_scalars(teven_slice, todd_slice2, res_slice, &cfg).unwrap();
        let res: Vec<F> = res_slice.as_slice().to_vec();
        res
    }

    pub fn commit(&mut self) -> MerkleTree {
        //to replace this with generics and merkle config
        let leaf_size: u64 = (F::one()).to_bytes_le().len().try_into().unwrap(); //4 for 32 bit fields
        let no_of_leaves = self.current_code_word.len();
        let hasher = Blake2s::new(leaf_size).unwrap();
        let compress = Blake2s::new(hasher.output_size() * 2).unwrap();
        let tree_height = no_of_leaves.ilog2() as usize;
        let layer_hashes: Vec<&Hasher> = std::iter::once(&hasher)
            .chain(std::iter::repeat(&compress).take(tree_height))
            .collect();
        let poly_slice: &mut [F] = self.current_code_word.as_mut_slice();
        let merkle_config = MerkleTreeConfig::default();
        let merkle_tree = MerkleTree::new(&layer_hashes, leaf_size, 0).unwrap();
        merkle_tree
            .build(HostSlice::from_slice(poly_slice), &merkle_config)
            .unwrap();
        merkle_tree
    }
    pub fn layer_query(&mut self, query_index: u64, layer_tree: &MerkleTree) -> MerkleProof {
        let config = MerkleTreeConfig::default();
        let code_slice = HostSlice::<F>::from_slice(&self.current_code_word);
        layer_tree
            .get_proof(code_slice, query_index, false, &config)
            .unwrap()
    }
    ///for diagnostic: This uses the actual tree, so if it didnt pass
    /// it indicates an error in the commit part or merkle definition.
    pub fn test_verify_path(&mut self, layer_query_proof: MerkleProof) -> bool {
        //to replace this with generics and merkle config
        let leaf_size: u64 = (F::one()).to_bytes_le().len().try_into().unwrap(); //4 for 32 bit fields
        let hasher = Blake2s::new(leaf_size).unwrap();
        let compress = Blake2s::new(hasher.output_size() * 2).unwrap();
        let layer_hashes: Vec<&Hasher> = std::iter::once(&hasher)
            .chain(std::iter::repeat(&compress).take(self.current_code_word.len().ilog2() as usize))
            .collect();
        let verifier_tree = MerkleTree::new(&layer_hashes, leaf_size, 0).unwrap();
        let result = verifier_tree.verify(&layer_query_proof);
        println!("result prover {:?}", result);
        result.unwrap()
    }
}

// s
