use icicle_hash::keccak::Keccak256;
use icicle_core::merkle::{MerkleProof, MerkleTree, MerkleTreeConfig};
use icicle_core::hash::HashConfig;
use icicle_runtime::memory::HostSlice;
use rand::Rng;

const N: usize = 256; // bits in hash/output
const SK_SIZE: usize = 32; // bytes per secret

fn hash(input: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    let hasher = Keccak256::new(0).unwrap();
    let _ = hasher.hash(HostSlice::from_slice(input), &HashConfig::default(), HostSlice::from_mut_slice(&mut out));
    out
}

fn build_tree(leaves: Vec<[u8; 32]>, config: &MerkleTreeConfig) -> (MerkleTree, Vec<u8>) {
    let leaf_size = 32u64;
    let leaf_bytes: Vec<u8> = leaves.iter().flat_map(|h| h.iter()).copied().collect();
    let hasher = Keccak256::new(leaf_size).unwrap();
    let compress = Keccak256::new(leaf_size * 2).unwrap();
    let tree_height = (leaves.len() as f64).log2() as usize;
    let layer_hashes = std::iter::once(&hasher)
        .chain(std::iter::repeat(&compress).take(tree_height))
        .collect::<Vec<_>>();
    let tree = MerkleTree::new(&layer_hashes[..=tree_height], leaf_size, 0).unwrap();
    tree.build(HostSlice::from_slice(&leaf_bytes), config).unwrap();
    (tree, leaf_bytes)
}

fn sign(
    message: &[u8],
    sk: &[[u8; 32]],
    tree: &MerkleTree,
    leaf_bytes: &[u8],
    config: &MerkleTreeConfig,
) -> (Vec<[u8; 32]>, Vec<MerkleProof>) {
    let msg_hash = hash(message);
    let mut sig = Vec::with_capacity(N);
    let mut proofs = Vec::with_capacity(N);
    for (i, bit) in msg_hash.iter().flat_map(|b| (0..8).rev().map(move |j| (b >> j) & 1)).enumerate() {
        let idx = i * 2 + (bit as usize);
        sig.push(sk[idx]);
        let proof = tree.get_proof(HostSlice::from_slice(leaf_bytes), idx as u64, false, config).unwrap();
        proofs.push(proof);
    }
    (sig, proofs)
}

fn verify(
    message: &[u8],
    sig: &[[u8; 32]],
    proofs: &[MerkleProof],
    tree_height: usize,
    expected_root: &[u8],
) -> bool {
    let msg_hash = hash(message);
    let leaf_size = 32u64;
    let hasher = Keccak256::new(leaf_size).unwrap();
    let compress = Keccak256::new(leaf_size * 2).unwrap();
    let layer_hashes = std::iter::once(&hasher)
        .chain(std::iter::repeat(&compress).take(tree_height))
        .collect::<Vec<_>>();
    let verifier_tree = MerkleTree::new(&layer_hashes, leaf_size, 0).unwrap();

    for (i, bit) in msg_hash.iter().flat_map(|b| (0..8).rev().map(move |j| (b >> j) & 1)).enumerate() {
        let expected_index = i * 2 + bit as usize;
        let expected_leaf = hash(&sig[i]);
        let (leaf, index) = proofs[i].get_leaf::<u8>();
        let root = proofs[i].get_root::<u8>();

        if leaf != expected_leaf {
            println!(
                "❌ Leaf mismatch at bit {} (i = {}): expected hash {:?}, got {:?}",
                bit, i, expected_leaf, leaf
            );
            return false;
        }

        if index != expected_index as u64 {
            println!(
                "❌ Index mismatch at bit {} (i = {}): expected index {}, got {}",
                bit, i, expected_index, index
            );
            return false;
        }

        if root != expected_root {
            println!(
                "❌ Root mismatch at bit {} (i = {}): expected root 0x{}, got 0x{}",
                bit,
                i,
                hex::encode(expected_root),
                hex::encode(root)
            );
            return false;
        }

        if !verifier_tree.verify(&proofs[i]).unwrap_or(false) {
            println!("❌ Merkle path invalid at bit {} (i = {})", bit, i);
            return false;
        }
    }

    println!("✅ All proofs passed");
    true
}


fn main() {
    // === Keygen === One time per message
    let mut rng = rand::rng();
    let mut sk = [[0u8; SK_SIZE]; N * 2];
    for s in sk.iter_mut() {
        rng.fill(s);
    }

    let leaves: Vec<[u8; 32]> = sk.iter().map(|s| hash(s)).collect();
    let merkle_config = MerkleTreeConfig::default();
    let (tree, leaf_bytes) = build_tree(leaves, &merkle_config);
    let root = tree.get_root::<u8>().unwrap();
    let tree_height = (N * 2) as f64;
    let tree_height = tree_height.log2() as usize;

    println!("Public key (Merkle root): 0x{}", hex::encode(&root));

    // === Signing ===
    let message = b"hello, world!";
    println!("Signing message: {}", String::from_utf8_lossy(message));
    let (sig, proofs) = sign(message, &sk, &tree, &leaf_bytes, &merkle_config);
    println!("Merkle based Signature generated for message. ");

    // === Verification ===
    let valid = verify(message, &sig, &proofs, tree_height, &root);
    println!("Signature valid? {}", valid);

    // === Tampered Message ===
    let tampered = b"hello, world !";
    println!("Tampering message: {}", String::from_utf8_lossy(tampered));
    let valid_tampered = verify(tampered, &sig, &proofs, tree_height, &root);
    println!("Signature valid for tampered message? {}", valid_tampered);
}
