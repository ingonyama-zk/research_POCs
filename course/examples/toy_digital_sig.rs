use icicle_hash::keccak::Keccak256;
use icicle_core::merkle::{MerkleProof, MerkleTree, MerkleTreeConfig};
use icicle_core::hash::HashConfig;
use icicle_runtime::memory::HostSlice;
use rand::Rng;

const N: usize = 256; // bits in hash/output
const SK_SIZE: usize = 32; // bytes per secret

/// Hash function wrapper using Keccak256
fn hash(input: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    let hasher = Keccak256::new(0).unwrap();
    let _ = hasher.hash(HostSlice::from_slice(input), &HashConfig::default(), HostSlice::from_mut_slice(&mut out));
    out
}

/// Build a Merkle tree from leaf hashes
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

/// Sign a message using the one-time signature scheme
/// WARNING: This reveals secret keys! Each key can only be used ONCE!
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
    
    // For each bit in the message hash, reveal the corresponding secret key
    for (i, bit) in msg_hash.iter().flat_map(|b| (0..8).rev().map(move |j| (b >> j) & 1)).enumerate() {
        let idx = i * 2 + (bit as usize);  // Select key based on bit value (0 or 1)
        sig.push(sk[idx]);  // CRITICAL: This reveals the secret key!
        let proof = tree.get_proof(HostSlice::from_slice(leaf_bytes), idx as u64, false, config).unwrap();
        proofs.push(proof);
    }
    (sig, proofs)
}

/// Verify a signature against a message
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

/// STUDENT EXERCISE 1: Analyze key reuse vulnerability
/// This function demonstrates what happens when you try to sign two different messages
/// with the same key pair. Students should understand why this breaks security.
fn exercise_1_key_reuse_attack(sk: &[[u8; 32]], tree: &MerkleTree, leaf_bytes: &[u8], config: &MerkleTreeConfig) {
    println!("\n=== EXERCISE 1: Key Reuse Attack ===");
    println!("🚨 WARNING: This demonstrates why you cannot reuse keys in this scheme!");
    
    let message1 = b"message one";
    let message2 = b"message two";
    
    println!("Message 1: {}", String::from_utf8_lossy(message1));
    println!("Message 2: {}", String::from_utf8_lossy(message2));
    
    let (_sig1, _) = sign(message1, sk, tree, leaf_bytes, config);
    let (_sig2, _) = sign(message2, sk, tree, leaf_bytes, config);
    
    let hash1 = hash(message1);
    let hash2 = hash(message2);
    
    let mut revealed_keys = std::collections::HashSet::new();
    let mut key_reuse_count = 0;
    
    // Check for key reuse between the two signatures
    for i in 0..N {
        let bit1 = (hash1[i / 8] >> (7 - (i % 8))) & 1;
        let bit2 = (hash2[i / 8] >> (7 - (i % 8))) & 1;
        
        let idx1 = i * 2 + bit1 as usize;
        let idx2 = i * 2 + bit2 as usize;
        
        // If same position uses different bits, both keys for that position are revealed!
        if bit1 != bit2 {
            key_reuse_count += 1;
            revealed_keys.insert(idx1);
            revealed_keys.insert(idx2);
            
            if key_reuse_count < 5 { // Show first few examples
                println!("🔓 Position {}: bit1={}, bit2={} → Both keys revealed! (indices {} and {})", 
                    i, bit1, bit2, idx1, idx2);
            }
        }
    }
    
    println!("📊 Total positions where both keys revealed: {}", key_reuse_count);
    println!("📊 Total unique keys revealed: {}", revealed_keys.len());
    println!("📊 Percentage of key space compromised: {:.1}%", 
        (revealed_keys.len() as f64 / (N * 2) as f64) * 100.0);
    
    println!("\n💡 STUDENT QUESTION:");
    println!("   Why is revealing both keys for a position a security problem?");
    println!("   What could an attacker do with this information?");
}

/// STUDENT EXERCISE 2: Implement multi-message support
/// Students should modify this to support multiple messages safely
fn exercise_2_multi_message_keygen() -> (Vec<[[u8; 32]; N * 2]>, Vec<Vec<u8>>) {
    println!("\n=== EXERCISE 2: Multi-Message Key Generation ===");
    println!("🎯 TASK: Generate separate key pairs for multiple messages");
    
    let num_messages = 3;
    let mut rng = rand::rng();
    let mut all_keys = Vec::new();
    let mut all_roots = Vec::new();
    
    for i in 0..num_messages {
        // Generate fresh keys for each message
        let mut sk = [[0u8; SK_SIZE]; N * 2];
        for s in sk.iter_mut() {
            rng.fill(s);
        }
        
        let leaves: Vec<[u8; 32]> = sk.iter().map(|s| hash(s)).collect();
        let merkle_config = MerkleTreeConfig::default();
        let (tree, _leaf_bytes) = build_tree(leaves, &merkle_config);
        let root = tree.get_root::<u8>().unwrap();
        
        println!("Key pair {} root: 0x{}", i + 1, hex::encode(&root));
        
        all_keys.push(sk);
        all_roots.push(root.to_vec());
    }
    
    println!("\n💡 STUDENT QUESTIONS:");
    println!("   1. How does storage requirement scale with number of messages?");
    println!("   2. What are the trade-offs compared to traditional signature schemes?");
    println!("   3. How would you implement a more efficient multi-message variant?");
    
    (all_keys, all_roots)
}

/// STUDENT EXERCISE 3: Security analysis
/// Students should analyze the security properties of this scheme
fn exercise_3_security_analysis() {
    println!("\n=== EXERCISE 3: Security Analysis ===");
    println!("🔍 Analyze the security properties of this signature scheme:");
    println!();
    println!("QUESTIONS TO CONSIDER:");
    println!("1. Forgery Resistance:");
    println!("   - Can an attacker forge a signature without knowing secret keys?");
    println!("   - What information does a signature reveal?");
    println!();
    println!("2. Key Size Analysis:");
    println!("   - How many secret keys do we need for 256-bit security?");
    println!("   - What's the total size of the secret key?");
    println!("   - How big is a signature?");
    println!();
    println!("3. Quantum Resistance:");
    println!("   - Is this scheme quantum-resistant? Why or why not?");
    println!("   - What assumptions does security rely on?");
    println!();
    println!("4. Practical Limitations:");
    println!("   - Why is this called a 'toy' implementation?");
    println!("   - What would need to change for production use?");
    
    // Some concrete numbers for analysis
    let secret_key_size = N * 2 * SK_SIZE;
    let signature_size = N * SK_SIZE + N * 32; // Rough estimate for signature + proofs
    
    println!("\n📊 CONCRETE NUMBERS:");
    println!("   Secret key size: {} bytes ({} KB)", secret_key_size, secret_key_size / 1024);
    println!("   Signature size (approx): {} bytes ({} KB)", signature_size, signature_size / 1024);
    println!("   Number of secret values: {}", N * 2);
}

/// STUDENT EXERCISE 4: Implement signature aggregation
/// Students should think about how to make signatures more efficient
fn exercise_4_signature_optimization() {
    println!("\n=== EXERCISE 4: Signature Optimization ===");
    println!("🚀 CHALLENGE: How can we make signatures smaller and more efficient?");
    println!();
    println!("IDEAS TO EXPLORE:");
    println!("1. Merkle Tree Optimization:");
    println!("   - Can we use different tree structures?");
    println!("   - How does tree depth affect proof size?");
    println!();
    println!("2. Compression Techniques:");
    println!("   - Can we compress the revealed keys?");
    println!("   - Are there redundancies in the proofs?");
    println!();
    println!("3. Alternative Constructions:");
    println!("   - What about using different hash-based signature schemes?");
    println!("   - How do SPHINCS+ or XMSS compare?");
    println!();
    println!("4. Implementation Exercise:");
    println!("   - Try modifying the tree height and measure signature size");
    println!("   - Implement proof batching or aggregation");
}

fn main() {
    println!("🎓 TOY DIGITAL SIGNATURE SCHEME - EDUCATIONAL VERSION");
    println!("=====================================================");
    
    // === Original Demo ===
    println!("\n=== BASIC DEMONSTRATION ===");
    
    // Keygen - One time per message
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

    // Signing
    let message = b"hello, world!";
    println!("Signing message: {}", String::from_utf8_lossy(message));
    let (sig, proofs) = sign(message, &sk, &tree, &leaf_bytes, &merkle_config);
    println!("Merkle based Signature generated for message.");

    // Verification
    let valid = verify(message, &sig, &proofs, tree_height, &root);
    println!("Signature valid? {}", valid);

    // Tampered Message
    let tampered = b"hello, world !";
    println!("Tampering message: {}", String::from_utf8_lossy(tampered));
    let valid_tampered = verify(tampered, &sig, &proofs, tree_height, &root);
    println!("Signature valid for tampered message? {}", valid_tampered);

    // === STUDENT EXERCISES ===
    println!("\n\n🎯 STUDENT EXERCISES");
    println!("====================");
    
    // Exercise 1: Demonstrate key reuse vulnerability
    exercise_1_key_reuse_attack(&sk, &tree, &leaf_bytes, &merkle_config);
    
    // Exercise 2: Multi-message key generation
    exercise_2_multi_message_keygen();
    
    // Exercise 3: Security analysis
    exercise_3_security_analysis();
    
    // Exercise 4: Optimization challenges
    exercise_4_signature_optimization();
    
    println!("\n\n📚 ADDITIONAL LEARNING RESOURCES:");
    println!("- Research Lamport signatures and Merkle signature schemes");
    println!("- Look into SPHINCS+, XMSS, and other hash-based signatures");
    println!("- Study the quantum threat to traditional signature schemes");
    println!("- Explore the trade-offs between security, efficiency, and key size");
}
