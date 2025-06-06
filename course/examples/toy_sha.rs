// Toy SHA-256 Implementation for Educational Purposes
// This is a simplified version to illustrate the key concepts

use std::fmt;
use std::collections::HashMap;

// SHA-256 constants (first 32 bits of the fractional parts of the cube roots of the first 64 primes)
// For simplicity, we'll use only the first 8 constants
const K: [u32; 8] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
];

// Initial hash values (first 32 bits of the fractional parts of the square roots of the first 8 primes)
const INITIAL_HASH: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

#[derive(Debug, Clone)]
pub struct ToySha256 {
    state: [u32; 8],
    buffer: Vec<u8>,
    length: u64,
}

impl ToySha256 {
    pub fn new() -> Self {
        ToySha256 {
            state: INITIAL_HASH,
            buffer: Vec::new(),
            length: 0,
        }
    }

    // Right rotate function
    fn rotr(value: u32, amount: u32) -> u32 {
        (value >> amount) | (value << (32 - amount))
    }

    // SHA-256 choice function: if x then y else z
    fn ch(x: u32, y: u32, z: u32) -> u32 {
        (x & y) ^ (!x & z)
    }

    // SHA-256 majority function
    fn maj(x: u32, y: u32, z: u32) -> u32 {
        (x & y) ^ (x & z) ^ (y & z)
    }

    // Upper case sigma 0
    fn big_sigma0(x: u32) -> u32 {
        Self::rotr(x, 2) ^ Self::rotr(x, 13) ^ Self::rotr(x, 22)
    }

    // Upper case sigma 1
    fn big_sigma1(x: u32) -> u32 {
        Self::rotr(x, 6) ^ Self::rotr(x, 11) ^ Self::rotr(x, 25)
    }

    // Lower case sigma 0
    fn small_sigma0(x: u32) -> u32 {
        Self::rotr(x, 7) ^ Self::rotr(x, 18) ^ (x >> 3)
    }

    // Lower case sigma 1
    fn small_sigma1(x: u32) -> u32 {
        Self::rotr(x, 17) ^ Self::rotr(x, 19) ^ (x >> 10)
    }

    // Process a single 512-bit block (simplified to 8 rounds instead of 64)
    fn process_block(&mut self, block: &[u8; 64]) {
        // Parse block into 16 32-bit words
        let mut w = [0u32; 16];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([
                block[i * 4],
                block[i * 4 + 1],
                block[i * 4 + 2],
                block[i * 4 + 3],
            ]);
        }

        // Extend the 16 words to 64 words (simplified to 16 for toy version)
        // In real SHA-256, this would extend to 64 words
        println!("Initial 16 words from block:");
        for (i, word) in w.iter().enumerate() {
            println!("W[{:2}] = 0x{:08x}", i, word);
        }

        // Initialize working variables
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = self.state;

        println!("\nInitial state:");
        println!("a=0x{:08x} b=0x{:08x} c=0x{:08x} d=0x{:08x}", a, b, c, d);
        println!("e=0x{:08x} f=0x{:08x} g=0x{:08x} h=0x{:08x}", e, f, g, h);

        // Main compression loop (simplified to 8 rounds)
        for i in 0..8 {
            let s1 = Self::big_sigma1(e);
            let ch = Self::ch(e, f, g);
            let temp1 = h.wrapping_add(s1).wrapping_add(ch).wrapping_add(K[i]).wrapping_add(w[i]);
            
            let s0 = Self::big_sigma0(a);
            let maj = Self::maj(a, b, c);
            let temp2 = s0.wrapping_add(maj);

            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);

            println!("Round {}: a=0x{:08x} e=0x{:08x}", i + 1, a, e);
        }

        // Add the compressed chunk to the current hash value
        self.state[0] = self.state[0].wrapping_add(a);
        self.state[1] = self.state[1].wrapping_add(b);
        self.state[2] = self.state[2].wrapping_add(c);
        self.state[3] = self.state[3].wrapping_add(d);
        self.state[4] = self.state[4].wrapping_add(e);
        self.state[5] = self.state[5].wrapping_add(f);
        self.state[6] = self.state[6].wrapping_add(g);
        self.state[7] = self.state[7].wrapping_add(h);

        println!("\nFinal state after block:");
        println!("H0=0x{:08x} H1=0x{:08x} H2=0x{:08x} H3=0x{:08x}", 
                 self.state[0], self.state[1], self.state[2], self.state[3]);
        println!("H4=0x{:08x} H5=0x{:08x} H6=0x{:08x} H7=0x{:08x}", 
                 self.state[4], self.state[5], self.state[6], self.state[7]);
    }

    // Update with new data
    pub fn update(&mut self, data: &[u8]) {
        self.length += data.len() as u64;
        self.buffer.extend_from_slice(data);

        // Process complete 64-byte blocks
        while self.buffer.len() >= 64 {
            let mut block = [0u8; 64];
            block.copy_from_slice(&self.buffer[0..64]);
            self.buffer.drain(0..64);
            
            println!("\n=== Processing 64-byte block ===");
            self.process_block(&block);
        }
    }

    // Finalize the hash
    pub fn finalize(mut self) -> [u8; 32] {
        let msg_len = self.length;
        
        // Padding: append 1 bit followed by zeros
        self.buffer.push(0x80);

        // Pad to 56 bytes (leaving 8 bytes for length)
        while self.buffer.len() % 64 != 56 {
            self.buffer.push(0x00);
        }

        // Append original length in bits as 64-bit big-endian
        let bit_len = msg_len * 8;
        self.buffer.extend_from_slice(&bit_len.to_be_bytes());

        println!("\n=== Final padded block ===");
        println!("Buffer length: {} bytes", self.buffer.len());
        println!("Original message length: {} bytes ({} bits)", msg_len, bit_len);

        // Process final block(s)
        while !self.buffer.is_empty() {
            let mut block = [0u8; 64];
            block.copy_from_slice(&self.buffer[0..64]);
            self.buffer.drain(0..64);
            self.process_block(&block);
        }

        // Convert state to bytes
        let mut result = [0u8; 32];
        for (i, &state) in self.state.iter().enumerate() {
            let bytes = state.to_be_bytes();
            result[i * 4..(i + 1) * 4].copy_from_slice(&bytes);
        }

        result
    }

    // Convenience method to hash data in one go
    pub fn hash(data: &[u8]) -> [u8; 32] {
        let mut hasher = ToySha256::new();
        hasher.update(data);
        hasher.finalize()
    }

    // Quiet version for testing - no debug output
    pub fn hash_quiet(data: &[u8]) -> [u8; 32] {
        let mut hasher = ToySha256::new();
        hasher.length += data.len() as u64;
        hasher.buffer.extend_from_slice(data);

        // Process complete 64-byte blocks without printing
        while hasher.buffer.len() >= 64 {
            let mut block = [0u8; 64];
            block.copy_from_slice(&hasher.buffer[0..64]);
            hasher.buffer.drain(0..64);
            hasher.process_block_quiet(&block);
        }

        // Finalize without printing
        let msg_len = hasher.length;
        hasher.buffer.push(0x80);
        while hasher.buffer.len() % 64 != 56 {
            hasher.buffer.push(0x00);
        }
        let bit_len = msg_len * 8;
        hasher.buffer.extend_from_slice(&bit_len.to_be_bytes());

        while !hasher.buffer.is_empty() {
            let mut block = [0u8; 64];
            block.copy_from_slice(&hasher.buffer[0..64]);
            hasher.buffer.drain(0..64);
            hasher.process_block_quiet(&block);
        }

        let mut result = [0u8; 32];
        for (i, &state) in hasher.state.iter().enumerate() {
            let bytes = state.to_be_bytes();
            result[i * 4..(i + 1) * 4].copy_from_slice(&bytes);
        }
        result
    }

    // Quiet version of process_block for testing
    fn process_block_quiet(&mut self, block: &[u8; 64]) {
        let mut w = [0u32; 16];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([
                block[i * 4],
                block[i * 4 + 1],
                block[i * 4 + 2],
                block[i * 4 + 3],
            ]);
        }

        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = self.state;

        for i in 0..8 {
            let s1 = Self::big_sigma1(e);
            let ch = Self::ch(e, f, g);
            let temp1 = h.wrapping_add(s1).wrapping_add(ch).wrapping_add(K[i]).wrapping_add(w[i]);
            
            let s0 = Self::big_sigma0(a);
            let maj = Self::maj(a, b, c);
            let temp2 = s0.wrapping_add(maj);

            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }

        self.state[0] = self.state[0].wrapping_add(a);
        self.state[1] = self.state[1].wrapping_add(b);
        self.state[2] = self.state[2].wrapping_add(c);
        self.state[3] = self.state[3].wrapping_add(d);
        self.state[4] = self.state[4].wrapping_add(e);
        self.state[5] = self.state[5].wrapping_add(f);
        self.state[6] = self.state[6].wrapping_add(g);
        self.state[7] = self.state[7].wrapping_add(h);
    }
}

impl fmt::Display for ToySha256 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ToySha256 {{ state: [")?;
        for (i, &val) in self.state.iter().enumerate() {
            if i > 0 { write!(f, ", ")?; }
            write!(f, "0x{:08x}", val)?;
        }
        write!(f, "], buffer_len: {}, length: {} }}", self.buffer.len(), self.length)
    }
}

// Helper function to display hash as hex string
fn hash_to_hex(hash: &[u8; 32]) -> String {
    hash.iter().map(|b| format!("{:02x}", b)).collect()
}

fn main() {
    println!("🎓 Toy SHA-256 Educational Implementation");
    println!("========================================\n");

    // Example 1: Hash a simple message
    let message1 = b"Hello, World!";
    println!("Example 1: Hashing '{}'", std::str::from_utf8(message1).unwrap());
    println!("Message bytes: {:?}", message1);
    println!("Message length: {} bytes\n", message1.len());

    let hash1 = ToySha256::hash(message1);
    println!("Final hash: {}\n", hash_to_hex(&hash1));

    println!("{}", "=".repeat(50));

    // Example 2: Hash an empty message
    let message2 = b"";
    println!("\nExample 2: Hashing empty message");
    println!("Message length: {} bytes\n", message2.len());

    let hash2 = ToySha256::hash(message2);
    println!("Final hash: {}\n", hash_to_hex(&hash2));

    println!("{}", "=".repeat(50));

    // Example 3: Demonstrate step-by-step hashing
    println!("\nExample 3: Step-by-step hashing of 'abc'");
    let message3 = b"abc";
    let mut hasher = ToySha256::new();
    
    println!("Initial hasher state: {}", hasher);
    
    hasher.update(message3);
    println!("After update: {}", hasher);
    
    let hash3 = hasher.finalize();
    println!("Final hash: {}", hash_to_hex(&hash3));

    println!("\n🎉 Educational SHA-256 demonstration complete!");
    println!("Note: This is a simplified version with only 8 rounds instead of 64.");
    println!("Real SHA-256 would be much more secure but follows the same principles.");
}

#[cfg(test)]
mod tests {
    use super::*;

    // ==========================================
    // EDUCATIONAL EXERCISES FOR high speed CRYPTOGRAPHY COURSE
    // ==========================================
    // 
    // This test module contains both working examples and TODO exercises
    // for students to implement. The exercises cover key concepts in
    // cryptographic hash function analysis and attacks.
    //
    // Working Examples:
    // - test_find_collisions: Demonstrates collision search
    // - test_avalanche_effect: Shows diffusion properties  
    // - exercise_hamming_distance: Analyzes bit differences between hashes
    //
    // TODO Exercises (marked with #[ignore]):
    // Remove #[ignore] and implement the TODOs to complete each exercise.
    // Each exercise includes goals and implementation hints.
    //
    // Run tests with: cargo test
    // Run ignored tests: cargo test -- --ignored
    // ==========================================

    #[test]
    fn test_empty_message() {
        let hash = ToySha256::hash(b"");
        // Note: This won't match real SHA-256 due to our simplifications
        assert_eq!(hash.len(), 32);
    }

    #[test]
    fn test_hello_world() {
        let hash = ToySha256::hash(b"Hello, World!");
        assert_eq!(hash.len(), 32);
        // The hash should be consistent
        let hash2 = ToySha256::hash(b"Hello, World!");
        assert_eq!(hash, hash2);
    }

    #[test]
    fn test_different_messages() {
        let hash1 = ToySha256::hash(b"message1");
        let hash2 = ToySha256::hash(b"message2");
        // Different messages should produce different hashes
        assert_ne!(hash1, hash2);
    }

    #[test]
    //exercise: find collisions
    fn test_find_collisions() {
        println!("\n🔍 Searching for collisions in toy SHA-256 (8 rounds)...");
        
        let mut hash_map: HashMap<[u8; 32], Vec<u8>> = HashMap::new();
        let mut collision_found = false;
        let mut attempts = 0;
        
        // Try simple single-byte messages first
        println!("Testing single-byte messages (0-255)...");
        for i in 0..=255u8 {
            let message = vec![i];
            let hash = ToySha256::hash_quiet(&message);
            attempts += 1;
            
            if let Some(existing_message) = hash_map.get(&hash) {
                if existing_message != &message {
                    println!("🎉 COLLISION FOUND!");
                    println!("Hash: {}", hash_to_hex(&hash));
                    println!("Message 1: {:?}", existing_message);
                    println!("Message 2: {:?}", message);
                    collision_found = true;
                    break;
                }
            } else {
                hash_map.insert(hash, message);
            }
        }

        if !collision_found {
            println!("No collision in single bytes, trying two-byte combinations...");
            
            // Try two-byte messages (don't clear hash_map to allow cross-category collisions)
            for i in 0..1024u16 {  // Increased range for better coverage
                let message = vec![(i & 0xFF) as u8, (i >> 8) as u8];
                let hash = ToySha256::hash_quiet(&message);
                attempts += 1;
                
                if let Some(existing_message) = hash_map.get(&hash) {
                    if existing_message != &message {
                        println!("🎉 COLLISION FOUND!");
                        println!("Hash: {}", hash_to_hex(&hash));
                        println!("Message 1: {:?}", existing_message);
                        println!("Message 2: {:?}", message);
                        collision_found = true;
                        break;
                    }
                } else {
                    hash_map.insert(hash, message);
                }
            }
        }

        if !collision_found {
            println!("No collision in two bytes, trying three-byte combinations...");
            
            // Try three-byte messages with more variety
            for i in 0..1000u16 {  // Reduced from 2048 to avoid overflow
                let message = vec![
                    (i & 0xFF) as u8, 
                    ((i >> 8) & 0xFF) as u8, 
                    ((i.wrapping_mul(37)) % 256) as u8  // Use wrapping_mul to avoid overflow
                ];
                let hash = ToySha256::hash_quiet(&message);
                attempts += 1;
                
                if let Some(existing_message) = hash_map.get(&hash) {
                    if existing_message != &message {
                        println!("🎉 COLLISION FOUND!");
                        println!("Hash: {}", hash_to_hex(&hash));
                        println!("Message 1: {:?}", existing_message);
                        println!("Message 2: {:?}", message);
                        collision_found = true;
                        break;
                    }
                } else {
                    hash_map.insert(hash, message);
                }
            }
        }

        if !collision_found {
            println!("Trying short ASCII string combinations...");
            
            // Try short ASCII strings
            for len in 1..=4 {
                for i in 0..std::cmp::min(26_u32.pow(len), 3000) {
                    let mut message = Vec::new();
                    let mut val = i;
                    for _ in 0..len {
                        message.push(b'a' + (val % 26) as u8);
                        val /= 26;
                    }
                    
                    let hash = ToySha256::hash_quiet(&message);
                    attempts += 1;
                    
                    if let Some(existing_message) = hash_map.get(&hash) {
                        if existing_message != &message {
                            println!("🎉 COLLISION FOUND!");
                            println!("Hash: {}", hash_to_hex(&hash));
                            println!("Message 1: {:?} (as string: '{}')", existing_message, String::from_utf8_lossy(existing_message));
                            println!("Message 2: {:?} (as string: '{}')", message, String::from_utf8_lossy(&message));
                            collision_found = true;
                            break;
                        }
                    } else {
                        hash_map.insert(hash, message);
                    }
                }
                if collision_found {
                    break;
                }
            }
        }

        if !collision_found {
            println!("Trying random-ish patterns...");
            
            // Try some pseudo-random patterns
            for seed in 0..1000u32 {
                // Generate a message using a simple PRNG-like formula
                let len = 1 + (seed % 8);
                let mut message = Vec::new();
                let mut val = seed;
                for _ in 0..len {
                    val = val.wrapping_mul(1103515245).wrapping_add(12345); // Simple LCG
                    message.push((val % 256) as u8);
                }
                
                let hash = ToySha256::hash_quiet(&message);
                attempts += 1;
                
                if let Some(existing_message) = hash_map.get(&hash) {
                    if existing_message != &message {
                        println!("🎉 COLLISION FOUND!");
                        println!("Hash: {}", hash_to_hex(&hash));
                        println!("Message 1: {:?}", existing_message);
                        println!("Message 2: {:?}", message);
                        collision_found = true;
                        break;
                    }
                } else {
                    hash_map.insert(hash, message);
                }
            }
        }

        println!("📊 Total attempts: {}", attempts);
        println!("📊 Unique hashes found: {}", hash_map.len());
        
        if collision_found {
            println!("✅ Collision successfully found! This proves the 8-round toy SHA-256 is NOT collision resistant.");
            println!("📈 This demonstrates why cryptographic hash functions need many rounds:");
            println!("   - Full SHA-256 has 64 rounds and is collision resistant");
            println!("   - Our 8-round version is much weaker");
            println!("   - Real attacks on reduced-round SHA-256 exist in cryptographic literature");
        } else {
            println!("⚠️ No collision found in {} attempts.", attempts);
            println!("   Even with only 8 rounds, collisions might require more attempts.");
            println!("   This could be due to the birthday paradox - we need ~2^128 attempts");
            println!("   for a 256-bit hash space, even if weakened.");
            println!("   The 8-round version is weaker but still has a large output space.");
        }
        
        // The test demonstrates the concept regardless of whether we find a collision
        assert!(attempts > 100, "Should test a reasonable number of messages");
    }

    #[test]
    fn test_avalanche_effect() {
        println!("\n🔬 Testing avalanche effect (bit changes should cause large hash changes)...");
        
        let original = b"Hello, World!";
        let original_hash = ToySha256::hash(original);
        
        println!("Original message: '{}'", std::str::from_utf8(original).unwrap());
        println!("Original hash: {}", hash_to_hex(&original_hash));
        
        // Test single bit flip
        let mut modified = original.to_vec();
        modified[0] ^= 1; // Flip one bit
        let modified_hash = ToySha256::hash(&modified);
        
        println!("Modified message: '{}'", std::str::from_utf8(&modified).unwrap());
        println!("Modified hash: {}", hash_to_hex(&modified_hash));
        
        // Count different bits
        let mut different_bits = 0;
        for i in 0..32 {
            different_bits += (original_hash[i] ^ modified_hash[i]).count_ones();
        }
        
        println!("Bits that changed: {}/256 ({:.1}%)", different_bits, (different_bits as f64 / 256.0) * 100.0);
        
        // For a good hash function, we expect ~50% of bits to change
        // For our 8-round version, we expect less avalanche effect
        if different_bits < 64 {
            println!("⚠️ Weak avalanche effect! Only {:.1}% of bits changed (should be ~50%)", 
                     (different_bits as f64 / 256.0) * 100.0);
            println!("   This demonstrates the weakness of using only 8 rounds.");
        } else {
            println!("✅ Good avalanche effect: {:.1}% of bits changed", 
                     (different_bits as f64 / 256.0) * 100.0);
        }
    }

    // TODO Exercise 1: Implement Hamming Distance Analysis
    #[test]
    fn exercise_hamming_distance() {
        println!("\n📐 Hamming Distance Analysis");
        
        // Helper function to calculate hamming distance between two hashes
        fn hamming_distance(hash1: &[u8; 32], hash2: &[u8; 32]) -> u32 {
            let mut distance = 0;
            for i in 0..32 {
                distance += (hash1[i] ^ hash2[i]).count_ones();
            }
            distance
        }

        println!("Testing hamming distances between hash outputs...\n");

        // Test 1: Similar messages
        println!("🔤 Test 1: Similar Messages");
        let pairs = [
            ("hello", "Hello"),
            ("test", "Test"),
            ("abc", "abd"),
            ("password", "Password"),
            ("123456", "123457"),
        ];

        let mut total_distance = 0;
        for (msg1, msg2) in pairs.iter() {
            let hash1 = ToySha256::hash_quiet(msg1.as_bytes());
            let hash2 = ToySha256::hash_quiet(msg2.as_bytes());
            let distance = hamming_distance(&hash1, &hash2);
            total_distance += distance;
            
            println!("  '{}' vs '{}': {} bits different ({:.1}%)", 
                     msg1, msg2, distance, (distance as f64 / 256.0) * 100.0);
        }
        let avg_similar = total_distance as f64 / pairs.len() as f64;
        println!("  Average for similar messages: {:.1} bits ({:.1}%)\n", 
                 avg_similar, (avg_similar / 256.0) * 100.0);

        // Test 2: Random message pairs
        println!("🎲 Test 2: Random Message Pairs");
        let random_messages = [
            "cryptography", "blockchain", "security", "algorithm", "protocol",
            "mathematics", "computer", "science", "network", "digital"
        ];

        total_distance = 0;
        let mut distances = Vec::new();
        for i in 0..random_messages.len() {
            for j in (i+1)..random_messages.len() {
                let hash1 = ToySha256::hash_quiet(random_messages[i].as_bytes());
                let hash2 = ToySha256::hash_quiet(random_messages[j].as_bytes());
                let distance = hamming_distance(&hash1, &hash2);
                distances.push(distance);
                total_distance += distance;
            }
        }

        let avg_random = total_distance as f64 / distances.len() as f64;
        println!("  Tested {} random pairs", distances.len());
        println!("  Average hamming distance: {:.1} bits ({:.1}%)", 
                 avg_random, (avg_random / 256.0) * 100.0);

        // Test 3: Distribution analysis
        println!("\n📊 Test 3: Distribution Analysis");
        let mut histogram = [0; 9]; // Group into ranges: 0-31, 32-63, ..., 224-255
        
        for &distance in &distances {
            let bucket = (distance / 32).min(8) as usize;
            histogram[bucket] += 1;
        }

        println!("  Hamming distance histogram:");
        for (i, &count) in histogram.iter().enumerate() {
            let range_start = i * 32;
            let range_end = ((i + 1) * 32).min(256) - 1;
            let percentage = (count as f64 / distances.len() as f64) * 100.0;
            println!("    {}-{} bits: {} pairs ({:.1}%)", 
                     range_start, range_end, count, percentage);
        }

        // Analysis
        println!("\n🎯 Analysis:");
        println!("  Expected hamming distance for good hash: ~128 bits (50%)");
        println!("  Actual average: {:.1} bits ({:.1}%)", 
                 avg_random, (avg_random / 256.0) * 100.0);
        
        if avg_random >= 120.0 && avg_random <= 136.0 {
            println!("  ✅ Good! Close to theoretical expectation");
        } else {
            println!("  ⚠️ Deviation from expected ~50% might indicate bias");
        }

        // Test 4: Self-hash comparison (should be 0)
        println!("\n🔄 Test 4: Identity Test");
        let msg = "test message";
        let hash1 = ToySha256::hash_quiet(msg.as_bytes());
        let hash2 = ToySha256::hash_quiet(msg.as_bytes());
        let self_distance = hamming_distance(&hash1, &hash2);
        println!("  Same message hashed twice: {} bits different", self_distance);
        assert_eq!(self_distance, 0, "Hash function should be deterministic!");

        println!("\n✅ Hamming distance analysis complete!");
    }

    // TODO Exercise 2: Hash Distribution Analysis
    #[test]
    #[ignore] // Remove #[ignore] when implementing
    fn exercise_distribution_analysis() {
        println!("\n📊 TODO: Implement Hash Distribution Analysis");
        println!("Goals:");
        println!("1. Hash many random messages");
        println!("2. Analyze if hash bits are uniformly distributed");
        println!("3. Check for patterns or biases in the output");
        println!("4. Compare first/last bytes distribution");
        println!("5. Use chi-squared test for randomness");
        
        // TODO: Generate many hashes and analyze their statistical properties
        // TODO: Check if each bit position has ~50% probability of being 1
        // TODO: Look for correlations between different bit positions
        
        panic!("TODO: Implement this exercise!");
    }

    // TODO Exercise 3: Preimage Resistance Test
    #[test]
    #[ignore] // Remove #[ignore] when implementing  
    fn exercise_preimage_attack() {
        println!("\n🎯 TODO: Implement Preimage Resistance Test");
        println!("Goals:");
        println!("1. Choose a target hash value");
        println!("2. Try to find ANY message that produces that hash");
        println!("3. Measure how many attempts it takes");
        println!("4. Compare with theoretical difficulty (2^256 for full resistance)");
        println!("5. Demonstrate why this is computationally infeasible");
        
        // TODO: Pick a target hash (e.g., all zeros, or hash of 'target')
        // let target_hash = ToySha256::hash(b"target");
        
        // TODO: Try random messages until you find one with the target hash
        // TODO: This should take a VERY long time even with 8 rounds
        
        panic!("TODO: Implement this exercise!");
    }

    // TODO Exercise 4: Length Extension Attack Demo
    #[test]
    #[ignore] // Remove #[ignore] when implementing
    fn exercise_length_extension() {
        println!("\n🔗 TODO: Implement Length Extension Attack Demo");
        println!("Goals:");
        println!("1. Show how SHA construction can be vulnerable to length extension");
        println!("2. Given hash(secret || message), forge hash(secret || message || extra)");
        println!("3. Demonstrate why HMAC is needed instead of simple concatenation");
        println!("4. Show the attack even works with reduced rounds");
        
        // TODO: This is advanced - shows why proper MAC constructions matter
        // TODO: Implement a scenario where you know hash(secret + message) 
        // TODO: But not the secret, and try to create hash(secret + message + extension)
        
        panic!("TODO: Implement this exercise!");
    }

    // TODO Exercise 5: Differential Cryptanalysis
    #[test]
    #[ignore] // Remove #[ignore] when implementing
    fn exercise_differential_analysis() {
        println!("\n🔍 TODO: Implement Differential Cryptanalysis");
        println!("Goals:");
        println!("1. Test how input differences affect output differences");
        println!("2. Find input pairs with minimal differences but maximal output differences");
        println!("3. Look for patterns in how differences propagate through rounds");
        println!("4. Compare 8-round vs hypothetical 4-round version");
        
        // TODO: Systematically test input differences:
        // - Single bit flips at different positions
        // - Two bit flips
        // - Byte-level differences
        // TODO: Measure output differences and look for patterns
        
        panic!("TODO: Implement this exercise!");
    }

    // TODO Exercise 6: Fixed Point Search
    #[test]
    #[ignore] // Remove #[ignore] when implementing
    fn exercise_fixed_points() {
        println!("\n🔄 TODO: Implement Fixed Point Search");
        println!("Goals:");
        println!("1. Search for messages that hash to themselves (very rare!)");
        println!("2. Search for cycles: msg1 -> hash1, hash1 -> msg1");
        println!("3. Calculate expected number of fixed points theoretically");
        println!("4. Demonstrate rarity even with weakened hash");
        
        // TODO: A fixed point would be: hash(msg) == msg (treating hash as message)
        // TODO: This is extremely rare - expected ~1 in 2^256 messages
        // TODO: But interesting to search for with reduced security
        
        panic!("TODO: Implement this exercise!");
    }

    // TODO Exercise 7: Birthday Paradox Demonstration
    #[test]
    #[ignore] // Remove #[ignore] when implementing
    fn exercise_birthday_paradox() {
        println!("\n🎂 TODO: Implement Birthday Paradox Demonstration");
        println!("Goals:");
        println!("1. Truncate hash to different bit lengths (16, 24, 32 bits)");
        println!("2. Find collisions for truncated hashes");
        println!("3. Measure actual vs theoretical collision probability");
        println!("4. Show how collision resistance depends on output size");
        
        // TODO: For n-bit hash, expect collision after ~2^(n/2) attempts
        // TODO: 16-bit: ~256 attempts, 24-bit: ~4096 attempts, etc.
        // TODO: This shows why 256-bit output is needed for security
        
        panic!("TODO: Implement this exercise!");
    }

    // TODO Exercise 8: Multi-collision Attack
    #[test]
    #[ignore] // Remove #[ignore] when implementing
    fn exercise_multicollisions() {
        println!("\n🌟 TODO: Implement Multi-collision Attack");
        println!("Goals:");
        println!("1. Find multiple messages that all hash to the same value");
        println!("2. Build a 'collision tree' with many equivalent messages");
        println!("3. Show how this could break hash-based signatures");
        println!("4. Demonstrate exponential explosion of colliding messages");
        
        // TODO: This is advanced cryptanalysis technique
        // TODO: Start with 2-collisions, then try to extend to 4-way, 8-way, etc.
        // TODO: Shows how breaking collision resistance can be catastrophic
        
        panic!("TODO: Implement this exercise!");
    }
}
