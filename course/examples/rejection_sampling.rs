use icicle_hash::keccak::Keccak256;
use icicle_runtime::memory::HostSlice;
use icicle_core::hash::HashConfig;
use std::time::Instant;
use hex;

/// Performs rejection sampling to find a hash with a specific property
fn rejection_sampling_hash(target_bits: u8) -> (Vec<u8>, [u8; 32], u32) {
    let hasher = Keccak256::new(0).unwrap();
    let mut attempts = 0;
    
    loop {
        attempts += 1;
        
        // Generate random 8-byte input
        let input: Vec<u8> = (0..8).map(|_| rand::random::<u8>()).collect();
        let mut output = [0u8; 32];
        
        // Hash the input
        let _ = hasher.hash(
            HostSlice::from_slice(&input),
            &HashConfig::default(),
            HostSlice::from_mut_slice(&mut output)
        );
        
        // Check if the hash meets our criteria (has required leading zero bits)
        if has_leading_zero_bits(&output, target_bits) {
            return (input, output, attempts);
        }
    }
}

/// Check if the hash has the required number of leading zero bits
fn has_leading_zero_bits(hash: &[u8; 32], target_bits: u8) -> bool {
    if target_bits == 0 {
        return true;
    }
    
    let full_bytes = target_bits / 8;
    let remaining_bits = target_bits % 8;
    
    // Check full bytes (must be all zeros)
    for i in 0..full_bytes as usize {
        if hash[i] != 0 {
            return false;
        }
    }
    
    // Check remaining bits in the next byte
    if remaining_bits > 0 {
        let byte_index = full_bytes as usize;
        if byte_index < hash.len() {
            let mask = 0xFF << (8 - remaining_bits);
            if (hash[byte_index] & mask) != 0 {
                return false;
            }
        }
    }
    
    true
}

fn main() {
    println!("🎓 Rejection Sampling Demonstration");
    println!("===================================\n");
    
    println!("Rejection sampling is a technique where we:");
    println!("1. Sample from a larger set S (all possible hashes)");
    println!("2. Accept only elements from subset T (hashes with specific properties)");
    println!("3. Repeat until we find an acceptable element\n");
    
    println!("In this example, we'll find hashes with increasing numbers of leading zero bits");
    println!("This is similar to Bitcoin's proof-of-work mechanism\n");
    
    // Try with different difficulty levels
    for target_bits in [1, 2, 4, 8, 12, 16].iter() {
        println!("Finding hash with {} leading zero bits:", target_bits);
        
        let start = Instant::now();
        let (input, output, attempts) = rejection_sampling_hash(*target_bits);
        let duration = start.elapsed();
        
        println!("  Input: {:?}", input);
        println!("  Hash: {}", hex::encode(output));
        println!("  First byte: 0x{:02x} (binary: {:08b})", output[0], output[0]);
        println!("  Attempts: {}", attempts);
        println!("  Time: {:?}", duration);
        println!("  Expected attempts: 2^{} = {}", target_bits, 2u32.pow(*target_bits as u32));
        println!();
    }
    
    println!("\n🔍 Analysis:");
    println!("- As the number of required zero bits increases, attempts grow exponentially");
    println!("- With k bits, we expect ~2^k attempts on average");
    println!("- This demonstrates why proof-of-work systems can be tuned for difficulty");
    println!("- Rejection sampling is efficient when |S|/|T| is reasonably small");
}