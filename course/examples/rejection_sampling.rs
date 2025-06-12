use icicle_hash::keccak::Keccak256;
use icicle_runtime::memory::HostSlice;
use icicle_core::hash::HashConfig;
use rand::{rng, Rng};
use std::time::Instant;

/// Performs rejection sampling to find a hash with a specific property
fn rejection_sampling_hash(target_bits: u8) -> (Vec<u8>, [u8; 32], u32) {
    let hasher = Keccak256::new(0).unwrap();
    let mut rng = rng();
    let mut attempts = 0;
    
    // Create a mask for checking the required number of leading zero bits
    // this is like a proof of work requirement
    let mask = if target_bits >= 8 {
        0xFF
    } else {
        0xFF << (8 - target_bits)
    };
    
    loop {
        attempts += 1;
        
        // Generate random 8-byte input
        let input: Vec<u8> = (0..8).map(|_| rng.random::<u8>()).collect();
        let mut output = [0u8; 32];
        
        // Hash the input
        let _ = hasher.hash(
            HostSlice::from_slice(&input),
            &HashConfig::default(),
            HostSlice::from_mut_slice(&mut output)
        );
        
        // Check if the hash meets our criteria (has required leading zero bits)
        if (output[0] & mask) == 0 {
            return (input, output, attempts);
        }
    }
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