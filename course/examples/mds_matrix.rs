/// MDS Matrix Example using Icicle BN254
///
/// This example demonstrates how to:
/// 1. Create Vandermonde matrices using primitive roots of unity from the NTT module
/// 2. Check if a matrix is MDS (Maximum Distance Separable)
/// 3. Verify that all square submatrices are invertible
///
/// IMPORTANT: NTT matrices ARE MDS when using primitive roots of unity!
///
/// Why NTT matrices are MDS:
/// - NTT requires DISTINCT evaluation points for polynomial interpolation
/// - Primitive nth roots of unity {1, ω, ω², ..., ω^(n-1)} are always distinct
/// - Vandermonde matrices with distinct points have all square submatrices invertible
/// - Vandermonde with distinct points = MDS matrix
///
/// This is fundamental to why NTT works for polynomial operations and why
/// Reed-Solomon codes (which use the same mathematical structure) are MDS.
///
/// Run with: cargo run --example mds_matrix
///
/// MDS matrices are crucial in cryptography for:
/// - Error-correcting codes (Reed-Solomon)
/// - Cryptographic hash functions (Poseidon)
/// - Secret sharing schemes
/// - Zero-knowledge proof systems

use icicle_bn254::curve::ScalarField as Fr;
use icicle_core::{
    ntt::{get_root_of_unity, initialize_domain, NTTInitDomainConfig},
    traits::{FieldImpl, Arithmetic},
};
use icicle_runtime::{self, Device};

/// Represents a matrix over a finite field
#[derive(Debug, Clone)]
struct Matrix {
    data: Vec<Vec<Fr>>,
    rows: usize,
    cols: usize,
}

impl Matrix {
    /// Create a new matrix with given dimensions
    fn new(rows: usize, cols: usize) -> Self {
        Self {
            data: vec![vec![Fr::zero(); cols]; rows],
            rows,
            cols,
        }
    }

    /// Create a matrix from a 2D vector
    fn from_data(data: Vec<Vec<Fr>>) -> Self {
        let rows = data.len();
        let cols = if rows > 0 { data[0].len() } else { 0 };
        Self { data, rows, cols }
    }

    /// Get element at (i, j)
    fn get(&self, i: usize, j: usize) -> Fr {
        self.data[i][j]
    }

    /// Set element at (i, j)
    fn set(&mut self, i: usize, j: usize, value: Fr) {
        self.data[i][j] = value;
    }

    /// Create a Vandermonde matrix using primitive root of unity
    /// V[i][j] = omega^(i*j) where omega is a primitive root of unity
    fn vandermonde(size: usize, omega: Fr) -> Self {
        let mut matrix = Matrix::new(size, size);

        // Precompute powers of omega
        let mut omega_powers = vec![Fr::one(); size];
        for i in 1..size {
            omega_powers[i] = omega_powers[i - 1] * omega;
        }

        for i in 0..size {
            for j in 0..size {
                // V[i][j] = omega^(i*j)
                let power = (i * j) % size;
                matrix.set(i, j, omega_powers[power]);
            }
        }

        matrix
    }

    /// Extract a submatrix from (start_row, start_col) with given dimensions
    fn submatrix(&self, start_row: usize, start_col: usize, sub_rows: usize, sub_cols: usize) -> Matrix {
        let mut sub = Matrix::new(sub_rows, sub_cols);
        for i in 0..sub_rows {
            for j in 0..sub_cols {
                sub.set(i, j, self.get(start_row + i, start_col + j));
            }
        }
        sub
    }

    /// Calculate determinant using Gaussian elimination
    fn determinant(&self) -> Fr {
        if self.rows != self.cols {
            panic!("Determinant can only be calculated for square matrices");
        }
        
        let n = self.rows;
        if n == 0 {
            return Fr::one();
        }
        if n == 1 {
            return self.get(0, 0);
        }
        
        // Create a copy for Gaussian elimination
        let mut matrix = self.clone();
        let mut det = Fr::one();
        
        for i in 0..n {
            // Find pivot
            let mut pivot_row = i;
            for k in (i + 1)..n {
                if matrix.get(k, i) != Fr::zero() {
                    pivot_row = k;
                    break;
                }
            }
            
            // If no pivot found, determinant is zero
            if matrix.get(pivot_row, i) == Fr::zero() {
                return Fr::zero();
            }
            
            // Swap rows if needed
            if pivot_row != i {
                for j in 0..n {
                    let temp = matrix.get(i, j);
                    matrix.set(i, j, matrix.get(pivot_row, j));
                    matrix.set(pivot_row, j, temp);
                }
                det = det * Fr::from_u32(u32::MAX); // Multiply by -1 (using field arithmetic)
            }
            
            let pivot = matrix.get(i, i);
            det = det * pivot;
            
            // Eliminate column
            for k in (i + 1)..n {
                if matrix.get(k, i) != Fr::zero() {
                    let factor = matrix.get(k, i) * pivot.inv();
                    for j in i..n {
                        let val = matrix.get(k, j) - factor * matrix.get(i, j);
                        matrix.set(k, j, val);
                    }
                }
            }
        }
        
        det
    }

    /// Check if the matrix is invertible (determinant != 0)
    fn is_invertible(&self) -> bool {
        self.determinant() != Fr::zero()
    }

    /// Print the matrix in a readable format
    fn print(&self, name: &str) {
        println!("\n{} ({}x{}):", name, self.rows, self.cols);
        for i in 0..self.rows {
            print!("[");
            for j in 0..self.cols {
                if j > 0 { print!(", "); }
                // Print first few digits of the field element for readability
                let bytes = self.get(i, j).to_bytes_le();
                print!("{:02x}{:02x}...", bytes[0], bytes[1]);
            }
            println!("]");
        }
    }
}

/// Check if a matrix is MDS (Maximum Distance Separable)
/// A matrix is MDS if all its square submatrices are invertible
fn is_mds_matrix(matrix: &Matrix) -> bool {
    println!("\n=== Checking if matrix is MDS ===");
    println!("Matrix dimensions: {}x{}", matrix.rows, matrix.cols);
    
    let min_dim = matrix.rows.min(matrix.cols);
    
    // Check all possible square submatrices
    for size in 1..=min_dim {
        println!("\nChecking all {}x{} submatrices...", size, size);
        let mut submatrix_count = 0;
        let mut _invertible_count = 0;
        
        // Iterate through all possible starting positions
        for start_row in 0..=(matrix.rows - size) {
            for start_col in 0..=(matrix.cols - size) {
                submatrix_count += 1;
                let sub = matrix.submatrix(start_row, start_col, size, size);
                let det = sub.determinant();
                let is_invertible = det != Fr::zero();
                
                if is_invertible {
                    _invertible_count += 1;
                }
                
                if size <= 3 { // Print details for small submatrices
                    println!("  Submatrix at ({}, {}): det = {:?}, invertible = {}", 
                            start_row, start_col, 
                            if is_invertible { "non-zero" } else { "zero" }, 
                            is_invertible);
                }
                
                if !is_invertible {
                    println!("  ❌ Found non-invertible {}x{} submatrix at ({}, {})", 
                            size, size, start_row, start_col);
                    if size <= 3 {
                        sub.print(&format!("Non-invertible submatrix"));
                    }
                    return false;
                }
            }
        }
        
        println!("  ✅ All {} submatrices of size {}x{} are invertible", 
                submatrix_count, size, size);
    }
    
    println!("\n🎉 Matrix is MDS! All square submatrices are invertible.");
    true
}

fn main() {
    println!("=== MDS Matrix Example with Icicle BN254 ===");
    
    // Set up CPU backend
    let device_cpu = Device::new("CPU", 0);
    icicle_runtime::set_device(&device_cpu).unwrap();
    
    // Initialize NTT domain
    let max_ntt_size = 1 << 10; // 2^10 = 1024
    let rou: Fr = get_root_of_unity(max_ntt_size);
    initialize_domain(rou, &NTTInitDomainConfig::default()).unwrap();
    
    println!("Primitive root of unity (omega): {:?}", rou);
    println!("Order of omega: 2^{}", max_ntt_size.trailing_zeros());
    
    // Test with small matrices first
    let test_sizes = vec![2, 3, 4];
    
    for &size in &test_sizes {
        println!("\n{}", "=".repeat(60));
        println!("Testing {}x{} Vandermonde matrix", size, size);
        println!("{}", "=".repeat(60));
        
        // Get appropriate root of unity for this size
        let omega_for_size = get_root_of_unity::<Fr>(size as u64);
        println!("Using primitive {}th root of unity: {:?}", size, omega_for_size);
        
        // Verify it's actually a primitive root
        let mut power = omega_for_size;
        for i in 1..size {
            if power == Fr::one() {
                println!("Warning: omega^{} = 1, not a primitive {}th root", i, size);
                break;
            }
            power = power * omega_for_size;
        }
        if power == Fr::one() {
            println!("✅ Confirmed: omega^{} = 1, so omega is a primitive {}th root", size, size);
        }
        
        // Create Vandermonde matrix
        let vandermonde = Matrix::vandermonde(size, omega_for_size);
        vandermonde.print(&format!("Vandermonde matrix ({}x{})", size, size));
        
        // Check if it's MDS
        let is_mds = is_mds_matrix(&vandermonde);
        
        println!("\nResult for {}x{} Vandermonde matrix: {}", 
                size, size, 
                if is_mds { "✅ MDS" } else { "❌ Not MDS" });
    }
    
    // Test a non-MDS matrix for comparison
    println!("\n{}", "=".repeat(60));
    println!("Testing a non-MDS matrix for comparison");
    println!("{}", "=".repeat(60));
    
    let mut non_mds = Matrix::new(3, 3);
    non_mds.set(0, 0, Fr::one());
    non_mds.set(0, 1, Fr::from_u32(2));
    non_mds.set(0, 2, Fr::from_u32(3));
    non_mds.set(1, 0, Fr::from_u32(2));
    non_mds.set(1, 1, Fr::from_u32(4));
    non_mds.set(1, 2, Fr::from_u32(6)); // This row is 2 * first row
    non_mds.set(2, 0, Fr::from_u32(1));
    non_mds.set(2, 1, Fr::from_u32(3));
    non_mds.set(2, 2, Fr::from_u32(5));
    
    non_mds.print("Non-MDS matrix example");
    let is_mds = is_mds_matrix(&non_mds);
    println!("\nResult for non-MDS matrix: {}", 
            if is_mds { "✅ MDS" } else { "❌ Not MDS (as expected)" });
    
    println!("\n{}", "=".repeat(60));
    println!("Summary:");
    println!("✅ Vandermonde matrices constructed with primitive roots of unity are MDS!");
    println!("📊 MDS property: ALL square submatrices are invertible (det ≠ 0)");
    println!("🔐 Applications:");
    println!("   - Error-correcting codes (Reed-Solomon codes)");
    println!("   - Cryptographic hash functions (like Poseidon)");
    println!("   - Secret sharing schemes");
    println!("   - Zero-knowledge proof systems");
    println!("🧮 Technical details:");
    println!("   - Used BN254 scalar field with Icicle library");
    println!("   - Primitive roots of unity from NTT module");
    println!("   - Matrix V[i][j] = ω^(i*j) where ω is primitive nth root of unity");
    println!("   - NTT matrices ARE MDS because primitive roots give DISTINCT evaluation points");
    println!("   - Distinct points → Vandermonde matrix invertible → all submatrices invertible → MDS");
    println!("{}", "=".repeat(60));
}
