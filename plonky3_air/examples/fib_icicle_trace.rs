use icicle_core::
    {field::Field,
    traits::{Arithmetic,FieldConfig,FieldImpl,GenerateRandom,MontgomeryConvertible},
    };
use plonky3_air::*;

use icicle_m31::field::{ScalarField as Fr};
//constraints
use p3_matrix::Matrix;
use p3_field::*;

pub struct FibonacciAir {
    pub num_steps: usize, // numbers of steps to run the fibonacci iterations
    pub final_value: u32, // precomputed final result after the numbers of steps.
}

impl<F: FieldImpl> BaseAir<F> for FibonacciAir {
    fn width(&self) -> usize {
        2 // Row width for fibonacci program is 2
    }
}

impl<AB: AirBuilder> Air<AB> for FibonacciAir
where
    AB::F: icicle_core::traits::FieldImpl,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.row_slice(0); // get the current row
        let next = main.row_slice(1); // get the next row
        // Your choice of Field
        
        // Enforce starting values
        builder.when_first_row().assert_zero(local[0]);
        builder.when_first_row().assert_one(local[1]);

        // Enforce state transition constraints
        builder.when_transition().assert_eq(next[0], local[1]);
        builder.when_transition().assert_eq(next[1], local[0] + local[1]);

        // Constrain the final value
        let final_value = AB::Expr::from_canonical_u32(self.final_value);
        builder.when_last_row().assert_eq(local[1], final_value);
    }
}

pub fn generate_fibonacci_trace<F:FieldImpl +Arithmetic>(num_steps: usize) -> Vec<F> {
    // Declaring the total fields needed to keep track of the execution with the given parameter, which in this case, is num_steps multiply by 2, where 2 is the width of the AIR scripts.
    let mut values: Vec<F> = Vec::with_capacity(num_steps * 2); 

    // Define your initial state, 0 and 1.
    let mut a: F = F::zero();
    // F::zero();
    let mut b: F = F::one();

    // Run your program and fill in the states in each iteration in the `values` vector
    for _ in 0..num_steps {
        values.push(a);
        values.push(b);
        let c: F =a+b;
        a = b;
        b = c;
    }

    // Convert it into 2D matrix.
    values
}


fn main()  {  
let num_steps: usize = 8; // Choose the number of Fibonacci steps.
let final_value: u32 = 21; // Choose the final Fibonacci value

// Instantiate the AIR Scripts instance.
let air: FibonacciAir = FibonacciAir { num_steps, final_value };
type Val = Fr;
// Generate the execution trace, based on the inputs defined above.
let trace = generate_fibonacci_trace::<Val>(num_steps);
println!("trace {:?}", trace);

//let eval = air.eval(&mut AB);
}

//[0x00000000, 0x00000001, 0x00000001, 0x00000001, 0x00000001, 0x00000002, 
//0x00000002, 0x00000003, 0x00000003, 0x00000005, 0x00000005, 0x00000008, 
//0x00000008, 0x0000000d, 0x0000000d, 0x00000015]