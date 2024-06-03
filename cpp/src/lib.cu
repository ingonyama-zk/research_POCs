#include <iostream>
#include <cassert>
#include <vector>
#include "polynomials/polynomials.h"
#include "polynomials/cuda_backend/polynomial_cuda_backend.cuh"
#include "ntt/ntt.cuh"
#include "api/bn254.h"
#include "vec_ops/vec_ops.cuh"
#include "poly_test.cuh"

int main(){
basic_commit();
return 0;
}