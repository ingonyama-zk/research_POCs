#include <iostream>
#include <cassert>
#include <vector>
#include "polynomials/polynomials.h"
#include "polynomials/cuda_backend/polynomial_cuda_backend.cuh"
#include "ntt/ntt.cuh"
#include "api/bn254.h"
#include "vec_ops/vec_ops.cuh"


using namespace bn254;
using namespace polynomials;
using namespace vec_ops;

typedef Polynomial<scalar_t> Polynomial_t;

static std::unique_ptr<scalar_t[]> generate_pows(scalar_t tau, uint32_t size){
    auto vec = std::make_unique<scalar_t[]>(size);
    vec[0] = scalar_t::one();
    for (size_t i = 1; i < size; ++i) {
      vec[i] = vec[i-1] * tau;
  }
  return std::move(vec);
}

static std::unique_ptr<affine_t[]> generate_SRS(uint32_t size) {
  auto secret_scalar = scalar_t::rand_host();
  auto gen = projective_t::generator();
  auto pows_of_tau = generate_pows(secret_scalar,size);
  auto SRS = std::make_unique<affine_t[]>(size);
  for (size_t i = 0; i < size; ++i) {
      SRS[i] = projective_t::to_affine(pows_of_tau[i] * gen);
  }
  return std::move(SRS);
}

static Polynomial_t randomize_polynomial(uint32_t size)
{
  auto coeff = std::make_unique<scalar_t[]>(size);
  for (int i = 0; i < size; i++)
    coeff[i] = scalar_t::rand_host();
  return Polynomial_t::from_coefficients(coeff.get(), size);
}

void basic_commit(){
  int N = 1025;
  // generate group elements string of length N: (1, beta,beta^2....,beta^{N-1}). g
  auto SRS = generate_SRS(2*N);
  const int MAX_NTT_LOG_SIZE = 24;

  auto ntt_config = ntt::default_ntt_config<scalar_t>();
  const scalar_t basic_root = scalar_t::omega(MAX_NTT_LOG_SIZE);
  ntt::init_domain(basic_root, ntt_config.ctx);
  Polynomial_t::initialize(std::make_unique<CUDAPolynomialFactory<>>());
  
  //goal:
  //test commitment equality [(f1+f2)^2 + (f1-f2)^2 ]_1 = [4 (f1^2+ f_2^2)]_1
  //test commitment equality [(f1+f2)^2 - (f1-f2)^2 ]_1 = [4 f1 *f_2]_1

  auto f1 = randomize_polynomial(N);
  auto f2 = randomize_polynomial(N);
  //deg 2N constraints (f1+f2)^2 + (f1-f2)^2 = 4 (f1^2+ f_2^2)
  auto L1 = (f1+f2)*(f1+f2) + (f1-f2)*(f1-f2);
  auto R1 = scalar_t::from(2) * (f1*f1 + f2*f2);
  //deg 2N constraints (f1+f2)^2 - (f1-f2)^2 = 4 f1 *f_2
  auto L2 = (f1+f2)*(f1+f2) - (f1-f2)*(f1-f2);
  auto R2 = scalar_t::from(4) * f1 * f2;
     
  // extract coeff using coeff view
  auto [viewL1, sizeL1, device_idL1] = L1.get_coefficients_view();
  auto [viewL2, sizeL2, device_idL2] = L2.get_coefficients_view(); 
  auto [viewR1, sizeR1, device_idR1] = R1.get_coefficients_view();
  auto [viewR2, sizeR2, device_idR2] = R2.get_coefficients_view();
  
  //prepare to commit
  msm::MSMConfig config = msm::default_msm_config();
  //device vars
  affine_t* points_d;
  projective_t* L1c = nullptr, *R1c = nullptr, *L2c = nullptr, *R2c = nullptr;
  //host vars (for result)
  projective_t hL1{}, hL2{}, hR1{}, hR2{};

  //Allocate memory on device (points)
  cudaMalloc(&points_d, sizeof(affine_t)* 2 * N);
    //Allocate memory on device (scalars)
  cudaMalloc(&L1c, sizeof(projective_t)), cudaMalloc(&R1c, sizeof(projective_t));
  cudaMalloc(&L2c, sizeof(projective_t)),cudaMalloc(&R2c, sizeof(projective_t));

  //copy SRS to device, scalars are already on device (we are using them via polynomial views)
  cudaMemcpy(points_d, SRS.get(), sizeof(affine_t)* 2 * N, cudaMemcpyHostToDevice);

  //msm bn254 api

  bn254_msm_cuda(viewL1.get(),points_d,N,config,L1c);
  bn254_msm_cuda(viewL2.get(),points_d,N,config,L2c);
  bn254_msm_cuda(viewR1.get(),points_d,N,config,R1c);
  bn254_msm_cuda(viewR2.get(),points_d,N,config,R2c);

  //out result and send to host
  cudaMemcpy(&hL1, L1c, sizeof(projective_t), cudaMemcpyDeviceToHost);
  cudaMemcpy(&hL2,L2c, sizeof(projective_t), cudaMemcpyDeviceToHost);
  cudaMemcpy(&hR1,R1c, sizeof(projective_t), cudaMemcpyDeviceToHost);
  cudaMemcpy(&hR2, R2c, sizeof(projective_t), cudaMemcpyDeviceToHost);

  //sanity checks
  auto affL1 = projective_t::to_affine(hL1);
  auto affR1 = projective_t::to_affine(hR1);

  auto affL2 = projective_t::to_affine(hL2);
  auto affR2 = projective_t::to_affine(hR2);

 //test commitment equality [(f1+f2)^2 + (f1-f2)^2]_1 = [4 (f_1^2+f_2^2]_1
  assert(affL1.x==affR1.x && affL1.y==affR1.y);
  std::cout << "Verified [(f1+f2)^2 + (f1-f2)^2]_1 = [4 (f_1^2+f_2^2]_1 " << std::endl;
 //test commitment equality [(f1+f2)^2 - (f1-f2)^2]_1 = [4 f_1 f_2]_1
  assert(affL2.x==affR2.x && affL2.y==affR2.y);
  std::cout << "Verified [(f1+f2)^2 - (f1-f2)^2]_1 = [4 f_1 f_2]_1 " << std::endl;
//print proof
  std::cout << "Proof: [" << affL1.x << ", " << affL1.y << "]" << std::endl;
//clear memory
cudaFree(L1c),cudaFree(L2c),cudaFree(R1c),cudaFree(R2c);
}