cmake_minimum_required(VERSION 3.18)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CUDA_STANDARD 17)
set(CMAKE_CUDA_STANDARD_REQUIRED TRUE)
set(CMAKE_CXX_STANDARD_REQUIRED TRUE)
if (${CMAKE_VERSION} VERSION_LESS "3.24.0")
    set(CMAKE_CUDA_ARCHITECTURES ${CUDA_ARCH})
else()
    set(CMAKE_CUDA_ARCHITECTURES native) # on 3.24+, on earlier it is ignored, and the target is not passed
endif ()
project(example LANGUAGES CUDA CXX)

set(CMAKE_CUDA_FLAGS "${CMAKE_CUDA_FLAGS} --expt-relaxed-constexpr -DCURVE_ID=BN254")
set(CMAKE_CUDA_FLAGS_RELEASE "")
set(CMAKE_CUDA_FLAGS_DEBUG "${CMAKE_CUDA_FLAGS_DEBUG} -g -G -O0")

add_executable(
    poly_api_examples
    src/lib.cu
    src/poly_test.cu
)

target_include_directories(poly_api_examples PRIVATE 
"../../icicle/icicle/include"
"${CMAKE_SOURCE_DIR}/include")

target_link_libraries(poly_api_examples 
${CMAKE_SOURCE_DIR}/../../icicle/icicle/build/lib/libingo_curve_bn254.a
${CMAKE_SOURCE_DIR}/../../icicle/icicle/build/lib/libingo_field_bn254.a
${CMAKE_SOURCE_DIR}/../../icicle/icicle/build/lib/libgmock_main.a
${CMAKE_SOURCE_DIR}/../../icicle/icicle/build/lib/libgmock.a
${CMAKE_SOURCE_DIR}/../../icicle/icicle/build/lib/libgtest_main.a
${CMAKE_SOURCE_DIR}/../../icicle/icicle/build/lib/libgtest.a
)
target_compile_definitions(poly_api_examples PUBLIC FIELD_ID BN254)
set_target_properties(poly_api_examples PROPERTIES CUDA_SEPARABLE_COMPILATION ON)