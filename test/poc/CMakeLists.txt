list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/../cosigner/cmake")

find_package(UUID REQUIRED)
find_package(Threads REQUIRED)

add_executable(poc_test poc_main.cpp)

if(APPLE)
    target_link_libraries(poc_test PRIVATE tests_main cosigner Threads::Threads)
else()
    target_link_libraries(poc_test PRIVATE tests_main cosigner Threads::Threads UUID::UUID)
endif()

add_test(NAME poc_test COMMAND poc_test)

# POC: fail-open in ring_pedersen_parameters_zkp_verify (ring_pedersen.c:794-799)
add_executable(poc_ring_pedersen_failopen poc_ring_pedersen_failopen.cpp)
target_include_directories(poc_ring_pedersen_failopen PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/../../src/common/crypto/commitments)
target_link_libraries(poc_ring_pedersen_failopen PRIVATE cosigner OpenSSL::Crypto)
add_test(NAME poc_ring_pedersen_failopen COMMAND poc_ring_pedersen_failopen)

# POC: key-share recovery once the ring-Pedersen ZKP is skipped
add_executable(poc_ring_pedersen_trapdoor poc_ring_pedersen_trapdoor.cpp)
target_include_directories(poc_ring_pedersen_trapdoor PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/../../src/common/crypto/commitments)
target_link_libraries(poc_ring_pedersen_trapdoor PRIVATE cosigner OpenSSL::Crypto)
add_test(NAME poc_ring_pedersen_trapdoor COMMAND poc_ring_pedersen_trapdoor)
