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
