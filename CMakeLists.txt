cmake_minimum_required(VERSION 3.15)
project(predicate_trace C CXX)

set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_COMPILER_ID Clang)

find_package(LLVM 10.0 REQUIRED CONFIG)
include_directories(${LLVM_INCLUDE_DIRS})
if (NOT LLVM_ENABLE_RTTI)
    set(CMAKE_CXX_FLAGS ${CMAKE_CXX_FLAGS} -fno-rtti)
endif ()

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/llvm-ir-cmake-utils/cmake")
include(LLVMIRUtil)
include(GoogleTest)

add_subdirectory(googletest)

add_library(predicate_trace_pass SHARED predicate_trace_pass.cpp predicate_trace_pass.h)
target_compile_definitions(predicate_trace_pass PUBLIC LLVM_USE_NEWPM)

add_library(predicate_trace_support SHARED predicate_trace_support.cpp)
target_include_directories(predicate_trace_support PUBLIC json/include)
target_link_libraries(predicate_trace_support PUBLIC LLVM)

add_executable(run_tests tests/run_tests.cpp)
target_include_directories(run_tests PUBLIC googletest/googletest/include)
target_link_libraries(run_tests PUBLIC gtest_main)

function(predicate_trace_test)
    add_executable(${ARGV0} tests/${ARGV0}.cpp)
    set_target_properties(${ARGV0} PROPERTIES LINKER_LANGUAGE CXX)
    set_target_properties(${ARGV0} PROPERTIES COMPILE_FLAGS "\
        -Xclang -load \
	-Xclang ${CMAKE_BINARY_DIR}/libpredicate_trace_pass.so \
	")
    add_dependencies(${ARGV0} predicate_trace_pass)
    target_link_libraries(${ARGV0} predicate_trace_support)
    add_dependencies(run_tests ${ARGV0})

endfunction()

predicate_trace_test(test_if_00)
predicate_trace_test(test_if_01)
predicate_trace_test(test_ifelse_00)
predicate_trace_test(test_for_00)
predicate_trace_test(test_fn_00)
predicate_trace_test(test_global_00)
predicate_trace_test(test_bswap_00)
