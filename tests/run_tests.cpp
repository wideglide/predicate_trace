#include <gtest/gtest.h>

#include <cstdlib>
#include <fstream>
#include <iostream>

static void run_predicate_trace_test(
    const char* test_command, const char* output_path, const char* expected) {
    auto result = setenv("PREDICATE_TRACE_LOG_PATH", output_path, 1);
    ASSERT_EQ(result, 0);
    result = std::system(test_command);
    ASSERT_EQ(result, 0);

    std::string observed;
    std::ifstream input(output_path);
    input.seekg(0, std::ios::end);
    observed.reserve(input.tellg());
    input.seekg(0, std::ios::beg);
    observed.append(
        std::istreambuf_iterator<char>(input.rdbuf()), std::istreambuf_iterator<char>());
    ASSERT_STREQ(observed.c_str(), expected);
}

#define PREDICATE_TRACE_TEST(test_name, expected)                                \
    TEST(PredTraceTest, test_name) {                                             \
        run_predicate_trace_test(                                                \
            "PRED_TRACE_LOG_PATH=/tmp/" #test_name ".json ./" #test_name " >/dev/null 2>&1", \
            "/tmp/" #test_name ".json",                                          \
            expected);                                                           \
    }

PREDICATE_TRACE_TEST(
    test_if_00, "{\"predicate_trace_statistics\":{\"predicate_counts\":[[[\"icmp\",\"sgt\"],1]]}}");
PREDICATE_TRACE_TEST(
    test_if_01, "{\"predicate_trace_statistics\":{\"predicate_counts\":[[[\"icmp\",\"sgt\"],2]]}}");
PREDICATE_TRACE_TEST(
    test_ifelse_00,
    "{\"predicate_trace_statistics\":{\"predicate_counts\":[[[\"icmp\",\"sgt\"],1]]}}");
PREDICATE_TRACE_TEST(
    test_for_00,
    "{\"predicate_trace_statistics\":{\"predicate_counts\":[[[\"icmp\",\"sge\"],11]]}}")
PREDICATE_TRACE_TEST(
    test_fn_00,
    "{\"predicate_trace_statistics\":{\"predicate_counts\":[[[\"icmp\",\"sgt\"],3],[[\"icmp\","
    "\"sge\"],1]]}}")
PREDICATE_TRACE_TEST(
    test_global_00,
    "{\"predicate_trace_statistics\":{\"predicate_counts\":[[[\"icmp\",\"sgt\"],1]]}}")
PREDICATE_TRACE_TEST(
    test_bswap_00,
    "{\"predicate_trace_statistics\":{\"predicate_counts\":[[[\"icmp\",\"sgt\"],2]]}}");
