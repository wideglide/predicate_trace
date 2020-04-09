#include <gtest/gtest.h>

#include <cstdlib>
#include <fstream>
#include <iostream>

static void run_pred_trace_test(
    const char* test_command, const char* output_path, const char* expected) {
    auto result = setenv("PRED_TRACE_LOG_PATH", output_path, 1);
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

#define PRED_TRACE_TEST(test_name, expected)                                     \
    TEST(PredTraceTest, test_name) {                                             \
        run_pred_trace_test(                                                     \
            "PRED_TRACE_LOG_PATH=/tmp/" #test_name ".json ./llvm-ir/" #test_name \
            "_exe/" #test_name "_exe >/dev/null 2>&1",                           \
            "/tmp/" #test_name ".json",                                          \
            expected);                                                           \
    }

PRED_TRACE_TEST(test_00, "{\"pred_trace_stats\":{\"pred_counts\":[[[\"icmp\",\"sgt\"],1]]}}");
