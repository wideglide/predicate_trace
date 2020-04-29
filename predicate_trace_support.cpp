#pragma clang diagnostic push
#pragma ide diagnostic ignored "bugprone-reserved-identifier"
#include <llvm/IR/Instructions.h>
#include <llvm/Support/SMTAPI.h>
#include <unistd.h>

#include <boost/filesystem.hpp>
#include <cstdint>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <mutex>
#include <nlohmann/json.hpp>
#include <stack>
#include <unordered_map>
#include <unordered_set>

#include "predicate_trace_fb.h"
#include "predicate_trace_pass.h"

#include <sys/syscall.h>
#define gettid() syscall(SYS_gettid)

using namespace llvm;
namespace fs = boost::filesystem;

/** Program exiting flag. */
uint32_t __predicate_trace_program_exiting = 0;

/** Predicate counts map. */
static std::
    unordered_map<std::pair<uint32_t, uint32_t>, size_t, llvm::pair_hash<uint32_t, uint32_t>>
        predicate_counts;

/** Predicate counts mutex. */
static std::mutex predicate_counts_mutex;

/**
 * Return a message logger.
 *
 * @return Logger.
 */
std::ostream& log() {
    std::cerr << "PREDICATE_TRACE: ";
    return std::cerr;
}

/**
 * Log predicate statistics.
 */
static void __attribute__((destructor)) __predicate_trace_log_statistics() {
    using json = nlohmann::json;

    std::lock_guard<std::mutex> lock(predicate_counts_mutex);

    char default_log_path[] = "/tmp/predicate_trace";
    auto log_path = getenv("PREDICATE_TRACE_LOG_PATH");
    if (!log_path) {
        log_path = default_log_path;
    }

    json o;
    std::unordered_map<
        std::pair<std::string, std::string>,
        size_t,
        llvm::pair_hash<std::string, std::string>>
        counts;
    for (auto& it : predicate_counts) {
        auto opcode = Instruction::getOpcodeName(it.first.first);
        auto predicate = CmpInst::getPredicateName(CmpInst::Predicate(it.first.second));
        auto key = std::make_pair<std::string, std::string>(opcode, predicate.str());
        counts.emplace(key, it.second);
    }

    o["predicate_counts"] = counts;
    fs::path log_dir = log_path;
    boost::system::error_code error;
    fs::create_directories(log_dir, error);
    fs::path file_path = log_dir / "statistics.json";
    log() << "logging statistics to " << file_path << "\n";
    std::ofstream output(file_path.string());
    output << o.dump();
}

/**
 * Update predicate statistics.
 *
 * @param opcode Comparison instruction opcode (ICmp or FCmp).
 * @param predicate Comparison instruction predicate.
 */
extern "C" void __predicate_trace_update_stats(uint32_t opcode, uint32_t predicate) noexcept {
    if (__predicate_trace_program_exiting) {
        return;
    }

    std::lock_guard<std::mutex> lock(predicate_counts_mutex);
    auto key = std::make_pair(opcode, predicate);
    auto it = predicate_counts.emplace(key, 1);
    if (!it.second) {
        size_t* x = &it.first->second;
        ++*x;
    }

    // TODO: We're also going to need a crash handler
}

// The feature vector needs to be wide enough to cover the predicate feature enum
// TODO: Should we worry about concurrency issues?
using FeatureMemory = std::map<const uint64_t, PredicateFeatures>;
static FeatureMemory features;
static std::mutex features_mutex;

/**
 * Return a value.
 *
 * @param ptr Pointer.
 * @return Value.
 */
extern "C" uint64_t __predicate_trace_load(const uint64_t ptr) noexcept {
    if (__predicate_trace_program_exiting) {
        return 0;
    }

    std::lock_guard<std::mutex> lock(features_mutex);
    auto it = features.find(ptr);
    if (it != features.end()) {
        return it->second.to_ullong();
    }

    it = features.upper_bound(ptr);
    if (it != features.end()) {
        if (it != features.begin()) {
            --it;
            return it->second.to_ullong();
        }
    }

    return 0;
}

/**
 * Set a value.
 *
 * @param ptr Pointer.
 * @param value Value.
 */
extern "C" void __predicate_trace_store(const uint64_t ptr, const uint64_t value) noexcept {
    if (__predicate_trace_program_exiting) {
        return;
    }

    std::lock_guard<std::mutex> lock(features_mutex);
    features[ptr] = value;
}

struct LocalScope {
    std::vector<PredicateFeatures> arguments_;
    PredicateFeatures return_value_;
};

static thread_local std::stack<LocalScope> call_stack;  // NOLINT(cert-err58-cpp)

/**
 * Push a new local scope.
 */
extern "C" void __predicate_trace_push_locals() noexcept {
    if (__predicate_trace_program_exiting) {
        return;
    }

    // Push a scope with one slot for the return value, if any
    call_stack.push({});
}

/**
 * Pop a local scope, returning the return value.
 *
 * @return Return value.
 */
extern "C" uint64_t __predicate_trace_pop_locals() noexcept {
    if (__predicate_trace_program_exiting) {
        return 0;
    }

    if (call_stack.empty()) {
        return 0;
    }

    auto return_value = call_stack.top().return_value_.to_ullong();
    call_stack.pop();
    return return_value;
}

/**
 * Push an argument value.
 *
 * @param value Value.
 */
extern "C" void __predicate_trace_push_argument(const uint64_t value) noexcept {
    if (__predicate_trace_program_exiting) {
        return;
    }

    if (call_stack.empty()) {
        return;
    }

    call_stack.top().arguments_.emplace_back(value);
}

/**
 * Return an argument value.
 *
 * @param index Index.
 * @return Value.
 */
extern "C" uint64_t __predicate_trace_get_argument(const uint32_t index) noexcept {
    if (__predicate_trace_program_exiting) {
        return 0;
    }

    if (call_stack.empty()) {
        return 0;
    }

    if (index >= call_stack.top().arguments_.size()) {
        return 0;
    }

    return call_stack.top().arguments_[index].to_ullong();
}

/**
 * Set a return value.
 *
 * @param value Value.
 */
extern "C" void __predicate_trace_set_return(const uint64_t value) noexcept {
    if (__predicate_trace_program_exiting) {
        return;
    }

    if (call_stack.empty()) {
        return;
    }

    call_stack.top().return_value_ = value;
}

// TODO: Unfortunately, destructors for thread-local data are run before the finalizer that logs
//       everything to disk, so we need to use globally-visible data here.  So, for now despite
//       the lock this code will give incorrect results for multithreaded programs.

/** Current predicate set at any given program point. */
static std::unordered_map<uint64_t, uint64_t> current_predicates;

/** Block predicates. */
static std::unordered_map<uint64_t, std::pair<uint64_t, uint64_t>> block_predicates;

/** Last conditional block. */
static uint64_t last_block_label;

/** Edge set. */
static std::unordered_set<std::pair<uint64_t, uint64_t>, llvm::pair_hash<uint64_t, uint64_t>> edges;

/** Predicates mutex. */
static std::mutex predicates_mutex;

/**
 * Log predicates.
 */
static void __attribute__((destructor)) __predicate_trace_log_predicates() {
    using namespace flatbuffers;
    using namespace PredicateTrace;

    std::lock_guard<std::mutex> lock(predicates_mutex);

    char default_log_path[] = "/tmp/predicate_trace";
    auto log_path = getenv("PREDICATE_TRACE_LOG_PATH");
    if (!log_path) {
        log_path = default_log_path;
    }

    fs::path log_dir = log_path;
    boost::system::error_code error;
    fs::create_directories(log_dir, error);

    std::vector<Edge> es;
    es.reserve(edges.size());
    for (auto& it : edges) {
        es.emplace_back(it.first, it.second);
    }

    std::vector<BlockPredicate> ps;
    ps.reserve(block_predicates.size());
    for (auto& it : block_predicates) {
        ps.emplace_back(it.first, it.second.first, it.second.second);
    }

    FlatBufferBuilder builder(1024);
    auto trace = CreateTraceDirect(builder, &es, &ps);
    builder.Finish(trace);

    fs::path file_path = log_dir / "predicates.fb";
    log() << "logging predicates to " << file_path << "\n";
    std::ofstream output(file_path.string(), std::ios::binary);
    output.write(reinterpret_cast<char*>(builder.GetBufferPointer()), builder.GetSize());
}

/**
 * Push a path predicate.
 *
 * @param block_label Block label.
 * @param predicate Predicate.
 */
extern "C" void __predicate_trace_push(uint64_t block_label, uint64_t predicate) noexcept {
    if (__predicate_trace_program_exiting) {
        return;
    }

    std::lock_guard<std::mutex> lock(predicates_mutex);
    current_predicates[block_label] = predicate;

    auto path_features = 0UL;
    for (auto& current_predicate : current_predicates) {
        path_features |= current_predicate.second;
    }

    auto it = block_predicates.find(block_label);
    if (it != block_predicates.end()) {
        it->second.first |= path_features;
        it->second.second = current_predicates.size();
    } else {
        block_predicates[block_label] = std::make_pair(path_features, current_predicates.size());
    }
}

/**
 * Pop a path predicate.
 *
 * @param true_block_label True block label.
 * @param false_block_label False block label.
 */
extern "C" void __predicate_trace_pop(
    uint64_t true_block_label, uint64_t false_block_label) noexcept {
    if (__predicate_trace_program_exiting) {
        return;
    }

    std::lock_guard<std::mutex> lock(predicates_mutex);
    current_predicates.erase(true_block_label);
    current_predicates.erase(false_block_label);
}

/**
 * Record a block transition.
 *
 * @param block_label Block label.
 */
extern "C" void __predicate_trace_record_transition(uint64_t block_label) noexcept {
    if (__predicate_trace_program_exiting) {
        return;
    }

    std::lock_guard<std::mutex> lock(predicates_mutex);
    if (last_block_label) {
        edges.emplace(last_block_label, block_label);
    }

    last_block_label = block_label;
}

#pragma clang diagnostic pop
