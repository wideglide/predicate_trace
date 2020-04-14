#include <llvm/IR/Instructions.h>
#include <llvm/Support/SMTAPI.h>

#include <cstdint>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <mutex>
#include <nlohmann/json.hpp>
#include <stack>
#include <unordered_map>

#include "predicate_trace_pass.h"

using namespace llvm;

struct hash_pair {
    template <typename X, typename Y>
    size_t operator()(const std::pair<X, Y>& x) const {
        return std::hash<X>()(x.first) ^ std::hash<Y>()(x.second);
    }
};

static bool set_finalizer = false;
static std::unordered_map<std::pair<uint32_t, uint32_t>, size_t, hash_pair> predicate_counts;
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
static void __predicate_trace_log_statistics() {
    using json = nlohmann::json;

    std::lock_guard<std::mutex> lock(predicate_counts_mutex);

    char default_path[] = "/tmp/predicate_trace.json";
    auto path = getenv("PREDICATE_TRACE_LOG_PATH");
    if (!path) {
        path = default_path;
    }

    json o;
    std::unordered_map<std::pair<std::string, std::string>, size_t, hash_pair> counts;
    for (auto& it : predicate_counts) {
        auto opcode = Instruction::getOpcodeName(it.first.first);
        auto predicate = CmpInst::getPredicateName(CmpInst::Predicate(it.first.second));
        auto key = std::make_pair<std::string, std::string>(opcode, predicate.str());
        counts.emplace(key, it.second);
    }

    o["predicate_trace_statistics"]["predicate_counts"] = counts;
    log() << "logging statistics to " << path << "\n";
    std::ofstream output(path);
    output << o.dump();
}

/**
 * Update predicate statistics.
 *
 * @param opcode Comparison instruction opcode (ICmp or FCmp).
 * @param predicate Comparison instruction predicate.
 */
extern "C" void __predicate_trace_update_stats(uint32_t opcode, uint32_t predicate) noexcept {
    std::lock_guard<std::mutex> lock(predicate_counts_mutex);

    auto key = std::make_pair(opcode, predicate);
    auto it = predicate_counts.emplace(key, 1);
    if (!it.second) {
        size_t* x = &it.first->second;
        ++*x;
    }

    // TODO: We're also going to need a crash handler
    if (!set_finalizer) {
        std::atexit(__predicate_trace_log_statistics);
        set_finalizer = true;
    }
}

// The feature vector needs to be wide enough to cover the predicate feature enum
using GlobalScope = std::map<const uint64_t*, PredicateFeatures>;
static GlobalScope globals;
static std::mutex globals_mutex;

/**
 * Return a value.
 *
 * TODO: Should we worry about concurrency issues with returned values here?
 *
 * @param ptr Pointer.
 * @return Value.
 */
extern "C" uint64_t __predicate_trace_load(const uint64_t* ptr) noexcept {
    std::lock_guard<std::mutex> lock(globals_mutex);
    auto it = globals.find(ptr);
    if (it != globals.end()) {
        return it->second.to_ullong();
    }

    it = globals.upper_bound(ptr);
    if (it != globals.end()) {
        if (it != globals.begin()) {
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
extern "C" void __predicate_trace_store(const uint64_t* ptr, const uint64_t value) noexcept {
    std::lock_guard<std::mutex> lock(globals_mutex);
    globals[ptr] = value;
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
    // Push a scope with one slot for the return value, if any
    call_stack.push({});
}

/**
 * Pop a local scope, returning the return value.
 *
 * @return Return value.
 */
extern "C" uint64_t __predicate_trace_pop_locals() noexcept {
    assert(!call_stack.empty());
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
    assert(!call_stack.empty());
    call_stack.top().arguments_.emplace_back(value);
}

/**
 * Return an argument value.
 *
 * @param index Index.
 * @return Value.
 */
extern "C" uint64_t __predicate_trace_get_argument(const uint32_t index) noexcept {
    assert(!call_stack.empty() && index < call_stack.top().arguments_.size());
    return call_stack.top().arguments_[index].to_ullong();
}

/**
 * Set a return value.
 *
 * @param value Value.
 */
extern "C" void __predicate_trace_set_return(const uint64_t value) noexcept {
    assert(!call_stack.empty());
    call_stack.top().return_value_ = value;
}

static thread_local std::unordered_map<uint64_t, uint64_t> predicates;

/**
 * Push a path predicate.
 *
 * @param block_label Block label.
 * @param predicate Predicate.
 */
extern "C" void __predicate_trace_push(uint64_t block_label, uint64_t predicate) noexcept {
    predicates[block_label] = predicate;
}

/**
 * Pop a path predicate.
 *
 * @param block_label Block label.
 */
extern "C" void __predicate_trace_pop(uint64_t block_label) noexcept {
    predicates.erase(block_label);
}
