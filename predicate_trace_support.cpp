#include <llvm/IR/Instructions.h>

#include <cstdint>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <mutex>
#include <nlohmann/json.hpp>
#include <unordered_map>

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
 * Log predicate statistics.
 */
static void __predicate_trace_log_statistics() {
    using json = nlohmann::json;
    using namespace llvm;

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

    o["predicate_trace_stats"]["predicate_counts"] = counts;
    std::cerr << "PREDICATE_TRACE: logging statistics to " << path << "\n";
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

    if (!set_finalizer) {
        std::atexit(__predicate_trace_log_statistics);
        set_finalizer = true;
    }
}

struct Expr {};

static std::unordered_map<uint64_t, Expr> predicate_set;
static std::mutex predicate_set_mutex;

/**
 * Push a path predicate.
 *
 * @param block_label Block label.
 */
extern "C" void __predicate_trace_push(uint64_t block_label) noexcept {
    std::lock_guard<std::mutex> lock(predicate_set_mutex);
}

/**
 * Pop a path predicate.
 *
 * @param block_label Block label.
 */
extern "C" void __predicate_trace_pop(uint64_t block_label) noexcept {
    std::lock_guard<std::mutex> lock(predicate_set_mutex);
}
