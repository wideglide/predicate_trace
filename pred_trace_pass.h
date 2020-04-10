#ifndef PREDICATE_TRACER_PRED_TRACE_PASS_H
#define PREDICATE_TRACER_PRED_TRACE_PASS_H

#include <llvm/Analysis/PostDominators.h>
#include <llvm/IR/PassManager.h>
#include <llvm/Pass.h>

#include <random>
#include <unordered_map>

struct PredicateTracerPass : llvm::PassInfoMixin<PredicateTracerPass> {
    explicit PredicateTracerPass() : rng_(std::time(nullptr)) {}
    llvm::PreservedAnalyses run(llvm::Module&, llvm::ModuleAnalysisManager&);

private:
    bool processBasicBlock(llvm::BasicBlock&);

    std::mt19937_64 rng_;
    std::unordered_map<llvm::BasicBlock*, uint64_t> block_labels_;
    llvm::Function* update_pred_stats_fn_{};
    llvm::Function* push_pred_fn_{};
    llvm::Function* pop_pred_fn_{};
    llvm::PostDominatorTree post_dom_tree_;
};

#endif  // PREDICATE_TRACER_PRED_TRACE_PASS_H
