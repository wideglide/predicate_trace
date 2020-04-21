#ifndef PREDICATE_TRACER_PREDICATE_TRACE_PASS_H
#define PREDICATE_TRACER_PREDICATE_TRACE_PASS_H

#include <llvm/Analysis/PostDominators.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/PassManager.h>
#include <llvm/Pass.h>

#include <bitset>
#include <random>
#include <unordered_map>

using PredicateFeatures = std::bitset<64>;

// TODO: Do we want to perform any counting?  e.g., for number of symbolic variables?
enum PredicateFeature {
    BoolSort = 0,
    BVSort,
    FPSort,
    BVAdd,
    BVSub,
    BVMul,
    BVSRem,
    BVURem,
    BVSDiv,
    BVUDiv,
    BVShl,
    BVAShr,
    BVLShr,
    BVNeg,
    BVNot,
    BVXor,
    BVOr,
    BVAnd,
    BVUlt,
    BVSlt,
    BVUgt,
    BVSgt,
    BVUle,
    BVSle,
    BVUge,
    BVSge,
    Not,
    Equal,
    And,
    Or,
    Ite,
    BVSignExt,
    BVZeroExt,
    BVExtract,
    BVConcat,
    FPNeg,
    FPIsInfinite,
    FPIsNaN,
    FPIsNormal,
    FPIsZero,
    FPMul,
    FPDiv,
    FPRem,
    FPAdd,
    FPSub,
    FPLt,
    FPGt,
    FPLe,
    FPGe,
    FPEqual,
    FPtoFP,
    SBVtoFP,
    UBVtoFP,
    FPtoSBV,
    FPtoUBV,
    BoolLit,
    BVLit,
    FPLit,
    Symbolic,
};

/**
 * Predicate trace pass.
 */
struct PredicateTracePass : llvm::PassInfoMixin<PredicateTracePass> {
    explicit PredicateTracePass();
    llvm::PreservedAnalyses run(llvm::Module&, llvm::ModuleAnalysisManager&);

private:
    void instrumentMain(llvm::Function&);
    void instrumentInstructions(llvm::BasicBlock&);
    llvm::Instruction* instrumentComparison(llvm::CmpInst*);
    llvm::Instruction* instrumentStore(llvm::StoreInst*);
    llvm::Instruction* instrumentCall(llvm::CallBase*);
    llvm::Instruction* instrumentReturn(llvm::ReturnInst*);
    void instrumentConditionalBranch(llvm::BranchInst*);
    llvm::Value* extractPredicate(llvm::IRBuilder<>&, llvm::Instruction*);
    llvm::Value* extractPredicate(llvm::IRBuilder<>&, llvm::Value*);
    std::size_t getBlockLabel(llvm::BasicBlock*);
    void setBlockLabel(llvm::BasicBlock*, std::size_t id);

    std::uint64_t module_id_;
    std::uint64_t function_id_;
    std::uint64_t num_blocks_;
    std::unordered_map<llvm::BasicBlock*, uint64_t> block_labels_;
    std::unordered_map<llvm::CallBase*, llvm::Value*> return_values_;
    llvm::Function* update_predicate_stats_fn_{};
    llvm::Function* load_fn_{};
    llvm::Function* store_fn_{};
    llvm::Function* push_locals_fn_{};
    llvm::Function* pop_locals_fn_{};
    llvm::Function* push_arg_fn_{};
    llvm::Function* get_arg_fn_{};
    llvm::Function* set_return_fn_{};
    llvm::Function* push_predicate_fn_{};
    llvm::Function* pop_predicate_fn_{};
    llvm::PostDominatorTree post_dom_tree_;
};

#endif  // PREDICATE_TRACER_PREDICATE_TRACE_PASS_H
