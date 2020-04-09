#ifndef PREDICATE_TRACER_PRED_TRACE_PASS_H
#define PREDICATE_TRACER_PRED_TRACE_PASS_H

#include <llvm/IR/PassManager.h>
#include <llvm/Pass.h>

struct PredicateTracerPass : llvm::PassInfoMixin<PredicateTracerPass> {
    llvm::PreservedAnalyses run(llvm::Module&, llvm::ModuleAnalysisManager&);
    bool processBasicBlock(llvm::BasicBlock&, llvm::Function*);
};

#endif  // PREDICATE_TRACER_PRED_TRACE_PASS_H
