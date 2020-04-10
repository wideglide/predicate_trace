#include "pred_trace_pass.h"

#include <llvm/Analysis/PostDominators.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/Instructions.h>
#include <llvm/Passes/PassBuilder.h>
#include <llvm/Passes/PassPlugin.h>
#include <llvm/Transforms/Utils/BasicBlockUtils.h>

using namespace llvm;

PreservedAnalyses PredicateTracerPass::run(Module& module, ModuleAnalysisManager& manager) {
    errs() << "instrumenting predicates for " << module.getName() << "\n";

    // Declare the statistics update function
    auto& context = module.getContext();
    auto update_pred_stats_fn_ty = FunctionType::get(
        Type::getVoidTy(context),
        {
            IntegerType::getInt32Ty(context),
            IntegerType::getInt32Ty(context),
        },
        false);
    auto update_pred_stats_fn_decl =
        module.getOrInsertFunction("__pred_trace_update_stats", update_pred_stats_fn_ty);
    update_pred_stats_fn_ = dyn_cast<Function>(update_pred_stats_fn_decl.getCallee());
    update_pred_stats_fn_->setDoesNotThrow();

    // Declare the predicate push function
    auto push_pred_fn_ty =
        FunctionType::get(Type::getVoidTy(context), {IntegerType::getInt64Ty(context)}, false);
    auto push_pred_fn_decl = module.getOrInsertFunction("__pred_trace_push", push_pred_fn_ty);
    push_pred_fn_ = dyn_cast<Function>(push_pred_fn_decl.getCallee());
    push_pred_fn_->setDoesNotThrow();

    // Declare the predicate pop function
    auto pop_pred_fn_ty =
        FunctionType::get(Type::getVoidTy(context), {IntegerType::getInt64Ty(context)}, false);
    auto pop_pred_fn_decl = module.getOrInsertFunction("__pred_trace_pop", pop_pred_fn_ty);
    pop_pred_fn_ = dyn_cast<Function>(pop_pred_fn_decl.getCallee());
    pop_pred_fn_->setDoesNotThrow();

    // Process all functions in the module
    bool modified = false;
    for (auto& function : module) {
        if (function.isDeclaration()) {
            continue;
        }

        // Compute the post-dominator tree for this function
        post_dom_tree_ = PostDominatorTree(function);

        // (Randomly) label all basic blocks
        for (auto& block : function) {
            block_labels_.emplace(&block, rng_());
        }

        // Process each basic block
        for (auto& block : function) {
            modified |= processBasicBlock(block);
        }
    }

    return modified ? PreservedAnalyses::none() : PreservedAnalyses::all();
}

bool PredicateTracerPass::processBasicBlock(BasicBlock& block) {
    bool modified = false;

    const auto get_cond_term = [&]() -> BranchInst* {
        auto term_insn = block.getTerminator();
        if (term_insn) {
            auto branch_insn = dyn_cast<BranchInst>(term_insn);
            if (branch_insn) {
                if (branch_insn->isConditional()) {
                    return branch_insn;
                }
            }
        }

        return nullptr;
    };

    // Check whether this block has a conditional terminator
    auto cond_term = get_cond_term();
    if (!cond_term) {
        return modified;
    }

    // Assume the condition is the comparison function and instrument it
    const auto cmp_insn = dyn_cast<CmpInst>(cond_term->getCondition());
    if (cmp_insn) {
        // Update the predicate statistics
        IRBuilder<> builder(&*cmp_insn);
        const auto opcode = builder.getInt32(cmp_insn->getOpcode());
        const auto predicate = builder.getInt32(cmp_insn->getPredicate());
        builder.CreateCall(update_pred_stats_fn_, {opcode, predicate});
        modified = true;
    } else {
        errs() << "WARNING: condition is not a comparison function\n";
        return modified;
    }

    // Insert code to pop path predicates at post-dominator
    auto block_label = block_labels_[&block];
    post_dom_tree_.recalculate(*block.getParent());
    auto post_dom_block = post_dom_tree_.findNearestCommonDominator(
        cond_term->getSuccessor(0), cond_term->getSuccessor(1));
    assert(post_dom_block != nullptr);
    IRBuilder<> builder(&*post_dom_block->getFirstInsertionPt());
    builder.CreateCall(pop_pred_fn_, {builder.getInt64(block_label)});

    // Insert basic block for each outgoing edge to push respective path predicates
    // TODO: Insert actual predicate and not just the block label
    auto true_block = SplitEdge(&block, cond_term->getSuccessor(0));
    assert(true_block != nullptr);
    block_labels_.emplace(true_block, rng_());
    builder.SetInsertPoint(&*true_block->getFirstInsertionPt());
    builder.CreateCall(push_pred_fn_, {builder.getInt64(block_label)});
    auto false_block = SplitEdge(&block, cond_term->getSuccessor(1));
    assert(false_block != nullptr);
    block_labels_.emplace(false_block, rng_());
    builder.SetInsertPoint(&*false_block->getFirstInsertionPt());
    builder.CreateCall(push_pred_fn_, {builder.getInt64(block_label)});

    return modified;
}

extern "C" LLVM_ATTRIBUTE_WEAK PassPluginLibraryInfo llvmGetPassPluginInfo() {
    return {
        LLVM_PLUGIN_API_VERSION,
        "predicate-trace",
        LLVM_VERSION_STRING,
        [](PassBuilder& builder) {
            builder.registerPipelineParsingCallback([](StringRef name,
                                                       ModulePassManager& manager,
                                                       ArrayRef<PassBuilder::PipelineElement>) {
                if (name == "predicate-trace") {
                    manager.addPass(PredicateTracerPass());
                    return true;
                }

                return false;
            });
        },
    };
}
