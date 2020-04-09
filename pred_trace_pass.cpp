#include "pred_trace_pass.h"

#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/Instructions.h>
#include <llvm/Passes/PassBuilder.h>
#include <llvm/Passes/PassPlugin.h>

using namespace llvm;

PreservedAnalyses PredicateTracerPass::run(Module& module, ModuleAnalysisManager& manager) {
    errs() << "instrumenting predicates for " << module.getName() << "\n";

    // Declare the statistics update function
    auto& context = module.getContext();
    auto update_fn_ty = FunctionType::get(
        Type::getVoidTy(context),
        {
            IntegerType::getInt32Ty(context),
            IntegerType::getInt32Ty(context),
        },
        false);
    auto update_fn_decl = module.getOrInsertFunction("__pred_trace_update_stats", update_fn_ty);
    auto update_fn_callee = dyn_cast<Function>(update_fn_decl.getCallee());
    update_fn_callee->setDoesNotThrow();

    bool modified = false;
    for (auto& function : module) {
        if (function.isDeclaration()) {
            continue;
        }

        for (auto& block : function) {
            modified |= processBasicBlock(block, update_fn_callee);
        }
    }

    return modified ? PreservedAnalyses::none() : PreservedAnalyses::all();
}

bool PredicateTracerPass::processBasicBlock(BasicBlock& block, Function* update_fn_callee) {
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
        return false;
    }

    // Log the first comparison instruction that precedes the conditional branch
    bool modified = false;
    for (auto insn = cond_term->getPrevNode(); insn; insn = insn->getPrevNode()) {
        auto cmp_insn = dyn_cast<CmpInst>(insn);
        if (cmp_insn) {
            // Update the predicate statistics
            IRBuilder<> builder(&*cmp_insn);
            const auto opcode = builder.getInt32(cmp_insn->getOpcode());
            const auto predicate = builder.getInt32(cmp_insn->getPredicate());
            builder.CreateCall(update_fn_callee, {opcode, predicate});
            modified = true;
            break;
        }
    }

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
