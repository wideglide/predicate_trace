#include "predicate_trace_pass.h"

#include <llvm/Analysis/PostDominators.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/Instructions.h>
#include <llvm/Transforms/Utils/BasicBlockUtils.h>

#include "llvm/Support/CommandLine.h"
#include "llvm/IR/DerivedUser.h"
#include "llvm/IR/LegacyPassManager.h"
#include "llvm/Transforms/IPO/PassManagerBuilder.h"

#include <iostream>

using namespace llvm;

static cl::opt<bool> enable_feature_tracking{
    "enable-predicate-feature-tracking",
    cl::desc("Enable run-time predicate feature vector tracking"),
    cl::init(false),
};

static raw_ostream& log() {
    errs() << "PREDICATE_TRACE: ";
    return errs();
}

// PredicateTracePass::PredicateTracePass() : module_id_(0), function_id_(0), num_blocks_(0) {}

namespace {
    class PredicateTracePass : public ModulePass {
        public:
            static char ID;
            PredicateTracePass() : ModulePass(ID) {}

            bool runOnModule(Module &) override;

private:
    void instrumentMain(Function&);
    void instrumentBlock(BasicBlock& block);
    Instruction* instrumentComparison(CmpInst*);
    Instruction* instrumentStore(StoreInst*);
    Instruction* instrumentCall(CallBase*);
    Instruction* instrumentReturn(ReturnInst*);
    void instrumentConditionalBranch(BranchInst*);
    Value* extractPredicate(IRBuilder<>&, Instruction*);
    Value* extractPredicate(IRBuilder<>&, Value*);
    std::size_t getBlockLabel(BasicBlock*);
    void setBlockLabel(BasicBlock*, std::size_t id);

    std::uint64_t module_id_;
    std::uint64_t function_id_;
    std::uint64_t num_blocks_;
    std::unordered_map<BasicBlock*, uint64_t> block_labels_;
    std::unordered_map<CallBase*, Value*> return_values_;
    GlobalValue* program_exiting_{};
    Function* update_predicate_stats_fn_{};
    Function* load_fn_{};
    Function* store_fn_{};
    Function* push_locals_fn_{};
    Function* pop_locals_fn_{};
    Function* push_arg_fn_{};
    Function* get_arg_fn_{};
    Function* set_return_fn_{};
    Function* push_predicate_fn_{};
    Function* pop_predicate_fn_{};
    Function* record_transition_{};
    PostDominatorTree post_dom_tree_;
    };
}


bool PredicateTracePass::runOnModule(Module &module) {

    log() << "instrumenting predicates for " << module.getName() << "\n";

    if (getenv("PREDICATE_TRACE_PASS_TRACKING") != NULL) {
        enable_feature_tracking = true;
    }

    auto& context = module.getContext();
    module_id_ = std::hash<std::string>{}(module.getModuleIdentifier());

    // Declare the program exiting flag
    program_exiting_ = dyn_cast<GlobalVariable>(
        module.getOrInsertGlobal("__predicate_trace_program_exiting", Type::getInt32Ty(context)));

    // Declare the statistics update function
    auto update_predicate_stats_fn_ty = FunctionType::get(
        Type::getVoidTy(context),
        {
            IntegerType::getInt32Ty(context),
            IntegerType::getInt32Ty(context),
        },
        false);
    auto update_predicate_stats_fn_decl =
        module.getOrInsertFunction("__predicate_trace_update_stats", update_predicate_stats_fn_ty);
    update_predicate_stats_fn_ = dyn_cast<Function>(update_predicate_stats_fn_decl.getCallee());
    update_predicate_stats_fn_->setDoesNotThrow();

    // Declare the load function
    auto load_fn_ty =
        FunctionType::get(Type::getInt64Ty(context), {Type::getInt64Ty(context)}, false);
    auto load_fn_decl = module.getOrInsertFunction("__predicate_trace_load", load_fn_ty);
    load_fn_ = dyn_cast<Function>(load_fn_decl.getCallee());
    load_fn_->setDoesNotThrow();

    // Declare the store function
    auto store_fn_ty = FunctionType::get(
        Type::getVoidTy(context), {Type::getInt64Ty(context), Type::getInt64Ty(context)}, false);
    auto store_fn_decl = module.getOrInsertFunction("__predicate_trace_store", store_fn_ty);
    store_fn_ = dyn_cast<Function>(store_fn_decl.getCallee());
    store_fn_->setDoesNotThrow();

    // Declare the local scope creator
    auto push_locals_fn_ty = FunctionType::get(Type::getVoidTy(context), {}, false);
    auto push_locals_fn_decl =
        module.getOrInsertFunction("__predicate_trace_push_locals", push_locals_fn_ty);
    push_locals_fn_ = dyn_cast<Function>(push_locals_fn_decl.getCallee());
    push_locals_fn_->setDoesNotThrow();

    // Declare the local scope destructor
    auto pop_locals_fn_ty = FunctionType::get(Type::getInt64Ty(context), {}, false);
    auto pop_locals_fn_decl =
        module.getOrInsertFunction("__predicate_trace_pop_locals", pop_locals_fn_ty);
    pop_locals_fn_ = dyn_cast<Function>(pop_locals_fn_decl.getCallee());
    pop_locals_fn_->setDoesNotThrow();

    // Declare the local argument push function
    auto push_arg_fn_ty =
        FunctionType::get(Type::getVoidTy(context), {Type::getInt64Ty(context)}, false);
    auto push_arg_fn_decl =
        module.getOrInsertFunction("__predicate_trace_push_argument", push_arg_fn_ty);
    push_arg_fn_ = dyn_cast<Function>(push_arg_fn_decl.getCallee());
    push_arg_fn_->setDoesNotThrow();

    // Declare the argument accessor
    auto get_arg_fn_ty =
        FunctionType::get(Type::getInt64Ty(context), {Type::getInt32Ty(context)}, false);
    auto get_arg_fn_decl =
        module.getOrInsertFunction("__predicate_trace_get_argument", get_arg_fn_ty);
    get_arg_fn_ = dyn_cast<Function>(get_arg_fn_decl.getCallee());
    get_arg_fn_->setDoesNotThrow();

    // Declare the return value mutator
    auto set_return_fn_ty =
        FunctionType::get(Type::getVoidTy(context), {Type::getInt64Ty(context)}, false);
    auto set_return_fn_decl =
        module.getOrInsertFunction("__predicate_trace_set_return", set_return_fn_ty);
    set_return_fn_ = dyn_cast<Function>(set_return_fn_decl.getCallee());
    set_return_fn_->setDoesNotThrow();

    // Declare the predicate push function
    auto push_predicate_fn_ty = FunctionType::get(
        Type::getVoidTy(context),
        {IntegerType::getInt64Ty(context), IntegerType::getInt64Ty(context)},
        false);
    auto push_predicate_fn_decl =
        module.getOrInsertFunction("__predicate_trace_push", push_predicate_fn_ty);
    push_predicate_fn_ = dyn_cast<Function>(push_predicate_fn_decl.getCallee());
    push_predicate_fn_->setDoesNotThrow();

    // Declare the predicate pop function
    auto pop_predicate_fn_ty = FunctionType::get(
        Type::getVoidTy(context),
        {IntegerType::getInt64Ty(context), IntegerType::getInt64Ty(context)},
        false);
    auto pop_predicate_fn_decl =
        module.getOrInsertFunction("__predicate_trace_pop", pop_predicate_fn_ty);
    pop_predicate_fn_ = dyn_cast<Function>(pop_predicate_fn_decl.getCallee());
    pop_predicate_fn_->setDoesNotThrow();

    // Declare the transition record function
    auto record_transition_fn_ty =
        FunctionType::get(Type::getVoidTy(context), {IntegerType::getInt64Ty(context)}, false);
    auto record_transition_fn_decl =
        module.getOrInsertFunction("__predicate_trace_record_transition", record_transition_fn_ty);
    record_transition_ = dyn_cast<Function>(record_transition_fn_decl.getCallee());
    record_transition_->setDoesNotThrow();

    // Process all functions in the module
    for (auto& function : module) {
        if (function.isDeclaration()) {
            continue;
        }

        // Process comparisons
        for (auto& block : function) {
            for (auto it = block.begin(); it != block.end(); ++it) {
                if (auto cmp_inst = dyn_cast<CmpInst>(it)) {
                    instrumentComparison(cmp_inst);
                }
            }
        }

        // Check if feature vector tracking should be added
        if (!enable_feature_tracking) {
            continue;
        }

        // Create a function ID
        function_id_ = std::hash<std::string>{}(function.getGlobalIdentifier());

        // Compute the post-dominator tree for this function
        post_dom_tree_ = PostDominatorTree(function);

        // Reset the return values map
        return_values_.clear();

        // Label all basic blocks
        num_blocks_ = 0UL;
        for (auto& block : function) {
            setBlockLabel(&block, num_blocks_++);
        }

        // Handle main if necessary
        if (function.getName() == "main") {
            instrumentMain(function);
        }

        // Instrument each basic block (must preserve CFG)
        for (auto& block : function) {
            instrumentBlock(block);
        }

        // Instrument any conditional branches (may change CFG by splitting blocks)
        for (auto& block : function) {
            // Check whether this block has a conditional terminator
            auto term_inst = block.getTerminator();
            if (term_inst) {
                auto branch_inst = dyn_cast<BranchInst>(term_inst);
                if (branch_inst && branch_inst->isConditional()) {
                    instrumentConditionalBranch(branch_inst);
                }
            }
        }
    }

    // We always modify the module
    return true;
}

void PredicateTracePass::instrumentMain(llvm::Function& function) {
    auto& block = function.getEntryBlock();

    PredicateFeatures argc;
    PredicateFeatures argv;
    argc.set(BVSort);
    argc.set(Symbolic);
    argv = argc;

    IRBuilder<> builder(&*block.getFirstInsertionPt());
    builder.CreateCall(push_locals_fn_, {});
    builder.CreateCall(push_arg_fn_, {builder.getInt64(argc.to_ullong())});
    builder.CreateCall(push_arg_fn_, {builder.getInt64(argv.to_ullong())});

    for (auto& it : function) {
        auto term_inst = it.getTerminator();
        if (auto ret_inst = dyn_cast<ReturnInst>(term_inst)) {
            builder.SetInsertPoint(term_inst);
            builder.CreateStore(builder.getInt32(1), program_exiting_);
        }
    }
}

void PredicateTracePass::instrumentBlock(BasicBlock& block) {
    // Instrument any special instructions in this block
    for (auto it = block.begin(); it != block.end(); ++it) {
        Instruction* last_inst = nullptr;
        if (auto store_inst = dyn_cast<StoreInst>(it)) {
            last_inst = instrumentStore(store_inst);
        } else if (auto call_inst = dyn_cast<CallInst>(it)) {
            auto called_fn = call_inst->getCalledFunction();
            if (!called_fn || !called_fn->getName().startswith("__predicate_trace_")) {
                last_inst = instrumentCall(call_inst);
            }
        } else if (auto ret_inst = dyn_cast<ReturnInst>(it)) {
            last_inst = instrumentReturn(ret_inst);
        }

        if (last_inst) {
            it = BasicBlock::InstListType::iterator(last_inst);
        }
    }

    // Record a block transition
    auto label = getBlockLabel(&block);
    IRBuilder<> builder(&*block.getFirstInsertionPt());
    builder.CreateCall(record_transition_, {builder.getInt64(label)});
}

llvm::Instruction* PredicateTracePass::instrumentStore(llvm::StoreInst* store_inst) {
    assert(store_inst);

    //    log() << "instrumenting store\n";
    //    store_inst->print(errs());
    //    errs() << "\n";

    IRBuilder<> builder(store_inst);
    auto value = extractPredicate(builder, store_inst->getValueOperand());
    auto cast_inst = builder.CreatePtrToInt(store_inst->getPointerOperand(), builder.getInt64Ty());
    builder.CreateCall(store_fn_, {cast_inst, value});
    return store_inst;
}

Instruction* PredicateTracePass::instrumentComparison(CmpInst* cmp_inst) {
    assert(cmp_inst);

    //    log() << "instrumenting comparison\n";
    //    cmp_inst->print(errs());
    //    errs() << "\n";

    // Add a call to the statistics update function
    IRBuilder<> builder(cmp_inst);
    builder.CreateCall(
        update_predicate_stats_fn_,
        {builder.getInt32(cmp_inst->getOpcode()), builder.getInt32(cmp_inst->getPredicate())});
    return cmp_inst;
}

Instruction* PredicateTracePass::instrumentCall(CallBase* call_inst) {
    assert(call_inst);

    //    log() << "instrumenting call\n";
    //    call_inst->print(errs());
    //    errs() << "\n";

    // Check if the callee does not return
    IRBuilder<> builder(call_inst);
    if (call_inst->doesNotReturn()) {
        builder.CreateStore(builder.getInt32(1), program_exiting_);
    }

    // Create a new function scope and propagate arguments to that scope
    builder.CreateCall(push_locals_fn_, {});
    for (auto it = call_inst->data_operands_begin(); it != call_inst->data_operands_end(); ++it) {
        auto value = extractPredicate(builder, *it);
        builder.CreateCall(push_arg_fn_, {value});
    }

    // Clean up the function scope and record the result in the locals map
    builder.SetInsertPoint(call_inst->getNextNode());
    auto pop_locals_inst = builder.CreateCall(pop_locals_fn_, {});
    return_values_[call_inst] = pop_locals_inst;
    return pop_locals_inst;
}

Instruction* PredicateTracePass::instrumentReturn(llvm::ReturnInst* return_inst) {
    assert(return_inst);

    //    log() << "instrumenting return\n";
    //    return_inst->print(errs());
    //    errs() << "\n";

    IRBuilder<> builder(return_inst);
    if (auto return_op = return_inst->getReturnValue()) {
        auto value = extractPredicate(builder, return_op);
        builder.CreateCall(set_return_fn_, {value});
    }

    return return_inst;
}

void PredicateTracePass::instrumentConditionalBranch(BranchInst* branch_inst) {
    assert(branch_inst && branch_inst->isConditional());

    const auto invertPredicate = [](IRBuilder<>& builder, Value* predicate) -> Value* {
        // Check if predicate is static
        if (auto const_int = dyn_cast<ConstantInt>(predicate)) {
            PredicateFeatures inverted(const_int->getZExtValue());
            inverted.set(Not);
            return builder.getInt64(inverted.to_ullong());
        }

        // We need to generate run-time inversion code
        return builder.CreateOr({predicate, builder.getInt64(1UL << Not)});
    };

    // Insert code to pop path predicates at post-dominator, if found
    post_dom_tree_.recalculate(*branch_inst->getParent()->getParent());
    auto post_dom_block = post_dom_tree_.findNearestCommonDominator(
        branch_inst->getSuccessor(0), branch_inst->getSuccessor(1));
    if (!post_dom_block) {
        // TODO: This can happen when there are multiple exit blocks, in which case we *could* just
        //       pop at all of them...
        log() << "no post-dominator block found!\n";
        return;
    }

    auto true_block = branch_inst->getSuccessor(0);
    assert(true_block != nullptr);
    auto true_block_label = getBlockLabel(true_block);
    auto false_block = branch_inst->getSuccessor(1);
    assert(false_block != nullptr);
    auto false_block_label = getBlockLabel(false_block);
    IRBuilder<> builder(&*post_dom_block->getFirstInsertionPt());
    builder.CreateCall(
        pop_predicate_fn_,
        {builder.getInt64(true_block_label), builder.getInt64(false_block_label)});

    // Insert basic block for each outgoing edge to push respective path predicates
    auto new_true_block = SplitEdge(branch_inst->getParent(), true_block);
    assert(new_true_block);
    setBlockLabel(new_true_block, num_blocks_++);
    builder.SetInsertPoint(branch_inst);
    auto true_predicate = extractPredicate(builder, branch_inst);
    builder.SetInsertPoint(&*new_true_block->getFirstInsertionPt());
    builder.CreateCall(push_predicate_fn_, {builder.getInt64(true_block_label), true_predicate});

    auto new_false_block = SplitEdge(branch_inst->getParent(), false_block);
    assert(new_false_block != nullptr);
    setBlockLabel(new_false_block, num_blocks_++);
    builder.SetInsertPoint(branch_inst);
    auto false_predicate = invertPredicate(builder, true_predicate);
    builder.SetInsertPoint(&*new_false_block->getFirstInsertionPt());
    builder.CreateCall(push_predicate_fn_, {builder.getInt64(false_block_label), false_predicate});
}

static PredicateFeatures createPredicate(CmpInst::Predicate predicate) {
    PredicateFeatures features;

    switch (predicate) {
        case CmpInst::FCMP_FALSE:
            features.set(FPSort);
            break;
        case CmpInst::FCMP_OEQ:
            features.set(FPSort);
            features.set(FPEqual);
            break;
        case CmpInst::FCMP_OGT:
            features.set(FPSort);
            features.set(FPGt);
            break;
        case CmpInst::FCMP_OGE:
            features.set(FPSort);
            features.set(FPGe);
            break;
        case CmpInst::FCMP_OLT:
            features.set(FPSort);
            features.set(FPLt);
            break;
        case CmpInst::FCMP_OLE:
            features.set(FPSort);
            features.set(FPLe);
            break;
        case CmpInst::FCMP_ONE:
            features.set(FPSort);
            features.set(FPEqual);
            features.set(Not);
            break;
        case CmpInst::FCMP_ORD:
            features.set(FPSort);
            break;
        case CmpInst::FCMP_UNO:
            features.set(FPSort);
            break;
        case CmpInst::FCMP_UEQ:
            features.set(FPSort);
            features.set(FPEqual);
            break;
        case CmpInst::FCMP_UGT:
            features.set(FPSort);
            features.set(FPGt);
            break;
        case CmpInst::FCMP_UGE:
            features.set(FPSort);
            features.set(FPGe);
            break;
        case CmpInst::FCMP_ULT:
            features.set(FPSort);
            features.set(FPLt);
            break;
        case CmpInst::FCMP_ULE:
            features.set(FPSort);
            features.set(FPLe);
            break;
        case CmpInst::FCMP_UNE:
            features.set(FPSort);
            features.set(FPEqual);
            features.set(Not);
            break;
        case CmpInst::FCMP_TRUE:
            features.set(FPSort);
            break;
        case CmpInst::BAD_FCMP_PREDICATE:
            features.set(FPSort);
            break;
        case CmpInst::ICMP_EQ:
            features.set(BVSort);
            features.set(Equal);
            break;
        case CmpInst::ICMP_NE:
            features.set(BVSort);
            features.set(Equal);
            features.set(Not);
            break;
        case CmpInst::ICMP_UGT:
            features.set(BVSort);
            features.set(BVUgt);
            break;
        case CmpInst::ICMP_UGE:
            features.set(BVSort);
            features.set(BVUge);
            break;
        case CmpInst::ICMP_ULT:
            features.set(BVSort);
            features.set(BVUlt);
            break;
        case CmpInst::ICMP_ULE:
            features.set(BVSort);
            features.set(BVUle);
            break;
        case CmpInst::ICMP_SGT:
            features.set(BVSort);
            features.set(BVSgt);
            break;
        case CmpInst::ICMP_SGE:
            features.set(BVSort);
            features.set(BVSge);
            break;
        case CmpInst::ICMP_SLT:
            features.set(BVSort);
            features.set(BVSlt);
            break;
        case CmpInst::ICMP_SLE:
            features.set(BVSort);
            features.set(BVSle);
            break;
        case CmpInst::BAD_ICMP_PREDICATE:
            features.set(BVSort);
            break;
    }

    return features;
}

Value* PredicateTracePass::extractPredicate(IRBuilder<>& builder, Value* value) {
    assert(value);

    if (auto inst = dyn_cast<Instruction>(value)) {
        return extractPredicate(builder, inst);
    } else if (auto global = dyn_cast<GlobalValue>(value)) {
        // Fetch global features at run-time
        auto cast_inst = builder.CreatePtrToInt(global, builder.getInt64Ty());
        return builder.CreateCall(load_fn_, {cast_inst});
    } else if (auto constant = dyn_cast<Constant>(value)) {
        if (constant->getType()->isFloatingPointTy()) {
            return builder.getInt64(1UL << FPLit);
        }
        return builder.getInt64(1UL << BVLit);
    } else if (auto block = dyn_cast<BasicBlock>(value)) {
        // We can ignore these
    } else if (auto arg = dyn_cast<Argument>(value)) {
        return builder.CreateCall(get_arg_fn_, {builder.getInt32(arg->getArgNo())});
    } else if (auto assembly = dyn_cast<InlineAsm>(value)) {
        //        log() << "encountered assembly value\n";
    } else if (auto metadata = dyn_cast<MetadataAsValue>(value)) {
        //        log() << "encountered metadata value\n";
    } else if (auto op = dyn_cast<Operator>(value)) {
        //        log() << "encountered operator value\n";
    } else if (auto derived = dyn_cast<DerivedUser>(value)) {
        //        log() << "encountered derived user value\n";
    } else {
        log() << "unknown value type!\n";
    }

    return builder.getInt64(0);
}

Value* PredicateTracePass::extractPredicate(IRBuilder<>& builder, Instruction* inst) {
    assert(inst);

    // Handle calls
    if (auto call_inst = dyn_cast<CallBase>(inst)) {
        // TODO: Investigate why we sometimes handle stale calls?  Note that this doesn't seem to
        //       cause problems with generated bitcode.
        auto it = return_values_.find(call_inst);
        if (it != return_values_.end()) {
            return it->second;
        }

        return builder.getInt64(0);
    }

    // Handle loads from memory
    if (auto load_inst = dyn_cast<LoadInst>(inst)) {
        IRBuilder<> load_builder(load_inst);
        auto cast_inst =
            load_builder.CreatePtrToInt(load_inst->getPointerOperand(), builder.getInt64Ty());
        return load_builder.CreateCall(load_fn_, {cast_inst});
    }

    // Handle phis
    if (auto phi_inst = dyn_cast<PHINode>(inst)) {
        // Create another phi for feature values
        IRBuilder<> phi_builder(phi_inst);
        auto feature_phi_inst =
            phi_builder.CreatePHI(phi_builder.getInt64Ty(), phi_inst->getNumIncomingValues());
        for (auto i = 0; i < phi_inst->getNumIncomingValues(); ++i) {
            auto incoming_block = phi_inst->getIncomingBlock(i);
            IRBuilder<> incoming_builder(incoming_block->getTerminator());
            auto value = extractPredicate(incoming_builder, phi_inst->getIncomingValue(i));
            feature_phi_inst->addIncoming(value, incoming_block);
        }

        return feature_phi_inst;
    }

    PredicateFeatures predicate;

    // Handle any instructions where we simply merge features from all operands
    switch (inst->getOpcode()) {
        case Instruction::FNeg:
            predicate.set(FPNeg);
            break;
        case Instruction::Add:
            predicate.set(BVAdd);
            break;
        case Instruction::FAdd:
            predicate.set(FPAdd);
            break;
        case Instruction::Sub:
            predicate.set(BVSub);
            break;
        case Instruction::FSub:
            predicate.set(FPSub);
            break;
        case Instruction::Mul:
            predicate.set(BVMul);
            break;
        case Instruction::FMul:
            predicate.set(FPMul);
            break;
        case Instruction::UDiv:
            predicate.set(BVUDiv);
            break;
        case Instruction::SDiv:
            predicate.set(BVSDiv);
            break;
        case Instruction::FDiv:
            predicate.set(FPDiv);
            break;
        case Instruction::URem:
            predicate.set(BVURem);
            break;
        case Instruction::SRem:
            predicate.set(BVSRem);
            break;
        case Instruction::FRem:
            predicate.set(FPRem);
            break;
        case Instruction::Shl:
            predicate.set(BVShl);
            break;
        case Instruction::LShr:
            predicate.set(BVLShr);
            break;
        case Instruction::AShr:
            predicate.set(BVAShr);
            break;
        case Instruction::And:
            predicate.set(And);
            break;
        case Instruction::Or:
            predicate.set(Or);
            break;
        case Instruction::Xor:
            predicate.set(BVXor);
            break;
        case Instruction::GetElementPtr:
            predicate.set(BVExtract);
            break;
        case Instruction::AtomicCmpXchg:
            predicate.set(Equal);
            break;
        case Instruction::AtomicRMW: {
            auto op = dyn_cast<AtomicRMWInst>(inst)->getOperation();
            if (op == AtomicRMWInst::BinOp::Xchg) {
                predicate.set(Equal);
            } else if (op == AtomicRMWInst::BinOp::Add) {
                predicate.set(BVAdd);
            } else if (op == AtomicRMWInst::BinOp::Sub) {
                predicate.set(BVSub);
            } else if (op == AtomicRMWInst::BinOp::And) {
                predicate.set(BVAnd);
            } else if (op == AtomicRMWInst::BinOp::Nand) {
                predicate.set(BVAnd);
                predicate.set(BVNot);
            } else if (op == AtomicRMWInst::BinOp::Or) {
                predicate.set(BVOr);
            } else if (op == AtomicRMWInst::BinOp::Xor) {
                predicate.set(BVXor);
            } else if (op == AtomicRMWInst::BinOp::Max) {
                predicate.set(BVSgt);
            } else if (op == AtomicRMWInst::BinOp::Min) {
                predicate.set(BVSlt);
            } else if (op == AtomicRMWInst::BinOp::UMax) {
                predicate.set(BVUgt);
            } else if (op == AtomicRMWInst::BinOp::UMin) {
                predicate.set(BVUlt);
            } else if (op == AtomicRMWInst::BinOp::FAdd) {
                predicate.set(FPAdd);
            } else if (op == AtomicRMWInst::BinOp::FSub) {
                predicate.set(FPSub);
            }
            break;
        }
        case Instruction::ZExt:
            predicate.set(BVZeroExt);
            break;
        case Instruction::SExt:
            predicate.set(BVSignExt);
            break;
        case Instruction::FPToUI:
            predicate.set(FPtoUBV);
            break;
        case Instruction::FPToSI:
            predicate.set(FPtoSBV);
            break;
        case Instruction::UIToFP:
            predicate.set(UBVtoFP);
            break;
        case Instruction::SIToFP:
            predicate.set(SBVtoFP);
            break;
            //        case Instruction::FPTrunc:
            //            break;
            //        case Instruction::FPExt:
            //            break;
            //        case Instruction::PtrToInt:
            //            break;
            //        case Instruction::IntToPtr:
            //            break;
            //        case Instruction::BitCast:
            //            break;
            //        case Instruction::AddrSpaceCast:
            //            break;
            //        case Instruction::ExtractElement:
            //            break;
            //        case Instruction::InsertElement:
            //            break;
            //        case Instruction::ShuffleVector:
            //            break;
            //        case Instruction::ExtractValue:
            //            break;
            //        case Instruction::InsertValue:
            //            break;
        case Instruction::ICmp:
        case Instruction::FCmp: {
            auto cmp_inst = dyn_cast<CmpInst>(inst);
            predicate = createPredicate(cmp_inst->getPredicate());
            break;
        }
        default:
            break;
    }

    std::vector<Value*> rt_values;
    for (auto i = 0; i < inst->getNumOperands(); i++) {
        auto value = extractPredicate(builder, inst->getOperand(i));
        if (auto constant_value = dyn_cast<ConstantInt>(value)) {
            predicate |= constant_value->getZExtValue();
        } else {
            rt_values.push_back(value);
        }
    }

    if (!rt_values.empty()) {
        // In the general case, we need to generate code to merge predicates...
        rt_values.push_back(builder.getInt64(predicate.to_ullong()));
        return builder.CreateOr(rt_values);
    }

    return builder.getInt64(predicate.to_ullong());
}

std::size_t PredicateTracePass::getBlockLabel(BasicBlock* block) {
    const auto it = block_labels_.find(block);
    if (it != block_labels_.end()) {
        return it->second;
    }

    return 0;
}
void PredicateTracePass::setBlockLabel(BasicBlock* block, std::size_t id) {
    std::uint64_t label = ((module_id_ & 0xffffffUL) << 40UL)
                          | ((function_id_ & 0xffffffUL) << 16UL) | (id & 0xffffUL);
    block_labels_[block] = label;
}

// Pass info
char PredicateTracePass::ID = 0; // LLVM ignores the actual value
static RegisterPass<PredicateTracePass> X("predicate-trace", "Predicate Trace", false, false);

// Pass loading stuff
// To use, run: clang -Xclang -load -Xclang <your-pass>.so <other-args> ...

// This function is of type PassManagerBuilder::ExtensionFn
static void loadPass(const PassManagerBuilder &Builder, legacy::PassManagerBase &PM) {
  PM.add(new PredicateTracePass());
}
// These constructors add our pass to a list of global extensions.
// static RegisterStandardPasses clangtoolLoader_Ox(PassManagerBuilder::EP_OptimizerLast, loadPass);
static RegisterStandardPasses LoadPass(PassManagerBuilder::EP_ModuleOptimizerEarly, loadPass);
static RegisterStandardPasses LoadPass0(PassManagerBuilder::EP_EnabledOnOptLevel0, loadPass);
