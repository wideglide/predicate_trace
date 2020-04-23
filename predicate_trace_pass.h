#ifndef PREDICATE_TRACER_PREDICATE_TRACE_PASS_H
#define PREDICATE_TRACER_PREDICATE_TRACE_PASS_H

#include <llvm/Analysis/PostDominators.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/Instructions.h>
#include "llvm/IR/LegacyPassManager.h"
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

#endif  // PREDICATE_TRACER_PREDICATE_TRACE_PASS_H
