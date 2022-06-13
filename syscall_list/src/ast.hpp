#pragma once

#include "CFG.h"
#include "CodeObject.h"
#include "Function.h"
#include "slicing.h"
#include "SymEval.h"
#include "DynAST.h"

#include "spdlog/spdlog.h"

class SyscallNumberVisitor: public Dyninst::ASTVisitor {
 public:
    bool resolved;

    Dyninst::Address number;
    SyscallNumberVisitor() : resolved(false), number(0xffffffff){}

    // We reach a constant node and record its value
    virtual Dyninst::AST::Ptr visit(Dyninst::DataflowAPI::ConstantAST* ast) {
        if (!resolved) {
            number = ast->val().val;
            resolved = true;
        }
        return Dyninst::AST::Ptr();
    };

    virtual Dyninst::AST::Ptr visit(Dyninst::DataflowAPI::VariableAST*) {
        resolved = false;
        return Dyninst::AST::Ptr();
    };

    virtual Dyninst::AST::Ptr visit(Dyninst::DataflowAPI::RoseAST* ast) {
        if ((ast->val().op == Dyninst::DataflowAPI::ROSEOperation::concatOp && ast->val().size == 64) ||
            (ast->val().op == Dyninst::DataflowAPI::ROSEOperation::extractOp && ast->val().size == 32)) {  // XXX: Might want to enforce lower 32 bits
            ast->child(0)->accept(this);
        } else {
            resolved = false;
        }
        return Dyninst::AST::Ptr();
    }
};

class ProcedureCallVisitor: public Dyninst::ASTVisitor {
 public:
    bool resolved;

    Dyninst::Address target;
    ProcedureCallVisitor() : resolved(true), target(0){}

    // We reach a constant node and record its value
    virtual Dyninst::AST::Ptr visit(Dyninst::DataflowAPI::ConstantAST* ast) {
        target = ast->val().val;
        return Dyninst::AST::Ptr();
    };

    // If the AST contains a variable
    // or an operation, then the control flow target cannot
    // be resolved through constant propagation
    // XXX Caveat:  Variables with  a Heap storage and inline address can actually be resolved!
    virtual Dyninst::AST::Ptr visit(Dyninst::DataflowAPI::VariableAST* ast) {
        if (ast->val().reg.absloc().type() == Dyninst::Absloc::Heap) {  // XXX: How do we resolve current address?
            this->target = ast->val().reg.absloc().addr();
        } else {
            this->resolved = false;
        }
        return Dyninst::AST::Ptr();
    };

    virtual Dyninst::AST::Ptr visit(Dyninst::DataflowAPI::RoseAST* ast) {
        resolved = false;
        // Recursively visit all children
        const auto totalChildren = ast->numChildren();
        for (unsigned i = 0 ; i < totalChildren; ++i) {
            ast->child(i)->accept(this);
        }
        return Dyninst::AST::Ptr();
    }
};
