#pragma once

#include "CFG.h"
#include "CodeObject.h"
#include "Function.h"
#include "slicing.h"
#include "SymEval.h"
#include "DynAST.h"

#include "spdlog/spdlog.h"

using namespace Dyninst::DataflowAPI;

class SimplifyAnAST: public Dyninst::ASTVisitor {
 public:
    virtual Dyninst::AST::Ptr visit(Dyninst::AST *t) {
        return t->ptr();
    }

    virtual Dyninst::AST::Ptr visit(Dyninst::DataflowAPI::BottomAST *b) {
        return b->ptr();
    }

    virtual Dyninst::AST::Ptr visit(Dyninst::DataflowAPI::ConstantAST *c) {
        return c->ptr();
    }

    virtual Dyninst::AST::Ptr visit(Dyninst::StackAST *s) {
        return s->ptr();
    }

    virtual Dyninst::AST::Ptr visit(Dyninst::DataflowAPI::VariableAST *v) {
        if (v->val().reg.absloc().reg() == aarch64::xzr) {
            return ConstantAST::create(Constant(
                0,
                64));
        } else {
            return v->ptr();
        }
    }

    virtual Dyninst::AST::Ptr visit(Dyninst::DataflowAPI::RoseAST* ast) {
        bool has_non_const = false;
        bool too_large = false;
        Dyninst::AST::Children newKids;
        for (unsigned i = 0; i < ast->numChildren(); ++i) {
            newKids.push_back(ast->child(i)->accept(this));
            has_non_const |= !(newKids[i]->getID() == Dyninst::AST::V_ConstantAST);
            if (newKids[i]->getID() == Dyninst::AST::V_ConstantAST) {
                if (ConstantAST::convert(newKids[i])->val().size > 64) {
                    too_large = true;
                }
            } else {
                spdlog::error("child {} is non const, original: {}, transformed: {}", i, ast->child(i)->getID(), newKids[i]->getID());
            }
        }

        if (has_non_const || too_large) {
            spdlog::error("Failed to evaluate: {}, non const: {}, too large: {}", ast->format(), has_non_const, too_large);
            return ast->ptr();
        }

        switch(ast->val().op) {
            case Dyninst::DataflowAPI:: ROSEOperation::andOp: {
                assert(newKids.size() == 2);
                const auto arg0 = ConstantAST::convert(newKids[0])->val();
                const auto arg1 = ConstantAST::convert(newKids[1])->val();
                return ConstantAST::create(Constant(
                    arg0.val & arg1.val,
                    std::max(arg0.size, arg1.size)));
            }
            case Dyninst::DataflowAPI:: ROSEOperation::addOp: {
                assert(newKids.size() == 2);
                const auto arg0 = ConstantAST::convert(newKids[0])->val();
                const auto arg1 = ConstantAST::convert(newKids[1])->val();
                return ConstantAST::create(Constant(
                    arg0.val + arg1.val,
                    std::max(arg0.size, arg1.size)));
            }
            case Dyninst::DataflowAPI:: ROSEOperation::negateOp: {
                assert(newKids.size() == 1);
                const auto arg0 = ConstantAST::convert(newKids[0])->val();
                return ConstantAST::create(Constant(
                    -arg0.val,
                    arg0.size));
            }
            case Dyninst::DataflowAPI:: ROSEOperation::orOp: {
                assert(newKids.size() == 2);
                const auto arg0 = ConstantAST::convert(newKids[0])->val();
                const auto arg1 = ConstantAST::convert(newKids[1])->val();
                return ConstantAST::create(Constant(
                    arg0.val | arg1.val,
                    std::max(arg0.size, arg1.size)));
            }
            case Dyninst::DataflowAPI:: ROSEOperation::xorOp: {
                assert(newKids.size() == 2);
                const auto arg0 = ConstantAST::convert(newKids[0])->val();
                const auto arg1 = ConstantAST::convert(newKids[1])->val();
                return ConstantAST::create(Constant(
                    arg0.val ^ arg1.val,
                    std::max(arg0.size, arg1.size)));
            }
            case Dyninst::DataflowAPI:: ROSEOperation::invertOp: {
                assert(newKids.size() == 1);
                const auto arg0 = ConstantAST::convert(newKids[0])->val();
                return ConstantAST::create(Constant(
                    ~arg0.val,
                    arg0.size));
            }
            case Dyninst::DataflowAPI:: ROSEOperation::shiftLOp: {
                assert(newKids.size() == 2);
                const auto arg0 = ConstantAST::convert(newKids[0])->val();
                const auto arg1 = ConstantAST::convert(newKids[1])->val();
                return ConstantAST::create(Constant(
                    arg0.val << arg1.val,
                    arg0.size));
            }
            case Dyninst::DataflowAPI:: ROSEOperation::shiftROp: {
                assert(newKids.size() == 2);
                const auto arg0 = ConstantAST::convert(newKids[0])->val();
                const auto arg1 = ConstantAST::convert(newKids[1])->val();
                return ConstantAST::create(Constant(
                    arg0.val >> arg1.val,
                    arg0.size));
            }
            case Dyninst::DataflowAPI:: ROSEOperation::shiftRArithOp: {
                assert(newKids.size() == 2);
                const auto arg0 = ConstantAST::convert(newKids[0])->val();
                const auto arg1 = ConstantAST::convert(newKids[1])->val();
                std::int64_t s;
                std::uint64_t u;
                std::memcpy(&s, &arg0.val, sizeof(s));
                s >>= arg1.val;
                memcpy(&u, &s, sizeof(s));
                return ConstantAST::create(Constant(
                    u,
                    arg0.size));
            }
            case Dyninst::DataflowAPI:: ROSEOperation::rotateLOp: {
                assert(newKids.size() == 2);
                const auto arg0 = ConstantAST::convert(newKids[0])->val();
                const auto arg1 = ConstantAST::convert(newKids[1])->val();
                auto h = arg0.val << arg1.val;
                auto l = arg0.val >> (64 - arg1.val);
                return ConstantAST::create(Constant(
                    h | l,
                    arg0.size));
            }
            case Dyninst::DataflowAPI:: ROSEOperation::rotateROp: {
                assert(newKids.size() == 2);
                const auto arg0 = ConstantAST::convert(newKids[0])->val();
                const auto arg1 = ConstantAST::convert(newKids[1])->val();
                auto h = arg0.val >> arg1.val;
                auto l = arg0.val << (64 - arg1.val);
                return ConstantAST::create(Constant(
                    h | l,
                    arg0.size));
            }
            case Dyninst::DataflowAPI:: ROSEOperation::concatOp: {
                assert(newKids.size() == 2);
                const auto arg0 = ConstantAST::convert(newKids[0])->val();
                const auto arg1 = ConstantAST::convert(newKids[1])->val();
                auto r = arg0.val;
                r |= (arg1.val << arg1.size);
                return ConstantAST::create(Constant(
                    r,
                    arg0.size + arg1.size));
            }
            case Dyninst::DataflowAPI:: ROSEOperation::extendOp: {
                assert(newKids.size() == 2);
                const auto arg0 = ConstantAST::convert(newKids[0])->val();
                const auto arg1 = ConstantAST::convert(newKids[1])->val();
                assert(arg0.size <= arg1.val);
                return ConstantAST::create(Constant(
                    arg0.val,
                    arg1.val));
            }
            case Dyninst::DataflowAPI:: ROSEOperation::signExtendOp: {
                assert(newKids.size() == 2);
                const auto arg0 = ConstantAST::convert(newKids[0])->val();
                const auto arg1 = ConstantAST::convert(newKids[1])->val();
                assert(arg0.size <= arg1.val);
                auto val = arg0.val;
                if (val & (1 << arg0.size)) {
                    val |= ~((1 << (arg0.size + 1)) - 1);
                }
                return ConstantAST::create(Constant(
                    val,
                    arg1.val));
            }
            case Dyninst::DataflowAPI:: ROSEOperation::extractOp: {
                assert(newKids.size() == 3);
                const auto arg0 = ConstantAST::convert(newKids[0])->val();
                const auto arg1 = ConstantAST::convert(newKids[1])->val();
                const auto arg2 = ConstantAST::convert(newKids[2])->val();
                return ConstantAST::create(Constant(
                    (arg0.val >> arg1.val) & ~((1 << (arg2.val + 1)) - 1),
                    arg2.val - arg1.val));
            }
            case Dyninst::DataflowAPI:: ROSEOperation::equalToZeroOp: {
                assert(newKids.size() == 1);
                const auto arg0 = ConstantAST::convert(newKids[0])->val();
                return ConstantAST::create(Constant(
                    (arg0.val == 0),
                    arg0.size));
            }
            case Dyninst::DataflowAPI:: ROSEOperation::sDivOp: {
                assert(newKids.size() == 2);
                const auto arg0 = ConstantAST::convert(newKids[0])->val();
                const auto arg1 = ConstantAST::convert(newKids[1])->val();
                std::int64_t s0, s1;
                std::uint64_t u;
                std::memcpy(&s0, &arg0.val, sizeof(s0));
                std::memcpy(&s1, &arg1.val, sizeof(s1));
                s0 /= s1;
                memcpy(&u, &s0, sizeof(s0));
                return ConstantAST::create(Constant(
                    u,
                    arg0.size));
            }
            case Dyninst::DataflowAPI:: ROSEOperation::sModOp: {
                assert(newKids.size() == 2);
                const auto arg0 = ConstantAST::convert(newKids[0])->val();
                const auto arg1 = ConstantAST::convert(newKids[1])->val();
                std::int64_t s0, s1;
                std::uint64_t u;
                std::memcpy(&s0, &arg0.val, sizeof(s0));
                std::memcpy(&s1, &arg1.val, sizeof(s1));
                s0 %= s1;
                memcpy(&u, &s0, sizeof(s0));
                return ConstantAST::create(Constant(
                    u,
                    arg0.size));
            }
            case Dyninst::DataflowAPI:: ROSEOperation::sMultOp: {
                assert(newKids.size() == 2);
                const auto arg0 = ConstantAST::convert(newKids[0])->val();
                const auto arg1 = ConstantAST::convert(newKids[1])->val();
                std::int64_t s0, s1;
                std::uint64_t u;
                std::memcpy(&s0, &arg0.val, sizeof(s0));
                std::memcpy(&s1, &arg1.val, sizeof(s1));
                s0 *= s1;
                memcpy(&u, &s0, sizeof(s0));
                return ConstantAST::create(Constant(
                    u,
                    arg0.size));
            }
            case Dyninst::DataflowAPI:: ROSEOperation::uDivOp: {
                assert(newKids.size() == 2);
                const auto arg0 = ConstantAST::convert(newKids[0])->val();
                const auto arg1 = ConstantAST::convert(newKids[1])->val();
                return ConstantAST::create(Constant(
                    arg0.val / arg1.val,
                    std::max(arg0.size, arg1.size)));
            }
            case Dyninst::DataflowAPI:: ROSEOperation::uModOp:{
                assert(newKids.size() == 2);
                const auto arg0 = ConstantAST::convert(newKids[0])->val();
                const auto arg1 = ConstantAST::convert(newKids[1])->val();
                return ConstantAST::create(Constant(
                    arg0.val % arg1.val,
                    std::max(arg0.size, arg1.size)));
            }
            case Dyninst::DataflowAPI:: ROSEOperation::uMultOp: {
                assert(newKids.size() == 2);
                const auto arg0 = ConstantAST::convert(newKids[0])->val();
                const auto arg1 = ConstantAST::convert(newKids[1])->val();
                return ConstantAST::create(Constant(
                    arg0.val * arg1.val,
                    std::max(arg0.size, arg1.size)));
            }
            case Dyninst::DataflowAPI:: ROSEOperation::ifOp:
            case Dyninst::DataflowAPI:: ROSEOperation::generateMaskOp:
            case Dyninst::DataflowAPI:: ROSEOperation::extendMSBOp:
            case Dyninst::DataflowAPI:: ROSEOperation::nullOp:
            case Dyninst::DataflowAPI:: ROSEOperation::derefOp:
            case Dyninst::DataflowAPI:: ROSEOperation::writeOp:
            case Dyninst::DataflowAPI:: ROSEOperation::writeRepOp:
            default:
                return RoseAST::create(ast->val(), newKids);
        }
    }
};

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

    virtual Dyninst::AST::Ptr visit(Dyninst::DataflowAPI::VariableAST* ast) {
        if (ast->val().reg.absloc().reg() == aarch64::xzr) {
            resolved = true;
            number = 0;
        } else {
            resolved = false;
        }
        return Dyninst::AST::Ptr();
    };

    virtual Dyninst::AST::Ptr visit(Dyninst::DataflowAPI::RoseAST* ast) {
        resolved = false;
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
