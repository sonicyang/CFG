#pragma once

#include <deque>

#include "CFG.h"
#include "CodeObject.h"
#include "Function.h"
#include "slicing.h"

#include "spdlog/spdlog.h"

class ConstantPredicates : public Dyninst::Slicer::Predicates {
public:
    virtual bool endAtPoint(Dyninst::Assignment::Ptr ap) {
        return ap->insn().writesMemory();
    }

    virtual bool addPredecessor(Dyninst::AbsRegion reg) {
        if (reg.absloc().type() == Dyninst::Absloc::Register) {
            const auto r = reg.absloc().reg();
            return !r.isPC();
        }
        return true;
    }
};

class SyscallNumberPredicates : public Dyninst::Slicer::Predicates {
    std::deque<Dyninst::ParseAPI::Function*> callstack;
public:
    SyscallNumberPredicates(const auto& callstack_) : callstack(callstack_) {}
    virtual std::vector<Dyninst::ParseAPI::Function*> followCallBackward(Dyninst::ParseAPI::Block* caller, CallStack_t& cs, Dyninst::AbsRegion argument) {
        callstack.pop_back();
        if (!callstack.empty()) {
            const auto target = callstack.back();
            spdlog::info("Backtracking... {}", target->name());
            return std::vector{target};
        } else {
            return {};
        }
    }

    virtual bool addPredecessor(Dyninst::AbsRegion reg) {
        spdlog::info("Pred...");
        return true;
    }
};
