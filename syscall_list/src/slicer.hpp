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

class IndirectPredicates : public Dyninst::Slicer::Predicates {
    std::deque<Dyninst::ParseAPI::Function*> callstack;
public:
    IndirectPredicates(const auto& callstack_) : callstack(callstack_) {
        callstack.pop_back();
    }
    virtual std::vector<Dyninst::ParseAPI::Function*> followCallBackward(Dyninst::ParseAPI::Block* caller, CallStack_t& cs, Dyninst::AbsRegion argument) {
        if (callstack.size() >= 1) {
            const auto target = callstack.back();
            callstack.pop_back();
            return std::vector{target};
        } else {
            return {};
        }
    }

    virtual bool addPredecessor(Dyninst::AbsRegion reg) {
        spdlog::debug("Predecessor {}", reg.format());
        if (reg.absloc().type() == Dyninst::Absloc::Register) {
            //const auto r = reg.absloc().reg();
            //spdlog::debug("Predecessor {}", reg.format());
        }
        return true;
    }

    virtual bool addNodeCallback(Dyninst::AssignmentPtr assign, std::set<Dyninst::ParseAPI::Edge*> &) {
        spdlog::debug("Add Node {}", assign->format());
        return true;
    }
};

class SyscallNumberPredicates : public Dyninst::Slicer::Predicates {
    std::deque<Dyninst::ParseAPI::Function*> callstack;
public:
    SyscallNumberPredicates(const auto& callstack_) : callstack(callstack_) {
        callstack.pop_back();
    }
    virtual std::vector<Dyninst::ParseAPI::Function*> followCallBackward(Dyninst::ParseAPI::Block* caller, CallStack_t& cs, Dyninst::AbsRegion argument) {
        if (callstack.size() >= 1) {
            const auto target = callstack.back();
            callstack.pop_back();
            return std::vector{target};
        } else {
            return {};
        }
    }

    virtual bool addPredecessor(Dyninst::AbsRegion reg) {
        return true;
    }
};
