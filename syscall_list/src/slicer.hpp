#pragma once

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
public:
    /* Ugly hack to clear system call register to 0
     * Because x86-64 uses eax only but dyninst thinks in rax and cannot infer bits 32:64 */
    virtual bool addNodeCallback(Dyninst::Assignment::Ptr ap, std::set<Dyninst::ParseAPI::Edge*>&) {
        /* If the syscall register referes to its self solely, set it to 0 */
        if (ap->inputs().size() == 0 && ap->out() == Dyninst::AbsRegion(Dyninst::x86_64::rax)) {
            ap->addInput(Dyninst::AbsRegion(Dyninst::Absloc(0x0)));
        }
        return true;
    }
};
