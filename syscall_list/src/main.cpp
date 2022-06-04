#include <deque>
#include <iostream>
#include <memory>
#include <set>
#include <string>
#include <unordered_set>
#include <tuple>
#include <regex>
#include <vector>

#include <spdlog/spdlog.h>

#include "BPatch.h"
#include "BPatch_addressSpace.h"
#include "BPatch_process.h"
#include "BPatch_object.h"
#include "BPatch_binaryEdit.h"
#include "BPatch_function.h"
#include "BPatch_point.h"
#include "BPatch_flowGraph.h"
#include "CFG.h"
#include "CodeObject.h"
#include "Function.h"
#include "Instruction.h"
#include "InstructionDecoder.h"

#include "elf.hpp"

namespace ParseAPI = Dyninst::ParseAPI;
namespace SymtabAPI = Dyninst::SymtabAPI;
namespace InstructionAPI = Dyninst::InstructionAPI;

BPatch bp;

static inline void traverse(const auto& object, const auto& symbol, std::set<std::pair<std::string, Dyninst::Address>>& seen, const int layer = 0) {
    const auto& elf = ELFCache.at(object);
    const auto& func = [&] {
        if constexpr (std::is_same_v<ParseAPI::Function*, std::decay_t<decltype(symbol)>>) {
            return symbol;
        } else if constexpr (std::is_same_v<std::set<std::string>, std::decay_t<decltype(symbol)>>) {
            const auto rsymbol = *symbol.cbegin();
            return elf.function_name_map.at(rsymbol);
        } else {
            return elf.function_name_map.at(symbol);
        }
    }();

    // Prevent Loop
    // XXX: Actually, an absolute DFS is not required, because we only want to know the syscalls used
    // all calls can share a single seen table
    const auto current = std::make_pair(object, func->addr());
    if (seen.contains(current)) {
        return;
    }
    seen.emplace(current);

    spdlog::info("{3: <{4}}{0} {1} {2}", object, func->name(), func->addr(), "", layer);

    if (!elf.cfg.contains(func)) {
        return;  // Don't call anything
    }

    for (const auto& callee : elf.cfg.at(func).static_) {
        traverse(object, callee, seen, layer + 1);
    }
    for (const auto& addr : elf.cfg.at(func).dynamic) {
        if (elf.GOT.contains(addr)) {
            const auto callee = elf.GOT.at(addr);
            traverse(callee.object, callee.symbols, seen, layer + 1);
        } else if (elf.PLT.contains(addr)) {
            const auto callee = elf.PLT.at(addr);
            traverse(callee.object, callee.symbols, seen, layer + 1);
        } else {
            spdlog::info("{2: <{3}}Bogus call {0} {1:x}", object, addr, "", layer + 1);
        }
    }
}

int main(const int argc, const char *argv[]) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <executable> <args...>\n";
        return -1;
    }

    spdlog::info("Create process from {}", argv[1]);
    const auto process = bp.processCreate(argv[1], argv + 2);
    process->stopExecution();

    const auto image = process->getImage();

    std::vector<BPatch_object*> objs;
    image->getObjects(objs);
    assert(objs.size() > 0);

    // Assume the last one is the executable
    const auto& exe_obj = *(objs.cend() - 1);
    const auto exe_name = exe_obj->name();
    const auto exe_path = exe_obj->pathName();

    /* Recursive create the cache */
    ELFCache.emplace(exe_name, ELF(exe_path, exe_name, *image->getModules()));

    /* Entry point, assume as _start */
    constexpr auto entry_name = "main";

    std::set<std::pair<std::string, Dyninst::Address>> seen;
    traverse(exe_name, entry_name, seen);
}
