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
#include "syscall_table.h"

namespace ParseAPI = Dyninst::ParseAPI;
namespace SymtabAPI = Dyninst::SymtabAPI;
namespace InstructionAPI = Dyninst::InstructionAPI;

BPatch bp;

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

    using syscall = std::pair<Dyninst::Address, std::size_t>;
    std::array<syscall, 512> syscalls_count{};
    for (Dyninst::Address c = 0; auto& entry : syscalls_count) {
        entry = std::make_pair(c++, 0);
    }
    std::size_t total_syscalls{};

    const auto func_printer = [](const auto layer, const auto& object, const auto& func) {
        //spdlog::info("{3: <{4}}{0} {1} {2}", object, func->name(), func->addr(), "", layer);
    };

    const auto syscall_printer = [&](const auto layer, const auto& object, const auto& func, const auto syscall_nbr) {
        //spdlog::info("{2: <{3}} syscall {0} {1}", syscall_nbr, "", "", layer + 1);
        syscalls_count[syscall_nbr].second++;
        total_syscalls++;
    };

    const auto bogus_printer = [](const auto layer, const auto& object, const auto& func, const auto addr) {
        //spdlog::info("{2: <{3}}Bogus call {0} {1:x}", object, addr, "", layer);
    };

    ELF::traverse_called_funcs(exe_name, entry_name, func_printer, syscall_printer, bogus_printer);

    const auto comp = [](const auto& p0, const auto& p1) {
            return p0.second < p1.second;
    };
    std::make_heap(syscalls_count.begin(), syscalls_count.end(), comp);

    spdlog::info("Syscall statistic (Total: {}):", total_syscalls);
    constexpr auto expand = 2;
    auto c = 0;
    while(true) {
        const auto[nbr, count] = *syscalls_count.cbegin();
        if (count) {
            spdlog::info("  {0:<6}{1:<25}: {2:<6} [{3:=<{4}}", nbr, syscall_name(nbr), count, "", static_cast<std::size_t>(count / (total_syscalls / 100. / expand)));
        } else {
            break;
        }
        std::pop_heap(syscalls_count.begin(), syscalls_count.end() - c, comp);
        c++;
    }
}
