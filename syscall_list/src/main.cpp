#include <deque>
#include <iostream>
#include <memory>
#include <set>
#include <string>
#include <unordered_set>
#include <tuple>
#include <regex>
#include <vector>

#include <fmt/format.h>
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
#include "Symtab.h"

#include "elf.hpp"
#include "syscall_table.h"

namespace ParseAPI = Dyninst::ParseAPI;
namespace SymtabAPI = Dyninst::SymtabAPI;
namespace InstructionAPI = Dyninst::InstructionAPI;

BPatch bp;

static inline auto init_logging() {
    const auto level = std::getenv("LOGLEVEL");
    if (level) {
        switch(std::stol(level)) {
            case 0:
                spdlog::set_level(spdlog::level::off);
                break;
            case 1:
                spdlog::set_level(spdlog::level::debug);
                break;
            case 2:
                spdlog::set_level(spdlog::level::warn);
                break;
            case 4:
                spdlog::set_level(spdlog::level::debug);
                break;
            case 5:
                spdlog::set_level(spdlog::level::trace);
                break;
            case 3:
            default:
                spdlog::set_level(spdlog::level::info);
        }
    }
}

int main(const int argc, char *argv[]) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <executable> <args...>\n";
        return -1;
    }

    init_logging();

    spdlog::info("Create process from {}", argv[1]);
    const auto process = bp.openBinary(argv[1]);

    const auto image = process->getImage();

    std::vector<BPatch_object*> objs;
    image->getObjects(objs);
    assert(objs.size() > 0);

    ELFCache::get().set_modules(image->getModules());

    // Assume the last one is the executable
    const auto& exe_obj = *(objs.cend() - 1);
    const auto exe_name = exe_obj->name();
    const auto exe_path = exe_obj->pathName();

    /* Create the cache for the exe*/
    ELFCache::get().find(exe_name, exe_path);

    /* Entry point, assume as _start */
    constexpr auto entry_name = "main";

    std::map<Dyninst::Address, std::vector<std::pair<std::string, Dyninst::ParseAPI::Function*>>> syscalls;

    const auto func_printer = [&](const auto layer, const auto& object, const auto& func) {
        //if (func->name().starts_with("targ"))
            //return;
        //spdlog::info("{3: <{4}}{0} {1} {2:x}", object, func->name(), func->addr(), "", layer);
    };

    const auto syscall_printer = [&](const auto layer, const auto& object, const auto& func, const auto syscall_nbr) {
        //spdlog::info("{2: <{3}} syscall {0} {1}", syscall_nbr, "", "", layer + 1);
        syscalls[syscall_nbr].emplace_back(std::make_pair(object, func));
    };

    const auto bogus_printer = [](const auto layer, const auto& object, const auto& func, const auto addr) {
        //spdlog::info("{2: <{3}}Bogus call {0} {1:x}", object, addr, "", layer);
    };

    ELF::traverse_called_funcs(exe_name, entry_name, func_printer, syscall_printer, bogus_printer);

    constexpr auto max_nbr = 512;
    spdlog::info("");
    spdlog::info("");
    spdlog::info("=========================");
    spdlog::info("Syscall statistic:");
    for (auto nbr = 0; nbr < max_nbr; nbr++) {
        const auto str = syscall_name(nbr);
        if (str) {
            const auto yes = syscalls.contains(nbr);
            std::string callers{};
            if (yes) {
                for (auto&[obj, func] : syscalls[nbr]) {
                    callers += fmt::format("{}@{}  ", func->name(), obj);
                }
                spdlog::info("{0:<3}{1:<4}{2:<25} : {3:}", yes ? "o" : "", nbr, str.value(), callers);
            }
        }
    }
}
