#include <deque>
#include <iostream>
#include <filesystem>
#include <memory>
#include <set>
#include <string>
#include <unordered_set>
#include <tuple>
#include <regex>
#include <vector>

#include <fmt/format.h>
#include <fmt/os.h>
#include <spdlog/spdlog.h>

#include <absl/flags/flag.h>
#include <absl/flags/parse.h>
#include <absl/flags/usage.h>

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

ABSL_FLAG(bool, lib, false, "Is a shared library");
ABSL_FLAG(std::string, entry, "main", "Entry for executable");
ABSL_FLAG(std::string, output, "", "Report filename");
ABSL_FLAG(bool, recursive, true, "Recursive scan");

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
    absl::SetProgramUsageMessage(fmt::format("Usage: {} <options> <ELF>\n", argv[0]));
    const auto args = absl::ParseCommandLine(argc, argv);
    if (args.size() < 2) {
        std::cerr << absl::ProgramUsageMessage();
        return -1;
    }

    init_logging();

    const auto filename = *(args.cbegin() + 1);
    const auto report_name = absl::GetFlag(FLAGS_output) == "" ?
        std::filesystem::path{filename}.filename().string() + ".report" : absl::GetFlag(FLAGS_output);

    spdlog::info("Create process from {}", filename);
    const auto bin = bp.openBinary(filename, false);

    if (bin == nullptr) {
        spdlog::error("Failed to open {}", filename);
    }

    const auto image = bin->getImage();

    std::vector<BPatch_object*> objs;
    image->getObjects(objs);
    assert(objs.size() > 0);

    ELFCache::get().set_modules(image->getModules());

    const auto islib = absl::GetFlag(FLAGS_lib);

    // Assume the last one is the input
    const auto& exe_obj = *(objs.cend() - 1);
    const auto exe_name = exe_obj->name();
    const auto exe_path = exe_obj->pathName();

    /* Create the cache for the exe*/
    ELFCache::get().find(exe_name, exe_path);

    std::map<Dyninst::Address, std::vector<std::pair<std::string, Dyninst::ParseAPI::Function*>>> syscalls;
    std::set<std::string> made_syscalls;
    std::vector<std::string> bad_syscalls;

    const auto func_printer = [&](const auto layer, const auto& object, const auto& func) {
        //if (func->name() == "syscall")
            //spdlog::info("Call to syscall(3) detected!");
        //spdlog::info("{3: <{4}}{0} {1} {2:x}", object, func->name(), func->addr(), "", layer);
    };

    const auto syscall_printer = [&](const auto layer, const auto& object, const auto& func, const auto syscall_nbr, const auto is_syscall) {
        if (is_syscall) {
            syscalls[syscall_nbr].emplace_back(std::make_pair(object + ":syscall(3)", func));
        } else {
            syscalls[syscall_nbr].emplace_back(std::make_pair(object, func));
        }
        if (!made_syscalls.contains(object)) {
            made_syscalls.emplace(object);
        }
        //spdlog::info("{2: <{3}} syscall {0} {1}", syscall_nbr, "", "", layer + 1);
    };

    const auto bogus_printer = [](const auto layer, const auto& object, const auto& func, const auto addr) {
        //spdlog::info("{2: <{3}}Bogus call {0} {1:x}", object, addr, "", layer);
    };

    const auto bogus_syscall_printer = [&](const auto layer, const auto& object, const auto& func, const auto is_syscall) {
        //spdlog::info("{2: <{3}}Bogus call {0} {1:x}", object, addr, "", layer);
        bad_syscalls.emplace_back(fmt::format("{}@{}:{}", func->name(), object, is_syscall ? "syscall(3)" : ""));
        if (!made_syscalls.contains(object)) {
            made_syscalls.emplace(object);
        }
    };

    const auto recusrive = absl::GetFlag(FLAGS_recursive);

    if (islib) {
        spdlog::info("{} is an shared library, scanning all functions", filename);

        ELF::traverse_called_funcs(recusrive, exe_name, func_printer, syscall_printer, bogus_printer, bogus_syscall_printer);

    } else {
        const auto entry_name = absl::GetFlag(FLAGS_entry);
        spdlog::info("{} is an executable, using {} as entry point", filename, entry_name);

        const std::string entries[] = {
            //"_start",
            entry_name
        };

        ELF::traverse_called_funcs(recusrive, exe_name, entries, func_printer, syscall_printer, bogus_printer, bogus_syscall_printer);
    }


    spdlog::info("Output report as {}", report_name);
    auto report = fmt::output_file(report_name);
    constexpr auto max_nbr = 512;
    report.print("File: {}\n", filename);

    report.print("Scanned ELFs: ");
    for (const auto&[name, elf] : ELFCache::get().getAll()) {
        report.print("{} ", name);
    }
    report.print("\n");

    report.print("ELFs made syscalls: ");
    for (const auto& name : made_syscalls) {
        report.print("{} ", name);
    }
    report.print("\n");

    report.print("=========================\n");
    report.print("Syscall statistic:\n");
    for (auto nbr = 0; nbr < max_nbr; nbr++) {
        const auto str = syscall_name(nbr);
        if (str) {
            const auto yes = syscalls.contains(nbr);
            std::string callers{};
            if (yes) {
                for (auto&[obj, func] : syscalls[nbr]) {
                    callers += fmt::format("{}@{}  ", func->name(), obj);
                }
                report.print("{0:<3}{1:<4}{2:<25} : {3:}\n", yes ? "o" : "", nbr, str.value(), callers);
            }
        }
    }
    report.print("=========================\n");
    {
        std::string callers{};
        for (const auto& bad_call : bad_syscalls) {
            callers += bad_call + "  ";
        }
        report.print("Failed to decode system call in:\n");
        report.print("  {}", callers);
    }
}
