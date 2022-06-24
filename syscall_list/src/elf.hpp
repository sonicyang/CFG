#pragma once

#include <iostream>

#include <cassert>
#include <compare>
#include <filesystem>
#include <map>
#include <optional>
#include <regex>
#include <set>
#include <stdexcept>
#include <string>
#include <deque>
#include <tuple>

#include "spdlog/spdlog.h"

#include "BPatch.h"
#include "BPatch_addressSpace.h"
#include "BPatch_process.h"
#include "BPatch_object.h"
#include "BPatch_binaryEdit.h"
#include "BPatch_function.h"
#include "BPatch_point.h"
#include "BPatch_flowGraph.h"
#include "ABI.h"
#include "CFG.h"
#include "CodeObject.h"
#include "Function.h"
#include "Instruction.h"
#include "InstructionDecoder.h"
#include "slicing.h"
#include "Node.h"

#include "slicer.hpp"
#include "ast.hpp"

struct ELF;

struct ELFCache {
    static inline auto& get() {
        static ELFCache instance;
        return instance;
    }

    static inline auto findLib(const std::string& name) {
        const std::filesystem::path search_path[] = {
            "/lib",
            "/lib64",
            "/usr/lib",
            "/usr/lib64",
            "/usr/local/lib",
            "/usr/local/lib64"
        };
        for (const auto& path : search_path) {
            if (std::filesystem::exists(path / name)) {
                return (path / name).string();
            }
        }
        throw std::runtime_error(name + " not found!");
    }

    inline auto& find(const std::string& name);
    inline auto& find(const std::string& name, const std::string& path);

    inline auto set_modules(auto* modules) {
        this->m = modules;
    }

 private:
    ELFCache() {};
    static inline std::map<std::string, ELF> cache;
    static inline std::vector<BPatch_module*>* m;
};

struct ELF {
    std::set<Dyninst::ParseAPI::Function*> functions;
    std::map<Dyninst::Address, Dyninst::ParseAPI::Function*> function_addr_map;
    std::map<std::string, Dyninst::ParseAPI::Function*> function_name_map;

    struct DynamicSymbol {
        std::string object;
        /* Might contain weak symbols and aliases */
        std::set<std::string> symbols;
        auto operator<=>(const DynamicSymbol&) const = default;
    };

    std::map<Dyninst::Address, DynamicSymbol> GOT;
    std::map<Dyninst::Address, DynamicSymbol> PLT;
    std::map<std::string, Dyninst::Address> rela_dyn_table;
    std::map<Dyninst::Address, Dyninst::Address> rela_plt_table;

    struct CallDest {
        std::set<std::pair<Dyninst::Address, Dyninst::ParseAPI::Function*>> static_;
        std::set<std::pair<Dyninst::Address, Dyninst::Address>> dynamic;
        bool do_syscall = false;
    };

    std::map<Dyninst::ParseAPI::Function*, CallDest> cfg;

    std::string name;
    std::string path;

    std::shared_ptr<Dyninst::ParseAPI::SymtabCodeSource> source;
    std::shared_ptr<Dyninst::ParseAPI::CodeObject> object;

    ELF() {};
    ELF(const ELF&) = default;
    ELF& operator=(const ELF&) = default;

 private:
    template<typename Table>
    static inline auto add_dynamic_entry(Table& table, const Dyninst::Address addr, const std::string& lib, const std::string& name) {
        if (table.contains(addr)) {
            //assert(table[addr].object == lib);
            table[addr].symbols.emplace(name);
        } else {
            table.emplace(addr, DynamicSymbol{lib, std::set{name}});
        }
    }

    static auto is_syscall(const auto& instr) {
        const std::regex syscall("syscall.*", std::regex::extended);
        std::smatch match;
        const auto instr_str = instr.format();
        return std::regex_match(instr_str, match, syscall);
    }

    static auto make_assignments(const auto& func, const auto& bb, const auto& addr, const auto& instr) {
        // Convert the instruction to assignments
        Dyninst::AssignmentConverter ac(true, true);
        std::vector<Dyninst::Assignment::Ptr> assignments;
        ac.convert(instr, addr, func, bb, assignments);
        return assignments;
    }

   static auto parse_syscall(const auto reg, const auto& func, const auto& bb, const auto& addr, const auto& instr, const auto& callstack) -> std::optional<Dyninst::Address> {
        // Fake a assignment of rax -> rax
        Dyninst::AbsRegion syscall_reg(reg);
        auto syscall_assign = Dyninst::Assignment::makeAssignment(instr, addr, func, bb, syscall_reg);
        syscall_assign->addInput(syscall_reg);

        // Create a Slicer that will start from the given assignment
        Dyninst::Slicer s(syscall_assign, bb, func);
        SyscallNumberPredicates mp{callstack};
        const auto slice = s.backwardSlice(mp);

        // Expand the expression
        Dyninst::DataflowAPI::Result_t symRet;
        Dyninst::DataflowAPI::SymEval::expand(slice, symRet);

        // Find the AST which outputs the syscall reg assignment
        const auto [_, syscall_nbr_assign] = *std::find_if(symRet.cbegin(), symRet.cend(),
            [&syscall_reg](const auto& in) {
                const auto& [key, val] = in;
                return key->out() == syscall_reg;
            });

        if (syscall_nbr_assign.get() == nullptr) {
            return {};
        }

        // Resolve is using the custom AST visitor
        SyscallNumberVisitor visitor;
        syscall_nbr_assign->accept(&visitor);

        if (visitor.resolved) {
            return visitor.number;
        } else {
            return {};
        }
    }

    static auto parse_syscall(const auto& func, const auto& callstack) {
        std::set<Dyninst::Address> ret;
        for (const auto& bb : func->blocks()) {
            const auto instr = bb->getInsn(bb->last());
            if (is_syscall(instr)) {
                const auto out_addr = bb->last();
                const auto reg = Dyninst::MachRegister::getSyscallNumberReg(func->region()->getArch());
                const auto syscall_nbr = parse_syscall(reg, func, bb, out_addr, instr, callstack);
                if (syscall_nbr) {
                    spdlog::debug("Syscall({}) detected! {} @ {:x}", syscall_nbr.value(), func->name(), out_addr);
                    ret.emplace(syscall_nbr.value());
                } else {
                    spdlog::warn("Syscall number decode failed {} @ {:x}", func->name(), out_addr);
                }
            }
        }
        return ret;
    }

    static auto parse_syscall_func(const auto& caller, const auto calling_addr, const auto& callstack) {
        std::set<Dyninst::Address> ret;
        for (const auto& bb : caller->blocks()) {
            const auto out_addr = bb->last();
            if (out_addr == calling_addr) {
                const auto instr = bb->getInsn(bb->last());
                const auto reg = x86_64::rdi;  // XXX: hardcoded for x86, 1st argument register
                const auto syscall_nbr = parse_syscall(reg, caller, bb, out_addr, instr, callstack);
                if (syscall_nbr) {
                    spdlog::debug("Syscall({}) detected! {} @ {:x}", syscall_nbr.value(), caller->name(), out_addr);
                    ret.emplace(syscall_nbr.value());
                } else {
                    spdlog::warn("Syscall number decode failed {} @ {:x}", caller->name(), out_addr);
                }
            }
        }
        return ret;
    }

    auto parse_external_call(const auto& func, const auto& bb) -> std::optional<Dyninst::Address> {
        // Decode
        const auto out_addr = bb->last();
        const auto instr = bb->getInsn(bb->last());
        spdlog::debug("DynInst failed to auto decode edge {:x}: {}", out_addr, instr.format());

        // Convert the instruction to assignments
        const auto assignments = make_assignments(func, bb, out_addr, instr);

        // An instruction can corresponds to multiple assignment.
        // Here we look for the assignment that changes the PC.
        const auto pc_assign = *std::find_if(assignments.cbegin(), assignments.cend(), [](const auto& assignment) {
            const auto& out = assignment->out();
            return out.absloc().type() == Dyninst::Absloc::Register && out.absloc().reg().isPC();
        });

        if (pc_assign->inputs().size() > 0 && pc_assign->inputs()[0].absloc().type() == Dyninst::Absloc::Heap) {
            // Don't brother to do slicing is we can find the PC relative call
            return pc_assign->inputs()[0].absloc().addr();
        } else {
            // Create a Slicer that will start from the given assignment
            Dyninst::Slicer s(pc_assign, bb, func);
            // Slice to fund the register indirect call
            Dyninst::Slicer::Predicates mp;
            const auto slice = s.backwardSlice(mp);

            // Expand the expression
            Dyninst::DataflowAPI::Result_t symRet;
            Dyninst::DataflowAPI::SymEval::expand(slice, symRet);

            // Resolve is using the custom AST visitor
            const auto pc_exp = symRet[pc_assign];
            ProcedureCallVisitor visitor;
            pc_exp->accept(&visitor);

            if (visitor.resolved && visitor.target) {  // Call to Null is ambiguous
                return visitor.target;
            }
        }

        return {};
    }

    auto parse_internal_call(const auto& func, const auto out_addr, const auto& target) {
        std::vector<Dyninst::ParseAPI::Function*> callees;
        target->trg()->getFuncs(callees);
        for (auto& callee : callees) {
            if (callee->name() == func->name() && callee->addr() == func->addr()) {
                continue;  // prevent recursive call
            } else if (this->PLT.contains(callee->addr())) {
                spdlog::debug("PLT {} has a edge to {:}", func->name(), *PLT[callee->addr()].symbols.cbegin());
                this->cfg[func].dynamic.emplace(out_addr, callee->addr());
            } else if (this->GOT.contains(callee->addr())) {
                spdlog::debug("GOT {} has a edge to {:}", func->name(), *GOT[callee->addr()].symbols.cbegin());
                this->cfg[func].dynamic.emplace(out_addr, callee->addr());
            } else {
                spdlog::debug("STATIC {} has a edge to {:}", func->name(), callee->name());
                this->cfg[func].static_.emplace(out_addr, callee);
            }
        }
    }

    static void traverse_called_funcs(const auto& object, const auto& symbol, auto& func_callback, auto& syscall_callback, auto& bogus_callback, auto& bogus_syscall_callback,
        std::set<std::pair<std::string, Dyninst::Address>>& seen, std::deque<Dyninst::ParseAPI::Function*>& callstack) {
        auto elf = ELFCache::get().find(object);
        const auto func = [&] {
            if constexpr (std::is_same_v<Dyninst::ParseAPI::Function*, std::decay_t<decltype(symbol)>>) {
                return symbol;
            } else if constexpr (std::is_same_v<std::set<std::string>, std::decay_t<decltype(symbol)>>) {
                const auto rsymbol = *symbol.cbegin();
                if (elf.function_name_map.contains(rsymbol)) {
                    return elf.function_name_map.at(rsymbol);
                } else {
                    spdlog::error("Failed to find function {} in {}", rsymbol, object);
                    return static_cast<Dyninst::ParseAPI::Function*>(nullptr);
                }
            } else {
                if (elf.function_name_map.contains(symbol)) {
                    return elf.function_name_map.at(symbol);
                } else {
                    spdlog::error("Failed to find function {} in {}", symbol, object);
                    return static_cast<Dyninst::ParseAPI::Function*>(nullptr);
                }
            }
        }();

        if (func == nullptr)
            return;

        // Prevent Loop
        const auto current = std::make_pair(object, func->addr());
        if (seen.contains(current)) {
            return;
        }
        seen.emplace(current);

        const auto layer = callstack.size();

        func_callback(layer, object, func);

        // resolve the cfg
        elf.resolve(func);

        if (!elf.cfg.contains(func)) {
            return;  // Don't call anything
        }

        callstack.push_back(func);

        const auto next_level = [&](const auto& obj, const auto sym) {
            traverse_called_funcs(obj, sym, func_callback, syscall_callback, bogus_callback, bogus_syscall_callback, seen, callstack);
        };

        if (elf.cfg[func].do_syscall) {
            const auto syscalls = parse_syscall(func, callstack);
            for (const auto& syscall_nbr : syscalls) {
                syscall_callback(layer + 1, object, func, syscall_nbr);
            }
            if (!syscalls.size()) {
                bogus_syscall_callback(layer, object, func);
            }
        }
        for (const auto&[out_addr, callee] : elf.cfg.at(func).static_) {
            if (object.starts_with("libc") && callee->name() == "syscall") {
                spdlog::debug("Special handing for syscall(3)");
                // parse the 1st register into syscall
                const auto syscalls = parse_syscall_func(func, out_addr, callstack);
                for (const auto& syscall_nbr : syscalls) {
                    syscall_callback(layer + 1, object, func, syscall_nbr);
                }
            }
            next_level(object, callee);
        }
        for (const auto&[out_addr, addr] : elf.cfg.at(func).dynamic) {
            const auto isGOT = elf.GOT.contains(addr);
            if (isGOT || elf.PLT.contains(addr)) {
                const auto& tab = isGOT ? elf.GOT : elf.PLT;
                const auto callee = tab.at(addr);
                if (callee.object.starts_with("libc") && callee.symbols.contains("syscall")) {
                    spdlog::debug("Special handing for syscall(3)");
                    // parse the 1st register into syscall
                    const auto syscalls = parse_syscall_func(func, out_addr, callstack);
                    for (const auto& syscall_nbr : syscalls) {
                        syscall_callback(layer + 1, object, func, syscall_nbr);
                    }
                }
                next_level(callee.object, callee.symbols);
            } else {
                bogus_callback(layer + 1, object, func, addr);
            }
        }

        callstack.pop_back();
    }

 public:
    template<typename M>
    ELF(const std::string& path_, const std::string& name_, const M& modules) :
        name(name_), path(path_),
        source(std::make_shared<Dyninst::ParseAPI::SymtabCodeSource>(const_cast<char*>(path_.c_str()))),
        object(std::make_shared<Dyninst::ParseAPI::CodeObject>(source.get())) {

        spdlog::info("Parsing ELF {}", path);

        spdlog::info("Gathering PLT infos...");
        const auto symtab = Dyninst::SymtabAPI::Symtab::findOpenSymtab(path);

        std::set<std::pair<std::string, std::string>> seen;

        object->parse();

        /* Parse PLT entries */
        std::vector<Dyninst::SymtabAPI::relocationEntry> fbt;
        symtab->getFuncBindingTable(fbt);

        for (const auto& fbt_entry : fbt) {
            const auto addr = fbt_entry.target_addr();
            const auto symbol_name = fbt_entry.name();

            spdlog::debug("PLT Resolving {} @ {:x}", symbol_name, addr);

            object->parse(addr, true);

            std::string fname;
            if (!fbt_entry.getDynSym()->getVersionFileName(fname)) {
                spdlog::error("Failed to find target file of relocation of {} @ {:x}", symbol_name, addr);
                continue;
            }

            add_dynamic_entry(this->PLT, addr, fname, symbol_name);
            seen.emplace(fname, symbol_name);
        }

        /* Commit all the changes */
        object->finalize();

        /* DynInst is a TARD, cannot let use parse GOT easily */
        const auto process_reloations = [&](const auto relocations) {
            for (const auto& relocation : relocations) {
                // XXX: For x86-64,
                if (relocation.getRelType() == 8) {  // ignore R_X86_64_RELATIVE
                    continue;
                } else if (relocation.getRelType() == 37) {  // ignore R_X86_64_IRELATIVE is a address alias
                    spdlog::debug("PLT.GOT sym {:x} @ {:x}", relocation.addend(), relocation.rel_addr());
                    rela_plt_table.emplace(relocation.rel_addr(), relocation.addend());
                } else {  // Treat other as calling a symbol with name
                    spdlog::debug("DYN sym {} @ {:x}", relocation.name(), relocation.rel_addr());
                    rela_dyn_table.emplace(relocation.name(), relocation.rel_addr());
                }
            }
        };
        {
            Dyninst::SymtabAPI::Region* rela_region;
            if (symtab->findRegion(rela_region, ".rela.dyn")) {
                process_reloations(rela_region->getRelocations());
            } else {
                spdlog::error("Failed to find .rela.dyn section, might fail to resolve GOT");
            }
        }
        {
            Dyninst::SymtabAPI::Region* rela_region;
            if (symtab->findRegion(rela_region, ".rela.plt")) {
                process_reloations(rela_region->getRelocations());
            } else {
                spdlog::error("Failed to find .rela.plt section, might fail to resolve PLT.GOT");
            }
        }

        /* Parse GOT entries */
        /* Only if it is in the rela.dyn table and not in any seciton is considered a GOT symbol */
        spdlog::debug("Gathering GOT infos...");
        std::vector<Dyninst::SymtabAPI::Symbol*> syms;
        symtab->getAllSymbols(syms);
        for (const auto& sym : syms) {
            const auto symbol_name = sym->getMangledName();
            // XXX: get version name of symbol, Not a problem for now though

            spdlog::debug("GOT Symbol {} {} @ {:x}", name, symbol_name, sym->getOffset());
            // In one of our sections?
            if (sym->getRegion() != nullptr) {  // Yes
                if (rela_dyn_table.contains(symbol_name)) {
                    /* Also link the relocation */
                    const auto addr_src = rela_dyn_table[symbol_name];
                    spdlog::debug("DYN SRC Resolving {} {} @ {:x}", name, symbol_name, addr_src);
                    add_dynamic_entry(this->GOT, addr_src, name, symbol_name);
                }


                const auto addr_dst = sym->getOffset();
                spdlog::debug("DYN DST Resolving {} {} @ {:x}", name, symbol_name, addr_dst);
                add_dynamic_entry(this->GOT, addr_dst, name, symbol_name);

                /* It is our function in disguise, parse it */
                object->parse(addr_dst, true);
            } else {  // No
                std::string fname;
                if (!sym->getVersionFileName(fname)) {
                    spdlog::error("Failed to find target file of relocation of {} {}", symbol_name, sym->getIndex());
                    continue;
                }

                if (!rela_dyn_table.contains(symbol_name)) {
                    if (!seen.contains(std::make_pair(fname, symbol_name))) {
                        spdlog::error("Failed to resolve address of relocation of {}", symbol_name);
                    }
                    continue;
                }

                const auto addr = rela_dyn_table[symbol_name];
                spdlog::debug("REMOTE Resolving {} {} @ {:x}", fname, symbol_name, addr);
                add_dynamic_entry(this->GOT, addr, fname, symbol_name);
            }
        }

        /* Commit all the changes */
        object->finalize();

        /* One more time */
        object->parse();
        object->finalize();

        /* Parse Functions and CFG */
        spdlog::info("Gathering Functions");
        for (const auto& mod : modules) {
            for(const auto& func : *mod->getProcedures(false)) {
                object->parse(reinterpret_cast<Dyninst::Address>(func->getBaseAddr()), true);
            }
        }

        /* Populate the function and CFG entries */
        for (const auto& func : object->funcs()) {
            const auto name = func->name();
            const auto addr = func->addr();

            spdlog::debug("Find Func {} @ {:x}", name, addr);

            this->functions.emplace(func);
            this->function_addr_map.emplace(addr, func);
            this->function_name_map.emplace(name, func);

            /* Hacks to handle Weak symbols causing name aliasing */
            if (this->PLT.contains(addr)) {
                this->function_addr_map.emplace(addr, func);
                for (const auto& alias : this->PLT[addr].symbols) {
                    if (alias == name) {
                        continue;
                    }
                    this->function_name_map.emplace(alias, func);
                    spdlog::debug("  A.k.a {}", alias);
                }
            }

            if (this->GOT.contains(addr)) {
                this->function_addr_map.emplace(addr, func);
                for (const auto& alias : this->GOT[addr].symbols) {
                    if (alias == name) {
                        continue;
                    }
                    this->function_name_map.emplace(alias, func);
                    spdlog::debug("  A.k.a {}", alias);
                }
            }
        }

        /* Commit all the changes */
        object->finalize();
    }

    inline auto resolve(Dyninst::ParseAPI::Function* func) {
        for (const auto& bb : func->blocks()) {
            for (const auto& target : bb->targets()) {
                if (target->type() == Dyninst::ParseAPI::EdgeTypeEnum::RET) {
                    // Ignore returns
                    continue;
                }
                const auto out_addr = bb->last();
                if (target->interproc()) {
                    // Possible calling a GOT using indirect call
                    // Ignore PLTs
                    if (target->sinkEdge() && !this->PLT.contains(bb->last())) {
                        // Decode
                        const auto instr = bb->getInsn(bb->last());
                        spdlog::debug("DynInst failed to auto decode edge {:x}: {}", out_addr, instr.format());

                        if(is_syscall(instr)) {
                            this->cfg[func].do_syscall = true;
                        } else {  // Not syscall
                            const auto callee_addr = parse_external_call(func, bb);
                            if (callee_addr) {
                                spdlog::debug("{} @ {:x} BB target AST resolved as a edge to {:x}", name, out_addr, callee_addr.value());
                                if (this->rela_plt_table.contains(callee_addr.value())) {
                                    /* Redirected by PLT.GOT entry */
                                    this->cfg[func].dynamic.emplace(out_addr, this->rela_plt_table[callee_addr.value()]);
                                } else {
                                    this->cfg[func].dynamic.emplace(out_addr, callee_addr.value());
                                }
                            } else {
                                spdlog::warn("{} @ {:x} {} BB target AST resolution Failed!", name, out_addr, instr.format());
                            }
                        } // End indirect call and syscall
                    } else {
                        parse_internal_call(func, out_addr, target);
                    }
                }
            }
        }
    }

    static void traverse_called_funcs(const auto& object, const auto& symbol, auto& func_callback, auto& syscall_callback, auto& bogus_callback, auto& bogus_syscall_callback) {
        std::set<std::pair<std::string, Dyninst::Address>> seen;
        std::deque<Dyninst::ParseAPI::Function*> callstack;
        traverse_called_funcs(object, symbol, func_callback, syscall_callback, bogus_callback, bogus_syscall_callback, seen, callstack);
    }
};

inline auto& ELFCache::find(const std::string& name, const std::string& path) {
    /* Recursively resolve any dynamic libraries, avoid recursive to our self */
    if (!this->cache.contains(name)) {
        this->cache.emplace(name, ELF(path, name, *m));
    }
    return this->cache[name];
}

inline auto& ELFCache::find(const std::string& name) {
    /* Recursively resolve any dynamic libraries, avoid recursive to our self */
    if (!this->cache.contains(name)) {
        const auto path = findLib(name);
        this->cache.emplace(name, ELF(path, name, *m));
    }
    return this->cache[name];
}
