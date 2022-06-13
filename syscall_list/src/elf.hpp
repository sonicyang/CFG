#pragma once

#include <iostream>

#include <cassert>
#include <compare>
#include <filesystem>
#include <map>
#include <regex>
#include <set>
#include <stdexcept>
#include <string>
#include <tuple>

#include "spdlog/spdlog.h"

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

inline std::map<std::string, ELF> ELFCache;

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

    struct CallDest {
        std::set<Dyninst::ParseAPI::Function*> static_;
        std::set<Dyninst::Address> dynamic;
    };

    std::map<Dyninst::ParseAPI::Function*, CallDest> cfg;

    std::string name;
    std::string path;

    std::shared_ptr<Dyninst::ParseAPI::SymtabCodeSource> source;
    std::shared_ptr<Dyninst::ParseAPI::CodeObject> object;

    ELF() {};
    ELF(const ELF&) = default;
    ELF& operator=(const ELF&) = default;

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

    template<typename Table>
    static inline auto add_dynamic_entry(Table& table, const Dyninst::Address addr, const std::string& lib, const std::string& name) {
        if (table.contains(addr)) {
            assert(table[addr].object == lib);
            table[addr].symbols.emplace(name);
        } else {
            table.emplace(addr, DynamicSymbol{lib, std::set{name}});
        }
    }

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
        std::map<std::string, Dyninst::Address> rela_dyn_table;
        std::map<Dyninst::Address, Dyninst::Address> rela_plt_table;
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

            for (const auto& bb : func->blocks()) {
                for (const auto& target : bb->targets()) {
                    if (target->interproc()) {
                        // Possible calling a GOT using indirect call
                        // Ignore PLTs and RET
                        if (target->sinkEdge() &&
                            !this->PLT.contains(bb->last()) &&
                            target->type() != Dyninst::ParseAPI::EdgeTypeEnum::RET) {
                            // Decode
                            const auto out_addr = bb->last();
                            const auto instr = bb->getInsn(bb->last());
                            spdlog::debug("DynInst failed to auto decode edge {:x}: {}", out_addr, instr.format());

                            // XXX: hardcoded for x86 to skip syscall instructions
                            const std::regex syscall("syscall.*", std::regex::extended);
                            std::smatch match;
                            const auto instr_str = instr.format();
                            if(std::regex_match(instr_str, match, syscall)) {
                                // Fake a assignment of rax -> rax
                                Dyninst::AbsRegion syscall_reg(Dyninst::MachRegister::getSyscallNumberReg(func->region()->getArch()));
                                auto syscall_assign = Dyninst::Assignment::makeAssignment(instr, out_addr, func, bb, syscall_reg);
                                syscall_assign->addInput(syscall_reg);

                                // Create a Slicer that will start from the given assignment
                                Dyninst::Slicer s(syscall_assign, bb, func);
                                Dyninst::Slicer::Predicates mp;
                                const auto slice = s.backwardSlice(mp);

                                // Expand the expression
                                Dyninst::DataflowAPI::Result_t symRet;
                                Dyninst::DataflowAPI::SymEval::expand(slice, symRet);

                                // Find the AST which outputs the syscall reg assignment
                                Dyninst::AST::Ptr syscall_nbr_assign;
                                for (auto&[key, in] : symRet) {
                                    if (key->out() == syscall_reg) {
                                        syscall_nbr_assign = in;
                                        break;
                                    }
                                }
                                assert(syscall_nbr_assign.get() != nullptr && "syscall_nbr_assign is null");

                                // Resolve is using the custom AST visitor
                                SyscallNumberVisitor visitor;
                                syscall_nbr_assign->accept(&visitor);

                                if (visitor.resolved) {
                                    const auto syscall_nbr = visitor.number;
                                    spdlog::info("Syscall({}) detected! {} @ {:x}", syscall_nbr, name, out_addr);
                                } else {
                                    spdlog::warn("Syscall number decode failed {} @ {:x}", name, out_addr);
                                }
                            } else {  // Not syscall
                                // Convert the instruction to assignments
                                Dyninst::AssignmentConverter ac(true, true);

                                std::vector<Dyninst::Assignment::Ptr> assignments;
                                ac.convert(instr, out_addr, func, bb, assignments);

                                // An instruction can corresponds to multiple assignment.
                                // Here we look for the assignment that changes the PC.
                                Dyninst::Assignment::Ptr pc_assign;
                                for (const auto& assignment : assignments) {
                                    const auto& out = assignment->out();
                                    if (out.absloc().type() == Dyninst::Absloc::Register &&
                                        out.absloc().reg().isPC()) {
                                        pc_assign = assignment;
                                        break;
                                    }
                                }

                                Dyninst::Address callee_addr{};
                                if (pc_assign->inputs().size() > 0 && pc_assign->inputs()[0].absloc().type() == Dyninst::Absloc::Heap) {
                                    // Don't brother to do slicing is we can find the PC relative call
                                    callee_addr = pc_assign->inputs()[0].absloc().addr();
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
                                        callee_addr = visitor.target;
                                    }
                                }

                                if (callee_addr) {
                                    spdlog::debug("{} @ {:x} BB target AST resolved as a edge to {:x}", name, out_addr, callee_addr);

                                    if (rela_plt_table.contains(callee_addr)) {
                                        /* Redirected by PLT.GOT entry */
                                        this->cfg[func].dynamic.emplace(rela_plt_table[callee_addr]);
                                    } else {
                                        this->cfg[func].dynamic.emplace(callee_addr);
                                    }
                                } else {
                                    spdlog::warn("{} @ {:x} {} BB target AST resolution Failed!", name, out_addr, instr.format());
                                }
                            } // End indirect call and syscall
                        } else {
                            std::vector<Dyninst::ParseAPI::Function*> callees;
                            target->trg()->getFuncs(callees);
                            for (auto& callee : callees) {
                                if (callee->name() == func->name() && callee->addr() == func->addr()) {
                                    continue;  // prevent recursive call
                                } else if (this->PLT.contains(callee->addr())) {
                                    this->cfg[func].dynamic.emplace(callee->addr());
                                } else if (this->GOT.contains(callee->addr())) {
                                    this->cfg[func].dynamic.emplace(callee->addr());
                                } else {
                                    this->cfg[func].static_.emplace(callee);
                                }
                            }
                        }
                    }
                }
            }
        }

        /* Commit all the changes */
        object->finalize();

        /* Recursively resolve any dynamic libraries, avoid recursive to our self */
        for (const auto& [addr, entry] : GOT) {
            const auto [obj, symbol] = entry;
            if (!ELFCache.contains(obj) && obj != this->name) {
                const auto path = findLib(obj);
                ELFCache.emplace(obj, ELF(path, obj, modules));
            }
        }

        for (const auto& [addr, entry] : PLT) {
            const auto [obj, symbol] = entry;
            if (!ELFCache.contains(obj) && obj != this->name) {
                const auto path = findLib(obj);
                ELFCache.emplace(obj, ELF(path, obj, modules));
            }
        }
    }
};

