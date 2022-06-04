#pragma once

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

    std::shared_ptr<Dyninst::ParseAPI::SymtabCodeSource> source;
    std::shared_ptr<Dyninst::ParseAPI::CodeObject> object;

    std::string name;
    std::string path;

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

        /* Parse PLT entries */
        std::vector<Dyninst::SymtabAPI::relocationEntry> fbt;
        symtab->getFuncBindingTable(fbt);

        for (const auto& fbt_entry : fbt) {
            const auto addr = fbt_entry.target_addr();
            const auto symbol_name = fbt_entry.name();

            spdlog::debug("Resolving {} @ {:x}", symbol_name, addr);

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
        std::map<std::string, Dyninst::Address> rela_table;
        {
            Dyninst::SymtabAPI::Region* rela_region;
            if (symtab->findRegion(rela_region, ".rela.dyn")) {
                for (const auto& relocation : rela_region->getRelocations()) {
                    rela_table.emplace(relocation.name(), relocation.rel_addr());
                }
            } else {
                spdlog::error("Failed to find .rela.dyn section, might fail to resolve GOT");
            }
        }

        /* Parse GOT entries */
        /* Only if it is in the rela.dyn table and not in any seciton is considered a GOT symbol */
        spdlog::info("Gathering GOT infos...");
        std::vector<Dyninst::SymtabAPI::Symbol*> syms;
        symtab->getAllSymbols(syms);
        for (const auto& sym : syms) {
            const auto symbol_name = sym->getMangledName();
            // XXX: get version name of symbol, Not a problem for now though

            if (sym->getLinkage() == Dyninst::SymtabAPI::Symbol::SymbolLinkage::SL_GLOBAL &&
                sym->getType() == Dyninst::SymtabAPI::Symbol::SymbolType::ST_FUNCTION &&  // isFunction won't work
                sym->isInDynSymtab()){

                // In one of our sections?
                if (sym->getRegion() != nullptr) {  // Yes
                    if (rela_table.contains(symbol_name)) {
                        /* Also link the relocation */
                        const auto addr_src = rela_table[symbol_name];
                        spdlog::info("Resolving {} {} @ {:x}", name, symbol_name, addr_src);
                        add_dynamic_entry(this->GOT, addr_src, name, symbol_name);
                    }


                    const auto addr_dst = sym->getOffset();
                    spdlog::info("Resolving {} {} @ {:x}", name, symbol_name, addr_dst);
                    add_dynamic_entry(this->GOT, addr_dst, name, symbol_name);

                    /* It is our function in disguise, parse it */
                    object->parse(addr_dst, true);
                } else {  // No
                    std::string fname;
                    if (!sym->getVersionFileName(fname)) {
                        spdlog::error("Failed to find target file of relocation of {} {}", symbol_name, sym->getIndex());
                        continue;
                    }

                    if (!rela_table.contains(symbol_name)) {
                        if (!seen.contains(std::make_pair(fname, symbol_name))) {
                            spdlog::error("Failed to resolve address of relocation of {}", symbol_name);
                        }
                        continue;
                    }

                    const auto addr = rela_table[symbol_name];

                    spdlog::info("Resolving {} {} @ {:x}", fname, symbol_name, addr);

                    add_dynamic_entry(this->GOT, addr, fname, symbol_name);
                }
            }
        }

        /* Commit all the changes */
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

            spdlog::info("Find Func {} @ {:x}", name, addr);

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
                    spdlog::info("  A.k.a {}", alias);
                }
            }

            if (this->GOT.contains(addr)) {
                this->function_addr_map.emplace(addr, func);
                for (const auto& alias : this->GOT[addr].symbols) {
                    if (alias == name) {
                        continue;
                    }
                    this->function_name_map.emplace(alias, func);
                    spdlog::info("  A.k.a {}", alias);
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
                            spdlog::debug("DynInst failed to decode edge {:x}: {}", out_addr, instr.format());

                            // Combine rip into dest
                            // XXX: Hardcode for x86 for now
                            {
                                // Assume a indirect jump to *<Imm>(%rip)
                                const auto op = instr.getOperand(0).format(func->region()->getArch());
                                const std::regex regex("(-?0x[a-f0-9]+)\\(%rip\\)", std::regex::extended);
                                std::smatch match;
                                if(std::regex_match(op, match, regex)) {
                                    const auto pc = bb->end();  // Account for the instruction size, RIP pointing the next instruction!
                                    const auto addr_str = match[1].str();
                                    const auto addr = std::stoul(addr_str, nullptr, 16) + pc;  // pc relative addressing
                                    spdlog::debug("{:x} {} resolve as a edge to {:x}", out_addr, instr.format(), addr);
                                    this->cfg[func].dynamic.emplace(addr);

                                    //std::set<Dyninst::ParseAPI::Function*> callees;
                                    //this->object->findFuncs(func->region(), addr, callees);
                                    //spdlog::info("{} {} {:x} - {:x}   {}", this->PLT.contains(addr), this->GOT.contains(addr), func->region()->low(), func->region()->high(), callees.size());
                                    //for (const auto& callee : callees) {
                                        //spdlog::info("    {} @ {:x}", callee->name(), callee->addr());
                                    //}


                                    //if (callee->name() == func->name() && callee->addr() == func->addr()) {
                                        //continue;  // prevent recursive call
                                    //} else if (this->PLT.contains(callee->addr())) {
                                        //this->cfg[func].dynamic.emplace(callee->addr());
                                    //} else if (this->GOT.contains(callee->addr())) {
                                        //this->cfg[func].dynamic.emplace(callee->addr());
                                    //} else {
                                        //this->cfg[func].static_.emplace(addr);
                                    //}
                                } else {
                                    spdlog::warn("Failed to decode edge {:x}: {}", out_addr, instr.format());
                                }
                            }
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

