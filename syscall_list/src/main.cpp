#include <iostream>
#include <memory>
#include <set>
#include <string>
#include <unordered_set>
#include <vector>

#include <spdlog/spdlog.h>

#include "BPatch.h"
#include "BPatch_flowGraph.h"
#include "BPatch_function.h"
#include "CFG.h"
#include "CodeObject.h"

namespace dp = Dyninst::ParseAPI;
namespace st = Dyninst::SymtabAPI;

BPatch bp;

int main(const int argc, const char *argv[]) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <executable> <args...>\n";
        return -1;
    }

    spdlog::info("Create process from {}", argv[1]);
    const auto process = bp.processCreate(argv[1], argv + 2);
    process->stopExecution();

    spdlog::info("Create Image");
    const auto image = process->getImage();

    const auto funcs = image->getProcedures();

    //const auto main_func = image->findFunction("main", funcs);

    //for (const auto& func : *funcs) {
        //spdlog::info("Func {} @ {}", func->getName(), func->getBaseAddr());
        ////const auto cfg = func->getCFG();
    //}
    std::vector<BPatch_function*> entries;
    image->findFunction("_start", entries);
    if (entries.empty()) {
        spdlog::error("Failed to find entry point");
        return 1;
    }

    const auto entry = entries[0];
    spdlog::info("_start @ {}", entry->getBaseAddr());


    spdlog::info("Perform CFG analyze and gather Basic Blocks");
    const auto cfg = entry->getCFG();
    std::set<BPatch_basicBlock *> basic_blocks;
    cfg->getAllBasicBlocks(basic_blocks);

    for (const auto& bb : basic_blocks) {
        spdlog::info("BB @ {:x}", bb->getStartAddress());

        if (bb->isExitBlock()) {

        }


        //std::vector<Dyninst::InstructionAPI::Instruction> insns;
        //bb->getInstructions(insns);

        //for (const auto& inst : insns) {
            //spdlog::info("{}", inst.format());
        //}
    }

    //const auto symtab = std::make_unique<dp::SymtabCodeSource>(argv[1]);
    //symtab->print_stats();
  //const auto code_obj = std::make_unique<dp::CodeObject>(symtab.get());

  //code_obj->parse();

  //auto all_funcs = code_obj->funcs();

  //// Remove compiler-generated and system functions
  //{
    ////auto ignore = [&all](dp::Function const *f) {
      ////auto const &name = f->name();
      ////bool const starts_with_underscore = name[0] == '_';
      ////bool const ends_with_underscore = name[name.length() - 1] == '_';
      ////bool const is_dummy = name == "frame_dummy";
      ////bool const is_clones = name.find("tm_clones") != std::string::npos;
      ////return starts_with_underscore || ends_with_underscore || is_dummy ||
             ////is_clones;
    ////};

    //std::erase_if(all_funcs, [](const auto func) {
        ////const auto& name = f->name();
        //return false;
    //});
  //}

  //for(auto i = 0; auto func : all_funcs) {
      //std::cout << i << " : " << func->name() << '\n';
  //}
}
