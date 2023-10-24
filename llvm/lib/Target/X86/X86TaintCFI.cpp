#include "X86.h"
#include "llvm/Support/CommandLine.h"
#include "X86Declassify.h"
#include "X86LLSCT.h"

#define PASS_KEY "llsct-cfi"
#define DEBUG_TYPE PASS_KEY

using namespace llvm;

namespace {

  cl::opt<bool> EnableTaintCFI {
    PASS_KEY,
    cl::desc("Enable LLSCT"),
    cl::init(false),
  };

  class X86TaintCFI final : public MachineFunctionPass {
  public:
    static inline char ID = 0;
    X86TaintCFI(): MachineFunctionPass(ID) {}

  private:
    void getAnalysisUsage(AnalysisUsage& AU) const override {
      AU.setPreservesCFG();
      MachineFunctionPass::getAnalysisUsage(AU);
    }

    bool runOnMachineFunction(MachineFunction& MF) override;
  };

  bool X86TaintCFI::runOnMachineFunction(MachineFunction& MF) {
    if (!llsct::EnableLLSCT)
      return false;

    if (!EnableTaintCFI)
      return false;


    X86::runDeclassifyCFIPass(MF);

    // MF.dump();
    
    return true;
  }
  
}


INITIALIZE_PASS(X86TaintCFI, PASS_KEY "-pass", "X86 LLSCT Taint CFI Pass", false, false)
FunctionPass *llvm::createX86TaintCFIPass() {
  return new X86TaintCFI();
}
