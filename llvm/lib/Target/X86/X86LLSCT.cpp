#include "X86LLSCT.h"

#include <optional>

#include "X86.h"
#include "X86InstrBuilder.h"
#include "X86Subtarget.h"
#include "llvm/CodeGen/MachineBasicBlock.h"
#include "llvm/CodeGen/MachineFunction.h"
#include "llvm/CodeGen/MachineInstr.h"
#include "llvm/CodeGen/MachineFunctionPass.h"
#include "llvm/CodeGen/MachineModuleInfo.h"
#include "llvm/Pass.h"
#include "llvm/CodeGen/LivePhysRegs.h"
#include "llvm/Support/WithColor.h"
#include "llvm/IR/Value.h"
#include "llvm/Analysis/ValueTracking.h"
#include "llvm/Analysis/AliasAnalysis.h"
#include "X86Declassify.h"
#include "llvm/TPE.h"

using namespace llvm;
using namespace llsct;

#define PASS_KEY "llsct"
#define DEBUG_TYPE PASS_KEY

namespace llsct {
  bool EnableLLSCT;

  static cl::opt<bool> NoCalleeSavedRegsOpt {
    "tpe-ncsrs",
    cl::desc("[TPE] Disable callee saved registers"),
    cl::init(true),
  };

  bool NoCalleeSavedRegs() {
    return EnableLLSCT && tpe::PrivacyPolicyOpt == tpe::ct && NoCalleeSavedRegsOpt;
  }
}

static cl::opt<bool, true> EnableLLSCTOpt {
  PASS_KEY,
  cl::desc("Enable LLSCT"),
  cl::location(llsct::EnableLLSCT),
  cl::init(false),
};

static cl::opt<bool> EnableDeclassify {
  PASS_KEY "-declassify",
  cl::desc("Enable LLSCT's Declassification Hint Pass"),
  cl::init(false),
};

static cl::opt<bool> DumpMIR {
  PASS_KEY "-dump-mir",
  cl::desc("Dump Machine IR coming into LLSCT Pass"),
  cl::init(false)
};

static cl::opt<std::string> DumpFunction {
  PASS_KEY "-dump-func",
  cl::desc("Dump Machine IR for all functions containing the given substring"),
  cl::init("")
};

namespace llvm::X86 {
  int getMemRefBeginIdx(const MCInstrDesc& Desc) {
    int MemRefBeginIdx = X86II::getMemoryOperandNo(Desc.TSFlags);
    if (MemRefBeginIdx < 0)
      return -1;
    MemRefBeginIdx += X86II::getOperandBias(Desc);
    return MemRefBeginIdx;
  }

  int getMemRefBeginIdx(const MachineInstr& MI) {
    return getMemRefBeginIdx(MI.getDesc());
  }
}

namespace {

  class X86LLSCT final : public MachineFunctionPass {
  public:
    static char ID;
    X86LLSCT(): MachineFunctionPass(ID) {}

  private:
    void getAnalysisUsage(AnalysisUsage& AU) const override {
      AU.setPreservesCFG();
      AU.addRequired<AAResultsWrapperPass>();
      MachineFunctionPass::getAnalysisUsage(AU);
    }

    bool runOnMachineFunction(MachineFunction& MF) override;
  };

  char X86LLSCT::ID = 0;

  bool X86LLSCT::runOnMachineFunction(MachineFunction& MF) {
    if (DumpMIR)
      MF.dump();
    
    if (!EnableLLSCT)
      return false;

    if (EnableDeclassify) {
      X86::runDeclassifyAnnotationPass(MF);
      // X86::runSavePublicCSRsPass(MF);
    }

    const StringRef DumpFunctionName = DumpFunction.getValue().c_str();
    if (!DumpFunctionName.empty() && MF.getName().contains(DumpFunctionName))
      MF.getFunction().print(errs());

    return true;
  }
  
  
}
  

INITIALIZE_PASS_BEGIN(X86LLSCT, PASS_KEY "-pass",
		      "X86 LLSCT pass", false, false)
INITIALIZE_PASS_END(X86LLSCT, PASS_KEY "-pass",
		    "X86 LLSCT pass", false, false)

FunctionPass *llvm::createX86LLSCTPass() {
  return new X86LLSCT();
}
