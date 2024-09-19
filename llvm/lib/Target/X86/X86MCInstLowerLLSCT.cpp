#include "X86MCInstLowerLLSCT.h"
#include "X86PTeX.h"
#include "MCTargetDesc/X86BaseInfo.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/IR/DataLayout.h"
#include "llvm/CodeGen/MachineBasicBlock.h"
#include "llvm/CodeGen/MachineFunction.h"
#include "llvm/IR/Function.h"
#include "llvm/Analysis/ValueTracking.h"
#include "llvm/Support/WithColor.h"
#include "llvm/IR/Instructions.h"

using namespace llvm;

namespace llvm::X86 {

static cl::opt<bool> AllowUntyped {
  "x86-ptex-allow-untyped",
  cl::desc("Allow untyped instructions (issue warning, but don't abort)"),
  cl::init(true),
  cl::Hidden,
};

// PTEX-TODO: Rename function.
void X86MCInstLowerTPE(const MachineInstr *MI, MCInst& OutMI) {
  if (!EnablePTeX())
    return;
  
  const auto addFlag = [&OutMI] (auto f) {
    const auto flags = OutMI.getFlags();
    assert((flags & f) == 0);
    OutMI.setFlags(flags | f);
  };
    
  // Declassify flag
  bool privty = MI->getFlag(MachineInstr::TPEPrivM);
  bool pubty = MI->getFlag(MachineInstr::TPEPubM);
  assert(!(privty && pubty));

  if (privty) {
    addFlag(X86::IP_TPE_PRIVM); // PTEX-TODO: Rename.
  } else if (pubty) {
    // Default case: no prefix required.
    // addFlag(X86::IP_TPE_PUBM);
  } else {
    if (AllowUntyped) {
      // WithColor::warning() << "PTeX embedding: encountered untyped instruction: " << *MI;
    } else {
      report_fatal_error("PTeX embedding: encountered untyped instruction");
    }
  }
}
  
}
