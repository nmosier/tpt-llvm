#include "X86MCInstLowerPTeX.h"
#include "X86PTeX.h"
#include "X86PrivacyTypeAnalysis.h"
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
  cl::init(false),
  cl::Hidden,
};

static bool shouldConsiderInstructionForPrefix(const MachineInstr &MI) {
  if (!EnablePTeX())
    return false;

  // PTEX-TODO: Need to unify.
  if (MI.isCall())
    return false;

  SmallVector<const MachineOperand *, 2> OutRegs;
  X86::getInstrDataOutputs(MI, OutRegs);

  if (!OutRegs.empty())
    return true;

  if (MI.mayLoad())
    return true;

  if (PrefixProtectedStores && MI.mayStore())
    return true;

  return false;
}

static void annotate(const MachineInstr *MI, MCInst& OutMI) {
  if (MI->getFlag(MachineInstr::AnnotatePointerLoad)) {
    OutMI.setFlags(X86::IP_USE_DS);
  }
}

// PTEX-TODO: Rename function.
void X86MCInstLowerTPE(const MachineInstr *MI, MCInst& OutMI) {
  annotate(MI, OutMI);

  if (!shouldConsiderInstructionForPrefix(*MI))
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
