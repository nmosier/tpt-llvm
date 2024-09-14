#include "X86LLSCT.h"

#include <optional>

// PTEX-TODO: Cull these includes.
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
#include "X86PrivacyTypeAnalysis.h"

using namespace llvm;

#define PASS_KEY "x86-ptex"
#define DEBUG_TYPE PASS_KEY

// PTEX-TODO: Rename.
namespace llsct {

bool EnableLLSCT = false;

cl::opt<bool, true> EnableLLSCTOpt {
  PASS_KEY,
  cl::desc("Enable PTeX"),
  cl::location(EnableLLSCT),
  cl::init(false),
};

}

// PTEX-TODO: Rename.

namespace {


class PrivacyTypes; // PTEX-FIXME: Remove.

class X86LLSCT final : public MachineFunctionPass {
public:
  static char ID;
  X86LLSCT(): MachineFunctionPass(ID) {}

  void getAnalysisUsage(AnalysisUsage& AU) const override {
    AU.setPreservesCFG();
    AU.addRequired<X86PrivacyTypeAnalysis>();
    MachineFunctionPass::getAnalysisUsage(AU);
  }

  bool runOnMachineFunction(MachineFunction& MF) override;

private:
  // Ensures that register types only transition from private->public
  // if the register is the output of an instruction.
  // Achieves this by inserting register moves around any violations.
  // Returns whether any instructions were inserted, i.e., whether it
  // changed the function.
  bool normalizePrivacyTypes(MachineFunction &MF, PrivacyTypes &PrivTys);

  bool lowerPrivacyTypes(MachineFunction &MF, PrivacyTypes &PrivTys);

  void validatePrivacyTypes(const X86PrivacyTypeAnalysis &PTA);
};

}

char X86LLSCT::ID = 0;

bool X86LLSCT::runOnMachineFunction(MachineFunction& MF) {
  if (!llsct::EnableLLSCT)
    return false;

  // Step 1: Infer privacy types for the function.
  const auto &PrivacyTypes = getAnalysis<X86PrivacyTypeAnalysis>();

  // Step 2: Normalize
  // What property do we want to uphold?
  // That registers only change from public to private or private to public
  // when written to the output of a function.
  // Extend privacy types with function in-types and out-types.
  
#if 0
  auto PrivacyTypes = X86::runTaintAnalysis(MF);

  // Then, preprocess the function to ensure that only output registers
  // can change their privacy from private to public.
  normalizePrivacyTypes(MF, PrivacyTypes);

  lowerPrivacyTypes(MF, PrivacyTypes);

  const StringRef DumpFunctionName = DumpFunction.getValue().c_str();
  if (!DumpFunctionName.empty() && MF.getName().contains(DumpFunctionName))
    MF.getFunction().print(errs());

  return true;
#else
  return false;
#endif
}

#if 0
bool X86LLSCT::normalizePrivacyTypes(MachineFunction &MF, PrivacyTypes &PrivTys) {
  bool Changed = false;

  // PTEX-TODO: Need to insert PUBRs for function arguments.
  // PTEX-TODO: Need to insert assert and/or fixup instructions with mixed public/private outputs.

  for (MachineBasicBlock &MBB : MF) {
    for (MachineInstr &MI : MBB) {
      // Check if any register changed to public before MI from prior instruction.
      for_each_instr_predecessor(MI, [&] (MachineInstr &PredMI) {
        const PrivacyMask& PreTy = PrivTys[&PredMI].post;
        const PrivacyMask& PostTy = PrivTys[&MI].pre;
        for (Register DeclReg : PrivacyMask::getDeclassifiedRegisters(PreTy, PostTy)) {
          TII->copyPhysReg(MBB, MI.getIterator(), DebugLoc(), DeclReg, DeclReg, /*KillSrc*/true);
          MachineInstr *MoveMI = MI.getPrevNode();
          assert(MoveMI == PredMI.getNextNode());
          PrivTys[MoveMI].pre = PreTy;
          PrivTys[MoveMI].post = PostTy;
          Changed = true;
        }
      });
    }
  }

  //
}

bool X86LLSCT::lowerPrivacyTypes(MachineFunction &MF, PrivacyTypes &PrivTys) {
  // Add PRIV or PUB flags to instructions.
  for (MachineBasicBlock& MBB : MF) {
    for (MachineInstr& MI : MBB) {
      // If this instruction has a public register output, mark it public.
      bool AnyOutputPublic = false;
      bool AnyOutputPrivate = false;
      const PrivacyMask &OutPrivacy = PrivTys[&MI].post;
      for (const MachineOperand &MO : MI.operands()) {
        if (MO.isReg() && MO.isDef()) {
          if (OutPrivacy.hasPubReg(MO.getReg())) {
            AnyOutputPublic = true;
          } else {
            AnyOutputPrivate = true;
          }
        }
      }
      assert(!(AnyOutputPublic && AnyOutputPrivate) && "Instruction has mixed public/private outputs!");
      if (AnyOutputPublic) {
        MI.setFlag(MachineInstr::PubM); // PTEX-TODO: Rename
      } else if (AnyOutputPrivate) {
        MI.setFlag(MachineInstr::PrivM);
      }
    }
  }

  // Add register moves to detect passive register declassifications.
  auto AddPubMove = [&] (MachineBasicBlock &MBB, MachineInstr &MI, Register DeclReg) {
    TII->copyPhysReg(MBB, MI.getIterator(), DebugLoc(), DeclReg, DeclReg, /*KillSrc*/true);
    MachineInstr *DeclMI = MI.getPrevNode();
    DeclMI->setFlag(MachineInstr::TPE_PubM);
  };
  for (MachineBasicBlock &MBB : MF) {
    const auto PredMBBs = getPredecessors(MBB);

    if (!PredMBBs) 
    for (MachineBasicBlock *PredMBB : getNonemptyPredecessors(MBB)) {
      AddPubMove(MBB, 
    }
    
    for (MachineInstr& MI : MBB) {
      getNonemptyPredecessors(MBB);
    }
  }
}
#endif  

INITIALIZE_PASS_BEGIN(X86LLSCT, PASS_KEY "-pass",
		      "X86 LLSCT pass", false, false)
INITIALIZE_PASS_END(X86LLSCT, PASS_KEY "-pass",
		    "X86 LLSCT pass", false, false)

FunctionPass *llvm::createX86LLSCTPass() {
  return new X86LLSCT();
}
