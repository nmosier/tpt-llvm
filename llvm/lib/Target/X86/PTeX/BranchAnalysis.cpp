#include "PTeX/BranchAnalysis.h"

#include "llvm/CodeGen/TargetInstrInfo.h"

#define DEBUG_TYPE "x86-ptex-analyze-branches"

using namespace llvm;
using X86::BranchAnalysis;

bool BranchAnalysis::run() {
  bool Changed = false;
  for (MachineBasicBlock &MBB : MF)
    Changed |= analyzeBlock(MBB);
  return Changed;
}

bool BranchAnalysis::analyzeBlock(MachineBasicBlock &MBB) {
  TargetInstrInfo::MachineBranchPredicate MBP;
  if (TII->analyzeBranchPredicate(MBB, MBP)) {
    LLVM_DEBUG(dbgs() << "ptex-analysis-branch: fail: failed to analyze branch predicate for block ";
               MBB.printName(dbgs());
               dbgs() << "\n");
    return false;
  }

  // Ignore branches without predicates.
  if (MBP.Predicate == MBP.PRED_INVALID)
    return false;

  // Don't handle memory-folded conditions.
  if (MBP.ConditionDef->mayLoadOrStore())
    return false;

  // Only continue if either the LHS or the RHS is protected.
  auto IsProt = [] (const MachineOperand &MO) -> bool {
    return MO.isReg() && !MO.isPublic();
  };
  const MachineOperand *ProtMO = nullptr;
  if (IsProt(MBP.LHS))
    ProtMO = &MBP.LHS;
  if (IsProt(MBP.RHS)) {
    if (ProtMO) {
      LLVM_DEBUG(dbgs() << "ptex-analysis-branch: fail: both LHS and RHS are protected\n");
      return false;
    }
    ProtMO = &MBP.RHS;
  }

  if (!ProtMO) {
    // Neither operands are protected, so nothing to do.
    return false;
  }

  MachineBasicBlock *DstMBB = nullptr;
  if (MBP.Predicate == MBP.PRED_EQ) {
    DstMBB = MBP.TrueDest;
  } else if (MBP.Predicate == MBP.PRED_NE) {
    DstMBB = MBP.FalseDest;
  } else {
    llvm_unreachable("bad predicate type!");
  }

  assert(DstMBB);
  if (DstMBB->pred_size() > 1) {
    // We have a critical edge that is impeding our analysis.
    // If critical edge splitting is enabled, we should never get here.
    assert(!X86::SplitCriticalEdges);
    assert(MBB.succ_size() > 1);
    LLVM_DEBUG(dbgs() << "ptex-analysis-branch: fail: unprotected destination block ";
               DstMBB->printName(dbgs());
               dbgs() << " for " << *ProtMO << " has " << DstMBB->pred_size() << " successors\n");
    return false;
  }

  const bool Changed = PTI.In[DstMBB].addReg(ProtMO->getReg());
  LLVM_DEBUG(dbgs() << "ptex-analysis-branch: success: source=";
             MBB.printName(dbgs());
             dbgs() << " destination=";
             DstMBB->printName(dbgs());
             dbgs() << " register=" << TRI->getRegAsmName(ProtMO->getReg()) << "\n");
  return Changed;
}
