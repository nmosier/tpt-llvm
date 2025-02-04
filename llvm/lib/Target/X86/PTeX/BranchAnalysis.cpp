#include "PTeX/BranchAnalysis.h"

#include "llvm/CodeGen/TargetInstrInfo.h"
#include "PTeX/PTeX.h"

#define DEBUG_TYPE "x86-ptex-analyze-branches"

using namespace llvm;
using X86::BranchAnalysis;

static cl::opt<bool> AnalyzeBranchesSplit {
  "x86-ptex-analyze-branches-split-critical",
  cl::desc("[PTeX] Split critical edges while analyzing branches"),
  cl::init(false),
  cl::Hidden,
};

bool BranchAnalysis::run() {
  bool Changed = false;
  // NOTE: We're iterating this way in case we insert MBBs during the analysis.
  for (MachineBasicBlock *MBB = &MF.front(); MBB; MBB = MBB->getNextNode())
    Changed |= analyzeBlock(*MBB);
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

  bool Changed = false;
  assert(DstMBB);
  if (DstMBB->pred_size() > 1) {
    assert(MBB.succ_size() > 1);
    // We have a critical edge that is impeding our analysis.
    if (!AnalyzeBranchesSplit) {
      LLVM_DEBUG(dbgs() << "ptex-analysis-branch: fail: unprotected destination block ";
                 DstMBB->printName(dbgs());
                 dbgs() << " for " << *ProtMO << " has " << DstMBB->pred_size() << " successors\n");
      return false;
    }
    DstMBB = PTI.splitCriticalEdge(&MBB, DstMBB);
    if (!DstMBB) {
      LLVM_DEBUG(dbgs() << "ptex-analysis-branch: fail: failed to split critical edge\n");
      return false;
    }
    Changed = true;
  }

  Changed |= PTI.In[DstMBB].addReg(ProtMO->getReg());
  LLVM_DEBUG(dbgs() << "ptex-analysis-branch: success: source=";
             MBB.printName(dbgs());
             dbgs() << " destination=";
             DstMBB->printName(dbgs());
             dbgs() << " register=" << TRI->getRegAsmName(ProtMO->getReg()) << "\n");
  return Changed;
}
