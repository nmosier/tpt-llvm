#include "PTeX/ForwardAnalysis.h"

#include "PTeX/Util.h"

using namespace llvm;
using llvm::X86::ForwardAnalysis;

void ForwardAnalysis::init() {
  const PublicPhysRegs top = computeTop(MF);

  for (MachineBasicBlock &MBB : MF) {
    In[&MBB] = top;
    Out[&MBB] = top;

    // Conservatively initialize the pub-ins of entry blocks to the parent analysis' pub-ins. We conservatively consider entry
    // blocks to be anything without a predecessor.
    if (MBB.pred_empty())
      In[&MBB] = Parent.In[&MBB];

    for (MachineInstr &MI : MBB)
      for (MachineOperand &MO : MI.operands())
        if (MO.isReg() && !MO.isUndef())
          PubOps.insert(&MO);
  }
}

bool ForwardAnalysis::block(MachineBasicBlock &MBB) {
  bool Changed = false;

  // Meet.
  for (MachineBasicBlock *PredMBB : MBB.predecessors())
    Changed |= In[&MBB].intersect(Out[PredMBB]);

  // Transfer.
  PublicPhysRegs PubRegs = In[&MBB];
  for (MachineInstr &MI : MBB)
    Changed |= instruction(MI, PubRegs);

  // Set out.
  Changed |= Out[&MBB].intersect(PubRegs);

  return Changed;
}

bool ForwardAnalysis::dataUsesPublic(const MachineInstr &MI, const PublicPhysRegs &PubRegs) const {
  if (MI.mayLoad())
    return false;

  for (const MachineOperand &MO : MI.operands())
    if (MO.isReg() && MO.isUse()  && !MO.isUndef() && !PubRegs.isPublic(MO.getReg()))
      return false;

  return true;
}

bool ForwardAnalysis::instruction(MachineInstr &MI, PublicPhysRegs &PubRegs) {
  bool Changed = false;

  // Remove any uses from PubOps that aren't public.
  for (MachineOperand &MO : MI.operands())
    if (MO.isReg() && MO.isUse() && !MO.isUndef() && !PubRegs.isPublic(MO.getReg()))
      Changed |= PubOps.erase(&MO);

  // Step forward.
  const bool InstrPublic = dataUsesPublic(MI, PubRegs) && !MI.isCall();
  PubRegs.stepForward(MI);
  if (InstrPublic)
    for (MachineOperand &MO : MI.operands())
      if (MO.isReg() && MO.isDef() && !MO.isUndef())
        PubRegs.addReg(MO.getReg());

  // Remove any defs from PubOps that aren't public.
  for (MachineOperand &MO : MI.operands())
    if (MO.isReg() && MO.isDef() && !MO.isUndef() && !PubRegs.isPublic(MO.getReg()))
      Changed |= PubOps.erase(&MO);

  return Changed;
}


bool ForwardAnalysis::run() {
  init();

  bool Changed;
  do {
    Changed = false;

    for (MachineBasicBlock &MBB : MF)
      Changed |= block(MBB);

  } while (Changed);

  bool OverallChanged = false;
  for (MachineOperand *MO : PubOps) {
    if (!MO->isPublic()) {
      OverallChanged = true;
      MO->setIsPublic();
    }
  }

  return OverallChanged;
}
