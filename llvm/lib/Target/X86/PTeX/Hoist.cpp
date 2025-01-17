#include "PTeX/Hoist.h"

#define DEBUG_TYPE "x86-ptex-hoist"

// TODO: Share this.
#define PTEX_DEBUG(...) LLVM_DEBUG(dbgs() << DEBUG_TYPE << ": "; __VA_ARGS__);


using namespace llvm;

static bool isDefHoistable(const MachineOperand &Def) {
  // A def is hoistable if:
  //  - it's live and no prior instructions in the same def or use an overlapping register
  //    and do not clobber it.
  // TODO: Consider dead defs?
  const TargetRegisterInfo *TRI = Def.getParent()->getParent()->getParent()->getSubtarget().getRegisterInfo();
  for (const MachineInstr *MI = Def.getParent()->getPrevNode(); MI; MI = MI->getPrevNode()) {
    for (const MachineOperand &MO : MI->operands()) {
      // Bail if we find an overlapping def/use.
      if ((MO.isReg() && TRI->regsOverlap(Def.getReg(), MO.getReg())) ||
          (MO.isRegMask() && MO.clobbersPhysReg(Def.getReg()))) {
        PTEX_DEBUG(dbgs() << "def \"" << MO << "\" is not hoistable because it is used/defined/clobbered by a prior instruction: " << *MI);
        return false;
      }
    }
  }

  PTEX_DEBUG(dbgs() << "def \"" << Def << "\" is hoistable\n");
  return true;
}

static bool isUseHoistable(const MachineOperand &Use) {
  // A use is hoistable if it's doesn't overlap with prior defs.
  const TargetRegisterInfo *TRI = Use.getParent()->getParent()->getParent()->getSubtarget().getRegisterInfo();
  for (const MachineInstr *MI = Use.getParent()->getPrevNode(); MI; MI = MI->getPrevNode()) {
    for (const MachineOperand &MO : MI->operands()) {
      if ((MO.isReg() && MO.isDef() && TRI->regsOverlap(Use.getReg(), MO.getReg())) ||
          (MO.isRegMask() && MO.clobbersPhysReg(Use.getReg()))) {
        PTEX_DEBUG(dbgs() << "use \"" << MO << "\" is not hoistable because it is defined/clobbered by a prior instruction: " << *MI);
        return false;
      }
    }
  }

  PTEX_DEBUG(dbgs() << "use \"" << Use << "\" is hoistable\n");
  return true;
}

static bool isInstrHoistable(const MachineInstr &MI) {
  if (MI.isCall() || MI.mayLoadOrStore()) {
    PTEX_DEBUG(dbgs() << "instruction in ";
               MI.getParent()->printName(dbgs());
               dbgs() << " not hoistable because of instruction type: " << MI);
    return false;
  }

  for (const MachineOperand &MO : MI.operands()) {
    if (!MO.isReg())
      continue;

    if (MO.isDef() && !isDefHoistable(MO)) {
      PTEX_DEBUG(dbgs() << "instruction has unhoistable def \"" << MO << "\": " << MI);
      return false;
    }

    if (MO.isUse() && !isUseHoistable(MO)) {
      PTEX_DEBUG(dbgs() << "instruction has unhoistable use \"" << MO << "\": " << MI);
      return false;
    }
  }

  PTEX_DEBUG(dbgs() << "found hoistable instruction: " << MI);
  return true;
}

static MachineInstr *getHoistableProtectedUse(const LivePhysRegs &ProtRegs, MachineBasicBlock &MBB) {
  // An instruction is hoistable from the current basic block if none of its uses have been def'd by prior instructions
  // and none of its defs are def'd or used by prior instructions.
  // my def !~ their def
  // my def !~ their use
  // my use !~ their def
  // my use * their use

  for (MachineInstr &MI : MBB) {
    // Never hoist terminators.
    if (MI.isTerminator())
      return nullptr;

    // Is one of this MI's uses in ProtRegs?
    // If so, let's try to hoist it.
    for (const MachineOperand &MO : MI.operands())
      if (MO.isReg() && MO.isUse() && !MO.isUndef())
        if (ProtRegs.contains(MO.getReg()))
          if (isInstrHoistable(MI))
            return &MI;
  }

  return nullptr;
}

static bool hoistInstructionToPredecessors(MachineInstr *MI, MachineBasicBlock &MBB, Pass &P) {
  MachineFunction *MF = MBB.getParent();

  std::set<MachineBasicBlock *> Predecessors;
  llvm::copy(MBB.predecessors(), std::inserter(Predecessors, Predecessors.end()));

  // Split critical edges.
  assert(MBB.pred_size() > 1);
  for (const MachineBasicBlock *Pred : Predecessors) {
    if (Pred->succ_size() > 1 && !Pred->canSplitCriticalEdge(&MBB)) {
      PTEX_DEBUG(dbgs() << "cannot split critical edge\n");
      return false;
    }
  }
  for (MachineBasicBlock *Pred : Predecessors) {
    if (Pred->succ_size() > 1) {
      [[maybe_unused]] const MachineBasicBlock *New = Pred->SplitCriticalEdge(&MBB, P);
      assert(New);
    }
  }

  Predecessors.clear();
  llvm::copy(MBB.predecessors(), std::inserter(Predecessors, Predecessors.end()));

  PTEX_DEBUG(dbgs() << "hoisting instruction from ";
             MBB.printName(dbgs());
             dbgs() << ": " << *MI);

  // Clear any kills and deads.
  // TODO: Be more precise about this.
  for (MachineOperand &MO : MI->operands()) {
    if (MO.isReg()) {
      if (MO.isUse()) {
        MO.setIsKill(false);
      } else {
        assert(MO.isDef());
        MO.setIsDead(false);
      }
    }
  }

  // Hoist the instructions.
  for (MachineBasicBlock *Pred : Predecessors) {
    assert(Pred->succ_size() == 1);

    // Clone instruction.
    MachineInstr *NewMI = MF->CloneMachineInstr(MI);

    // Place right before terminators.
    Pred->insert(Pred->getFirstTerminator(), NewMI);


    PTEX_DEBUG(dbgs() << "hoisted to ";
               Pred->printName(dbgs());
               dbgs() << "\n");
  }

  // Update live-ins.
  // TODO: Make more precise. For now, we unconditionally add the defs,
  // which pollutes the live-ins.
  for (const MachineOperand &MO : MI->operands())
    if (MO.isReg() && MO.isDef() && !MO.isUndef())
      MBB.addLiveIn(MO.getReg());

  MI->eraseFromParent();

  // FIXME: Disable.
  MF->verify();

  return true;
}


bool X86::hoistProtectedUses(MachineFunction &MF, const X86::PTeXInfo &PTI, Pass &P) {
  // Iterate over each control-flow edge.
  // Check if any registers are in-protected at the destination block but
  // out-unprotected at the source block.

  for (MachineBasicBlock &DstMBB : MF) {
    // Nothing to do if DstMBB has only one predecessor.
    if (DstMBB.pred_size() <= 1)
      continue;

    for (MachineBasicBlock *SrcMBB : DstMBB.predecessors()) {
      // Are any registers out-unprotected at SrcMBB but in-protected at DstMBB?
      // If not, skip this edge.
      PublicPhysRegs PubRegs = PTI.Out.at(SrcMBB);
      PubRegs.removeRegs(PTI.In.at(&DstMBB));
      if (PubRegs.empty())
        continue;

      // Try to find hoistable instructions that use in-protected registers.
      MachineInstr *HoistableMI = getHoistableProtectedUse(PubRegs.getLPR(), DstMBB);
      if (!HoistableMI) {
        PTEX_DEBUG(dbgs() << ": fail: no sinkable instruction in destination MBB: ";
                   DstMBB.printName(dbgs());
                   dbgs() << "\n");
        continue;
      }

      // Now, hoist the instruction.
      return hoistInstructionToPredecessors(HoistableMI, DstMBB, P);
    }
  }

  return false;
}
