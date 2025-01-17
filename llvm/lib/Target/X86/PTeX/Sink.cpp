#include "PTeX/Sink.h"

#include "X86Subtarget.h"

#define DEBUG_TYPE "x86-ptex-sink"

using namespace llvm;

static bool isDefSinkable(const MachineOperand &MO) {
  assert(MO.isReg() && MO.isDef());

  const MachineInstr *MI = MO.getParent();
  const MachineBasicBlock *MBB = MI->getParent();
  const TargetRegisterInfo *TRI = MBB->getParent()->getSubtarget().getRegisterInfo();

  const MachineOperand *LastFullDef = &MO;
  for (const MachineInstr *NextMI = MI->getNextNode(); NextMI; NextMI = NextMI->getNextNode()) {

    // First, check for overlapping uses in NextMI.
    for (const MachineOperand &NextMO : NextMI->operands()) {
      // Is the register used?
      if (NextMO.isReg() && !NextMO.isUndef() && NextMO.isUse() && !MO.isUndef() &&
          TRI->regsOverlap(MO.getReg(), NextMO.getReg())) {
        // Yes, it's used. Bail - the def is not sinkable.
        LLVM_DEBUG(dbgs() << "ptex-sink: def \"" << MO << "\" is not sinkable because it is used by \""
                   << NextMO << "\" in instruction: " << *NextMI);
        return false;
      }
    }

    for (const MachineOperand &NextMO : NextMI->operands()) {
      if (!NextMO.isReg())
        continue;

      // Is the def partially clobbered?
      if (NextMO.isDef() && !NextMO.isUndef() && !MO.isUndef() &&
          TRI->isSubRegister(MO.getReg(), NextMO.getReg())) {
        // Yes, the def is partially clobbered.
        LLVM_DEBUG(dbgs() << "ptex-sink: def \"" << MO << "\" is not sinkable because it is partially clobbered by \""
                   << NextMO << "\" in instruction: " << *NextMI);
        return false;
      }

      // If we see a full def, we break out of the loop, since we're no longer
      // dealing with the original def.
      if (NextMO.isDef() && TRI->isSuperRegisterEq(MO.getReg(), NextMO.getReg())) {
        LastFullDef = &NextMO;
        goto done;
      }
    }
  }

 done:

  // If the only full def is our def, then the def is sinkable.
  if (LastFullDef == &MO) {
    LLVM_DEBUG(dbgs() << "ptex-sink: def \"" << MO << "\" is sinkable because nobody overwrote it\n");
    return true;
  }

  // Otherwise, the register was subsequently def'ed.
  // If the def is dead, then we can sink our def.
  if (LastFullDef->isDead()) {
    LLVM_DEBUG(dbgs() << "ptex-sink: def \"" << MO << "\" is sinkable because the final full def of the register \""
               << *LastFullDef << "\" is dead\n");
    return true;
  }

  // Is the last full def live-out?
  LivePhysRegs LPR(*TRI);
  LPR.addLiveOuts(*MBB);
  for (MCRegAliasIterator R(LastFullDef->getReg(), TRI, true); R.isValid(); ++R) {
    if (LPR.contains(*R)) {
      LLVM_DEBUG(dbgs() << "ptex-sink: def \"" << MO << "\" is not sinkable because the final full non-original def \"" << *LastFullDef << "\" is live-out: "
                 << *LastFullDef->getParent());
      return false;
    }
  }

  LLVM_DEBUG(dbgs() << "ptex-sink: def \"" << MO << "\" is sinkable because the final full non-original def is not live-out\n");
  return true;
}

static bool isUseSinkable(const MachineOperand &Use) {
  // Undef uses are always sinkable.
  if (Use.isUndef()) {
    LLVM_DEBUG(dbgs() << "ptex-sink: use " << Use << " is sinkable because its undef\n");
    return true;
  }

  const MachineInstr *UseMI = Use.getParent();
  const TargetRegisterInfo *TRI = UseMI->getParent()->getParent()->getSubtarget().getRegisterInfo();
  for (const MachineInstr *MI = UseMI->getNextNode(); MI; MI = MI->getNextNode()) {
    for (const MachineOperand &MO : MI->operands()) {
      if (MO.isReg() && MO.isDef() && TRI->regsOverlap(MO.getReg(), Use.getReg())) {
        LLVM_DEBUG(dbgs() << "ptex-sink: use " << Use << " is not sinkable because a subsequent instruction def \""
                   << MO << "\" overwrites the register: " << *MI);
        return false;
      }

      if (MO.isRegMask() && MO.clobbersPhysReg(Use.getReg())) {
        LLVM_DEBUG(dbgs() << "ptex-sink: use \"" << Use << "\" is not sinkable because it was clobbered by instruction: " << *MI);
        return false;
      }
    }
  }

  return true;
}

static bool isInstrSinkable(MachineInstr &MI, LivePhysRegs &Defs, LivePhysRegs &Uses) {
  if (MI.isCall() || MI.mayLoadOrStore()) {
    LLVM_DEBUG(dbgs() << "ptex-sink: instruction in ";
               MI.getParent()->printName(dbgs());
               dbgs() << " not sinkable because of instruction type: " << MI);
    return false;
  }

  for (const MachineOperand &MO : MI.operands()) {
    if (!MO.isReg())
      continue;

    if (MO.isDef() && !isDefSinkable(MO)) {
      LLVM_DEBUG(dbgs() << "ptex-sink: instruction has unsinkable def: " << MI);
      return false;
    }

    if (MO.isUse() && !isUseSinkable(MO)) {
      LLVM_DEBUG(dbgs() << "ptex-sink: instruction has unsinkable use: " << MI);
      return false;
    }
  }

  LLVM_DEBUG(dbgs() << "ptex-sink: found sinkable instruction: " << MI);

  return true;
}

static MachineInstr *getSinkableProtectedDefs(const LivePhysRegs &ProtRegs, MachineBasicBlock &MBB) {
  LLVM_DEBUG(dbgs() << "ptex-sink: analyzing block:\n" << MBB);

  // NOTE: Need to make sure that an instruction is sinkable only if all its uses haven't since
  // been defined.
  const MachineFunction *MF = MBB.getParent();
  const TargetRegisterInfo *TRI = MF->getSubtarget().getRegisterInfo();
  LivePhysRegs Defs(*TRI); // TODO: Can remove these, methinks.
  LivePhysRegs Uses(*TRI);
  for (MachineInstr &MI : llvm::reverse(MBB)) {
    // Is one of this MI's defs in Regs?
    // If so, this MI is sinkable, and we're done.
    for (const MachineOperand &MO : MI.operands())
      if (MO.isReg() && !MO.isUndef() && MO.isDef())
        if (ProtRegs.contains(MO.getReg()))
          if (isInstrSinkable(MI, Defs, Uses))
            return &MI;

    // Update defs and uses.
    for (const MachineOperand &MO : MI.operands()) {
      if (MO.isReg() && !MO.isUndef() && MO.getReg() != X86::NoRegister) {
        const MCPhysReg Reg = MO.getReg();
        if (MO.isUse())
          Uses.addReg(Reg);
        if (MO.isDef())
          Defs.addReg(Reg);
      }
    }
  }

  return nullptr;
}

static void fixupKillForUse(MachineOperand &MyUse) {
  const MCPhysReg MyReg = MyUse.getReg();
  MachineInstr *MyMI = MyUse.getParent();
  const TargetRegisterInfo *TRI = MyMI->getParent()->getParent()->getSubtarget().getRegisterInfo();
  for (MachineInstr *TheirMI = MyMI; TheirMI; TheirMI = TheirMI->getNextNode()) {
    // Check for use-kills overlapping with our operand.
    for (MachineOperand &TheirUse : TheirMI->operands()) {
      if (!(TheirUse.isReg() && TheirUse.isUse() && TheirUse.isKill()))
        continue;

      const MCPhysReg TheirReg = TheirUse.getReg();

      // In case of a perfect kill match, our use inherits the kill
      // and their use loses the kill.
      // We continue to look at the rest of the operands, however,
      // in case there's a duplicate kill (e.g., add killed rax, killed rax).
      if (MyReg == TheirReg) {
        // NOTE: This ordering is essential in the case that TheirUse == MyUse.
        TheirUse.setIsKill(false);
        MyUse.setIsKill();
      }
    }

    // If we set our use as killed, then we're done.
    if (MyUse.isKill())
      return;

    // Otherwise, check if our register was fully overwritten by a def.
    for (const MachineOperand &TheirDef : TheirMI->operands()) {
      if (!(TheirDef.isReg() && TheirDef.isDef()))
        continue;
      const MCPhysReg TheirReg = TheirDef.getReg();
      if (TRI->isSuperRegisterEq(MyReg, TheirReg)) {
        // Our use was fully clobbered by their def, so we're done.
        return;
      }
    }
  }
}

static bool sinkInstructionToSuccessors(MachineInstr *MI, MachineBasicBlock &MBB, Pass &P) {
  MachineFunction *MF = MBB.getParent();

  std::unordered_set<MachineBasicBlock *> Successors;
  llvm::copy(MBB.successors(), std::inserter(Successors, Successors.end()));

  // Split critical edges.
  assert(MBB.succ_size() > 1);
  for (const MachineBasicBlock *Succ : Successors) {
    if (Succ->pred_size() > 1 && !MBB.canSplitCriticalEdge(Succ)) {
      LLVM_DEBUG(dbgs() << "ptex-sink: cannot split critical edge\n");
      return false;
    }
  }
  for (MachineBasicBlock *Succ : Successors) {
    if (Succ->pred_size() > 1) {
      [[maybe_unused]] const MachineBasicBlock *New = MBB.SplitCriticalEdge(Succ, P);
      assert(New);
    }
  }

  Successors.clear();
  llvm::copy(MBB.successors(), std::inserter(Successors, Successors.end()));

  LLVM_DEBUG(dbgs() << "ptex-sink: sinking instruction from ";
             MBB.printName(dbgs());
             dbgs() << ": " << *MI);

  // For each used register, check if it is killed later on in the block.
  for (MachineOperand &MyUse : MI->operands())
    if (MyUse.isReg() && MyUse.isUse() && !MyUse.isUndef())
      fixupKillForUse(MyUse);

  // TODO: Only sink the instruction if its def's are live or it has side-effects.
  // FIXME: Probably shouldn't sink load insturctions.
  for (MachineBasicBlock *SuccMBB : Successors) {
    assert(SuccMBB->pred_size() == 1);

    // Clone instruction.
    MachineInstr *NewMI = MF->CloneMachineInstr(MI);

    // Push to front of successor.
    SuccMBB->insert(SuccMBB->begin(), NewMI);

    // Update live ins of successor.
    // This involves removing defs and adding uses.
    for (const MachineOperand &MO : MI->operands())
      if (MO.isReg() && MO.isDef())
        SuccMBB->removeLiveIn(MO.getReg());
    for (const MachineOperand &MO : MI->operands())
      if (MO.isReg() && MO.isUse() && !MO.isUndef() && MO.getReg() != X86::NoRegister)
        SuccMBB->addLiveIn(MO.getReg());

    LLVM_DEBUG(dbgs() << "ptex-sink: sunk to ";
               SuccMBB->printName(dbgs());
               dbgs() << "\n");
  }
  MI->eraseFromParent();

  // FIXME: Disable.
  MF->verify();

  return true;
}

bool X86::sinkProtectedDefs(MachineFunction &MF, const X86::PTeXAnalysis &PA, Pass &P) {
  // Iterate over each control-flow edge.
  // Check if any registers are out-protected at the source block but
  // in-unprotected at the destination block.

  // Stage 1: Collect.
  for (MachineBasicBlock &SrcMBB : MF) {
    // Nothing to do if SrcMBB only has one successor (or none).
    if (SrcMBB.succ_size() <= 1)
      continue;

    for (MachineBasicBlock *DstMBB : SrcMBB.successors()) {
      // Are any registers out-protected at SrcMBB but in-unprotected at DstMBB?
      // If not, skip this edge.
      PublicPhysRegs PubRegs = PA.In.at(DstMBB);
      PubRegs.removeRegs(PA.Out.at(&SrcMBB));
      if (PubRegs.empty())
        continue;

      // Try to find sinkable instructions that define out-protected instructions.
      MachineInstr *SinkableMI = getSinkableProtectedDefs(PubRegs.getLPR(), SrcMBB);
      if (!SinkableMI) {
        LLVM_DEBUG(dbgs() << "ptex-sink: failed to find sinkable instruction in source MBB: ";
                   SrcMBB.printName(dbgs());
                   dbgs() << "\n");
        continue;
      }

      // Now, sink selected instruction to the beginning of SrcMBB's successors.
      return sinkInstructionToSuccessors(SinkableMI, SrcMBB, P);
    }
  }

  return false;
}
