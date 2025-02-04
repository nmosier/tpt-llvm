#include "PTeX/Rotate.h"

#include "llvm/CodeGen/MachineLoopInfo.h"
#include "llvm/CodeGen/MachineDominators.h"

#define DEBUG_TYPE "x86-ptex-rotate"

#define PTEX_DEBUG(...) LLVM_DEBUG(dbgs() << DEBUG_TYPE << ": "; __VA_ARGS__);

using namespace llvm;

static bool rotateBlock(MachineBasicBlock *DestMBB, X86::PTeXInfo &PTI, const SmallVectorImpl<MachineBasicBlock *> &SrcMBBs) {
  // For now, only handle cases where DestMBB is the layout successor of any SrcMBB.
  for (MachineBasicBlock *SrcMBB : SrcMBBs)
    if (SrcMBB->isLayoutSuccessor(DestMBB))
      return false;

  // Bail if there are EH_LABELs in DestMBB, since they define symbols that would get duplicated.
  // TODO: There might be a way to fix this.
  for (const MachineInstr &MI : *DestMBB) {
    if (MI.isEHLabel())
      return false;
  }

  // Create the new block.
  MachineFunction *MF = DestMBB->getParent();
  MachineBasicBlock *NewMBB = MF->CreateMachineBasicBlock(DestMBB->getBasicBlock());
  MF->insert(MF->end(), NewMBB);

  // Replace uses of the old destination block with the new destination block in all of the sources.
  for (MachineBasicBlock *SrcMBB : SrcMBBs)
    SrcMBB->ReplaceUsesOfBlockWith(DestMBB, NewMBB);

  // Duplicate all the instructions from the old destination into the new destination.
  for (const MachineInstr &DestMI : *DestMBB) {
    MachineInstr *NewMI = MF->CloneMachineInstr(&DestMI);
    NewMBB->insert(NewMBB->end(), NewMI);
  }

  // Populate the register protection information for the new destination.
  PTI.In[NewMBB] = PTI.In[DestMBB];
  PTI.Out[NewMBB] = PTI.Out[DestMBB];

  // Point NewMBB to successors of DestMBB.
  for (auto succ_it = DestMBB->succ_begin(); succ_it != DestMBB->succ_end(); ++succ_it)
    NewMBB->copySuccessor(DestMBB, succ_it);

  // Copy in liveins to NewMBB.
  for (auto P : DestMBB->liveins())
    NewMBB->addLiveIn(P);

  // If DestMBB can fall through, then add an explicit jump to NewMBB.
  if (MachineBasicBlock *FallMBB = DestMBB->getFallThrough(false)) {
    const TargetInstrInfo *TII = MF->getSubtarget().getInstrInfo();
    TII->insertUnconditionalBranch(*NewMBB, FallMBB, DebugLoc());
  }

  PTEX_DEBUG(dbgs() << "inserted new block: new=";
             NewMBB->printName(dbgs());
             dbgs() << " srcs=";
             llvm::interleaveComma(SrcMBBs, dbgs(), [] (const MachineBasicBlock *SrcMBB) { SrcMBB->printName(dbgs()); });
             dbgs() << " dest=";
             DestMBB->printName(dbgs());
             dbgs() << "\n");

  // Success!
  return true;
}

static bool shouldRotateLoop(MachineBasicBlock *Header, MachineLoop *Loop, const X86::PTeXInfo &PTI, SmallVectorImpl<MachineBasicBlock *> &InternalSrcs) {
  [[maybe_unused]] const TargetRegisterInfo *TRI = Header->getParent()->getSubtarget().getRegisterInfo();

  // We only care about blocks that have multiple predecessors.
  if (Header->pred_size() <= 1)
    return false;

  // Partition the predecessors into loop-external and loop-internal.
  for (MachineBasicBlock *SrcMBB : Header->predecessors())
    if (Loop->contains(SrcMBB))
      InternalSrcs.push_back(SrcMBB);
  assert(!InternalSrcs.empty());

  // We only care if all loop-external predecessors marked a live register out-unprotected but
  // the header marked it in-protected.
  X86::PublicPhysRegs PubRegs = PTI.Out.at(InternalSrcs.front());
  for (MachineBasicBlock *InternalSrc : InternalSrcs)
    PubRegs.intersect(PTI.Out.at(InternalSrc));
  PubRegs.removeRegs(PTI.In.at(Header));
  if (PubRegs.empty())
    return false;

  // Are any of these registers live-in to the header?
  for (MCPhysReg Reg : PubRegs) {
    if (Header->isLiveIn(Reg)) {
      PTEX_DEBUG(dbgs() << "should rotate loop header ";
                 Header->printName(dbgs());
                 dbgs() << " due to live-in register " << TRI->getRegAsmName(Reg) << " out-unprotected at";
                 for (MachineBasicBlock *MBB : InternalSrcs) {
                   dbgs() << " ";
                   MBB->printName(dbgs());
                 }
                 dbgs() << "\n");
      return true;
    }
  }

  // None of the registers were live-in.
  return false;
}

bool X86::rotateLoops(MachineFunction &MF, X86::PTeXInfo &PTI) {
  bool Changed = false;
  MachineDominatorTree MDT(MF);
  MachineLoopInfo MLI(MDT);
  struct RotateInfo {
    MachineBasicBlock *DestMBB;
    SmallVector<MachineBasicBlock *> SrcMBBs;
  };
  SmallVector<RotateInfo> Worklist;
  for (MachineLoop *Loop : MLI) {
    if (MachineBasicBlock *Header = Loop->getHeader()) {
      RotateInfo WorkItem;
      WorkItem.DestMBB = Header;
      if (shouldRotateLoop(Header, Loop, PTI, WorkItem.SrcMBBs))
        Worklist.push_back(WorkItem);
    }
  }
  for (const RotateInfo &WorkItem : Worklist)
    Changed |= rotateBlock(WorkItem.DestMBB, PTI, WorkItem.SrcMBBs);
  return Changed;
}
