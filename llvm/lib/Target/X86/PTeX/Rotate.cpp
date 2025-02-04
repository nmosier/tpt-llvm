#include "PTeX/Rotate.h"

#include "llvm/CodeGen/MachineLoopInfo.h"
#include "llvm/CodeGen/MachineDominators.h"

#define DEBUG_TYPE "x86-ptex-rotate"

#define PTEX_DEBUG(...) LLVM_DEBUG(dbgs() << DEBUG_TYPE << ": "; __VA_ARGS__);

using namespace llvm;

static bool rotateEdge(MachineBasicBlock *SrcMBB, MachineBasicBlock *DestMBB, X86::PTeXInfo &PTI) {
#if 0
  static unsigned counter = 0;
  if (++counter > 500)
    std::abort();
#endif
  
  // Create the new block.
  MachineFunction *MF = SrcMBB->getParent();
  MachineBasicBlock *NewMBB = MF->CreateMachineBasicBlock(DestMBB->getBasicBlock());
  MF->insert(MF->end(), NewMBB);

  // NOTE: Important to do this first, so we don't duplicate the wrong successors.
  SrcMBB->ReplaceUsesOfBlockWith(DestMBB, NewMBB);

  for (const MachineInstr &DestMI : *DestMBB) {
    MachineInstr *NewMI = MF->CloneMachineInstr(&DestMI);
    NewMBB->insert(NewMBB->end(), NewMI);
  }
  PTI.In[NewMBB] = PTI.In[DestMBB];
  PTI.Out[NewMBB] = PTI.Out[DestMBB];

  // Point NewMBB to successors of DestMBB.
  for (auto succ_it = DestMBB->succ_begin(); succ_it != DestMBB->succ_end(); ++succ_it)
    NewMBB->copySuccessor(DestMBB, succ_it);

  // Point the terminators of SrcMBB to NewMBB, not DestMBB.
  
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
             dbgs() << " src=";
             SrcMBB->printName(dbgs());
             dbgs() << " dest=";
             DestMBB->printName(dbgs());
             dbgs() << "\n");

  // Success!
  return true;
}

static bool rotateBlock(MachineBasicBlock *DestMBB, X86::PTeXInfo &PTI, MachineFunctionPass &P) {
#if 0
  assert(DestMBB->pred_size() > 1);
  // Split any critical edges incoming to DestMBB.

 split_critical_edges:
  for (MachineBasicBlock *SrcMBB : DestMBB->predecessors()) {
    if (SrcMBB->succ_size() > 1) {
      if (SrcMBB->SplitCriticalEdge(DestMBB, P)) {
        goto split_critical_edges;
      } else {
        PTEX_DEBUG(dbgs() << "failed to split critical edge ";
                   SrcMBB->printName(dbgs());
                   dbgs() << " -> ";
                   DestMBB->printName(dbgs());
                   dbgs() << "\n");
        return false;
      }
    }
  }
#endif

  MachineBasicBlock *IgnoreSrcMBB = *DestMBB->pred_begin();
  SmallSet<MachineBasicBlock *, 2> SrcMBBs;
  for (MachineBasicBlock *SrcMBB : DestMBB->predecessors()) {
    SrcMBBs.insert(SrcMBB);
    if (SrcMBB->isLayoutSuccessor(DestMBB))
      IgnoreSrcMBB = SrcMBB;
  }
    
  bool Changed = false;
  for (MachineBasicBlock *SrcMBB : SrcMBBs)
    if (SrcMBB != IgnoreSrcMBB)
      Changed |= rotateEdge(SrcMBB, DestMBB, PTI);

  return Changed;
}

static bool shouldRotateBlock(MachineBasicBlock *DestMBB, const X86::PTeXInfo &PTI) {
  const TargetRegisterInfo *TRI = DestMBB->getParent()->getSubtarget().getRegisterInfo();

  // We only care about blocks that have multiple predecessors.
  if (DestMBB->pred_size() <= 1)
    return false;

  {
    SmallSet<MachineBasicBlock *, 2> SrcMBBs;
    for (MachineBasicBlock *SrcMBB : DestMBB->predecessors())
      SrcMBBs.insert(SrcMBB);
    if (SrcMBBs.size() <= 1)
      return false;
  }

  // We only care if some predecessor has a live register that is out-unprotected
  // but at MBB it's in-protected.
  for (MachineBasicBlock *SrcMBB : DestMBB->predecessors()) {
    X86::PublicPhysRegs PubRegs = PTI.Out.at(SrcMBB);
    PubRegs.removeRegs(PTI.In.at(DestMBB));
    if (PubRegs.empty())
      continue;

    // Are any of these registers live-in to DestMBB?
    for (MCPhysReg Reg : PubRegs) {
      if (DestMBB->isLiveIn(Reg)) {
        PTEX_DEBUG(dbgs() << "should rotate block ";
                   DestMBB->printName(dbgs());
                   dbgs() << " due to live-in register " << TRI->getRegAsmName(Reg) << " out-unprotected at ";
                   SrcMBB->printName(dbgs());
                   dbgs() << "\n");
        return true;
      }
    }
  }

  return false;
}

static bool checkRotateBlock(MachineBasicBlock *Dest, X86::PTeXInfo &PTI, MachineFunctionPass &P) {
  if (shouldRotateBlock(Dest, PTI)) {
    return rotateBlock(Dest, PTI, P);
  } else {
    return false;
  }
}

static bool rotateLoopHeaders(MachineFunction &MF, X86::PTeXInfo &PTI, MachineFunctionPass &P) {
  bool Changed = false;
  MachineDominatorTree MDT(MF);
  MachineLoopInfo MLI(MDT);
  SmallVector<MachineBasicBlock *> Headers;
  for (MachineLoop *Loop : MLI) {
    MachineBasicBlock *Header = Loop->getHeader();
    if (Header && Loop->isLoopExiting(Header) && !Loop->isLoopLatch(Header))
      Headers.push_back(Header);
  }
  for (MachineBasicBlock *Header : Headers)
    Changed |= checkRotateBlock(Header, PTI, P);
  return Changed;
}

bool X86::rotateLoops(MachineFunction &MF, X86::PTeXInfo &PTI, MachineFunctionPass &P, bool rotate_all) {
  assert(!rotate_all && "rotate_all not implemented yet!");
  return rotateLoopHeaders(MF, PTI, P);
}
