#include "PTeX/Util.h"
#include "PTeX/PublicPhysRegs.h"
#include "llvm/CodeGen/MachineFunction.h"
#include "llvm/CodeGen/TargetSubtargetInfo.h"
#include "llvm/CodeGen/MachineRegisterInfo.h"
#include "MCTargetDesc/X86BaseInfo.h"
#include "llvm/CodeGen/MachineLoopUtils.h"
#include "llvm/ADT/PostOrderIterator.h"
#include "llvm/CodeGen/TargetInstrInfo.h"

using namespace llvm;
using llvm::X86::PublicPhysRegs;

void llvm::impl::addRegToCover(MCPhysReg OurReg, SmallVectorImpl<MCPhysReg> &TheirRegs,
                         const TargetRegisterInfo *TRI) {
  for (auto TheirRegIt = TheirRegs.begin(); TheirRegIt != TheirRegs.end(); ) {
    const MCPhysReg TheirReg = *TheirRegIt;

    // If there's no overlap, then skip.
    if (!TRI->regsOverlap(OurReg, TheirReg)) {
      ++TheirRegIt;
      continue;
    }

    // If our register is a subset of an existing one, then don't add it to the set.
    if (TRI->isSubRegister(TheirReg, OurReg))
      return;

    // If their register is a subset of our register, then remove their register from
    // the set before adding ours.
    if (TRI->isSubRegister(OurReg, TheirReg)) {
      TheirRegIt = TheirRegs.erase(TheirRegIt);
    } else {
      ++TheirRegIt;
    }
  }

  // Add our register to the set.
  TheirRegs.push_back(OurReg);
}

PublicPhysRegs X86::computeTop(MachineFunction &MF) {
  const TargetRegisterInfo *TRI = MF.getSubtarget().getRegisterInfo();

  PublicPhysRegs top(TRI);

  // Add all callee-saved registers.
  for (const MCPhysReg *CSR = MF.getRegInfo().getCalleeSavedRegs(); *CSR; ++CSR)
    top.addReg(*CSR);

  // Add all registers that are uses/defs of any instruction.
  for (const MachineBasicBlock &MBB : MF) {
    for (const MachineInstr &MI : MBB) {
      for (const MachineOperand &MO : MI.operands()) {
        if (MO.isReg()) {
          top.addReg(MO.getReg());
        }
      }
    }
  }

  return top;
}


static int getMemRefBeginIdx(const MCInstrDesc& Desc) {
  int MemRefBeginIdx = X86II::getMemoryOperandNo(Desc.TSFlags);
  if (MemRefBeginIdx < 0)
    return -1;
  MemRefBeginIdx += X86II::getOperandBias(Desc);
  return MemRefBeginIdx;
}

int X86::getMemRefBeginIdx(const MachineInstr& MI) {
  return ::getMemRefBeginIdx(MI.getDesc());
}

void X86::getInstrDataOutputs(const MachineInstr &MI, SmallVectorImpl<const MachineOperand *> &Outs) {
  if (MI.isCall() || MI.isReturn() || MI.isBranch())
    return;

  for (const MachineOperand &MO : MI.operands())
    if (MO.isReg() && MO.isDef())
      if (!(MO.isImplicit() && registerIsAlwaysPublic(MO.getReg())))
        Outs.push_back(&MO);
}

// TODO: Remove these?

// TODO: Remove.
static MCPhysReg canonicalizeRegister(MCPhysReg Reg) {
  if (Reg == X86::EFLAGS)
    return Reg;
  if (Register Reg64 = getX86SubSuperRegister(Reg, 64))
    return Reg64;
  return Reg;
}

static std::array<Register, 5> AlwaysPublicRegisters = {
  X86::NoRegister, X86::RSP, X86::RIP, X86::SSP, X86::MXCSR,
};

// TODO: Remove.
bool X86::registerIsAlwaysPublic(Register Reg) {
  return llvm::is_contained(AlwaysPublicRegisters, canonicalizeRegister(Reg));
}

#if 0
bool unpeelSingleMachineLoopIteration(MachineLoop *L) {
  // Approach:
  // Replicate the whole loop body. We'll replicate it before the current header, I guess.
  // We should do it in linear order.
  // For now, don't handle loops that aren't linear blocks.

  // Bail out if any loop blocks' addresses are taken.
  for (MachineBasicBlock *MBB : L->blocks())
    if (MBB->hasAddressTaken())
      return false;

  // Attempt to recover the linear layout.
  std::vector<MachineBasicBlock *> OrigBlocks;
  for (MachineBasicBlock *MBB = L->getTop(); L->contains(MBB); MBB = MBB->getNextNode())
    OrigBlocks.push_back(MBB);

  // If we didn't get all the blocks, then report failure to unpeel the loop.
  if (OrigBlocks.size() != L->getNumBlocks())
    return false;

  // Now, duplicate entire loop body right before the loop header.
  // Construct a block translation map from unpeeled iteration to main loop body.
  std::unordered_map<MachineBasicBlock *, MachineBasicBlock *> OrigToNew, NewToOrig;
  auto InsertPt = OrigBlocks.front()->getIterator();
  for (MachineBasicBlock *OrigMBB : OrigBlocks) {
    MachineBasicBlock *NewMBB = MF.CreateMachineBasicBlock(OrigMBB->getBasicBlock());
    MF.insert(InsertPt, NewMBB);
    for (const MachineInstr &OrigMI : *OrigMBB) {
      MachineInstr *NewMI = MF.CloneMachineInstr(&OrigMI);
      NewMBB->insert(NewMBB->end(), NewMI);
    }
    OrigToNew[OrigMBB] = NewMBB;
    NewToOrig[NewMBB] = OrigMBB;
  }

  MachineBasicBlock *OrigHeader = L->getHeader();
  MachineBasicBlock *NewHeader = OrigToNew.at(OrigHeader);

  // Fixup the external incoming edges.
  for (MachineBasicBlock *MBB : OrigHeader->predecessors()) {
    if (!L->contains(MBB)) {
      MBB->removeSuccessor(OrigHeader);
      MBB->addSuccessor(NewHeader);
      for (MachineInstr &Terminator : MBB->terminators()) {

      }
    }
  }
}
#else
bool llvm::unpeelSingleMachineLoopIteration(MachineLoop *L) {
  // Is this a single-block loop?
  if (L->getNumBlocks() != 1)
    return false;
  MachineBasicBlock *OrigHeader = L->getHeader();
  if (OrigHeader->succ_size() != 2)
    return false;
  if (OrigHeader->pred_size() != 2)
    return false;
  if (OrigHeader->hasAddressTaken())
    return false;

  MachineFunction *MF = L->getHeader()->getParent();

  MachineBasicBlock *UnpeeledHeader = MF->CreateMachineBasicBlock(OrigHeader->getBasicBlock());
  MF->insert(OrigHeader->getIterator(), UnpeeledHeader);
  for (const MachineInstr &OrigMI : *OrigHeader) {
    MachineInstr *NewMI = MF->CloneMachineInstr(&OrigMI);
    UnpeeledHeader->insert(UnpeeledHeader->end(), NewMI);
  }

  // This initializes predecessors.
  for (MachineBasicBlock *Entering : OrigHeader->predecessors())
    if (!L->contains(Entering))
      Entering->ReplaceUsesOfBlockWith(OrigHeader, UnpeeledHeader);

  // This initializes successors.
  // TODO: Probabilities?
  for (MachineBasicBlock *Succ : OrigHeader->successors())
    UnpeeledHeader->addSuccessor(Succ);

  if (MF->getRegInfo().tracksLiveness())
    for (const auto &LiveIn : OrigHeader->liveins())
      UnpeeledHeader->addLiveIn(LiveIn);

  return true;
}
#endif

void llvm::getExitReachingBlocks(MachineFunction &MF, std::unordered_set<MachineBasicBlock *> &ExitReachingBlocks) {
  auto &Set = ExitReachingBlocks;

  // Initialization: add all exit blocks to set.
  for (MachineBasicBlock &MBB : MF)
    if (MBB.succ_empty())
      Set.insert(&MBB);

  bool Changed;
  do {
    Changed = false;
    for (MachineBasicBlock *MBB : llvm::post_order(&MF)) {
      if (llvm::any_of(MBB->successors(), [&Set] (MachineBasicBlock *SuccMBB) -> bool {
        return Set.count(SuccMBB);
      }))
        Changed |= Set.insert(MBB).second;
    }
  } while (Changed);
}

static bool isSensitiveInstr(const MachineInstr &MI) {
  return MI.isCall() || MI.isReturn() ||
      llvm::any_of(MI.operands(), std::mem_fn(&MachineOperand::isRegMask)) ||
      MI.hasUnmodeledSideEffects() ||
      MI.hasOrderedMemoryRef();
}

bool llvm::hasRegisterHazard(const MachineInstr &MI1, const MachineInstr &MI2) {
  if (isSensitiveInstr(MI1) || isSensitiveInstr(MI2))
    return true;

  // Check for overlapping defs/uses.
  const TargetRegisterInfo *TRI = MI1.getParent()->getParent()->getSubtarget().getRegisterInfo();
  for (const MachineOperand &MO1 : MI1.operands())
    if (MO1.isReg())
      for (const MachineOperand &MO2 : MI2.operands())
        if (MO2.isReg())
          if ((MO1.isDef() || MO2.isDef()) && TRI->regsOverlap(MO1.getReg(), MO2.getReg()))
            return true;
  return false;
}

#if 0
static bool mayAlias(const PseudoSourceValue *PSV1, const PseudoSourceValue *PSV2) {
  const bool DiffKinds = PSV1->kind() != PSV2.kind();

  const auto IsStack = [] (const PseudoSourceValue *PSV) -> bool {
      return PSV->isStack() || isa<FixedStackPseudoSourceValue>(PSV);
  };

  switch (PSV1->kind()) {
  case PseudoSourceValue::Stack:
    switch (PSV2->kind()) {
    case PseudoSourceValue::Stack:
      return true;
    case PseudoSourceValue::
    }
  }

  case PseudoSourceValue::FixedStack:

    case PseudoSourceValue::GOT:
      case PseudoSourceValue::JumpTable:
      case PseudoSourceValue::ConstantPool:
      case PseudoSourceValue::GlobalValueCallEntry:
      case PseudoSourceValue::ExternalSymbolCallEntry:
      case PseudoSourceValue::TargetCustom:
      return PSV1->kind() != PSV2->kind();

}
#endif

static bool mayAlias(const MachineMemOperand *MMO1, const MachineMemOperand *MMO2, const MachineFrameInfo *MFI) {
  assert(!MMO1->isVolatile() && !MMO2->isVolatile());

  // FIXME: Check if volatile?

  const auto IsConstantLoad = [MFI] (const MachineMemOperand *MMO) -> bool {
    if (MMO->isStore())
      return false;
    assert(MMO->isLoad());
    if (MMO->isInvariant())
      return true;
    if (const PseudoSourceValue *PSV = MMO->getPseudoValue();
        PSV && PSV->isConstant(MFI))
      return true;
    return false;
  };

  // If one of them is constant, no alias.
  if (IsConstantLoad(MMO1) || IsConstantLoad(MMO2))
    return false;

  // If both are LLVM-IR values, then always assume they may alias.
  if (MMO1->getValue() && MMO2->getValue())
    return true;

  // One of them is a pseudo-source value. Make that the first one.
  if (!MMO1->getPseudoValue())
    std::swap(MMO1, MMO2);
  assert(MMO1->getPseudoValue());

  // If the second MMO is a LLVM-IR value, then fall back to PSV's mayAlias.
  if (MMO2->getValue())
    return MMO1->getPseudoValue()->mayAlias(MFI);

  // Otherwise, we have two pseudo source values.
  // TODO: This is lazy.
  return true;
}

bool llvm::hasMemoryHazard(const MachineInstr &MI1, const MachineInstr &MI2) {
  // If either instruction is sensitive, then conservatively report memory hazard.
  if (isSensitiveInstr(MI1) || isSensitiveInstr(MI2))
    return true;

  // If neither is a memory instruction, then there's no memory hazard.
  if (!MI1.mayLoadOrStore() || !MI2.mayLoadOrStore())
    return false;

  // If both are just loads, then there's no memory hazard.
  if (!MI1.mayStore() && !MI2.mayStore())
    return false;

  // Let's compare their memory operands.
  assert(MI1.getNumMemOperands() > 0 &&
         MI2.getNumMemOperands() > 0);
  const MachineFrameInfo *MFI = &MI1.getParent()->getParent()->getFrameInfo();
  for (const MachineMemOperand *MMO1 : MI1.memoperands())
    for (const MachineMemOperand *MMO2 : MI2.memoperands())
      if (mayAlias(MMO1, MMO2, MFI))
        return true;

  return false;
}

static cl::opt<std::string> DebugMF {
    "x86-ptex-debug-mf",
    cl::desc("[PTeX] Debug MF"),
    cl::init(""),
    cl::Hidden,
};

bool llvm::debugMF(const MachineFunction &MF) {
  if (DebugMF.getValue().empty())
    return true;
  if (DebugMF.getValue() == MF.getName())
    return true;
  return false;
}
