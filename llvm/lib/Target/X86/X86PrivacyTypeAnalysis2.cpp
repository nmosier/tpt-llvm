#include "X86PrivacyTypeAnalysis.h"
#include "X86PrivacyTypeAnalysis2.h"

#include <array>

#include "X86.h"
#include "llvm/CodeGen/TargetSubtargetInfo.h"
#include "llvm/CodeGen/LivePhysRegs.h"
#include "llvm/IR/GlobalValue.h"
#include "llvm/IR/Function.h"
#include "llvm/CodeGen/TargetInstrInfo.h"
#include "X86RegisterInfo.h"
#include "X86Subtarget.h"

#define unimplemented() \
  do {                                                      \
    std::stringstream ss;                                   \
    ss << __FILE__ << ":" << __LINE__ << ": unimplemented"; \
    const std::string s = ss.str();                         \
    report_fatal_error(s.c_str());                          \
  } while (false)

#define DEBUG_TYPE "x86-ptex"

using namespace llvm;

namespace llvm {

namespace X86 {

// TODO: Should be able to remove NoRegister from this set.
static std::array<Register, 5> AlwaysPublicRegisters = {
  X86::NoRegister, X86::RSP, X86::RIP, X86::SSP, X86::MXCSR,
};

bool isRegAlwaysPublic(Register Reg, const TargetRegisterInfo &TRI) {
  if (Reg.isVirtual())
    return false;
  if (!Reg.isValid())
    return true;
  for (Register PubReg : AlwaysPublicRegisters)
    if (PubReg != X86::NoRegister && TRI.isSubRegisterEq(PubReg, Reg))
      return true;
  return false;
}

}

PublicPhysRegs::PublicPhysRegs(const PublicPhysRegs &Other) {
  TRI = Other.TRI;
  assert(TRI);
  LPR.init(*TRI);
  addRegs(Other);
}

PublicPhysRegs &PublicPhysRegs::operator=(const PublicPhysRegs &Other) {
  TRI = Other.TRI;
  assert(TRI);
  LPR.init(*TRI);
  clear();
  addRegs(Other);
  return *this;
}

void PublicPhysRegs::init(const TargetRegisterInfo *TRI) {
  this->TRI = TRI;
  LPR.init(*TRI);
}

bool PublicPhysRegs::intersect(const PublicPhysRegs &Other) {
  SmallVector<MCPhysReg> RemoveRegs;
  for (MCPhysReg MyPubReg : *this)
    if (!Other.isPublic(MyPubReg))
      RemoveRegs.push_back(MyPubReg);
  for (MCPhysReg Reg : RemoveRegs)
    LPR.removeReg(Reg); // TODO: Call PublicPhysReg's version if we add one.
  return !RemoveRegs.empty();
}

void PublicPhysRegs::stepForward(const MachineInstr &MI) {
  // First, add in any operands that are marked public.
  for (const MachineOperand &MO : MI.operands())
    if (MO.isReg() && MO.isUse() && MO.isPublic())
      addReg(MO.getReg());
  
  // Then, use LPR's stepForward to remove defs and clobbers.
  // However, this adds all (non-dead) defs to the set, which we don't want.
  // So we need to remove all non-public defs afterwards.
  SmallVector<std::pair<MCPhysReg, const MachineOperand *>> Clobbers;
  LPR.stepForward(MI, Clobbers);

  // Remove all non-public defs that LPR.stepForward() added.
  for (const MachineOperand &MO : MI.operands())
    if (MO.isReg() && MO.isDef() && !MO.isPublic())
      LPR.removeReg(MO.getReg()); // TODO: Use our version of removeReg if added.
}

void PublicPhysRegs::stepBackward(const MachineInstr &MI) {
  // First, add in any defs that are marked public.
  for (const MachineOperand &MO : MI.operands())
    if (MO.isReg() && MO.isDef() && MO.isPublic())
      addReg(MO.getReg());

  // Then, use LPR's stepBackwartd to remove defs and clobbers.
  // However, this adds all (non-undef'ed) uses to the set, which we don't want.
  // So we need to remove all non-public uses afterwards.
  LPR.stepBackward(MI);

  // Remove all non-public uses.
  for (const MachineOperand &MO : MI.operands())
    if (MO.isReg() && MO.isUse() && !MO.isPublic())
      LPR.removeReg(MO.getReg()); // TODO: Use our version of removeReg if added.
}

bool PublicPhysRegs::addReg(MCPhysReg PubReg) {
  if (LPR.contains(PubReg) || X86::isRegAlwaysPublic(PubReg, *TRI))
    return false;

  LPR.addReg(PubReg);
  return true;
}

bool PublicPhysRegs::addRegs(const PublicPhysRegs &From) {
  bool Changed = false;
  for (MCPhysReg PubReg : From)
    Changed |= addReg(PubReg);
  return Changed;
}

bool PublicPhysRegs::isPublic(MCPhysReg Reg) const {
  // First, check if this register is always public.
  if (X86::isRegAlwaysPublic(Reg, *TRI))
    return true;

  // Otherwise, check if the entire register is in the pub-reg set.
  // Note that this requires being conservative in the opposite direction
  // of LivePhysRegs::contains(), so we can't use that.
  for (MCPhysReg PubReg : *this)
    if (TRI->isSubRegisterEq(PubReg, Reg))
      return true;

  // Otherwise, it's private.
  return false;
}

static void markOpPublic(MachineOperand &MO) {
  if (MO.isReg() && !MO.isUndef())
    MO.setIsPublic();
}

static void markAllOpsPublic(MachineInstr &MI) {
  llvm::for_each(MI.operands(), markOpPublic);
}

namespace X86 {

void PrivacyTypeAnalysis::initTransmittedUses(MachineInstr &MI) {
  if (MI.isCall())
    markOpPublic(MI.getOperand(0));
  
  if (MI.isBranch())
    markAllOpsPublic(MI);

  const int MemIdx = X86::getMemRefBeginIdx(MI);
  if (MI.mayLoadOrStore() && MemIdx >= 0) {
    markOpPublic(MI.getOperand(MemIdx + X86::AddrBaseReg));
    markOpPublic(MI.getOperand(MemIdx + X86::AddrIndexReg));
  }
}

void PrivacyTypeAnalysis::initPointerLoadsOrStores(MachineInstr &MI) {
  for (MachineMemOperand *MMO : MI.memoperands())
    if (MMO->getType().isPointer())
      markAllOpsPublic(MI);
}

void PrivacyTypeAnalysis::initAlwaysPublicRegs(MachineInstr &MI) {
  const TargetRegisterInfo &TRI = *MI.getParent()->getParent()->getSubtarget().getRegisterInfo();
  for (MachineOperand &MO : MI.operands())
    if (MO.isReg() && isRegAlwaysPublic(MO.getReg(), TRI))
      MO.setIsPublic();  
}

void PrivacyTypeAnalysis::initFrameSetupAndDestroy(MachineInstr &MI) {
  if (MI.getFlag(MachineInstr::FrameSetup) ||
      MI.getFlag(MachineInstr::FrameDestroy))
    markAllOpsPublic(MI);
}

void PrivacyTypeAnalysis::initPointerCallArgs(MachineInstr &MI) {
  if (!MI.isCall())
    return;

  const auto &CSI = MF.getCallSitesInfo();
  const auto CSIIt = CSI.find(&MI);
  if (CSIIt == CSI.end()) {
    LLVM_DEBUG(dbgs() << "Call has no callsite info, skipping: " << MI);
    return;
  }

  const TargetInstrInfo *TII = MI.getParent()->getParent()->getSubtarget().getInstrInfo();
  const MachineOperand &CalleeMO = TII->getCalleeOperand(MI);
  if (!CalleeMO.isGlobal()) {
    LLVM_DEBUG(dbgs() << "Callee operand is not global, skipping: " << MI);
    return;
  }

  const Function *CalleeFunc = dyn_cast<Function>(CalleeMO.getGlobal());
  if (!CalleeFunc) {
    LLVM_DEBUG(dbgs() << "Skipping non-function callee: " << MI);
    return;
  }

  const auto &ArgRegPairs = CSIIt->second.ArgRegPairs;
  if (CalleeFunc->isVarArg()) {
    LLVM_DEBUG(dbgs() << "Skipping variadic function call: " << MI);
    return;
  }

  // Mark arguments public.
  for (const auto &Pair : ArgRegPairs) {
    const Argument *Arg = CalleeFunc->getArg(Pair.ArgNo);
    if (Arg->getType()->isPointerTy()) {
      MachineOperand *MO = MI.findRegisterUseOperand(Pair.Reg);
      assert(MO && "Call doesn't use argument!");
      assert(MO->getReg() == Pair.Reg && "Call argument register mismatch!");
      MO->setIsPublic();
    }
  }

  // Mark pointer-typed return values public.
  // Don't need to do anything fancy here because pointers will always be passed
  // in RAX.
  if (CalleeFunc->getReturnType()->isPointerTy())
    for (MachineOperand &MO : MI.operands())
      if (MO.isReg() && MO.isDef() && MO.isImplicit())
        MO.setIsPublic();
}

void PrivacyTypeAnalysis::initPointerTypes(MachineInstr &MI) {
  const MachineRegisterInfo &MRI = MF.getRegInfo();  
  for (MachineOperand &MO : MI.operands()) {
    // PTEX-FIXME: MI.mayLoadOrStore() is too aggressive.
    // We do care about stores that have a pointer operand.
    if (MO.isReg() && !MO.isImplicit() && MRI.getType(MO.getReg()).isPointer() &&
        (MO.isDef() || (MO.isUse() && !MI.mayLoadOrStore()))) {
      MO.setIsPublic();
      LLVM_DEBUG(dbgs() << "PTeX.LLT: marking instruction operand '" << MO << "' public: " << MI);
    }
  }
}

void PrivacyTypeAnalysis::initPointerReturnValue(MachineInstr &MI) {
  if (!MI.isReturn())
    return;

  if (!MF.getFunction().getReturnType()->isPointerTy())
    return;

  for (MachineOperand &MO : MI.operands())
    if (MO.isReg() && MO.isUse() && MO.isImplicit())
      MO.setIsPublic();
}

void PrivacyTypeAnalysis::init() {
  const TargetRegisterInfo *TRI = MF.getSubtarget().getRegisterInfo();
  
  // Initialize operand types.
  for (MachineBasicBlock &MBB : MF) {
    for (MachineInstr &MI : MBB) {
      initTransmittedUses(MI);
      initPointerLoadsOrStores(MI);      
      initAlwaysPublicRegs(MI);
      initFrameSetupAndDestroy(MI);
      initPointerCallArgs(MI);
      initPointerTypes(MI);
      initPointerReturnValue(MI);
    }
  }

  // Init pub-in and pub-out maps.
  for (MachineBasicBlock &MBB : MF) {
    In[&MBB].init(TRI);
    Out[&MBB].init(TRI);
  }
}

bool PrivacyTypeAnalysis::forward() {
  ForwardPrivacyTypeAnalysis Forward(MF, In, Out);
  return Forward.run();
}

bool PrivacyTypeAnalysis::backward() {
  BackwardPrivacyTypeAnalysis Backward(MF, In, Out);
  return Backward.run();
}

bool PrivacyTypeAnalysis::run() {
  init();

  bool Changed = false;
  bool FwdChange, BwdChange;
  do {
    FwdChange = forward();
    BwdChange = backward();
    Changed |= FwdChange || BwdChange;
  } while (FwdChange || BwdChange);

  return Changed;
}

void ForwardPrivacyTypeAnalysis::init() {
  const TargetRegisterInfo *TRI = MF.getSubtarget().getRegisterInfo();

  for (MachineBasicBlock &MBB : MF) {
    // Allocate pub-ins and pub-outs.
    In[&MBB].init(TRI);
    Out[&MBB].init(TRI);

    // Optimistically initialize the pub-ins and pub-outs to the live-ins and live-outs
    // of all other blocks.
    In[&MBB].addLiveIns(MBB);
    Out[&MBB].addLiveOuts(MBB);

    // Conservatively initialize the pub-ins of entry blocks to the parent analysis' pub-ins. We conservatively consider entry
    // blocks to be anything without a predecessor.
    if (MBB.pred_empty())
      In[&MBB] = ParentIn[&MBB];
  }
}

bool ForwardPrivacyTypeAnalysis::block(MachineBasicBlock &MBB) {
  bool Changed = false;
  
  // Meet block pub-ins. This means intersecting In[MBB] with In[PredMBB] for each predecessor PredMBB.
  // Note that this is safe to apply to all blocks, including entry blocks, because entries have no predecessors.
  // Thus, the pub-ins of entries will not change.
  for (MachineBasicBlock *PredMBB : MBB.predecessors())
    Changed |= In[&MBB].intersect(Out[PredMBB]);

  // Now, transfer across the block.
  PublicPhysRegs PubRegs = In[&MBB];
  for (MachineInstr &MI : MBB)
    Changed |= instruction(MI, PubRegs);

  // Finally, update the pub-outs. We intersect them here as to avoid
  // marking extra stuff public (e.g., registers that aren't live-out).
  Changed |= Out[&MBB].intersect(PubRegs);
  
  return Changed;
}

bool ForwardPrivacyTypeAnalysis::dataUsesPublic(const MachineInstr &MI, const PublicPhysRegs &PubRegs) const {
  if (MI.mayLoad())
    return false;

  for (const MachineOperand &MO : MI.operands())
    if (MO.isReg() && MO.isUse()  && !MO.isUndef() && !PubRegs.isPublic(MO.getReg()))
      return false;

  return true;
}

bool ForwardPrivacyTypeAnalysis::instruction(MachineInstr &MI, PublicPhysRegs &PubRegs) {
  bool Changed = false;

  // To start, if any (non-undef'ed) uses are public, then mark the operand public.
  for (MachineOperand &MO : MI.operands()) {
    if (MO.isReg() && MO.isUse() && !MO.isUndef() && PubRegs.isPublic(MO.getReg()) && !MO.isPublic()) {
      MO.setIsPublic();
      Changed = true;
    }
  }

  // Step forward.
  // TODO: Don't think we need PubRegs here. We can just look at the operands.
  const bool DefsPublic = dataUsesPublic(MI, PubRegs) && !MI.isCall();
  PubRegs.stepForward(MI); // NOTE: This doesn't know about DefsPublic; need to manually add them.

  // Mark defs public.
  if (DefsPublic) {
    for (MachineOperand &MO : MI.operands()) {
      if (MO.isReg() && MO.isDef() && !MO.isUndef() && !MO.isPublic()) {
        PubRegs.addReg(MO.getReg());
        MO.setIsPublic();
        Changed = true;
      }
    }
  }

  ParentChanged |= Changed;

  return Changed;
}

// TODO: Can factor out most of this code.
void BackwardPrivacyTypeAnalysis::init() {
  const TargetRegisterInfo *TRI = MF.getSubtarget().getRegisterInfo();

  for (MachineBasicBlock &MBB : MF) {
    // Allocate pub-ins and pub-outs.
    In[&MBB].init(TRI);
    Out[&MBB].init(TRI);

    // Optimistically initialize the pub-ins and pub-outs to the live-ins and live-outs
    // of all other blocks.
    In[&MBB].addLiveIns(MBB);
    Out[&MBB].addLiveOuts(MBB);

    // Conservatively initialize the pub-outs of exit blocks to the parent analysis' pub-outs.
    // We consider anything without a successor to be an exit block.
    if (MBB.succ_empty())
      Out[&MBB] = ParentOut[&MBB];
  }
}

bool BackwardPrivacyTypeAnalysis::block(MachineBasicBlock &MBB) {
  bool Changed = false;

  // Meet block pub-out with successor block pub-ins.
  for (MachineBasicBlock *SuccMBB : MBB.successors())
    Changed |= Out[&MBB].intersect(In[SuccMBB]);

  // Now, transfer across the block, *in reverse order*.
  PublicPhysRegs PubRegs = Out[&MBB];
  for (MachineInstr &MI : llvm::reverse(MBB))
    Changed |= instruction(MI, PubRegs);

  // Finally, update the pub-ins.
  Changed |= In[&MBB].intersect(PubRegs);

  return Changed;
}

// Returns true if any of the instruction data operands are public.
bool BackwardPrivacyTypeAnalysis::dataDefsPublic(const MachineInstr &MI) const {
  for (const MachineOperand &MO : MI.operands())
    if (MO.isReg() && MO.isDef() && MO.isPublic() && !(MO.isImplicit() && registerIsAlwaysPublic(MO.getReg())))
      return true;
  return false;
}

bool BackwardPrivacyTypeAnalysis::instruction(MachineInstr &MI, PublicPhysRegs &PubRegs) {
  bool Changed = false;

  // To start, if any defs are public, then mark the operand public.
  for (MachineOperand &MO : MI.operands()) {
    if (MO.isReg() && MO.isDef() && !MO.isUndef() && PubRegs.isPublic(MO.getReg()) && !MO.isPublic()) {
      MO.setIsPublic();
      Changed = true;
    }
  }

  // Step backward.
  const bool MarkUsesPublic = dataDefsPublic(MI) && !MI.isCall();
  PubRegs.stepBackward(MI);

  // Mark uses public.
  if (MarkUsesPublic) {
    for (MachineOperand &MO : MI.operands()) {
      if (MO.isReg() && MO.isDef() && !MO.isUndef() && !MO.isPublic()) {
        PubRegs.addReg(MO.getReg());
        MO.setIsPublic();
        Changed = true;
      }
    }
  }

  ParentChanged |= Changed;

  return Changed;
}

void DirectionalPrivacyTypeAnalysis::mergeIntoParent() {
  for (MachineBasicBlock &MBB : MF) {
    ParentChanged |= ParentIn[&MBB].addRegs(In[&MBB]);
    ParentChanged |= ParentOut[&MBB].addRegs(Out[&MBB]);
  }
}

bool DirectionalPrivacyTypeAnalysis::run() {
  init();

  bool IterChanged;
  unsigned IterCount = 0;
  do {
    IterChanged = false;
    for (MachineBasicBlock &MBB : MF)
      IterChanged |= block(MBB);
    ++IterCount;
  } while (IterChanged);

  LLVM_DEBUG(dbgs() << "forward iterations: " << IterCount << "\n");

  // Copy newly pub-in/pub-out regs to the parent's pub-ins/pub-outs.
  mergeIntoParent();

  return ParentChanged;
}

void PrivacyTypeAnalysis::print(raw_ostream &os) const {
  os << "===== Privacy Types for Function \"" << MF.getName() << "\" =====\n\n";

  auto PrintBlockNames = [&] (const auto &range) {
    for (auto it = range.begin(); it != range.end(); ++it) {
      if (it != range.begin())
        os << " ";
      (*it)->printName(os);
    }
  };

  for (MachineBasicBlock &MBB : MF) {
    MBB.printName(os);
    os << ":\n";
    os << "    // preds: ";
    PrintBlockNames(MBB.predecessors());
    os << "\n";
    os << "    // succs: ";
    PrintBlockNames(MBB.successors());
    os << "\n";
    os << "    // pub-in: " << In.at(&MBB);
    PublicPhysRegs PubRegs = In.at(&MBB);
    for (MachineInstr &MI : MBB) {
      os << "    // public: " << PubRegs;
      os << "    " << MI;
      PubRegs.stepForward(MI);
    }
    os << "    // public: " << PubRegs;
    os << "    // pub-out: " << Out.at(&MBB);
  }
}

}

}
