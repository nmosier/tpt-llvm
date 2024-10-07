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
#include "llvm/CodeGen/MachineFrameInfo.h"

#define unimplemented() \
  do {                                                      \
    std::stringstream ss;                                   \
    ss << __FILE__ << ":" << __LINE__ << ": unimplemented"; \
    const std::string s = ss.str();                         \
    report_fatal_error(s.c_str());                          \
  } while (false)

#define PASS_KEY "x86-ptex"
#define DEBUG_TYPE PASS_KEY

using namespace llvm;

static cl::opt<bool> EnableStackPrivacyAnalysis {
  PASS_KEY "-stack",
  cl::desc("[PTeX] Enable stack privacy analysis"),
  cl::init(true),
  cl::Hidden,
};

static cl::opt<bool> FullDefDeclassification {
  PASS_KEY "-defs",
  cl::desc("[PTeX] Mark def'ed registers public if any subregister is marked public"),
  cl::init(true),
  cl::Hidden,
};

namespace llvm {

namespace X86 {

// TODO: Should be able to remove NoRegister from this set.
static std::array<Register, 5> AlwaysPublicRegisters = {
  X86::NoRegister, X86::RSP, X86::RIP, X86::SSP, X86::MXCSR,
};

bool regAlwaysPublic(Register Reg, const TargetRegisterInfo &TRI) {
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

bool setInstrPublic(MachineInstr &MI) {
  bool Changed = false;

  // Mark instruction itself as public.
  if (!MI.getFlag(MachineInstr::TPEPubM)) {
    MI.setFlag(MachineInstr::TPEPubM);
    Changed = true;
  }

  // Mark each register operand as public.
  for (MachineOperand &MO : MI.operands()) {
    if (MO.isReg() && !MO.isUndef() && !MO.isPublic()) {
      MO.setIsPublic();
      Changed = true;
    }
  }

  if (Changed)
    LLVM_DEBUG(dbgs() << "set instr public: " << MI);

  return Changed;
}

namespace X86 {

template <class Base>
bool DirectionalPrivacyTypeAnalysis<Base>::setInstrPublic(MachineInstr &MI) const {
  const bool Changed = llvm::setInstrPublic(MI);
  if (Changed)
    LLVM_DEBUG(dbgs() << getName() << " set instr public: " << MI);
  return Changed;
}

}

[[nodiscard]] static bool syncOperands(PublicPhysRegs &PubRegs, MachineInstr &MI, auto Pred) {
  // TODO: Experiment with also marking changed if we add a new register to PubRegs.
  bool Changed = false;
  for (MachineOperand &MO : MI.operands()) {
    if (MO.isReg() && !MO.isUndef() && Pred(MO)) {
      const bool PubMO = MO.isPublic();
      const bool PubReg = PubRegs.isPublic(MO.getReg());
      if (PubMO && !PubReg) {
        PubRegs.addReg(MO.getReg());
      } else if (!PubMO && PubReg) {
        MO.setIsPublic();
        Changed = true;
      }
    }
  }
  return Changed;
}

[[nodiscard]] static bool syncUses(PublicPhysRegs &PubRegs, MachineInstr &MI) {
  return syncOperands(PubRegs, MI, std::mem_fn(&MachineOperand::isUse));
}

[[nodiscard]] static bool syncDefs(PublicPhysRegs &PubRegs, MachineInstr &MI) {
  return syncOperands(PubRegs, MI, std::mem_fn(&MachineOperand::isDef));
}

PublicPhysRegs::PublicPhysRegs(const PublicPhysRegs &Other) {
  TRI = Other.TRI;
  assert(TRI);
  LPR.init(*TRI);
  addRegs(Other);
}

void PublicPhysRegs::dump() const {
  print(errs());
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

void PublicPhysRegs::addPublicUses(const MachineInstr &MI) {
  for (const MachineOperand &MO : MI.operands())
    if (MO.isReg() && MO.isUse() && MO.isPublic())
      addReg(MO.getReg());
}

void PublicPhysRegs::stepForward(const MachineInstr &MI) {
  // First, add in any operands that are marked public.
  addPublicUses(MI);

  // Then update defs.
  updateDefs(MI);
}

void PublicPhysRegs::stepBackward(const MachineInstr &MI) {
  // Remove defined registers and regmask kills from the set.
  removeAllDefs(MI);

  // Add any public uses.
  addPublicUses(MI);
}

void PublicPhysRegs::removeAllDefs(const MachineInstr &MI) {
  LPR.removeDefs(MI);
}

void PublicPhysRegs::updateDefs(const MachineInstr &MI) {
  // First, remove all defs.
  LPR.removeDefs(MI);

  // Add back in any public defs.
  for (const MachineOperand &MO : MI.operands())
    if (MO.isReg() && MO.isDef() && MO.isPublic())
      addReg(MO.getReg());
}

bool PublicPhysRegs::addReg(MCPhysReg PubReg) {
  if (LPR.contains(PubReg) || X86::regAlwaysPublic(PubReg, *TRI))
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
  if (X86::regAlwaysPublic(Reg, *TRI))
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

void impl::addRegToCover(MCPhysReg OurReg, SmallVectorImpl<MCPhysReg> &TheirRegs,
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
    if (MO.isReg() && regAlwaysPublic(MO.getReg(), TRI))
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
      assert(MO->isUse());
      if (!MO->isUndef())
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
    if (MO.isReg() && MO.isUse() && !MO.isUndef())
      MO.setIsPublic();
}

void PrivacyTypeAnalysis::initPublicInstr(MachineInstr &MI) {
  if (MI.getFlag(MachineInstr::TPEPubM))
    for (MachineOperand &MO : MI.operands())
      if (MO.isReg() && !MO.isUndef())
        MO.setIsPublic();
}

void PrivacyTypeAnalysis::initGOTLoads(MachineInstr &MI) {
  if (!MI.mayLoad())
    return;

  // Are any operands x86-gotpcrel GlobalAddresses?
  const bool HasGotpcrelMO = llvm::any_of(MI.operands(), [] (const MachineOperand &MO) {
    return MO.getTargetFlags() == X86II::MO_GOTPCREL;
  });
  if (!HasGotpcrelMO)
    return;

  // Yes. Such accesses always return pointers.
  setInstrPublic(MI);
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
      initPublicInstr(MI);
      initGOTLoads(MI);
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

bool PrivacyTypeAnalysis::stack() {
  StackPrivacyAnalysis Stack(MF);
  return Stack.run();
}

bool PrivacyTypeAnalysis::run() {
  init();

  bool OverallChanged = false;
  bool IterChanged;
  do {
    IterChanged = false;

    IterChanged |= forward();
    IterChanged |= backward();
    if (EnableStackPrivacyAnalysis)
      IterChanged |= stack();

    OverallChanged |= IterChanged;
  } while (IterChanged);

  return OverallChanged;
}

void ForwardPrivacyTypeAnalysis::init() {
  const TargetRegisterInfo *TRI = MF.getSubtarget().getRegisterInfo();

  for (MachineBasicBlock &MBB : MF) {
    // Allocate pub-ins and pub-outs.
    In[&MBB].init(TRI);
    Out[&MBB].init(TRI);

    // Optimistically initialize the pub-ins and pub-outs to the live-ins and live-outs
    // of all other blocks.
    // TODO: Need to change this.
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
    if (MO.isReg() && MO.isUse()  && !MO.isUndef() && !MO.isPublic() && !PubRegs.isPublic(MO.getReg()))
      return false;

  return true;
}

bool ForwardPrivacyTypeAnalysis::instruction(MachineInstr &MI, PublicPhysRegs &PubRegs) {
  bool Changed = false;

  // Sync PubRegs -> MO uses.
  Changed |= syncUses(PubRegs, MI);

  // Check if data inputs are public.
  // If so, mark instruction public.
  if (dataUsesPublic(MI, PubRegs) && !MI.isCall())
    Changed |= setInstrPublic(MI);

  // Step forward.
  PubRegs.stepForward(MI);

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
  const TargetRegisterInfo *TRI = MI.getParent()->getParent()->getSubtarget().getRegisterInfo();
  for (const MachineOperand &MO : MI.operands())
    if (MO.isReg() && MO.isDef() && MO.isPublic() && !(MO.isImplicit() && regAlwaysPublic(MO.getReg(), *TRI)))
      return true;
  return false;
}

bool BackwardPrivacyTypeAnalysis::instruction(MachineInstr &MI, PublicPhysRegs &PubRegs) {
  bool Changed = false;
  const TargetRegisterInfo *TRI = MI.getParent()->getParent()->getSubtarget().getRegisterInfo();

  if (FullDefDeclassification) {
    for (MachineOperand &MO : MI.operands()) {
      if (MO.isReg() && MO.isDef() && !MO.isUndef() && !MO.isPublic()) {
        // Is a subregister public?
        const bool SubregPublic = llvm::any_of(TRI->subregs(MO.getReg()), [&] (MCPhysReg SubReg) -> bool {
          return PubRegs.isPublic(SubReg);
        });
        if (SubregPublic) {
          MO.setIsPublic();
          Changed = true;
        }
      }
    }
  }

  // Sync PubRegs -> MO defs.
  Changed |= syncDefs(PubRegs, MI);

  // If the data defs are public, then mark the instruction public.
  if (dataDefsPublic(MI) && !MI.isCall())
    Changed |= setInstrPublic(MI);

  // Step backward.
  PubRegs.stepBackward(MI);

  // Sync PubRegs -> MO uses.
  Changed |= syncUses(PubRegs, MI);

  ParentChanged |= Changed;
  return Changed;
}

template <class Base>
void DirectionalPrivacyTypeAnalysis<Base>::mergeIntoParent() {
  for (MachineBasicBlock &MBB : MF) {
    ParentChanged |= ParentIn[&MBB].addRegs(In[&MBB]);
    ParentChanged |= ParentOut[&MBB].addRegs(Out[&MBB]);
  }
}

template <class Base>
bool DirectionalPrivacyTypeAnalysis<Base>::run() {
  init();

  bool IterChanged;
  unsigned IterCount = 0;
  do {
    IterChanged = false;
    for (MachineBasicBlock *MBB : base()->blocks())
      IterChanged |= block(*MBB);
    ++IterCount;
  } while (IterChanged);

  LLVM_DEBUG(dbgs() << getName() << " iterations: " << IterCount << "\n");

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

bool StackPrivacyAnalysis::run() {
  const MachineFrameInfo &MFI = MF.getFrameInfo();
  const TargetInstrInfo *TII = MF.getSubtarget().getInstrInfo();

  // First, create a map from spill slots to stack spill/restore instructions.
  struct SpillSlotInfo {
    SmallVector<MachineInstr *> Stores;
    SmallVector<MachineInstr *> Loads;
  };
  std::map<int, SpillSlotInfo> SpillSlotInfos;
  for (MachineBasicBlock &MBB : MF) {
    for (MachineInstr &MI : MBB) {
      int FrameIndex;
      if (TII->isStoreToStackSlot(MI, FrameIndex)) {
        SpillSlotInfos[FrameIndex].Stores.push_back(&MI);
      } else if (TII->isLoadFromStackSlot(MI, FrameIndex)) {
        SpillSlotInfos[FrameIndex].Loads.push_back(&MI);
      }
    }
  }

  // Then, process loads/stores from each spill slot.
  bool Changed = false;
  for (const auto &[FrameIndex, SpillInfo] : SpillSlotInfos)
    if (MFI.isSpillSlotObjectIndex(FrameIndex))
      Changed |= spillSlot(FrameIndex, SpillInfo.Stores, SpillInfo.Loads);

  return Changed;
}

bool StackPrivacyAnalysis::spillSlot(int SpillSlot, ArrayRef<MachineInstr *> Stores, ArrayRef<MachineInstr *> Loads) {
  bool Changed = false;

  // TODO: 'undef' doesn't always mean the instruction operands independently of it.
  // It can also mean that the register has a poison value.
  bool AllStoresPublic = true;
  for (const MachineInstr *MI : Stores)
    for (const MachineOperand &MO : MI->operands())
      if (MO.isReg() && MO.isUse() && !MO.isUndef())
        AllStoresPublic &= MO.isPublic();

  // Forward Analysis: Are all stores public? If so, mark all loads public.
  if (AllStoresPublic)
    for (MachineInstr *MI : Loads)
      Changed |= setInstrPublic(*MI);

  // Backward analysis is harder, since we need to be conservative.
  // It's not as simple as marking all stores public if all loads are public.

  return Changed;
}

}

}
