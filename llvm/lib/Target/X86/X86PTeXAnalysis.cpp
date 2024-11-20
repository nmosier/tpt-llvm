#include "X86PrivacyTypeAnalysis.h"
#include "X86PTeXAnalysis.h"

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
#include "X86PublicPhysRegs.h"

using llvm::X86::PublicPhysRegs;

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

enum Mode {
  CTS,
  CT,
  CTDecl,
  NST,
};

static cl::opt<Mode> AnalysisType {
  PASS_KEY "-type",
  cl::desc("PTeX analysis type"),
  cl::init(CT),
  cl::values(
      clEnumValN(CTS, "cts", "Static constant-time protection types"),
      clEnumValN(CT, "ct", "Constant-time protection types"),
      clEnumValN(CTDecl, "ctdecl", "Constant-time w/ declassification protection types"),
      clEnumValN(NST, "nst", "Non-secret-transmitting code")),
};

namespace llvm {

static bool fullDefDeclassification() {
  return AnalysisType != NST;
}

void print(raw_ostream &os, const auto &In, const auto &Out, MachineFunction &MF, bool Small = false) {
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
      if (!Small)
        os << "    // public: " << PubRegs;
      os << "    " << MI;
      PubRegs.stepForward(MI);
    }
    if (!Small)
      os << "    // public: " << PubRegs;
    os << "    // pub-out: " << Out.at(&MBB);
    os << "\n";
  }
}


bool setInstrPublic(MachineInstr &MI, StringRef reason) {
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
    LLVM_DEBUG(dbgs() << reason << ": set instr public: " << MI);

  return Changed;
}

namespace X86 {

template <class Base>
bool DirectionalPrivacyTypeAnalysis<Base>::setInstrPublic(MachineInstr &MI) const {
  return llvm::setInstrPublic(MI, getName());
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

void PTeXAnalysis::initTransmittedUses(MachineInstr &MI) {
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

void PTeXAnalysis::initPointerLoadsOrStores(MachineInstr &MI) {
  for (MachineMemOperand *MMO : MI.memoperands())
    if (MMO->getType().isPointer())
      markAllOpsPublic(MI);
}

void PTeXAnalysis::initMachineMemOperands(MachineInstr &MI) {
  for (MachineMemOperand *MMO : MI.memoperands()) {
    if (MMO->getType().isPointer()) {
      // If it's pointer-typed, unprotect it.
      markAllOpsPublic(MI);
      LLVM_DEBUG(dbgs() << __func__ << ": marking public due to MMO pointer type: " << MI);
    } else if (const PseudoSourceValue *Ptr = MMO->getPseudoValue()) {
      switch (Ptr->kind()) {
      case PseudoSourceValue::GOT:
      case PseudoSourceValue::JumpTable:
      case PseudoSourceValue::ConstantPool:
      case PseudoSourceValue::GlobalValueCallEntry:
      case PseudoSourceValue::ExternalSymbolCallEntry:
        markAllOpsPublic(MI);
        LLVM_DEBUG(dbgs() << __func__ << ": marking public due to PSV: " << MI);
        break;
      }
    }
  }
}

void PTeXAnalysis::initAlwaysPublicRegs(MachineInstr &MI) {
  const TargetRegisterInfo &TRI = *MI.getParent()->getParent()->getSubtarget().getRegisterInfo();
  for (MachineOperand &MO : MI.operands())
    if (MO.isReg() && regAlwaysPublic(MO.getReg(), TRI))
      MO.setIsPublic();  
}

void PTeXAnalysis::initFrameSetupAndDestroy(MachineInstr &MI) {
  if (MI.getFlag(MachineInstr::FrameSetup) ||
      MI.getFlag(MachineInstr::FrameDestroy))
    markAllOpsPublic(MI);
}

void PTeXAnalysis::initPointerCallArgs(MachineInstr &MI) {
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
    MachineOperand *MO = MI.findRegisterUseOperand(Pair.Reg);

    const auto Log = [&] (StringRef msg) {
      LLVM_DEBUG(dbgs() << __func__ << ": " << msg << ": " << *Arg << " :: " << *MO << " :: " << MI);
    };
    
    if (!Arg->getType()->isPointerTy()) {
      Log("not marking non-pointer call argument public");
      continue;
    }

    assert(MO && "Call doesn't use argument!");
    assert(MO->getReg() == Pair.Reg && "Call argument register mismatch!");
    assert(MO->isUse());

    if (MO->isUndef()) {
      Log("not marking undef call argument public");
      continue;
    }

    Log("marking pointer call argument public");
    MO->setIsPublic();
  }

  // Mark pointer-typed return values public.
  // Don't need to do anything fancy here because pointers will always be passed
  // in RAX.
  if (CalleeFunc->getReturnType()->isPointerTy())
    for (MachineOperand &MO : MI.operands())
      if (MO.isReg() && MO.isDef() && MO.isImplicit())
        MO.setIsPublic();
}

void PTeXAnalysis::initPointerTypes(MachineInstr &MI) {
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

void PTeXAnalysis::initPointerReturnValue(MachineInstr &MI) {
  if (!MI.isReturn())
    return;

  if (!MF.getFunction().getReturnType()->isPointerTy())
    return;

  for (MachineOperand &MO : MI.operands())
    if (MO.isReg() && MO.isUse() && !MO.isUndef())
      MO.setIsPublic();
}

void PTeXAnalysis::initPublicInstr(MachineInstr &MI) {
  if (MI.getFlag(MachineInstr::TPEPubM))
    for (MachineOperand &MO : MI.operands())
      if (MO.isReg() && !MO.isUndef())
        MO.setIsPublic();
}

void PTeXAnalysis::initGOTLoads(MachineInstr &MI) {
  if (!MI.mayLoad())
    return;

  // Are any operands x86-gotpcrel GlobalAddresses?
  const bool HasGotpcrelMO = llvm::any_of(MI.operands(), [] (const MachineOperand &MO) {
    return MO.getTargetFlags() == X86II::MO_GOTPCREL;
  });
  if (!HasGotpcrelMO)
    return;

  // Yes. Such accesses always return pointers.
  setInstrPublic(MI, __func__);
}

void PTeXAnalysis::init() {
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
      initMachineMemOperands(MI);
    }
  }

  // Init pub-in and pub-out maps.
  for (MachineBasicBlock &MBB : MF) {
    In[&MBB].init(TRI);
    Out[&MBB].init(TRI);
  }

  // Init entry blocks pub-ins to include all callee-saved registers.
  const MCPhysReg *CSRs = TRI->getCalleeSavedRegs(&MF);
  assert(*CSRs);
  for (const MCPhysReg *CSRIt = CSRs; *CSRIt; ++CSRIt)
    In[&MF.front()].addReg(*CSRIt);
}

bool PTeXAnalysis::forward() {
  ForwardPrivacyTypeAnalysis Forward(MF, In, Out);
  return Forward.run();
}

bool PTeXAnalysis::backward() {
  BackwardPrivacyTypeAnalysis Backward(MF, In, Out);
  return Backward.run();
}

bool PTeXAnalysis::stack() {
  StackPrivacyAnalysis Stack(MF);
  return Stack.run();
}

bool PTeXAnalysis::run() {
  init();

  LLVM_DEBUG(dbgs() << "==== init ====\n");
  LLVM_DEBUG(print(dbgs(), /*Small*/true));
    
  bool OverallChanged = false;
  bool IterChanged;
  do {
    IterChanged = false;
    IterChanged |= forward();

    LLVM_DEBUG(dbgs() << "==== fwd ====\n");
    LLVM_DEBUG(print(dbgs(), /*Small*/true));
    
    IterChanged |= backward();

    LLVM_DEBUG(dbgs() << "==== bwd ====\n");
    LLVM_DEBUG(print(dbgs(), /*Small*/true));    
    
    if (EnableStackPrivacyAnalysis)
      IterChanged |= stack();

    OverallChanged |= IterChanged;

    LLVM_DEBUG(print(dbgs(), /*Small*/true));
  } while (IterChanged);

  LLVM_DEBUG(print(dbgs()));

  return OverallChanged;
}

template <class Base>
PublicPhysRegs DirectionalPrivacyTypeAnalysis<Base>::computeTop() const {
  PublicPhysRegs top(MF.getSubtarget().getRegisterInfo());

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
  

void ForwardPrivacyTypeAnalysis::init() {
  const TargetRegisterInfo *TRI = MF.getSubtarget().getRegisterInfo();
  const PublicPhysRegs top = computeTop();

  for (MachineBasicBlock &MBB : MF) {
    In[&MBB] = top;
    Out[&MBB] = top;

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

static void getExitReachingBlocks(MachineFunction &MF, std::unordered_set<MachineBasicBlock *> &ExitReachingBlocks) {
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

// TODO: Can factor out most of this code.
void BackwardPrivacyTypeAnalysis::init() {
  const TargetRegisterInfo *TRI = MF.getSubtarget().getRegisterInfo();
  const PublicPhysRegs bot(TRI);
  const PublicPhysRegs top = computeTop();

  // Compute which blocks are reachable by exits using a mini data-flow pass.
  std::unordered_set<MachineBasicBlock *> ExitReachingBlocks;
  getExitReachingBlocks(MF, ExitReachingBlocks);

  for (MachineBasicBlock &MBB : MF) {
    if (AnalysisType == CTS) {
      In[&MBB] = bot;
    } else {
      In[&MBB] = top;
    }

    // Conservatively initialize the pub-outs of exit blocks to the parent analysis' pub-outs.
    // We consider anything without a successor to be an exit block.
    if (MBB.succ_empty()) {
      Out[&MBB] = ParentOut[&MBB];
    } else if (AnalysisType == CTS || !ExitReachingBlocks.count(&MBB)) {
      Out[&MBB] = bot;
    } else {
      Out[&MBB] = top;
    }
  }
}

bool BackwardPrivacyTypeAnalysis::block(MachineBasicBlock &MBB) {
  bool Changed = false;

  // Meet block pub-out with successor block pub-ins.
  for (MachineBasicBlock *SuccMBB : MBB.successors()) {
    if (AnalysisType == CTS) {
      Changed |= Out[&MBB].addRegs(In[SuccMBB]);
    } else {
      Changed |= Out[&MBB].intersect(In[SuccMBB]);
    }
  }

  // Now, transfer across the block, *in reverse order*.
  PublicPhysRegs PubRegs = Out[&MBB];
  for (MachineInstr &MI : llvm::reverse(MBB))
    Changed |= instruction(MI, PubRegs);

  // Finally, update the pub-ins.
  if (AnalysisType == CTS) {
    Changed |= In[&MBB].addRegs(PubRegs);
  } else {
    Changed |= In[&MBB].intersect(PubRegs);
  }

  return Changed;
}

static bool backpropSafeForInst_CTDecl(const MachineInstr &MI) {
  const TargetInstrInfo *TII = MI.getParent()->getParent()->getSubtarget().getInstrInfo();
  
  // Special cases: MOVSX, MOVZX
  const StringRef OpName = TII->getName(MI.getOpcode());
  if (OpName.starts_with("MOV"))
    return true;
  
  const unsigned NumProtectedUses = llvm::count_if(MI.operands(), [] (const MachineOperand &MO) -> bool {
    return MO.isReg() && MO.isUse() && !MO.isPublic();
  });

  if (MI.mayLoad()) {
    // If this is a memory intruction, then allow no protected inputs.
    if (NumProtectedUses != 0)
      return false;
  } else {
    // If this is a non-memory instruction, then allow exactly one
    // protected input.
    if (NumProtectedUses != 1)
      return false;
  }

  switch (MI.getOpcode()) {
#define MAKE_CASE(name) case X86::name:
#define STD_ARITH(base, X)                      \
    X(base##8rr)                                \
        X(base##8ri)                            \
        X(base##8rm)                            \
        X(base##8mr)                            \
        X(base##8mi)                            \
        X(base##16rr)                           \
        X(base##16rm)                           \
        X(base##16mr)                           \
        X(base##16ri8)                          \
        X(base##16ri)                           \
        X(base##16mi8)                          \
        X(base##16mi)                           \
        X(base##32rr)                           \
        X(base##32rm)                           \
        X(base##32mr)                           \
        X(base##32ri8)                          \
        X(base##32ri)                           \
        X(base##32mi8)                          \
        X(base##32mi)                           \
        X(base##64rr)                           \
        X(base##64rm)                           \
        X(base##64mr)                           \
        X(base##64ri8)                          \
        X(base##64ri32)                         \
        X(base##64mi8)                          \
        X(base##64mi32)

#define STD_UNOP_SZ(base, size, X)              \
    X(base##size##r)                            \
        X(base##size##m)
    
#define STD_UNOP(base, X)                        \
    STD_UNOP_SZ(base, 8, X)                      \
        STD_UNOP_SZ(base, 16, X)                 \
        STD_UNOP_SZ(base, 32, X)                 \
        STD_UNOP_SZ(base, 64, X)
        
  case X86::MOV64rm:
  case X86::MOV64rr:
  case X86::COPY:
  case X86::LEA64r:
  case X86::LEA32r:
  case X86::LEA16r:
    STD_ARITH(ADD, MAKE_CASE)
        STD_ARITH(SUB, MAKE_CASE)
        STD_ARITH(XOR, MAKE_CASE)
        STD_UNOP(NEG, MAKE_CASE)
        STD_UNOP(NOT, MAKE_CASE)
        STD_UNOP(INC, MAKE_CASE)
        STD_UNOP(DEC, MAKE_CASE)

        LLVM_DEBUG(dbgs() << "backpropagation safe for instruction: " << MI);
        return true;
  default:
    return false;
  }
}

static bool backpropSafeForInst_NST(const MachineInstr &MI) {
  const TargetInstrInfo *TII = MI.getParent()->getParent()->getSubtarget().getInstrInfo();
  const bool IsCopy = TII->isFullCopyInstr(MI);
  if (IsCopy)
    LLVM_DEBUG(dbgs() << "NST-copy: " << MI);
  return IsCopy;
}

static bool backpropSafeForInst(const MachineInstr &MI) {
  switch (AnalysisType) {
  case CTDecl:
    return backpropSafeForInst_CTDecl(MI);

  case NST:
    return backpropSafeForInst_NST(MI);

  case CT:
  case CTS:
    return true;

  default:
    report_fatal_error("unhandled analysis type in backpropSafeForInst");
  }
}

// Returns true if any of the instruction data operands are public.
bool BackwardPrivacyTypeAnalysis::dataDefsPublic(const MachineInstr &MI) const {
  if (!backpropSafeForInst(MI))
    return false;

  const TargetRegisterInfo *TRI = MI.getParent()->getParent()->getSubtarget().getRegisterInfo();
  for (const MachineOperand &MO : MI.operands())
    if (MO.isReg() && MO.isDef() && MO.isPublic() && !(MO.isImplicit() && regAlwaysPublic(MO.getReg(), *TRI)))
      return true;
  return false;
}

bool BackwardPrivacyTypeAnalysis::instruction(MachineInstr &MI, PublicPhysRegs &PubRegs) {
  bool Changed = false;
  const TargetRegisterInfo *TRI = MI.getParent()->getParent()->getSubtarget().getRegisterInfo();

  if (fullDefDeclassification()) {
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
  if (dataDefsPublic(MI) && !MI.isCall()) {
    Changed |= setInstrPublic(MI);
  } else {
    LLVM_DEBUG(dbgs() << "fwd-instr: can't backpropate for instr: " << MI);
  }

  // If an explicit output is public, then mark implicit outputs public.
  if (!MI.isCall() && llvm::any_of(MI.operands(), [] (const MachineOperand &MO) -> bool {
    return MO.isReg() && MO.isDef() && !MO.isImplicit() && MO.isPublic();
  })) {
    for (MachineOperand &MO : MI.operands()) {
      if (MO.isReg() && MO.isDef() && MO.isImplicit() && !MO.isPublic()) {
        MO.setIsPublic();
        Changed = true;
      }
    }
  }

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

void PTeXAnalysis::print(raw_ostream &os, bool Small) const {
  llvm::print(os, In, Out, MF, Small);
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
      Changed |= setInstrPublic(*MI, "stack");

  // Backward analysis is harder, since we need to be conservative.
  // It's not as simple as marking all stores public if all loads are public.

  return Changed;
}

}

}
