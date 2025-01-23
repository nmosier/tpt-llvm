#include "PTeX/PTeXAnalysis.h"

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
#include "PTeX/PublicPhysRegs.h"
#include "PTeX/ForwardAnalysis.h"
#include "PTeX/BackwardAnalysis.h"
#include "PTeX/Util.h"
#include "PTeX/BranchAnalysis.h"
#include "PTeX/StackAnalysis.h"

using namespace llvm;
using llvm::X86::PublicPhysRegs;
using llvm::X86::PTeXAnalysis;

#define PASS_KEY "x86-ptex"
#define DEBUG_TYPE PASS_KEY

static cl::opt<bool> AnalyzeBranches {
  PASS_KEY "-analyze-branches",
  cl::desc("[PTeX] Analyze branches"),
  cl::init(false),
  cl::Hidden,
};

static cl::opt<bool> AnalyzeStack {
  PASS_KEY "-analyze-stack",
  cl::desc("[PTeX] Analyze stack"),
  cl::init(false),
  cl::Hidden,
};

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
    if (MO.isReg() && regAlwaysPublic(MO.getReg(), TRI) && !MO.isUndef() && MO.getReg() != X86::NoRegister)
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
    markOpPublic(*MO);
  }

  // Mark pointer-typed return values public.
  // Don't need to do anything fancy here because pointers will always be passed
  // in RAX.
  if (CalleeFunc->getReturnType()->isPointerTy())
    for (MachineOperand &MO : MI.operands())
      if (MO.isReg() && MO.isDef() && MO.isImplicit())
        markOpPublic(MO);
}

void PTeXAnalysis::initPointerTypes(MachineInstr &MI) {
  const MachineRegisterInfo &MRI = MF.getRegInfo();
  for (MachineOperand &MO : MI.operands()) {
    // PTEX-FIXME: MI.mayLoadOrStore() is too aggressive.
    // We do care about stores that have a pointer operand.
    if (MO.isReg() && !MO.isImplicit() && MRI.getType(MO.getReg()).isPointer() &&
        (MO.isDef() || (MO.isUse() && !MI.mayLoadOrStore()))) {
      markOpPublic(MO);
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
      markOpPublic(MO);
}

// TODO: Remove?
void PTeXAnalysis::initPublicInstr(MachineInstr &MI) {
  if (MI.getFlag(MachineInstr::TPEPubM))
    for (MachineOperand &MO : MI.operands())
      if (MO.isReg() && !MO.isUndef())
        markOpPublic(MO);
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

  markAllOpsPublic(MI);
}

void PTeXAnalysis::init() {
  // Init pub-in and pub-out maps.
  for (MachineBasicBlock &MBB : MF) {
    In[&MBB].init(TRI);
    Out[&MBB].init(TRI);
  }

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

  // Init entry blocks pub-ins to include all callee-saved registers.
  const MCPhysReg *CSRs = TRI->getCalleeSavedRegs(&MF);
  assert(*CSRs);
  for (const MCPhysReg *CSRIt = CSRs; *CSRIt; ++CSRIt)
    In[&MF.front()].addReg(*CSRIt);

  // TODO: Mark CSRs at exit public?
}

bool PTeXAnalysis::forward() {
  ForwardAnalysis Forward(*this);
  bool Changed = false;
  Changed |= Forward.run();
  Changed |= merge(Forward);
  return Changed;
}

bool PTeXAnalysis::backward() {
  BackwardAnalysis Backward(*this);
  bool Changed = false;
  Changed |= Backward.run();
  Changed |= merge(Backward);
  return Changed;
}

bool PTeXAnalysis::stack() {
#if 0
  StackAnalysis Stack(MF, *this);
  return Stack.run();
#else
  return false;
#endif
}

bool PTeXAnalysis::branch() {
  BranchAnalysis Branch(*this);
  return Branch.run();
}

void PTeXAnalysis::run() {
  init();

  LLVM_DEBUG(dbgs() << "==== init ====\n");
  LLVM_DEBUG(print(dbgs()));

  bool IterChanged;
  int NumIters = 0;
  do {
    IterChanged = false;

    IterChanged |= forward();
    IterChanged |= backward();
    if (AnalyzeBranches)
      IterChanged |= branch();
    if (AnalyzeStack)
      IterChanged |= stack();
    IterChanged |= fixup();

    LLVM_DEBUG(dbgs() << "==== iter " << NumIters << "====\n");
    LLVM_DEBUG(print(dbgs()));

    ++NumIters;
  } while (IterChanged);

  LLVM_DEBUG(dbgs() << "==== final protcetion types ====\n");
  LLVM_DEBUG(print(dbgs()));
}

void PTeXAnalysis::markOpPublic(MachineOperand &MO) {
  if (MO.isReg() && !MO.isUndef())
    MO.setIsPublic();
}

// TODO: Make more generic -- accept range of ops. Can be invoked by Fwd and Bwd analyses.
void PTeXAnalysis::markAllOpsPublic(MachineInstr &MI) {
  for (MachineOperand &MO : MI.operands())
    markOpPublic(MO);
}

// TODO: Re-examine this.
bool PTeXAnalysis::fixup() {
  bool Changed = false;
  for (MachineBasicBlock &MBB : MF) {
    for (MachineInstr &MI : MBB) {
      if (MI.isCall())
        continue;

      // HACK: If there are some explicit outputs and all of them are marked public, then mark the implicit output public, too.
      const auto IsExplicitDef = [] (const MachineOperand &MO) -> bool {
        return MO.isReg() && MO.isDef() && !MO.isImplicit() && !MO.isUndef();
      };
      if (llvm::any_of(MI.operands(), IsExplicitDef) &&
          llvm::all_of(MI.operands(), [&] (const MachineOperand &MO) -> bool {
            // IsImplicitDef => MO.isPublic()
            return !IsExplicitDef(MO) || MO.isPublic();
          })) {
        for (MachineOperand &MO : MI.operands()) {
          if (MO.isReg() && MO.isDef() && MO.isImplicit() && !MO.isUndef() && !MO.isPublic() && MO.getReg() == X86::EFLAGS) {
            LLVM_DEBUG(dbgs() << "HACK: marking implicit output " << MO << " public: " << MI);
            MO.setIsPublic();
            Changed = true;
          }
        }
      }
    }
  }
  return Changed;
}
