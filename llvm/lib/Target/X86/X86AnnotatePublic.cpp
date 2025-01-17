#include <unordered_set>
#include <unordered_map>

#include "X86.h"
#include "llvm/CodeGen/MachineFunction.h"
#include "llvm/CodeGen/MachineFunctionPass.h"
#include "llvm/ADT/STLExtras.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/CodeGen/TargetSubtargetInfo.h"
#include "llvm/CodeGen/LivePhysRegs.h"
#include "llvm/CodeGen/RDFGraph.h"
#include "PTeX/Util.h"
#include "llvm/CodeGen/MachineRegisterInfo.h"
#include "MCTargetDesc/X86BaseInfo.h"

#define PASS_KEY "x86-annotate-public"
#define DEBUG_TYPE PASS_KEY

using namespace llvm;

namespace {

enum Mode {
  AnnotateNone,
  AnnotatePointers,
  AnnotateBoundToLeak,
};

cl::opt<Mode> EnableAnnotations {
  PASS_KEY,
  cl::desc("Enable public data annotation for stats gathering"),
  cl::init(AnnotateNone),
  cl::values(
      clEnumValN(AnnotateNone, "none", "Don't annotate any public data"),
      clEnumValN(AnnotatePointers, "pointers", "Annotate pointers"),
      clEnumValN(AnnotateBoundToLeak, "bound-to-leak", "Annotate bound-to-leak data")),
};

cl::opt<bool> AnnotateAllPointers {
  PASS_KEY "-all",
  cl::desc("Annotate all pointers, not just those that leak along all control-flow paths"),
  cl::init(false),
  cl::Hidden,
};

// This pass inserts a prefix for all pointers that will always leak.
// Any reasonable threat model considers pointers to be public/unprotected,
// so this is a good proxy for determining how much the protection scheme
// is overprotecting code.
//
// In our initial implementation, we will just consider pointers that leak within
// the same basic block. However, we will probably next want to consider pointers
// that leak along all control-flow paths.
class X86AnnotatePointers final : public MachineFunctionPass {
public:
  static char ID;

  X86AnnotatePointers() : MachineFunctionPass(ID) {}

  bool runOnMachineFunction(MachineFunction &MF) override;

  void getAnalysisUsage(AnalysisUsage &AU) const override {
    AU.setPreservesCFG();
    MachineFunctionPass::getAnalysisUsage(AU);
  }

private:
  using InstrSet = std::unordered_set<MachineInstr *>;
  void detectPointerLoads(MachineFunction &MF, InstrSet &AnnotateInstrs);
  void detectBoundToLeakInstrs(MachineFunction &MF, InstrSet &AnnotateInstrs);
};

}

char X86AnnotatePointers::ID = 0;

bool X86AnnotatePointers::runOnMachineFunction(MachineFunction &MF) {
  if (EnableAnnotations == AnnotateNone)
    return false;

  bool Changed = false;
  std::unordered_set<MachineInstr *> AnnotateInstrs;

  switch (EnableAnnotations) {
  case AnnotatePointers:
    detectPointerLoads(MF, AnnotateInstrs);
    break;

  case AnnotateBoundToLeak:
    // Bound-to-leak is not supported for SSA
    // machine functions.
    if (!MF.getRegInfo().isSSA())
      detectBoundToLeakInstrs(MF, AnnotateInstrs);
    break;

  default:
    llvm_unreachable("unreachable!");
  }

  for (MachineInstr *MI : AnnotateInstrs) {
    MI->setFlag(MachineInstr::AnnotatePointerLoad); // FIXME: Rename.
    LLVM_DEBUG(dbgs() << "annotating " << *MI);
  }

  Changed |= !AnnotateInstrs.empty();

  return Changed;
}

static bool detectPointerLoadsVirtInstr(const MachineInstr &MI, const MachineRegisterInfo &MRI) {
  // Check if this instruction has any pointer-typed data operands.
  auto IsVirtPtrData = [&] (const MachineOperand &MO) -> bool {
    // Is it a pointer-typed virtual register?
    if (!(MO.isReg() && MRI.getType(MO.getReg()).isPointer()))
      return false;

    // Is this an address operand, not a data operand?
    if (MI.mayLoadOrStore())
      if (const int MemIdx = X86::getMemRefBeginIdx(MI); MemIdx >= 0)
        for (int i = MemIdx; i < MemIdx + X86::AddrNumOperands; ++i)
          if (&MO == &MI.getOperand(i))
            return false;

    // It's a data operand.
    return true;
  };

  // Does this instruction have any pointer-typed data operands?
  if (!llvm::any_of(MI.operands(), IsVirtPtrData))
    return false;

  return true;
}

template <class Container>
static void detectPointerLoadsVirt(MachineFunction &MF, Container &PointerLoads) {
  const MachineRegisterInfo &MRI = MF.getRegInfo();
  for (MachineBasicBlock &MBB : MF)
    for (MachineInstr &MI : MBB)
      if (detectPointerLoadsVirtInstr(MI, MRI))
        PointerLoads.insert(&MI);
}

template <class Container>
static void detectPointerLoadsPhys(MachineFunction &MF, Container &PointerLoads) {
  const auto &TRI = *MF.getSubtarget().getRegisterInfo();

  std::unordered_map<MachineBasicBlock *, LivePhysRegs> Map;

  for (MachineBasicBlock &MBB : MF) {
    Map.emplace(std::piecewise_construct,
                std::forward_as_tuple(&MBB),
                std::forward_as_tuple(TRI));
  }

  bool Dump = false;

  bool Changed;
  unsigned NumIters = 0;
  do {
    Changed = false;

    ++NumIters;

    if (Dump)
      errs() << "===== iteration " << NumIters << " =====\n";

    for (MachineBasicBlock &MBB : MF) {
      LivePhysRegs &PtrRegs = Map[&MBB];
      const size_t OldSize = llvm::size(PtrRegs);
      PtrRegs.clear();

      // Meet: out is 'or' of successors' ins.
      for (MachineBasicBlock *SuccMBB : MBB.successors())
        for (Register SuccPtrReg : Map[SuccMBB])
          PtrRegs.addReg(SuccPtrReg);

      if (Dump)
        errs() << PtrRegs;

      // Transfer over instructions.
      for (MachineInstr &MI : llvm::reverse(MBB)) {
        // Was a def leaked as a pointer?
        const bool DefIsPtr = llvm::any_of(MI.defs(), [&] (const MachineOperand &MO) {
          assert(MO.isReg() && MO.isDef() && !MO.isImplicit());
          return PtrRegs.contains(MO.getReg());
        });
        if (DefIsPtr)
          PointerLoads.insert(&MI);

        // Remove defs.
        PtrRegs.removeDefs(MI);

        // Add any leaked address base registers.
        const int MemRefBeginIdx = X86::getMemRefBeginIdx(MI);
        if (MI.mayLoadOrStore() && MemRefBeginIdx >= 0) {
          const MachineOperand &MO = MI.getOperand(MemRefBeginIdx + X86::AddrBaseReg);
          if (MO.isReg()) {
            const Register PtrReg = MO.getReg();
            assert(PtrReg != X86::NoRegister);
            PtrRegs.addReg(PtrReg);
          }
        }

        if (Dump)
          errs() << MI << PtrRegs;
      }

      if (Dump)
        errs() << "\n";

      const size_t NewSize = llvm::size(PtrRegs);
      Changed |= (OldSize != NewSize);
    }
  } while (Changed);
}

template <class Container>
static void detectPointerLoadsMemOps(MachineFunction &MF, Container &PointerLoads) {
  for (MachineBasicBlock &MBB : MF) {
    for (MachineInstr &MI : MBB) {
      const bool AnyPtr = llvm::any_of(MI.memoperands(), [] (const MachineMemOperand *MMO) -> bool {
        return MMO->getType().isPointer();
      });
      if (AnyPtr) {
        PointerLoads.insert(&MI);
      }
    }
  }
}

void X86AnnotatePointers::detectPointerLoads(MachineFunction &MF, InstrSet &PointerLoads) {
  if (MF.getRegInfo().isSSA()) {
    detectPointerLoadsVirt(MF, PointerLoads);
  } else {
    detectPointerLoadsPhys(MF, PointerLoads);
  }
  detectPointerLoadsMemOps(MF, PointerLoads);
}

void X86AnnotatePointers::detectBoundToLeakInstrs(MachineFunction &MF, InstrSet &AnnotateInstrs) {
  const TargetRegisterInfo &TRI = *MF.getSubtarget().getRegisterInfo();
  std::unordered_map<MachineBasicBlock *, LivePhysRegs> In, Out;

  // Initialize ins and outs.
  for (MachineBasicBlock &MBB : MF) {
    In[&MBB].init(TRI);
    Out[&MBB].init(TRI);
    In[&MBB].addLiveIns(MBB);
    if (!MBB.succ_empty())
      Out[&MBB].addLiveOuts(MBB);
  }

  const auto CountPubRegs = [] (const auto &Map) -> size_t {
    size_t n = 0;
    for (const auto &[_, PubRegs] : Map)
      n += llvm::size(PubRegs);
    return n;
  };

  const auto TotalPubRegs = [&In, &Out, CountPubRegs] () -> size_t {
    return CountPubRegs(In) + CountPubRegs(Out);
  };

  const auto StepInstr = [&] (const MachineInstr &MI, LivePhysRegs &PubRegs) {
    // Remove any register defs.
    PubRegs.removeDefs(MI);

    // Add any leaked operands.
    const auto MarkUsePublic = [&] (const MachineOperand &MO) {
      if (MO.isReg() && MO.isUse() && !MO.isUndef())
        PubRegs.addReg(MO.getReg());
    };
    if (MI.isCall())
      for (const MachineOperand &MO : MI.operands())
        if (MO.isReg() && !MO.isImplicit())
          MarkUsePublic(MO);
#if 0
    if (MI.isBranch())
      for (const MachineOperand &MO : MI.operands())
        MarkUsePublic(MO);
#endif
    const int MemIdx = X86::getMemRefBeginIdx(MI);
    if (MI.mayLoadOrStore() && MemIdx >= 0) {
      MarkUsePublic(MI.getOperand(MemIdx + X86::AddrBaseReg));
      MarkUsePublic(MI.getOperand(MemIdx + X86::AddrIndexReg));
    }
  };

  // Dataflow pass.
  while (true) {
    const size_t OrigPubRegs = TotalPubRegs();

    for (MachineBasicBlock &MBB : MF) {
      // Remove any pub-out registers that *aren't* pub-out in at least one successor.
      for (MachineBasicBlock *SuccMBB : MBB.successors())
        for (MCPhysReg Reg : In[SuccMBB])
          Out[&MBB].removeReg(Reg);

      // Transfer backwards across block.
      LivePhysRegs PubRegs(TRI);
      for (MCPhysReg PubReg : Out[&MBB])
        PubRegs.addReg(PubReg);
      for (MachineInstr &MI : llvm::reverse(MBB))
        StepInstr(MI, PubRegs);

      // Set pub-ins.
      In[&MBB].clear();
      for (MCPhysReg PubReg : PubRegs)
        In[&MBB].addReg(PubReg);
    }

    const size_t NewPubRegs = TotalPubRegs();
    assert(NewPubRegs <= OrigPubRegs);
    if (NewPubRegs == OrigPubRegs)
      break;
  }

  // Copy out instructions all of whose explicit outputs are marked public.
  for (MachineBasicBlock &MBB : MF) {
    LivePhysRegs PubRegs(TRI);
    for (MCPhysReg PubReg : Out[&MBB])
      PubRegs.addReg(PubReg);
    for (MachineInstr &MI : llvm::reverse(MBB)) {
      const auto EligibleMO = [] (const MachineOperand &MO) -> bool {
        return MO.isReg() && MO.isDef() && !MO.isImplicit() && !MO.isUndef();
      };
      const auto NumEligible = llvm::count_if(MI.operands(), EligibleMO);
      const auto NumEligiblePub = llvm::count_if(MI.operands(), [&] (const MachineOperand &MO) -> bool {
        return EligibleMO(MO) && PubRegs.contains(MO.getReg());
      });
      if (NumEligible == NumEligiblePub && NumEligiblePub == 1)
        AnnotateInstrs.insert(&MI);

      StepInstr(MI, PubRegs);
    }
  }
}

INITIALIZE_PASS_BEGIN(X86AnnotatePointers, PASS_KEY "-pass", "X86 Annotate Public Data pass", false, false)
INITIALIZE_PASS_END(X86AnnotatePointers, PASS_KEY "-pass", "X86 Annotate Public Data pass", false, false)

FunctionPass *llvm::createX86AnnotatePointersPass() {
  return new X86AnnotatePointers();
}
