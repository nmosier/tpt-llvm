#include <unordered_set>
#include <unordered_map>

#include "X86.h"
#include "llvm/CodeGen/MachineFunction.h"
#include "llvm/CodeGen/MachineFunctionPass.h"
#include "llvm/ADT/STLExtras.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/CodeGen/TargetSubtargetInfo.h"
#include "llvm/CodeGen/LivePhysRegs.h"
#include "X86PrivacyTypeAnalysis.h"
#include "llvm/CodeGen/RDFGraph.h"
#include "X86BoundToLeakAnalysis.h"

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

void X86AnnotatePointers::detectPointerLoads(MachineFunction &MF, InstrSet &PointerLoads) {
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

void X86AnnotatePointers::detectBoundToLeakInstrs(MachineFunction &MF, InstrSet &AnnotateInstrs) {
  X86::BoundToLeakAnalysis BTLA(MF);
  BTLA.run();

  // Copy instructions that were marked public to now be annotated.
  for (MachineBasicBlock &MBB : MF) {
    for (MachineInstr &MI : MBB) {
      if (llvm::any_of(MI.operands(), [] (const MachineOperand &MO) -> bool {
        return MO.isReg() && MO.isDef() && !MO.isImplicit() && !MO.isUndef() && MO.isPublic();
      })) {
        AnnotateInstrs.insert(&MI);
      }
    }
  }
}

INITIALIZE_PASS_BEGIN(X86AnnotatePointers, PASS_KEY "-pass", "X86 Annotate Public Data pass", false, false)
INITIALIZE_PASS_END(X86AnnotatePointers, PASS_KEY "-pass", "X86 Annotate Public Data pass", false, false)

FunctionPass *llvm::createX86AnnotatePointersPass() {
  return new X86AnnotatePointers();
}
