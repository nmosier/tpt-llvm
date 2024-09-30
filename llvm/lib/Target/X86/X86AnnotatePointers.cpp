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

#define PASS_KEY "x86-annotate-pointers"
#define DEBUG_TYPE PASS_KEY

using namespace llvm;

namespace {

cl::opt<bool> EnableAnnotatePointers {
  PASS_KEY,
  cl::desc("Enable pointer annotation for stats gathering"),
  cl::init(false),
  cl::Hidden,
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

  std::unordered_set<MachineInstr *> detectPointerLoads(MachineFunction &MF);
};

}

char X86AnnotatePointers::ID = 0;

bool X86AnnotatePointers::runOnMachineFunction(MachineFunction &MF) {
  if (!EnableAnnotatePointers)
    return false;

  bool Changed = false;

  bool Dump = false;

  const std::unordered_set<MachineInstr *> PointerLoads = detectPointerLoads(MF);

  for (MachineInstr *PointerLoad : PointerLoads) {
    PointerLoad->setFlag(MachineInstr::AnnotatePointerLoad);
    if (Dump)
      errs() << "pointer load: " << *PointerLoad;
  }

  Changed |= !PointerLoads.empty();

  return Changed;
}

std::unordered_set<MachineInstr *> X86AnnotatePointers::detectPointerLoads(MachineFunction &MF) {
  const auto &TRI = *MF.getSubtarget().getRegisterInfo();

  std::unordered_set<MachineInstr *> PointerLoads;
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

  return PointerLoads;
}

INITIALIZE_PASS_BEGIN(X86AnnotatePointers, PASS_KEY "-pass", "X86 Annotate Pointers pass", false, false)
INITIALIZE_PASS_END(X86AnnotatePointers, PASS_KEY "-pass", "X86 Annotate Pointers pass", false, false)

FunctionPass *llvm::createX86AnnotatePointersPass() {
  return new X86AnnotatePointers();
}
