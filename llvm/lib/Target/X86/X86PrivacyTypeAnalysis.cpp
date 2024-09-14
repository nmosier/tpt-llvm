#include "X86PrivacyTypeAnalysis.h"

#include "X86.h"
#include "llvm/CodeGen/TargetSubtargetInfo.h"
#include "X86Subtarget.h"
#include "MCTargetDesc/X86BaseInfo.h"
#include "llvm/CodeGen/TargetInstrInfo.h"
#include "llvm/CodeGen/MachineJumpTableInfo.h"
#include "llvm/Support/WithColor.h"

#define PASS_KEY "x86-privacy-types"

using namespace llvm;

using X86::PrivacyType;
using X86::PrivacyMask;
using X86::PrivacyNode;
using X86::PrivatelyTyped;
using X86::PubliclyTyped;

// TODO LIST:
// [ ] Don't print out always-public registers in list.
// [ ] Print out both outs and ins back-to-back if they differ.
// [ ] Label instr-ins, etc.
// [ ] Option to colorize printouts. Color newly public instructions green; color now missing instructions red.

char X86PrivacyTypeAnalysis::ID = 0;

static llvm::cl::opt<bool> DumpResults {
  PASS_KEY "-dump",
  cl::desc("Dump privacy types"),
  cl::init(false),
  cl::Hidden,
};

// PTEX-TODO: Rename to DumpDelta.
static llvm::cl::opt<bool> DumpIncremental {
  PASS_KEY "-dump-incr",
  cl::desc("Dump incremental privacy types"),
  cl::init(false),
  cl::Hidden,
};


static std::array<Register, 4> AlwaysPublicRegisters = {X86::NoRegister, X86::RSP, X86::RIP, X86::SSP};

bool llvm::X86::registerIsAlwaysPublic(Register Reg) {
  return llvm::is_contained(AlwaysPublicRegisters, Reg);
}

struct DataflowStep {
  const char *name;
  MachineInstr *MI;

  DataflowStep(const char *name, MachineInstr *MI): name(name), MI(MI) {}
  
};
static std::optional<DataflowStep> dataflow_step;

static int getJumpTableIndexFromAddr(const MachineInstr &MI) {
  const MCInstrDesc &Desc = MI.getDesc();
  int MemRefBegin = X86II::getMemoryOperandNo(Desc.TSFlags);
  assert(MemRefBegin >= 0 && "instr should have memory operand");
  MemRefBegin += X86II::getOperandBias(Desc);
 
  const MachineOperand &MO = MI.getOperand(MemRefBegin + X86::AddrDisp);
  if (!MO.isJTI())
    return -1;
 
  return MO.getIndex();
}
 
static int getJumpTableIndexFromReg(const MachineRegisterInfo &MRI,
                                    Register Reg) {
  if (!Reg.isVirtual())
    return -1;
  MachineInstr *MI = MRI.getUniqueVRegDef(Reg);
  if (MI == nullptr)
    return -1;
  unsigned Opcode = MI->getOpcode();
  if (Opcode != X86::LEA64r && Opcode != X86::LEA32r)
    return -1;
  return getJumpTableIndexFromAddr(*MI);
}

int X86::getJumpTableIndex(const MachineInstr &MI, const MachineFunction &MF) {
  unsigned Opcode = MI.getOpcode();
  // Switch-jump pattern for non-PIC code looks like:
  //   JMP64m $noreg, 8, %X, %jump-table.X, $noreg
  if (Opcode == X86::JMP64m || Opcode == X86::JMP32m) {
    return getJumpTableIndexFromAddr(MI);
  }
  // The pattern for PIC code looks like:
  //   %0 = LEA64r $rip, 1, $noreg, %jump-table.X
  //   %1 = MOVSX64rm32 %0, 4, XX, 0, $noreg
  //   %2 = ADD64rr %1, %0
  //   JMP64r %2
  if (Opcode == X86::JMP64r || Opcode == X86::JMP32r) {
    Register Reg = MI.getOperand(0).getReg();
    if (!Reg.isVirtual())
      return -1;
    const MachineFunction &MF = *MI.getParent()->getParent();
    const MachineRegisterInfo &MRI = MF.getRegInfo();
    MachineInstr *Add = MRI.getUniqueVRegDef(Reg);
    if (Add == nullptr)
      return -1;
    if (Add->getOpcode() != X86::ADD64rr && Add->getOpcode() != X86::ADD32rr)
      return -1;
    int JTI1 = getJumpTableIndexFromReg(MRI, Add->getOperand(1).getReg());
    if (JTI1 >= 0)
      return JTI1;
    int JTI2 = getJumpTableIndexFromReg(MRI, Add->getOperand(2).getReg());
    if (JTI2 >= 0)
      return JTI2;
  }
  return -1;
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

Register PrivacyMask::canonicalizeRegister(Register Reg) {
  if (Reg == X86::EFLAGS)
    return Reg;
  if (Register Reg64 = getX86SubSuperRegisterOrZero(Reg, 64))
    return Reg64;
  // PTEX-TODO: Do we need to worry about YMMs, etc?
  return Reg;  
}

void PrivacyMask::set(Register Reg, PrivacyType Ty) {
  // PTEX-TODO: Should also consider register classes.
  Reg = canonicalizeRegister(Reg);
  switch (Ty) {
  case PubliclyTyped:
    PubRegs.set(Reg);
    break;
  case PrivatelyTyped:
    PubRegs.reset(Reg);
    break;
  default: llvm_unreachable("bad privacy type");
  }
}

PrivacyType PrivacyMask::get(Register Reg) const {
  // PTEX-TODO: Should also consider register classes.
  Reg = canonicalizeRegister(Reg);
  return PubRegs.test(Reg) ? PubliclyTyped : PrivatelyTyped;
}

bool PrivacyMask::inheritPublic(const PrivacyMask &o, PrivacyMask *diff) {
  if (diff)
    diff->PubRegs = o.PubRegs & ~PubRegs;
  const auto before_count = PubRegs.count();
  PubRegs |= o.PubRegs;
  const auto after_count = PubRegs.count();
  return before_count != after_count;
}

void PrivacyMask::inheritPrivate(const PrivacyMask &o) {
  PubRegs &= o.PubRegs;
}

bool PrivacyMask::allPrivate() const {
  return PubRegs.none();
}

PrivacyMask::Bitset PrivacyMask::regmaskToBitset(const uint32_t *mask) {
  Bitset bitset;
  for (unsigned Reg = 0; Reg < NUM_TARGET_REGS; ++Reg)
    if ((mask[Reg / 32] & (1u << (Reg % 32))) != 0)
      bitset.set(Reg);
  return bitset;
}

void PrivacyMask::setRegMask(const uint32_t *RegMask, PrivacyType Ty, bool invert) {
  Bitset bitset = regmaskToBitset(RegMask);
  if (invert)
    bitset.flip();
  switch (Ty) {
  case PubliclyTyped:
    PubRegs |= bitset;
    break;
  case PrivatelyTyped:
    PubRegs &= ~bitset;
    break;
  default: llvm_unreachable("Bad privacy type!");
  }
}

[[nodiscard]] static bool isPublicInstr(const MachineInstr& MI) { return MI.getFlag(MachineInstr::TPEPubM); }
[[nodiscard]] static bool setPublicInstr(MachineInstr &MI) {
  const bool Changed = !isPublicInstr(MI);
  MI.setFlag(MachineInstr::TPEPubM);
  return Changed;
}


void X86PrivacyTypeAnalysis::getAnalysisUsage(AnalysisUsage &AU) const {
  MachineFunctionPass::getAnalysisUsage(AU);
  AU.setPreservesAll();
}

void X86PrivacyTypeAnalysis::addBlockEdge(MachineBasicBlock *Src, MachineBasicBlock *Dst) {
  BlockSuccessors[Src].insert(Dst);
  BlockPredecessors[Dst].insert(Src);
}

void X86PrivacyTypeAnalysis::clear() {
  BlockPrivacy.clear();
  InstrPrivacy.clear();
  BlockSuccessors.clear();
  BlockPredecessors.clear();
}

PrivacyNode &X86PrivacyTypeAnalysis::getBlockPrivacy(MachineBasicBlock *MBB) {
  return BlockPrivacy[MBB];
}

PrivacyMask &X86PrivacyTypeAnalysis::getBlockPrivacyIn(MachineBasicBlock *MBB) {
  return getBlockPrivacy(MBB).in;
}

PrivacyMask &X86PrivacyTypeAnalysis::getBlockPrivacyOut(MachineBasicBlock *MBB) {
  return getBlockPrivacy(MBB).out;
}

PrivacyNode &X86PrivacyTypeAnalysis::getInstrPrivacy(MachineInstr *MI) {
  return InstrPrivacy[MI];
}

PrivacyMask &X86PrivacyTypeAnalysis::getInstrPrivacyIn(MachineInstr *MI) {
  return getInstrPrivacy(MI).in;
}

PrivacyMask &X86PrivacyTypeAnalysis::getInstrPrivacyOut(MachineInstr *MI) {
  return getInstrPrivacy(MI).out;
}

const X86PrivacyTypeAnalysis::BasicBlockSet &X86PrivacyTypeAnalysis::getBlockPredecessors(MachineBasicBlock *MBB) {
  return BlockPredecessors[MBB];
}

// PTEX-TODO: use namespace llvm::X86.
const X86PrivacyTypeAnalysis::BasicBlockSet &X86PrivacyTypeAnalysis::getBlockSuccessors(MachineBasicBlock *MBB) {
  return BlockSuccessors[MBB];
}

static bool allInputsPublic(const MachineInstr &MI, const PrivacyMask &Privacy) {
  if (MI.mayLoad() && !isPublicInstr(MI))
    return false;

  for (const MachineOperand &MO : MI.operands())
    if (MO.isReg() && MO.isUse() && !MO.isUndef() && Privacy.get(MO.getReg()) == PrivatelyTyped)
      return false;

  return true;
}

static bool allOutputsPublic(const MachineInstr &MI, const PrivacyMask &Privacy) {
  if (MI.mayStore() && !isPublicInstr(MI))
    return false;

  for (const MachineOperand &MO : MI.operands())
    if (MO.isReg() && MO.isDef() && Privacy.get(MO.getReg()) == PrivatelyTyped)
      return false;

  return true;
}

static bool anyDataOutputPublic(const MachineInstr &MI, const PrivacyMask &Privacy) {
  // PTEX-TODO: Might be able to consider store flag here.

  for (const MachineOperand &MO : MI.operands())
    if (MO.isReg() && MO.isDef() && (!MO.isImplicit() || MO.getReg() == X86::EFLAGS) &&
        Privacy.get(MO.getReg()) == PubliclyTyped)
      return true;

  return false;
}

static void setClobberedRegistersPrivacy(const MachineInstr &MI, PrivacyMask &Privacy, PrivacyType Ty) {
  for (const MachineOperand& MO : MI.operands()) {
    if (MO.isReg()) {
      if (MO.isDef())
        Privacy.set(MO.getReg(), Ty);
    } else if (MO.isRegMask()) {
      assert(MI.isCall() && "Found RegMask operand in non-call instruction!");
      Privacy.setRegMask(MO.getRegMask(), Ty, true);
    }
  }
}

static bool isArithInstr(const MachineInstr &MI) {
  if (MI.isCall() || MI.isReturn())
    return false;
  return true;
}

bool X86PrivacyTypeAnalysis::runOnMachineFunction(MachineFunction &MF) {
  // PTEX-TODO: Split these out into different functions.

  // PART I: Compute block-level control-flow graph.

  // Step 1: Add regular edges.
  for (MachineBasicBlock &MBB : MF)
    for (MachineBasicBlock *SuccMBB : MBB.successors())
      addBlockEdge(&MBB, SuccMBB);

  // Step 2: Add jump table edges.
  for (MachineBasicBlock &MBB : MF) {
    const auto MBBI = MBB.getFirstTerminator();
    if (MBBI == MBB.end())
      continue;
    const int JumpTableIndex = X86::getJumpTableIndex(*MBBI, MF);
    if (JumpTableIndex < 0)
      continue;
    const MachineJumpTableInfo *JTI = MF.getJumpTableInfo();
    for (MachineBasicBlock *SuccMBB : JTI->getJumpTables()[JumpTableIndex].MBBs)
      addBlockEdge(&MBB, SuccMBB);
  }

  // PART II: Initially publicly-type registers where applicable.

  // Step 1: Mark all transmitted operands as public.
  for (MachineBasicBlock &MBB : MF) {
    for (MachineInstr &MI : MBB) {
      auto PubliclyTypeUse = [&] (const MachineOperand &MO) {
        if (!MO.isReg())
          return;
        assert(MO.isUse());
        getInstrPrivacyIn(&MI).set(MO.getReg(), PubliclyTyped);
      };

      // Publicly-type all inputs of control-flow instructions.
      if (MI.isCall()) {
        PubliclyTypeUse(MI.getOperand(0));
      } else if (MI.isBranch()) {
        for (const MachineOperand &MO : MI.operands())
          PubliclyTypeUse(MO);
      }

      // Declassify address operands.
      int MemIdx = X86::getMemRefBeginIdx(MI);
      if (MI.mayLoadOrStore() && MemIdx >= 0) {
        PubliclyTypeUse(MI.getOperand(MemIdx + X86::AddrBaseReg));
        PubliclyTypeUse(MI.getOperand(MemIdx + X86::AddrIndexReg));
      }
    }
  }

  // Step 2: Mark all inputs/outputs of accesses to pointer data public.
  for (MachineBasicBlock &MBB : MF) {
    for (MachineInstr &MI : MBB) {
      for (MachineMemOperand *MMO : MI.memoperands()) {
        if (!MMO->getType().isPointer())
          continue;
        for (const MachineOperand &MO : MI.operands()) {
          if (!MO.isReg())
            continue;
          const Register Reg = MO.getReg();
          if (MO.isUse()) {
            getInstrPrivacyIn(&MI).set(Reg, PubliclyTyped);
          } else if (MO.isDef() && !MI.isCall()) {
            getInstrPrivacyOut(&MI).set(Reg, PubliclyTyped);
          } else {
            llvm_unreachable("Register operand is neither use nor def!");
          }
        }
      }
    }
  }

  // Step 3: Mark all always-public registers as public.
  for (Register Reg : AlwaysPublicRegisters) {
    for (MachineBasicBlock &MBB : MF) {
      getBlockPrivacyIn(&MBB).set(Reg, PubliclyTyped);
      getBlockPrivacyOut(&MBB).set(Reg, PubliclyTyped);
      for (MachineInstr &MI : MBB) {
        getInstrPrivacyIn(&MI).set(Reg, PubliclyTyped);
        getInstrPrivacyOut(&MI).set(Reg, PubliclyTyped);
      }
    }
  }


  // PTEX-NOTE: We don't need to mark callee-saved registers as publicly-typed,
  // since the saves will be inserted later on. 

  // PTEX-TODO: Need to fix up privacy types at function entry. Specifically, type all callee-saved registers public.

  // PART II: Iterative data-flow propoagation.

  bool Changed;
  unsigned NumIters = 0;
  do {
    Changed = false;

    PrivacyMask Diff;
    PrivacyMask *DiffPtr = (DumpIncremental ? &Diff : nullptr);
    auto PrintDiff = [&] (const char *Name, const auto& Elt) {
      if (DiffPtr && !Diff.allPrivate()) {
        errs() << "===== " << Name << " =====\n";
        errs() << Name << ": " << Elt;
        Diff.print(errs(), MF.getSubtarget().getRegisterInfo());
        errs() << "\n==========\n";
      }
    };

    // Step 1: Basic block forward meet.
    for (MachineBasicBlock &MBB : MF) {
      // Don't meet on the entry block.
      if (&MBB == &MF.front())
        continue;
      const auto& preds = getBlockPredecessors(&MBB);
      assert(!preds.empty() && "A non-entry basic block has no predecessors!");
      auto pred_it = preds.begin();
      PrivacyMask Privacy = getBlockPrivacyOut(*pred_it++);
      while (pred_it != preds.end())
        Privacy.inheritPrivate(getBlockPrivacyOut(*pred_it++));
      Changed |= getBlockPrivacyIn(&MBB).inheritPublic(Privacy, DiffPtr);
    }

    // Step 2: Basic block backward meet.
    for (MachineBasicBlock &MBB : MF) {
      for (MachineBasicBlock *SuccMBB : getBlockSuccessors(&MBB)) {
        Changed |= getBlockPrivacyOut(&MBB).inheritPublic(getBlockPrivacyIn(SuccMBB), DiffPtr);
      }
    }

    // Step 3: Mark instructions publicly-typed if all inputs are publicly-typed.
    for (MachineBasicBlock &MBB : MF) {
      for (MachineInstr &MI : MBB) {
        if (allInputsPublic(MI, getInstrPrivacyIn(&MI)) && !MI.isCall()) {
          const bool WasPubInstr = isPublicInstr(MI);
          Changed |= setPublicInstr(MI);
          if (!WasPubInstr && DumpIncremental)
            errs() << "pub-instr-in: " << MI;
        }
      }
    }

    // Step 4: Mark instructions publicly-typed if all outputs are publicly-typed.
    for (MachineBasicBlock &MBB : MF) {
      for (MachineInstr &MI : MBB) {
        if (anyDataOutputPublic(MI, getInstrPrivacyOut(&MI)) && !MI.isCall()) {
          const bool WasPubInstr = isPublicInstr(MI);
          Changed |= setPublicInstr(MI);
          if (!WasPubInstr && DumpIncremental)
            errs() << "pub-instr-out: " << MI;
        }
      }
    }

    // Step 5: Publicly-type all inputs and outputs of public instructions.
    for (MachineBasicBlock &MBB : MF) {
      for (MachineInstr &MI : MBB) {
        if (isPublicInstr(MI)) {
          PrivacyMask In = getInstrPrivacyIn(&MI);
          PrivacyMask Out = getInstrPrivacyOut(&MI);
          for (const MachineOperand &MO : MI.operands()) {
            if (MO.isReg()) {
              if (MO.isDef()) {
                Out.set(MO.getReg(), PubliclyTyped);
              } else if (MO.isUse()) {
                In.set(MO.getReg(), PubliclyTyped);
              } else {
                llvm_unreachable("");
              }
            }
          }
          Changed |= getInstrPrivacyIn(&MI).inheritPublic(In, DiffPtr);
          PrintDiff("pub-inst-in", MI);
          Changed |= getInstrPrivacyOut(&MI).inheritPublic(Out, DiffPtr);
          PrintDiff("pub-inst-out", MI);
        }
      }
    }

    // Step 6: Transfer forward.
    for (MachineBasicBlock &MBB : MF) {
      for (MachineInstr &MI : MBB) {
        PrivacyMask Privacy = getInstrPrivacyIn(&MI);
        setClobberedRegistersPrivacy(MI, Privacy, PrivatelyTyped);
        Changed |= getInstrPrivacyOut(&MI).inheritPublic(Privacy, DiffPtr);
        PrintDiff("transfer-fwd", MI);
      }
    }

    // Step 7: Transfer backward.
    for (MachineBasicBlock &MBB : MF) {
      for (MachineInstr &MI : MBB) {
        PrivacyMask Privacy = getInstrPrivacyOut(&MI);
        setClobberedRegistersPrivacy(MI, Privacy, PrivatelyTyped);
        Changed |= getInstrPrivacyIn(&MI).inheritPublic(Privacy, DiffPtr);
        PrintDiff("transfer-bwd", MI);
      }
    }
    
#if 0
    // Step 3: Instruction forward transfer.
    for (MachineBasicBlock &MBB : MF) {
      for (MachineInstr &MI : MBB) {
        PrivacyMask Privacy = getInstrPrivacyIn(&MI);

        // 3.1: Are all inputs public?
        // PTEX-TODO: Rewrite this function to directly return privacy type.
        const bool AllInputsPublic = allInputsPublic(MI, Privacy);

        // 3.2: Mark clobbered registers private.
        setClobberedRegistersPrivacy(MI, Privacy, PrivatelyTyped);

        // 3.3: Mark outputs private/public accordingly.
        const PrivacyType Ty = ((AllInputsPublic && isArithInstr(MI)) ? PubliclyTyped : PrivatelyTyped);
        for (const MachineOperand &MO : MI.operands())
          if (MO.isReg() && MO.isDef())
            Privacy.set(MO.getReg(), Ty);

        // PTEX-TODO: Set memory as private to, e.g., for stores?

        Changed |= getInstrPrivacyOut(&MI).inheritPublic(Privacy, DiffPtr);
        PrintDiff("instr-fwd", MI);
      }
    }

    // Step 4: Instruction backward transfer.
    for (MachineBasicBlock &MBB : MF) {
      for (MachineInstr &MI : MBB) {        
        PrivacyMask Privacy = getInstrPrivacyOut(&MI);

        // 4.1: Are all outputs public?
        // PTEX-TODO: Can change this function to directly return privacy type.
        const bool AllOutputsPublic = allOutputsPublic(MI, Privacy);

        // 4.2: Mark clobbered registers private.
        setClobberedRegistersPrivacy(MI, Privacy, PrivatelyTyped);

        // 4.2: Mark inputs private/public accordingly.
        const PrivacyType Ty = ((AllOutputsPublic && isArithInstr(MI)) ? PubliclyTyped : PrivatelyTyped);
        for (const MachineOperand &MO : MI.operands())
          if (MO.isReg() && MO.isUse() && !MO.isUndef())
            Privacy.set(MO.getReg(), Ty);

        // PTEX-TODO: Set memory as private for loads, e.g.?

        Changed |= getInstrPrivacyIn(&MI).inheritPublic(Privacy, DiffPtr);
        PrintDiff("instr-bwd", MI);
      }
    }

    // Step 5: Instruction sideways transfer.
    for (MachineBasicBlock &MBB : MF) {
      for (MachineInstr &MI : MBB) {
        // PTEX-TODO: Should be able to handle calls here?
        if (MI.isCall())
          continue;

        PrivacyMask Privacy = getInstrPrivacyOut(&MI);

        // If one explicit output is public or EFLAGS is public, then all explicit/EFLAGS outputs are public.
        if (anyDataOutputPublic(MI, Privacy))
          for (const MachineOperand &MO : MI.operands())
            if (MO.isReg() && MO.isDef())
              Privacy.set(MO.getReg(), PubliclyTyped);

        Changed |= getInstrPrivacyOut(&MI).inheritPublic(Privacy, DiffPtr);
        PrintDiff("instr-side", MI);
      }
    }
#endif

    // Step 6.1: Sync empty block in- and out-privacies.
    for (MachineBasicBlock &MBB : MF) {
      if (!MBB.empty())
        continue;
      PrivacyMask &BlockIn = getBlockPrivacyIn(&MBB);
      PrivacyMask &BlockOut = getBlockPrivacyOut(&MBB);
      Changed |= BlockIn.inheritPublic(BlockOut, nullptr);
      Changed |= BlockOut.inheritPublic(BlockIn, nullptr);
    }

    // Step 6.2: Sync non-empty block and instruction in-privacies.
    for (MachineBasicBlock &MBB : MF) {
      if (MBB.empty())
        continue;
      PrivacyMask &BlockIn = getBlockPrivacyIn(&MBB);
      PrivacyMask &InstrIn = getInstrPrivacyIn(&MBB.front());
      Changed |= BlockIn.inheritPublic(InstrIn, nullptr);
      Changed |= InstrIn.inheritPublic(BlockIn, nullptr);
    }

    // Step 6.3: Sync non-empty block and insturction out-privacies.
    for (MachineBasicBlock &MBB : MF) {
      if (MBB.empty())
        continue;
      PrivacyMask &BlockOut = getBlockPrivacyOut(&MBB);
      PrivacyMask &InstrOut = getInstrPrivacyOut(&MBB.back());
      Changed |= BlockOut.inheritPublic(InstrOut, nullptr);
      Changed |= InstrOut.inheritPublic(BlockOut, nullptr);
    }

    // Step 6.4: Sync instruction in- and out-privacies.
    for (MachineBasicBlock &MBB : MF) {
      for (MachineInstr &MI : MBB) {
        if (MachineInstr *SuccMI = MI.getNextNode()) {
          PrivacyMask &InstrOut = getInstrPrivacyOut(&MI);
          PrivacyMask &InstrIn = getInstrPrivacyIn(SuccMI);
          Changed |= InstrOut.inheritPublic(InstrIn, nullptr);
          Changed |= InstrIn.inheritPublic(InstrOut, nullptr);
        }
      }
    }

    // Step ???: Mark load data public? Mark store data public?

    ++NumIters;

    // dumpResults(errs(), MF);

  } while (Changed);

  // PTEX-TODO: Need to make sure we mark that CSRs are publicly-typed at function entry and function exits!

  // PTEX-TODO: Consider adding an instruction flag to mark whether an instruction that may load is publicly-typed.

  validate(MF);

  // Print out for debugging.
  if (DumpResults) {
    dumpResults(errs(), MF);
  }

  return false;
}

void X86PrivacyTypeAnalysis::validate(MachineFunction &MF) {
  for (MachineBasicBlock &MBB : MF) {
    if (MBB.empty()) {
      assert(getBlockPrivacyIn(&MBB) == getBlockPrivacyOut(&MBB));
    } else {
      assert(getBlockPrivacyIn(&MBB) == getInstrPrivacyIn(&MBB.front()));
      assert(getInstrPrivacyOut(&MBB.back()) == getBlockPrivacyOut(&MBB));
    }
  }

  // Make sure RSP is always publicly-typed.
  // PTEX-TODO: Make standalone function?
  for (Register Reg : AlwaysPublicRegisters) {
    auto DoAssert = [&] (const PrivacyMask &Privacy, const auto &X, const char *dir) {
      const PrivacyType Ty = Privacy.get(Reg);
      if (Ty != PubliclyTyped) {
        WithColor::error(errs(), "internal PTeX error") << "always-public register " << MF.getSubtarget().getRegisterInfo()->getRegAsmName(Reg) << " is not publicly " <<
            dir << "-typed here:\n" << X;
        report_fatal_error("aborting");
      }
    };
    for (MachineBasicBlock &MBB : MF) {
      DoAssert(getBlockPrivacyIn(&MBB), MBB, "in");
      DoAssert(getBlockPrivacyOut(&MBB), MBB, "out");
      for (MachineInstr &MI : MBB) {
        DoAssert(getInstrPrivacyIn(&MI), MI, "in");
        DoAssert(getInstrPrivacyOut(&MI), MI, "out");
      }
    }
  }
}

template <typename OutputIt>
OutputIt PrivacyMask::getPublicRegs(OutputIt out) const {
  for (unsigned Reg = 0; Reg < PubRegs.size(); ++Reg) {
    if (!PubRegs.test(Reg))
      continue;
    assert(canonicalizeRegister(Reg) == Reg);
    *out++ = Reg;
  }
}

void PrivacyMask::print(raw_ostream& os, const TargetRegisterInfo *TRI) const {
  // PTEX-TODO: Re-use code from getPublicRegs().
  bool first = true;
  for (unsigned Reg = 0; Reg < PubRegs.size(); ++Reg) {
    if (!PubRegs.test(Reg))
      continue;
    assert(canonicalizeRegister(Reg) == Reg);
    if (first) {
      first = false;
    } else {
      os << " ";
    }
    os << TRI->getRegAsmName(static_cast<Register>(Reg));
  }
}

void X86PrivacyTypeAnalysis::dumpResults(raw_ostream &os, MachineFunction &MF) {
  os << "===== Privacy Types for Function \"" << MF.getName() << "\" =====\n\n";

  const TargetRegisterInfo *TRI = MF.getSubtarget().getRegisterInfo();

  auto PrintPrivacy = [&] (const PrivacyMask &Privacy) {
    os << "    // public:";
    Privacy.print(os, TRI);
    os << "\n";
  };

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
    PrintBlockNames(getBlockPredecessors(&MBB));
    os << "\n";
    os << "    // succs: ";
    PrintBlockNames(getBlockSuccessors(&MBB));
    os << "\n";
    
    for (auto MBBI = MBB.begin(); MBBI != MBB.end(); ++MBBI) {
      PrintPrivacy(getInstrPrivacyIn(&*MBBI));
      os << "    " << *MBBI;
    }
    PrintPrivacy(getBlockPrivacyOut(&MBB));
    os << "\n";
  }
}

X86PrivacyTypeAnalysis::X86PrivacyTypeAnalysis() : MachineFunctionPass(ID) {}

INITIALIZE_PASS(X86PrivacyTypeAnalysis, PASS_KEY, "X86 Privacy Type Analysis", true, true)
