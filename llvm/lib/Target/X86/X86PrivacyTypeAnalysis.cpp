#include "X86PrivacyTypeAnalysis.h"

#include "X86.h"
#include "llvm/CodeGen/TargetSubtargetInfo.h"
#include "X86Subtarget.h"
#include "MCTargetDesc/X86BaseInfo.h"
#include "llvm/CodeGen/TargetInstrInfo.h"
#include "llvm/CodeGen/MachineJumpTableInfo.h"
#include "llvm/Support/WithColor.h"
#include "X86PTeX.h"

#define PASS_KEY "x86-privty"
#define DEBUG_TYPE PASS_KEY

using namespace llvm;

using X86::PrivacyMask;
using X86::PrivacyNode;

// TODO LIST:
// [ ] Don't print out always-public registers in list.
// [ ] Print out both outs and ins back-to-back if they differ.
// [ ] Label instr-ins, etc.
// [ ] Option to colorize printouts. Color newly public instructions green; color now missing instructions red.

static llvm::cl::opt<bool> DumpResultsOpt {
  PASS_KEY "-dump",
  cl::desc("Dump privacy types"),
  cl::init(false),
  cl::Hidden,
};

static llvm::cl::opt<bool> DumpResultsPartialOpt {
  PASS_KEY "-dump-partial",
  cl::desc("Dump partial privacy types"),
  cl::init(false),
  cl::Hidden,
};

// PTEX-TODO: Rename to DumpDelta.
static llvm::cl::opt<bool> DumpIncrementalOpt {
  PASS_KEY "-dump-incr",
  cl::desc("Dump incremental privacy types"),
  cl::init(false),
  cl::Hidden,
};

static llvm::cl::opt<std::string> DumpFilter {
  "x86-ptex-dump-filter",
  cl::desc("Only dump given functions, as comma-separated list"),
  cl::init(""),
  cl::Hidden,
};

static cl::opt<bool> FutureLeakage {
  PASS_KEY "-future-only",
  cl::desc("[PTeX] Only mark data public if it'll leak in the future along all control-flow paths"),
  cl::init(false), // PTEX-TODO: Change this if we commit to it.
  cl::Hidden,
};

namespace llvm::X86 {
bool DumpCheckFilter(const MachineFunction &MF) {
  const std::string &s = DumpFilter.getValue();
  return s.empty() || s == MF.getName();
}
}

static bool DumpResults(const MachineFunction &MF) {
  return DumpResultsOpt && X86::DumpCheckFilter(MF);
}

static bool DumpResultsPartial(const MachineFunction &MF) {
  return DumpResultsPartialOpt && X86::DumpCheckFilter(MF);
}

static bool DumpIncremental(const MachineFunction &MF) {
  return DumpIncrementalOpt && X86::DumpCheckFilter(MF);
}

static std::array<Register, 5> AlwaysPublicRegisters = {
  X86::NoRegister, X86::RSP, X86::RIP, X86::SSP, X86::MXCSR,
};

namespace llvm::X86 {
ArrayRef<Register> getAlwaysPublicRegisters() {
  return AlwaysPublicRegisters;
}
}

bool llvm::X86::registerIsAlwaysPublic(Register Reg) {
  return llvm::is_contained(AlwaysPublicRegisters, PrivacyMask::canonicalizeRegister(Reg));
}

X86::PrivacyMask::Bitset X86::PrivacyMask::getPrivateBitset() const {
  Bitset bitset = this->PubRegs;
  bitset.flip();
  return bitset;
}

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

bool PrivacyMask::isCanonicalRegister(Register Reg) {
  return canonicalizeRegister(Reg) == Reg;
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

[[nodiscard]] static bool getInstrPublic(const MachineInstr& MI) {
  return X86::getInstrPrivacy(MI) == PubliclyTyped;
}

[[nodiscard]] static bool setInstrPublic(MachineInstr &MI) {
  const bool Changed = !getInstrPublic(MI);
  X86::setInstrPrivacy(MI, PubliclyTyped);
  return Changed;
}


void X86PrivacyTypeAnalysis::addBlockEdge(MachineBasicBlock *Src, MachineBasicBlock *Dst) {
  BlockSuccessors[Src].insert(Dst);
  BlockPredecessors[Dst].insert(Src);
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
  if (MI.mayLoad() && !getInstrPublic(MI))
    return false;
  
  for (const MachineOperand &MO : MI.operands())
    if (MO.isReg() && MO.isUse() && !MO.isUndef() && Privacy.get(MO.getReg()) == PrivatelyTyped)
      return false;

  return true;
}

bool X86::isPush(const MachineInstr &MI) {
  switch (MI.getOpcode()) {
  case X86::PUSH16r:
  case X86::PUSH32r:
  case X86::PUSH16rmr:
  case X86::PUSH32rmr:
  case X86::PUSH16rmm:
  case X86::PUSH32rmm:
  case X86::PUSH64r:
  case X86::PUSH64rmr:
  case X86::PUSH64rmm:
    return true;
  default:
    return false;
  }
}

void X86::getInstrDataOutputs(const MachineInstr &MI, SmallVectorImpl<const MachineOperand *> &Outs) {
  if (MI.isCall() || MI.isReturn() || MI.isBranch())
    return;

  for (const MachineOperand &MO : MI.operands())
    if (MO.isReg() && MO.isDef())
      if (!(MO.isImplicit() && registerIsAlwaysPublic(MO.getReg())))
        Outs.push_back(&MO);
}

void X86::PrivacyMask::markAllInstrOutsPublic(const MachineInstr &MI) {
  for (const MachineOperand &MO : MI.operands())
    if (MO.isReg() && MO.isDef())
      set(MO.getReg(), PubliclyTyped);
}

static bool anyDataOutputPublic(const MachineInstr &MI, const PrivacyMask &Privacy) {
  SmallVector<const MachineOperand *, 2> Outputs;      
  X86::getInstrDataOutputs(MI, Outputs);
  for (const MachineOperand *MO : Outputs)
    if (Privacy.get(MO->getReg()) == PubliclyTyped)
      return true;

  return false;
}

static void setClobberedRegistersPrivacy(const MachineInstr &MI, PrivacyMask &Privacy, PrivacyType Ty) {
  for (const MachineOperand& MO : MI.operands()) {
    if (MO.isReg()) {
      if (MO.isDef())
        Privacy.set(MO.getReg(), Ty);
    } else if (MO.isRegMask()) {
      assert((MI.isCall() || MI.getOpcode() == X86::EH_SjLj_Setup)
             && "Found RegMask operand in non-call instruction!");
      Privacy.setRegMask(MO.getRegMask(), Ty, true);
    }
  }
}

#if 0
// Whether the instruction can be treated as if it has arithmetic dependencies, i.e.,
// the outputs are public iff the inputs are public.
static bool isArithInstr(const MachineInstr &MI) {
  // If there are no output registers, then trivially not arithmetic.
  if (llvm::none_of(MI.operands(), [] (const MachineOperand &MO) -> bool {
    return MO.isReg() && MO.isDef();
  }))
    return false;

  // Control flow instructions aren't arithmetic.
  if (MI.isCall() || MI.isBranch())
    return false;

  // If it has at least one non-implicit-or-EFLAGS output, assume arithmetic.
  if (llvm::none_of(MI.operands(), [] (const MachineOperand &MO) -> bool {
    return MO.isReg() && MO.isDef() && (!MO.isImplicit() || MO.getReg() == X86::EFLAGS);
  })) {
    return true;
  }

  // Pushes and pops aren't arithmetic.
  switch (MI.getOpcode()) {
  case X86::PUSH16r:
  case X86::PUSH32r:
  case X86::PUSH16rmr:
  case X86::PUSH32rmr:
  case X86::PUSH16rmm:
  case X86::PUSH32rmm:
  case X86::PUSH64r:
  case X86::PUSH64rmr:
  case X86::PUSH64rmm:
    return false;
  }

  
  errs() << MI;
  report_fatal_error("unhandled instruction with only implicit outputs");
}
#endif

void X86PrivacyTypeAnalysis::run() {
  [[maybe_unused]] const TargetInstrInfo *TII = MF.getSubtarget().getInstrInfo();
  [[maybe_unused]] const TargetRegisterInfo *TRI = MF.getSubtarget().getRegisterInfo();

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


  if (DumpResultsPartial(MF)) {
    errs() << "==== Privacy Types (Partial, Before Init) =====\n";
    dumpResults(errs(), MF);
    errs() << "===============================================\n";
  }

  // Step 1: Mark all transmitted operands as public.
  for (MachineBasicBlock &MBB : MF) {
    for (MachineInstr &MI : MBB) {

      auto PubliclyTypeUse = [&] (const MachineOperand &MO) {
        if (!MO.isReg())
          return;
        assert(MO.isUse());
        if (MO.isUndef())
          return;
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

  if (DumpResultsPartial(MF)) {
    errs() << "==== Privacy Types (Partial, After Xmits) =====\n";
    dumpResults(errs(), MF);
    errs() << "===============================================\n";
  }
  
  // Step 2: Mark all inputs/outputs of accesses to pointer data public.
  for (MachineBasicBlock &MBB : MF) {
    for (MachineInstr &MI : MBB) {
      for (MachineMemOperand *MMO : MI.memoperands()) {
        if (!MMO->getType().isPointer())
          continue;
        (void) setInstrPublic(MI);
        for (const MachineOperand &MO : MI.operands()) {
          if (!MO.isReg())
            continue;
          const Register Reg = MO.getReg();
          if (MO.isUse() && !MO.isUndef()) {
            getInstrPrivacyIn(&MI).set(Reg, PubliclyTyped);
          } else if (MO.isDef() && !MI.isCall()) {
            getInstrPrivacyOut(&MI).set(Reg, PubliclyTyped);
          }
        }
      }
    }
  }

  if (DumpResultsPartial(MF)) {
    errs() << "==== Privacy Types (Partial, After Pointers) =====\n";
    dumpResults(errs(), MF);
    errs() << "===============================================\n";
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

  if (DumpResultsPartial(MF)) {
    errs() << "==== Privacy Types (Partial, After Always-Public) =====\n";
    dumpResults(errs(), MF);
    errs() << "=======================================================\n";
  }
  
  // Step 4: Mark all frame setup and destroy inputs/outputs publicly-typed.
  for (MachineBasicBlock &MBB : MF) {
    for (MachineInstr &MI : MBB) {
      if (MI.getFlag(MachineInstr::FrameSetup) ||
          MI.getFlag(MachineInstr::FrameDestroy)) {
        for (MachineOperand &MO : MI.operands()) {
          if (MO.isReg()) {
            if (MO.isUse()) {
              if (!MO.isUndef())
                getInstrPrivacyIn(&MI).set(MO.getReg(), PubliclyTyped);
            } else if (MO.isDef()) {
              getInstrPrivacyOut(&MI).set(MO.getReg(), PubliclyTyped);
            } else {
              llvm_unreachable("register operand is neither def nor use!");
            }
          }
        }
      }
    }
  }

  if (DumpResultsPartial(MF)) {
    errs() << "===== Privacy Types (Partial, After Frame-Setup/Destroy) =====\n";
    dumpResults(errs(), MF);
    errs() << "==============================================================\n";
  }

  // Step 5: Mark all pointer call arguments public.
  {
    const auto &CSI = MF.getCallSitesInfo();
    for (MachineBasicBlock &MBB : MF) {
      for (MachineInstr &MI : MBB) {
        if (!MI.isCall())
          continue;
        const auto it = CSI.find(&MI);
        if (it == CSI.end()) {
          LLVM_DEBUG(dbgs() << "Call has no callsite info, skipping: " << MI);
          continue;
        }
        const MachineOperand &CalleeMO = TII->getCalleeOperand(MI);
        if (!CalleeMO.isGlobal()) {
          LLVM_DEBUG(dbgs() << "Callee operand is not global, skipping: " << MI);
          continue;
        }
        const Function *CalleeFunc = dyn_cast<Function>(CalleeMO.getGlobal());
        if (!CalleeFunc) {
          LLVM_DEBUG(dbgs() << "Skipping non-function callee: " << MI);
          continue;
        }
        const auto &ArgRegPairs = it->second.ArgRegPairs;
        if (CalleeFunc->isVarArg()) {
          LLVM_DEBUG(dbgs() << "Skipping variadic function call: " << MI);
          continue;
        }
        for (const auto &Pair : ArgRegPairs) {
          const Argument *Arg = CalleeFunc->getArg(Pair.ArgNo);
          if (Arg->getType()->isPointerTy()) {
            getInstrPrivacyIn(&MI).set(Pair.Reg, PubliclyTyped);
            LLVM_DEBUG(dbgs() << "Marked argument " << Pair.ArgNo << " (register "
                       << TRI->getRegAsmName(Pair.Reg) << ") public: " << MI);
          }
        }
      }
    }
  }

  // TODO: Should merge all into same MBB.

#if 0
  // Step 5: Mark all undef'ed register operands privately-typed.
  for (MachineBasicBlock &MBB : MF) {
    for (MachineInstr &MI : MBB) {
      for (const MachineOperand &MO : MI.operands()) {
        if (MO.isReg() && MO.isUse() && MO.isUndef()) {
          getInstrPrivacyIn(&MI).set(MO.getReg(), PrivatelyTyped);
        }
      }
    }
  }
#endif

  // PTEX-NOTE: We don't need to mark callee-saved registers as publicly-typed,
  // since the saves will be inserted later on. 

  // PTEX-TODO: Need to fix up privacy types at function entry. Specifically, type all callee-saved registers public.

  bool Changed;
  PrivacyMask Diff;
  PrivacyMask *DiffPtr = (DumpIncremental(MF) ? &Diff : nullptr);
  auto PrintDiff = [&] (const char *Name, const auto& Elt) {
    if (DiffPtr && !Diff.allPrivate()) {
      errs() << "===== " << Name << " =====\n";
      errs() << Name << ": " << Elt;
      Diff.print(errs(), MF.getSubtarget().getRegisterInfo());
      errs() << "\n==========\n";
    }
  };
  unsigned NumIters = 0;

  // PART II: Iterative data-flow propagation.
  do {
    Changed = false;

    if (DumpResultsPartial(MF)) {
      errs() << "==== Privacy Types (Partial, Before Backward, Iteration " << NumIters << ") =====\n";
      dumpResults(errs(), MF);
      errs() << "===================================================\n";
    }
    
    // SECTION II-A: Backward data-flow.
    for (MachineBasicBlock &MBB : MF) {

      // STEP II-A-1: Block-level backward meet.
      if (FutureLeakage) {
        const auto &succs = getBlockSuccessors(&MBB);
        if (!succs.empty()) {
          auto succ_it = succs.begin();
          PrivacyMask Privacy = getBlockPrivacyIn(*succ_it++);
          while (succ_it != succs.end())
            Privacy.inheritPrivate(getBlockPrivacyIn(*succ_it++));
          Changed |= getBlockPrivacyOut(&MBB).inheritPublic(Privacy, DiffPtr);
        }
      } else {
        // Register is out-typed public iff it's in-typed public along any future control-flow paths.
        for (MachineBasicBlock *SuccMBB : getBlockSuccessors(&MBB)) {
          Changed |= getBlockPrivacyOut(&MBB).inheritPublic(getBlockPrivacyIn(SuccMBB), DiffPtr);
          PrintDiff("bwd-block-out", MBB);
        }
      }

      // STEP II-A-2: Step backwards through basic block.
      PrivacyMask Privacy = getBlockPrivacyOut(&MBB);
      for (MachineInstr &MI : llvm::reverse(MBB)) {

        // SUBSTEP II-A-2-i: Copy step privacy to instruction's out-privacy.
        Changed |= getInstrPrivacyOut(&MI).inheritPublic(Privacy, DiffPtr);
        Privacy = getInstrPrivacyOut(&MI);
        PrintDiff("bwd-instr-out", MI);
        // PTEX-TODO: Should we assert equality?

        // SUBSTEP II-A-2-ii: Mark instruction public if any data outputs are public.
        if (anyDataOutputPublic(MI, Privacy)) {
#if 0
          for (const MachineOperand &MO : MI.operands())
            if (MO.isReg() && MO.isDef())
              Privacy.set(MO.getReg(), PubliclyTyped);
#endif
          if (DumpIncremental(MF) && !getInstrPublic(MI))
            errs() << "bwd-instr-pub: " << MI;
          Changed |= setInstrPublic(MI);
        }

        // SUBSTEP II-A-2-iii: Mark all clobbered registers private.
        setClobberedRegistersPrivacy(MI, Privacy, PrivatelyTyped);

        // SUBSTEP II-A-2-iv: Mark all inputs public if instruction is public.
        if (getInstrPublic(MI)) {
          for (const MachineOperand &MO : MI.operands()) {
            if (MO.isReg() && MO.isUse() && !MO.isUndef()) {
              Privacy.set(MO.getReg(), PubliclyTyped);
            }
          }
        }

        // SUBSTEP II-A-2-v: Copy out step privacy to instruction's in-privacy.
        Changed |= getInstrPrivacyIn(&MI).inheritPublic(Privacy, DiffPtr);
        Privacy = getInstrPrivacyIn(&MI);
        PrintDiff("bwd-instr-in", MI);
        
      }

      // STEP II-A-3: Copy out privacy to block's in-privacy.
      Changed |= getBlockPrivacyIn(&MBB).inheritPublic(Privacy, DiffPtr);
      PrintDiff("bwd-block-in", MBB);
    }

    if (DumpResultsPartial(MF)) {
      errs() << "==== Privacy Types (Partial, After Backward, Before Forward, Iteration " << NumIters << ") =====\n";
      dumpResults(errs(), MF);
      errs() << "==================================================================\n";
    }

    // SECTION II-B: Forward data-flow.
    for (MachineBasicBlock &MBB : MF) {

      // STEP II-B-1: Basic block forward meet.
      if (&MBB != &MF.front()) {
        const auto& preds = getBlockPredecessors(&MBB);
        assert(!preds.empty() && "A non-entry MBB has no predecessors!");
        auto pred_it = preds.begin();
        PrivacyMask Privacy = getBlockPrivacyOut(*pred_it++);
        while (pred_it != preds.end())
          Privacy.inheritPrivate(getBlockPrivacyOut(*pred_it++));
        Changed |= getBlockPrivacyIn(&MBB).inheritPublic(Privacy, DiffPtr);
      }

      // STEP II-B-2: Step forward through basic block.
      PrivacyMask Privacy = getBlockPrivacyIn(&MBB);
      for (MachineInstr &MI : MBB) {

        // SUBSTEP II-B-2-i: Copy step privacy to instruction's in-privacy.
        Changed |= getInstrPrivacyIn(&MI).inheritPublic(Privacy, DiffPtr);
        Privacy = getInstrPrivacyIn(&MI);
        PrintDiff("fwd-instr-in", MI);
        // PTEX-TODO: Assert equality here?

        // SUBSTEP II-B-2-ii: Mark insturction public if all data inputs are public.
        if (allInputsPublic(MI, Privacy) && !MI.isCall()) {
          if (DumpIncremental(MF) && !getInstrPublic(MI))
            errs() << "fwd-instr-pub " << MI;
          Changed |= setInstrPublic(MI);
        }

        // SUBSTEP II-B-2-iii: Mark all clobbered registers private.
        setClobberedRegistersPrivacy(MI, Privacy, PrivatelyTyped);

        // SUBSTEP II-B-2-iv: Mark all outputs public if instruction is public.
        if (getInstrPublic(MI)) {
          for (const MachineOperand &MO : MI.operands()) {
            if (MO.isReg() && MO.isDef()) {
              Privacy.set(MO.getReg(), PubliclyTyped);
            }
          }
        }

        // SUBSTEP II-B-2-v: Copy out privacy to instruction out-privacy.
        Changed |= getInstrPrivacyOut(&MI).inheritPublic(Privacy, DiffPtr);
        Privacy = getInstrPrivacyOut(&MI);
        PrintDiff("fwd-instr-out", MI);
      }

      // STEP II-B-3: Copy out step privacy to block out-privacy.
      Changed |= getBlockPrivacyOut(&MBB).inheritPublic(Privacy, DiffPtr);
    }

    ++NumIters;

    // dumpResults(errs(), MF);

  } while (Changed);

  // PTEX-TODO: Need to make sure we mark that CSRs are publicly-typed at function entry and function exits!

  // PTEX-TODO: Consider adding an instruction flag to mark whether an instruction that may load is publicly-typed.

  // Print out for debugging.
  if (DumpResults(MF)) {
    dumpResults(errs(), MF);
  }

  validate(MF);  
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
  // TODO: This is redundant I think./
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

#if 0
  // Ensure all undef'ed registers are privately-typed.
  for (MachineBasicBlock &MBB : MF) {
    for (MachineInstr &MI : MBB) {
      for (const MachineOperand &MO : MI.operands()) {
        if (MO.isReg() && MO.isUse() && MO.isUndef()) {
          assert(getInstrPrivacyIn(&MI).get(MO.getReg()) == PrivatelyTyped);
        }
      }
    }
  }
#endif
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
