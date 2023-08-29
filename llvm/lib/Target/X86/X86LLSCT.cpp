#include "X86LLSCT.h"

#include <optional>

#include "X86.h"
#include "X86InstrBuilder.h"
#include "X86Subtarget.h"
#include "llvm/CodeGen/MachineBasicBlock.h"
#include "llvm/CodeGen/MachineFunction.h"
#include "llvm/CodeGen/MachineInstr.h"
#include "llvm/CodeGen/MachineFunctionPass.h"
#include "llvm/CodeGen/MachineModuleInfo.h"
#include "llvm/Pass.h"
#include "llvm/CodeGen/LivePhysRegs.h"
#include "llvm/Support/WithColor.h"
#include "llvm/IR/Value.h"
#include "llvm/Analysis/ValueTracking.h"
#include "llvm/Analysis/AliasAnalysis.h"
#include "X86Declassify.h"

using namespace llvm;
using namespace llsct;

#define PASS_KEY "llsct"
#define DEBUG_TYPE PASS_KEY

namespace llsct {
  bool EnableLLSCT;
}

static cl::opt<bool, true> EnableLLSCTOpt {
  PASS_KEY,
  cl::desc("Enable LLSCT"),
  cl::location(llsct::EnableLLSCT),
  cl::init(false),
};

static cl::opt<bool> EnableLLSCTRet {
  PASS_KEY "-ret",
  cl::desc("Enable LLSCT Return Hardening"),
  cl::init(false),
};

static cl::opt<bool> EnableLLSCTStackInit {
  PASS_KEY "-stackinit",
  cl::desc("Enable LLSCT Stack Initialization"),
  cl::init(false),
};

static cl::opt<bool> EnableDeclassify {
  PASS_KEY "-declassify",
  cl::desc("Enable LLSCT's Declassification Hint Pass"),
  cl::init(false),
};

static cl::opt<bool> DumpMIR {
  PASS_KEY "-dump-mir",
  cl::desc("Dump Machine IR coming into LLSCT Pass"),
  cl::init(false)
};

namespace llvm::X86 {
  int getMemRefBeginIdx(const MCInstrDesc& Desc) {
    int MemRefBeginIdx = X86II::getMemoryOperandNo(Desc.TSFlags);
    if (MemRefBeginIdx < 0)
      return -1;
    MemRefBeginIdx += X86II::getOperandBias(Desc);
    return MemRefBeginIdx;
  }

  int getMemRefBeginIdx(const MachineInstr& MI) {
    return getMemRefBeginIdx(MI.getDesc());
  }
}

namespace {

  class X86LLSCT final : public MachineFunctionPass {
  public:
    static char ID;
    X86LLSCT(): MachineFunctionPass(ID) {}

  private:
    void getAnalysisUsage(AnalysisUsage& AU) const override {
      AU.setPreservesCFG();
      AU.addRequired<AAResultsWrapperPass>();
      MachineFunctionPass::getAnalysisUsage(AU);
    }

    bool runOnMachineFunction(MachineFunction& MF) override;
  };

  char X86LLSCT::ID = 0;

  bool hasMemRef(const MCInstrDesc& Desc) {
    return X86::getMemRefBeginIdx(Desc) >= 0;
  }

  bool hasMemRef(const MachineInstr& MI) {
    return X86::getMemRefBeginIdx(MI) >= 0;
  }

  // InsertPt points to one past the call.
  bool hardenPostCall(MachineBasicBlock& MBB, MachineInstr& Ret, MachineBasicBlock::iterator InsertPt,
		      iterator_range<LivePhysRegs::const_iterator> LiveRegs, DebugLoc Loc = DebugLoc()) {
    MachineFunction& MF = *MBB.getParent();
    const auto *TRI = MF.getSubtarget<X86Subtarget>().getRegisterInfo();
    const auto *TII = MF.getSubtarget().getInstrInfo();
    const auto *FrameLowering = MF.getSubtarget().getFrameLowering();
    MCSymbol *RetSymbol = MF.getContext().createTempSymbol("llsct_ret_addr", /*AlwaysAddSuffix*/ true);
    Ret.setPostInstrSymbol(MF, RetSymbol);

    const Register ExpectedReg = X86::R11;
    const Register ActualReg = X86::RDI;
    const Register ZeroSubReg = X86::ESI;
    const Register ZeroReg = X86::RSI;
    // mov %expected, [rsp-8]
    BuildMI(MBB, InsertPt, Loc, TII->get(X86::MOV64rm), ExpectedReg)
      .addReg(/*Base*/ X86::RSP)
      .addImm(/*Scale*/ 1)
      .addReg(/*Index*/ X86::NoRegister)
      .addImm(/*Displacement*/ -8)
      .addReg(/*Segment*/ X86::NoRegister);
    // lea %actual, [postcall]
    BuildMI(MBB, InsertPt, Loc, TII->get(X86::LEA64r), ActualReg)
      .addReg(/*Base*/ X86::RIP)
      .addImm(/*Scale*/ 1)
      .addReg(/*Index*/ X86::NoRegister)
      .addSym(/*Disp*/ RetSymbol)
      .addReg(/*Segment*/ X86::NoRegister);
    // mov %zero, 0
    BuildMI(MBB, InsertPt, Loc, TII->get(X86::MOV32r0), ZeroSubReg);
    BuildMI(MBB, InsertPt, Loc, TII->get(X86::SUBREG_TO_REG), ZeroReg)
      .addImm(0)
      .addReg(ZeroSubReg)
      .addImm(X86::sub_32bit);
    // cmp %expected, %actual
    BuildMI(MBB, InsertPt, Loc, TII->get(X86::CMP64rr))
      .addReg(ExpectedReg)
      .addReg(ActualReg);
    
    llvm::SmallSet<Register, 8> Seen;
    const auto HardenReg = [&] (Register Reg) {
      assert(Reg.isPhysical() && "stack pointer must be physical register");
      if (!Seen.insert(Reg).second)
	return;
      BuildMI(MBB, InsertPt, Loc, TII->get(X86::CMOV64rr), Reg)
	.addReg(Reg)
	.addReg(ZeroReg)
	.addImm(X86::COND_NE);
    };
    HardenReg(X86::RSP);
    if (FrameLowering->hasFP(MF))
      HardenReg(X86::RBP);
    if (TRI->hasBasePointer(MF))
      HardenReg(X86::RBX);

    // Skip all implicit defs of call, since these are return value registers?
    for (const MachineOperand& MO : Ret.implicit_operands())
      if (MO.isReg() && MO.isImplicit() && MO.isDef())
	Seen.insert(getX86SubSuperRegisterOrZero(MO.getReg(), 64));
    
    for (const Register SubLiveReg : LiveRegs) {
      assert(SubLiveReg.isPhysical() && "All registers should be physical at this point");
      const Register LiveReg = getX86SubSuperRegisterOrZero(SubLiveReg, 64);
      if (LiveReg != X86::NoRegister)
	HardenReg(LiveReg);
    }

    return true;
  }
  
  bool hardenPostCalls(MachineBasicBlock& MBB) {
    auto& MF = *MBB.getParent();
    const auto *TRI = MF.getSubtarget().getRegisterInfo();
    
    bool changed = false;
    auto MBBI = MBB.begin();
    while (MBBI != MBB.end()) {
      const bool isCall = MBBI->isCall() && !MBBI->isReturn();
      MachineInstr& MI = *MBBI;
      LivePhysRegs LiveRegs(*TRI);
      {
	LiveRegs.addLiveOuts(MBB);
	for (MachineInstr& StepMI : reverse(MBB)) {
	  if (&StepMI == &MI)
	    break;
	  LiveRegs.stepBackward(StepMI);
	}
      }
      ++MBBI;
      if (isCall)
	changed |= hardenPostCall(MBB, MI, MBBI, LiveRegs);
    }
    return changed;
  }


  bool hardenPostCalls(MachineFunction& MF) {
    bool changed = false;
    for (auto& MBB : MF)
      changed |= hardenPostCalls(MBB);
    return changed;
  }

  struct StackSlot {
    int FrameIdx;
    uint64_t Bytes;
    unsigned Offset;
    const MachineInstr *Load;
    const MachineMemOperand *MemOp;
  };

  bool stackInit(MachineFunction& MF) {
    bool changed = false;
    const auto *TII = MF.getSubtarget().getInstrInfo();
    
    std::vector<StackSlot> slots;
    
    for (MachineBasicBlock& MBB : MF) {
      for (MachineInstr& MI : MBB) {
	// Only considering stack memory constant-addressed by loads.
	if (!MI.mayLoad())
	  continue;

	// Check for single memory operand.
	// Otherwise we bail for now.
	if (!MI.hasOneMemOperand())
	  continue;

	const MachineMemOperand *MMO = MI.memoperands()[0];
	const Value *Ptr = MMO->getValue();
	if (!Ptr)
	  continue;

	// Check if it's a stack access.
	{
	  int64_t AllocOffset;
	  const DataLayout DL(MF.getFunction().getParent());
	  const Value *BasePtr = GetPointerBaseWithConstantOffset(Ptr, AllocOffset, DL);
	  if (!(BasePtr && isa<AllocaInst>(BasePtr)))
	    continue;
	}
	
	const int Idx = X86::getMemRefBeginIdx(MI);
	assert(Idx >= 0 && "Expect a nonnegative mem ref index begin for IR-visible stack accesses!");
	const MachineOperand& Base = MI.getOperand(Idx + X86::AddrBaseReg);
	if (!Base.isFI()) {
	  auto& os = WithColor::warning() << __FILE__ << ":" << __LINE__ << ": skipping CA stack load with non-FI base operand: ";
	  MI.print(os);
	  continue;
	}

	assert(Base.isFI() && "Expect frame index for address base!");
	assert(MI.getOperand(Idx + X86::AddrScaleAmt).getImm() > 0 && "Bad scale amount!");
	assert(MI.getOperand(Idx + X86::AddrIndexReg).getReg() == X86::NoRegister && "Have an index register in a CA stack access!");

	StackSlot slot;
	slot.FrameIdx = Base.getIndex();

	// Don't handle arguments passed on the stack for now. We should figure out how to handle this later, though.
	if (slot.FrameIdx < 0)
	  continue;

	slot.Bytes = MMO->getSize();
	const auto Offset = MI.getOperand(Idx + X86::AddrDisp).getImm();
	assert(Offset >= 0 && "Negative offsets aren't allowed for stack slots!");
	slot.Offset = static_cast<unsigned>(Offset);
	slot.Load = &MI;
	slot.MemOp = MMO;
	slots.push_back(slot);
      }
    }
    
    // Insert initializations and set flags appropriately.
    MachineBasicBlock& Entry = MF.front();
    auto InsertPt = Entry.begin();
    DebugLoc Loc;
    for (const StackSlot& Slot : slots) {
      int Opcode;
      switch (Slot.Bytes) {
      case 1: Opcode = X86::MOV8mi; break;
      case 2: Opcode = X86::MOV16mi; break;
      case 4: Opcode = X86::MOV32mi; break;
      case 8: Opcode = X86::MOV64mi32; break;
      case 16: // XMM
      case 10: // FP
	// FIXME: We're just ignoring 128 XMM loads for now.
	continue;
      case 0:
	WithColor::warning() << "unknown frame index size in load: " << *Slot.Load;
	continue;
      default:
	WithColor::warning() << "unexpected frame index size " << Slot.Bytes << " in load: " << *Slot.Load;
	continue;
      }
      MachineInstr& MI = *BuildMI(Entry, InsertPt, Loc, TII->get(Opcode))
	.addFrameIndex(Slot.FrameIdx)
	.addImm(1)
	.addReg(X86::NoRegister)
	.addImm(Slot.Offset)
	.addReg(X86::NoRegister)
	.addImm(0)
	.addMemOperand(MF.getMachineMemOperand(Slot.MemOp, Slot.MemOp->getFlags() | static_cast<MachineMemOperand::Flags>(X86::AcSsbd)));
      
      changed = true;
    }

    return changed;
  }


#if 0
  bool annotateIndirectAddressible(MachineFunction& MF) {
    bool changed = false;

    // Simply mark all IR-visible constant-address stack accesses as indirect-addressible.
    // We can have a more intelligent and performant version of this later on.

    for (MachineBasicBlock& MBB : MF) {
      for (MachineInstr& MI : MBB) {
	if (!MI.mayLoadOrStore())
	  continue;

	// For now, only handle instructions with <= 1 memory operand.
	if (MI.getNumMemOperands() > 1)
	  continue;

	if (MI.getNumMemOperands() == 0) {
	  const int Idx = X86::getMemRefBeginIdx(MI);
	  assert(Idx < 0 && "We expect there to be a memory operand accompanying a memory ref!");
	  assert(MI.hasRegisterImplicitUseOperand(X86::RSP) && "Expect there to be an implicit access of the stack!");
	  continue;
	}

	MachineMemOperand *MMO = MI.memoperands()[0];

	const Value *Ptr = MMO->getValue();
	if (!Ptr)
	  continue;

	{
	  int64_t AllocOffset;
	  const DataLayout DL(MF.getFunction().getParent());
	  const Value *BasePtr = GetPointerBaseWithConstantOffset(Ptr, AllocOffset, DL);
	  if (!(BasePtr && isa<AllocaInst>(BasePtr)))
	    continue;
	}

	MMO->setFlags(static_cast<MachineMemOperand::Flags>(X86::AcIndAddr));
      }
    }
    

    return changed;
  }
#endif

  StringRef getInstrName(const MachineInstr& MI) {
    const MCInstrInfo *MII = MI.getMF()->getSubtarget().getInstrInfo();
    // const MCInstrDesc &MCID = MII->get(MI.getOpcode());
    return MII->getName(MI.getOpcode());
  }
  

#if 0
  void experiments(const MachineFunction& MF) {
    const auto *TII = MF.getSubtarget().getInstrInfo();
    for (const MachineBasicBlock& MBB : MF) {
      for (const MachineInstr& MI : MBB) {
	if (MI.mayLoadOrStore()) {
	  errs() << "Instruction: ";
	  MI.dump();
	}
	if (MI.mayLoad()) {
	  unsigned LoadRegIndex;
	  const unsigned UnfoldOpcode =
	    TII->getOpcodeAfterMemoryUnfold(X86::PUSH64rmm/*MI.getOpcode()*/, /*unfoldLoad*/true, /*unfoldStore*/false, &LoadRegIndex);
	  errs() << "Unfolded load opcode: " << getInstrName(MI) << " " << (int) LoadRegIndex << "\n";
	}
	if (MI.mayStore()) {
	  unsigned StoreRegIndex;
	  const unsigned UnfoldOpcode = TII->getOpcodeAfterMemoryUnfold(MI.getOpcode(),
									/*unfoldLoad*/false, /*unfoldStore*/true,
									&StoreRegIndex);
	  errs() << "Unfolded store opcode: " << getInstrName(MI) << " " << (int) StoreRegIndex << "\n";
	}
      }
    }
  }
#endif
  

  bool X86LLSCT::runOnMachineFunction(MachineFunction& MF) {
    if (DumpMIR)
      MF.dump();
    
    if (!EnableLLSCT)
      return false;

    if (EnableDeclassify)
      X86::runDeclassificationPass(MF);

#if 0
    for (BasicBlock& B : MF.getFunction()) {
      [[maybe_unused]] volatile std::string s = static_cast<Value *>(&B)->getNameOrAsOperand();
    }
#endif

    // Populate SSBD flag.
    
    bool changed = false;
    if (EnableLLSCTRet)
      changed |= hardenPostCalls(MF);
    if (EnableLLSCTStackInit)
      changed |= stackInit(MF);
#if 0
    if (EnableLLSCTIndAddr)
      changed |= annotateIndirectAddressible(MF);
#endif

    // Protect test
#if 0
    {
      MachineBasicBlock& Entry = MF.front();
      auto InsertPt = Entry.begin();
      const auto *TII = MF.getSubtarget().getInstrInfo();
      BuildMI(Entry, InsertPt, DebugLoc(), TII->get(X86::PROTECT), X86::RSP)
	.addReg(X86::RSP);
      changed = true;
    }
#endif

    return changed;
  }
  
  
}


static bool isNcaMemRef(const MachineInstr& MI, int MemIdx) {
  const MachineOperand& BaseMO = MI.getOperand(MemIdx + X86::AddrBaseReg);
  const MachineOperand& IndexMO = MI.getOperand(MemIdx + X86::AddrIndexReg);
  
  // If we have at least one (non-frame-index, non-RIP) register operand,
  // and neither operand is load-dependent, we need to check the load.
  unsigned BaseReg = 0, IndexReg = 0;
  if (!BaseMO.isFI() && BaseMO.getReg() != X86::RIP &&
      BaseMO.getReg() != X86::NoRegister)
    BaseReg = BaseMO.getReg();
  if (IndexMO.getReg() != X86::NoRegister)
    IndexReg = IndexMO.getReg();

  return BaseReg || IndexReg;
}

#if 0
MachineInstr::StFlags_t llvm::X86::getDefaultStoreFlags_Prologue() {
  return MachineInstr::StEnable | MachineInstr::StSsbd | MachineInstr::StStrict | MachineInstr::StSecret;
}

MachineInstr::StFlags_t llvm::X86::getDefaultStoreFlags_CaStack() {
  return MachineInstr::StEnable | MachineInstr::StSsbd | MachineInstr::StSecret;
}

MachineInstr::StFlags_t llvm::X86::getDefaultStoreFlags_CaGlobal() {
  return MachineInstr::StEnable;
}

MachineInstr::StFlags_t llvm::X86::getDefaultStoreFlags_Nca() {
  return MachineInstr::StEnable | MachineInstr::StNca | MachineInstr::StSecret;
}

MachineInstr::LdFlags_t llvm::X86::getDefaultLoadFlags_Epilogue() {
  return MachineInstr::LdEnable | MachineInstr::LdSsbd | MachineInstr::LdStrict | MachineInstr::LdLeak;
}

MachineInstr::LdFlags_t llvm::X86::getDefaultLoadFlags_CaStack() {
  return MachineInstr::LdEnable | MachineInstr::LdSsbd | MachineInstr::LdLeak;
}

MachineInstr::LdFlags_t llvm::X86::getDefaultLoadFlags_CaGlobal() {
  return MachineInstr::LdEnable;
}

MachineInstr::LdFlags_t llvm::X86::getDefaultLoadFlags_Nca() {
  return MachineInstr::LdEnable | MachineInstr::LdNca | MachineInstr::LdLeak;
}
#endif


#if 0
void llvm::X86::getAccessInfo(const MachineInstr& MI, SmallVectorImpl<AccessInfo>& Infos) {
  const MachineFunction& MF = *MI.getMF();
  const auto *TRI = MF.getSubtarget<X86Subtarget>().getRegisterInfo();
  const auto *TFL = MF.getSubtarget().getFrameLowering();
  const unsigned Opcode = MI.getOpcode();
  
  if (!MI.mayLoadOrStore())
    return;
  

  // "Constant-address" registers: stack pointer, frame pointer, and base pointer (if they exist).
  llvm::SmallSet<Register, 3> StackRegs;
  StackRegs.insert(X86::RSP);
  if (TFL->hasFP(MF))
    StackRegs.insert(TRI->getFramePtr());
  if (TRI->hasBasePointer(MF))
    StackRegs.insert(TRI->getBaseRegister());


  const auto add_info = [&Infos] (AccessInfo::AccessMode Mode, AccessInfo::AccessKind Kind, const auto& AddrRegs) {
    AccessInfo Info;
    Info.Mode = Mode;
    Info.Kind = Kind;
    Info.AddrRegs = AddrRegs;
    Infos.push_back(Info);
  };
  const SmallSet<Register, 2> NoAddrRegs;

  // Compute memory reference registers.
  std::optional<AccessInfo::AccessKind> MemRefKind;
  SmallSet<Register, 2> MemRefAddrRegs;
  const int MemRefIdx = X86::getMemRefBeginIdx(MI);
  if (MemRefIdx >= 0) {
    const MachineOperand& BaseMO = MI.getOperand(MemRefIdx + X86::AddrBaseReg);
    const MachineOperand& IndexMO = MI.getOperand(MemRefIdx + X86::AddrIndexReg);
    assert((BaseMO.isReg() || IndexMO.isReg()) && "At least one of base and index addrs must be registers!");
    
    if (BaseMO.isReg()) {
      const Register BaseReg = BaseMO.getReg();
      if (BaseReg == X86::NoRegister || BaseReg == X86::RIP) {
	MemRefKind = AccessInfo::Global;
      } else if (StackRegs.contains(BaseReg)) {
	MemRefKind = AccessInfo::Stack;
      } else {
	MemRefAddrRegs.insert(BaseReg);
	MemRefKind = AccessInfo::Nca;
      }
    } else if (BaseMO.isFI()) {
      MemRefKind = AccessInfo::Stack;
    } else if (BaseMO.isGlobal() || BaseMO.isSymbol()) {
      MemRefKind = AccessInfo::Global;
    } else {
      llvm_unreachable("Unhandled operand!");
    }

    if (IndexMO.isReg()) {
      const Register IndexReg = IndexMO.getReg();
      assert((!StackRegs.contains(IndexReg) && IndexReg != X86::RIP) && "Unexpected index register!");
      if (IndexReg != X86::NoRegister) {
	MemRefAddrRegs.insert(IndexReg);
	MemRefKind = AccessInfo::Nca;
      }
    } else if (MemRefKind != AccessInfo::Nca) {
      llvm_unreachable("Unhandled case!");
    }

    assert(MemRefKind >= 0 && "MemRefKind unset!");
  }

  const auto add_memref = [&] (AccessInfo::AccessMode Mode) {
    assert(MemRefIdx >= 0 && "Calling add_memref without memory reference!");
    AccessInfo Info;
    Info.Mode = Mode;
    Info.Kind = *MemRefKind;
    Info.AddrRegs = MemRefAddrRegs;
  };
  

  switch (Opcode) {
  // These instructions don't actually access memory.
  case X86::TRAP:
  case X86::INLINEASM:
  case X86::MFENCE:
  case X86::LFENCE:
    return;

  case X86::PUSH64r:
    add_info(AccessInfo::Store, AccessInfo::Stack, NoAddrRegs);
    return;

  case X86::POP64r:
    add_info(AccessInfo::Load, AccessInfo::Stack, NoAddrRegs);
    break;

  case X86::MOV64rm:
    add_memref(AccessInfo::Load);
    return;

  case X86::MOV8mi:
  case X86::MOV32mr:
  case X86::MOV64mr:
  case X86::MOVSDmr:
    add_memref(AccessInfo::Store);
    break;
    
  default:
    WithColor::error() << __FILE__ << ":" << __LINE__ << ": unhandled instruction: "; MI.print(errs());
    std::exit(1);
  }
}
#endif

#if 0

using LK = MachineInstr::LoadKind;
LK llvm::X86::classifyLoad(const MachineInstr& MI) {
  const auto *TII = MI.getMF()->getSubtarget().getInstrInfo();
  const unsigned Opcode = MI.getOpcode();
  
  if (!MI.mayLoad() || Opcode == X86::TRAP)
    return LK::None;

  if (Opcode == X86::INLINEASM) {
    LLVM_DEBUG(dbgs() << "  Skipping inline assembly that may load: ";
	       MI.dump());
    return LK::None;
  }

  if (Opcode == X86::MFENCE || Opcode == X86::LFENCE)
    return LK::None;

  if (MI.isIndirectBranch())
    return LK::Nca;

  assert(!MI.getFlag(MachineInstr::FrameSetup) && "Not expecting loads in frame setup!");

  // Check if it's an epilogue store.
  if (MI.getFlag(MachineInstr::FrameDestroy)) {
    assert(!hasMemRef(MI) && "Not expecting loads to have memory reference operand in frame destroy!");
    return LK::Epilogue;
  }

  // Check if there is NCA load.
  const int MemRef = X86::getMemRefBeginIdx(MI);
  if (MemRef >= 0) {
    // Check
    const unsigned UnfoldOpcode =
      TII->getOpcodeAfterMemoryUnfold(MI.getOpcode(), /*unfoldLoad*/true, /*unfoldStore*/false, nullptr);
    if (UnfoldOpcode && hasMemRef(TII->get(UnfoldOpcode))) {
      // Then the memory ref is from something else, like a store.
      // Thus we expect this is a POP64rmm instruction.
      if (UnfoldOpcode == X86::POP64r)
	return LK::CaStack;
      llvm_unreachable("don't know how to handle this load instruction");
    }

    
    // Otherwise, the memory reference belongs to the load, and we need to analyze it.
    const MachineOperand& BaseMO = MI.getOperand(MemRef + X86::AddrBaseReg);
    const MachineOperand& IndexMO = MI.getOperand(MemRef + X86::AddrIndexReg);
    if (BaseMO.isReg()) {
      const Register BaseReg = BaseMO.getReg();
      if (BaseReg != X86::NoRegister && BaseReg != X86::RIP)
	return LK::Nca;
    }
    
    assert(IndexMO.isReg() && "Don't know how to handle non-reg index register in memory reference!");
    const Register IndexReg = BaseMO.getReg();
    if (IndexReg != X86::NoRegister)
      return LK::Nca;

    if (BaseMO.isFI()) {
      return LK::CaStack;
    }

    assert(BaseMO.isReg() && "Only registers should be the base at this point!");
    
    // if (BaseMO.isGlobal() || BaseMO.isSymbol())
    // return LK::CaGlobal;
    const Register BaseReg = BaseMO.getReg();
    assert((BaseReg == X86::NoRegister || BaseReg == X86::RIP) && "Expected a global load here!");
    return LK::CaGlobal;
  }

  switch (Opcode) {
  case X86::TAILJMPm64:
    return LK::Nca;
  }

  // No memory reference and is a load.
  llvm_unreachable("Don't know how to handle this load without a memory reference!");
}

#if 0
using SK = MachineInstr::StoreKind;
SK llvm::X86::classifyStore(const MachineInstr& MI) {
  const auto *TII = MI.getMF()->getSubtarget().getInstrInfo();

  if (!MI.mayStore())
    return SK::None;

  assert(!MI.getFlag(MachineInstr::FrameDestroy) && "Not expecting stores in frame destroy!");

  // Check if it's a prologue store.
  if (MI.getFlag(MachineInstr::FrameSetup)) {
    assert(!hasMemRef(MI) && "Not expecting stores to have memory reference operands in frame setup!");
    return SK::Prologue;
  }

  // Check if there is NCA store.
  const int MemRef = X86::getMemRefBeginIdx(MI);
  if (MmeRef >= 0) {
    const unsigned UnfoldOpcode =
      TII->getOpcodeAfterMemoryUnfold(X86::
  }
}
#endif



#if 0
MachineInstr::StFlags_t llvm::X86::getDefaultStoreFlags(const MachineInstr& MI) {
  if (!MI.mayStore())
    return MachineInstr::StNoFlags;

  const auto *TII = MI.getMF()->getSubtarget().getInstrInfo();

  // Frame setup stores (callee-saved regs, push rbp, etc.)
  // FIXME: Does this include initialization stack stores? Probably not.
  if (MI.getFlag(MachineInstr::FrameSetup)) {
    assert(!hasMemRef(MI) && "Frame setup instructions generally shouldn't have memory references!");
    // NOTE: We always assume that we're storing a secret. This is a safe and conservative assumption.
    return MachineInstr::StEnable | MachineInstr::StSsbd | MachineInstr::StStrict | MachineInstr::StSecret;
  }
  
  int MemIdx = getMemRefIdx(MI);  
  if (!MemIdx) {
    // Not sure how to handle these yet.
    // Trap and fix approach.
    MI.dump();
    llvm_unreachable("no memory reference in non-frame-setup instruction");
  }

  // Check if the memory reference is a stack store.

  MachineInstr::StFlags_t Flags; 
  if (isNcaMemRef(MI, MemIdx))
    Flags |= MachineInstr::StNca;
  Flags |= MachineInstr::StSecret;
    

  
  // Other stack stores. We assume they are public (though this may change).
  
}


MachineInstr::flags_t llvm::X86::getDefaultAccessFlags(const MachineInstr& MI) {
  const auto *TII = MI.getMF()->getSubtarget().getInstrInfo();
  
  MachineInstr::flags_t Flags = MachineInstr::NoFlags;

  if (MI.mayStore()) {
    // Frame loads.
    if (MI.getFlag(MachineInstr::FrameSetup)) {
      assert(!hasMemRef(MI) && "Frame setup instructions generally shouldn't have memory references!");
      Flags |= MachineInstr::StEnable | MachineInstr::StSsbd | MachineInstr::StClass;
    }
    
    // Strict requirement for all frame stores.
    if (MI.getFlag(MachineInstr::FrameSetup))
      Flags |= MachineInstr::StEnable | MachineInstr::StSsbd | MachineInstr::StClass;

    // Check if NCA. This might have false positives, but no false negatives.
    
      
    
    static const int PushOpcodes[] = 
    
    if (MI.getOpcode() == X86::PUSH64r) {
  }

  if (MI.mayStore()) {
    
  }

  return Flags;
}
#endif
#endif
  

INITIALIZE_PASS_BEGIN(X86LLSCT, PASS_KEY "-pass",
		      "X86 LLSCT pass", false, false)
INITIALIZE_PASS_END(X86LLSCT, PASS_KEY "-pass",
		    "X86 LLSCT pass", false, false)

FunctionPass *llvm::createX86LLSCTPass() {
  return new X86LLSCT();
}
