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

using namespace llvm;

#define PASS_KEY "llsct"
#define DEBUG_TYPE PASS_KEY

static cl::opt<bool> EnableLLSCT {
  PASS_KEY,
  cl::desc("Enable LLSCT"),
  cl::init(false),
};

static cl::opt<bool> EnableLLSCTRet {
  PASS_KEY "-ret",
  cl::desc("Enable LLSCT Return Hardening"),
  cl::init(true),
};

static cl::opt<bool> EnableLLSCTStackInit {
  PASS_KEY "-stackinit",
  cl::desc("Enable LLSCT Stack Initialization"),
  cl::init(true),
};

namespace {

  class X86LLSCT final : public MachineFunctionPass {
  public:
    static char ID;
    X86LLSCT(): MachineFunctionPass(ID) {}

  private:
    void getAnalysisUsage(AnalysisUsage& AU) const override {
      AU.setPreservesCFG();
      MachineFunctionPass::getAnalysisUsage(AU);
    }

    bool runOnMachineFunction(MachineFunction& MF) override;
  };

  char X86LLSCT::ID = 0;

  int getMemRefBeginIdx(const MachineInstr& MI) {
    const MCInstrDesc& Desc = MI.getDesc();
    int MemRefBeginIdx = X86II::getMemoryOperandNo(Desc.TSFlags);
    if (MemRefBeginIdx < 0)
      return -1;
    MemRefBeginIdx += X86II::getOperandBias(Desc);
    return MemRefBeginIdx;
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
  };

  bool stackInit(MachineFunction& MF) {
    bool changed = false;
    const auto *TII = MF.getSubtarget().getInstrInfo();
    
    std::vector<StackSlot> slots;
    
    for (MachineBasicBlock& MBB : MF) {
      for (MachineInstr& MI : MBB) {
	if (!MI.mayLoad())
	  continue;
	const int Idx = getMemRefBeginIdx(MI);
	if (Idx >= 0) {
	  // FIXME: Extract to 'is CA stack access' function.
	  // Check if frame index.
	  const MachineOperand& Base = MI.getOperand(Idx + X86::AddrBaseReg);
	  if (!Base.isFI())
	    continue;
	  
	  // Check if constant-address (i.e., index operand is noregister).
	  assert(MI.getOperand(Idx + X86::AddrScaleAmt).getImm() > 0 && "Bad scale amount!");
	  if (MI.getOperand(Idx + X86::AddrIndexReg).getReg() != X86::NoRegister)
	    continue;
	  
	  StackSlot slot;
	  slot.FrameIdx = Base.getIndex();
	  if (slot.FrameIdx < 0)
	    continue;
	  slot.Bytes = 0;
	  for (const MachineMemOperand *MMO : MI.memoperands())
	    slot.Bytes = std::max(slot.Bytes, MMO->getSize());
	  const auto Offset = MI.getOperand(Idx + X86::AddrDisp).getImm();
	  assert(Offset >= 0 && "Negative offsets aren't allowed for stack slots!");
	  slot.Offset = static_cast<unsigned>(Offset);
	  slot.Load = &MI;
	  slots.push_back(slot);
	}
      }
    }

    // Insert initializations
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
      BuildMI(Entry, InsertPt, Loc, TII->get(Opcode))
	.addFrameIndex(Slot.FrameIdx)
	.addImm(1)
	.addReg(X86::NoRegister)
	.addImm(Slot.Offset)
	.addReg(X86::NoRegister)
	.addImm(0);
      changed = true;
    }

    return changed;
  }


  bool X86LLSCT::runOnMachineFunction(MachineFunction& MF) {
    if (!EnableLLSCT)
      return false;
    
    bool changed = false;
    if (EnableLLSCTRet)
      changed |= hardenPostCalls(MF);
    if (EnableLLSCTStackInit)
      changed |= stackInit(MF);
    
    return changed;
  }
  
  
}

INITIALIZE_PASS_BEGIN(X86LLSCT, PASS_KEY,
		      "X86 LLSCT pass", false, false)
INITIALIZE_PASS_END(X86LLSCT, PASS_KEY,
		    "X86 LLSCT pass", false, false)

FunctionPass *llvm::createX86LLSCTPass() {
  return new X86LLSCT();
}
