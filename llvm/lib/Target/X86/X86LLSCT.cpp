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

using namespace llvm;

#define PASS_KEY "llsct"
#define DEBUG_TYPE PASS_KEY

static cl::opt<bool> EnableLLSCT {
  PASS_KEY,
  cl::desc("Enable LLSCT"),
  cl::init(false),
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

  // InsertPt points to one past the call.
  bool hardenPostCall(MachineBasicBlock& MBB, MachineInstr& Ret, MachineBasicBlock::iterator InsertPt,
		      iterator_range<LivePhysRegs::const_iterator> LiveRegs, DebugLoc Loc = DebugLoc()) {
    MachineFunction& MF = *MBB.getParent();
    const auto *TRI = MF.getSubtarget<X86Subtarget>().getRegisterInfo();
    auto& MRI = MF.getRegInfo();
    const auto *TII = MF.getSubtarget().getInstrInfo();
    const auto *FrameLowering = MF.getSubtarget().getFrameLowering();
    MCSymbol *RetSymbol = MF.getContext().createTempSymbol("llsct_ret_addr", /*AlwaysAddSuffix*/ true);
    Ret.setPostInstrSymbol(MF, RetSymbol);

    const TargetRegisterClass *AddrRC = &X86::GR64RegClass;
    const Register ExpectedReg = MRI.createVirtualRegister(AddrRC);
    const Register ActualReg = MRI.createVirtualRegister(AddrRC);
    const Register ZeroSubReg = MRI.createVirtualRegister(&X86::GR32RegClass);
    const Register ZeroReg = MRI.createVirtualRegister(&X86::GR64RegClass);
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

    const auto HardenReg = [&] (Register Reg) {
      assert(Reg.isPhysical() && "stack pointer must be physical register");
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
    for (Register LiveReg : LiveRegs) {
      assert(LiveReg.isPhysical() && "All registers should be physical at this point");
      HardenReg(LiveReg);
    }
    
    return true;
  }
  
  bool hardenPostCalls(MachineBasicBlock& MBB) {
    auto& MF = *MBB.getParent();
    const auto *TRI = MF.getSubtarget().getRegisterInfo();
    
    bool changed = false;
    auto MBBI = MBB.begin();
    LivePhysRegs LiveRegs(*TRI);
    LiveRegs.addLiveIns(MBB);
    while (MBBI != MBB.end()) {
      const bool isCall = MBBI->isCall() && !MBBI->isReturn();
      MachineInstr& MI = *MBBI;
      SmallVector<std::pair<MCPhysReg, const MachineOperand *>> Clobbers;
      LiveRegs.stepForward(MI, Clobbers);
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

  
  bool X86LLSCT::runOnMachineFunction(MachineFunction& MF) {
    bool changed = false;
    changed |= hardenPostCalls(MF);
    
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
