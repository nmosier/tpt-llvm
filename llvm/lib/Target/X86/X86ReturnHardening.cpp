#include "X86.h"
#include "X86InstrInfo.h"
#include "llvm/CodeGen/MachineFunctionPass.h"
#include "llvm/CodeGen/MachineInstrBuilder.h"
#include "X86Subtarget.h"
#include "llvm/IR/Module.h"
#include "llvm/MC/MCContext.h"

using namespace llvm;

namespace {

  cl::opt<bool> EnableReturnHardening {
    "x86-return-hardening",
    cl::desc("Enable Return Hardening"),
    cl::init(false),
    cl::Hidden,
  };

  class X86ReturnHardening final : public MachineFunctionPass {
  public:
    static inline char ID = 0;

    X86ReturnHardening(): MachineFunctionPass(ID) {
      initializeX86ReturnHardeningPass(*PassRegistry::getPassRegistry());
    }

    bool runOnMachineFunction(MachineFunction& MF) override {
      if (!EnableReturnHardening)
	return false;

      bool changed = false;

      const auto *TII = MF.getSubtarget().getInstrInfo();

      for (MachineBasicBlock& MBB : MF) {
	for (MachineInstr& MI : MBB) {
	  if (!MI.isCall() || MI.isTerminator())
	    continue;

	  if (MI.getOpcode() == X86::CALL64pcrel32) {
	    const MachineOperand& MO = MI.getOperand(0);
	    if (MO.isGlobal() && MO.getGlobal()->getName() == "__sigsetjmp")
	      continue;
	  }

	  auto MBBI_pre = MI.getIterator();
	  auto MBBI_post = std::next(MI.getIterator());

	  /*
	    mov [rsp-8], 0
	    call <target>
	    .label
	    lea rsi, [rel .label]
	    xor edi, edi
	    cmp rsi, [rsp - 8]
	    cmovne rsp, rdi
	   */

	  // mov [rsp - 8], 0
	  BuildMI(MBB, MBBI_pre, DebugLoc(), TII->get(X86::MOV64mi32))
	    .addReg(/*Base*/ X86::RSP)
	    .addImm(/*Scale*/ 1)
	    .addReg(/*Index*/ X86::NoRegister)
	    .addImm(/*Disp*/ -8)
	    .addReg(/*Seg*/ X86::NoRegister)
	    .addImm(0);

	  // .label
	  MCSymbol *RetSymbol = MI.getPostInstrSymbol();
	  if (!RetSymbol) {
	    RetSymbol = MF.getContext().createTempSymbol("llsct_ret_addr", /*AlwaysAddSuffix*/ true);
	    MI.setPostInstrSymbol(MF, RetSymbol);
	  }

	  // lea rsi, [rel .label]
	  BuildMI(MBB, MBBI_post, DebugLoc(), TII->get(X86::LEA64r), X86::RSI)
	    .addReg(/*Base*/X86::RIP)
	    .addImm(/*Scale*/1)
	    .addReg(/*Index*/X86::NoRegister)
	    .addSym(/*Disp*/RetSymbol)
	    .addReg(/*Segment*/X86::NoRegister);

	  // xor edi, edi
	  BuildMI(MBB, MBBI_post, DebugLoc(), TII->get(X86::XOR32rr), X86::EDI)
	    .addReg(X86::EDI)
	    .addReg(X86::EDI);

	  // cmp rsi, [rsp - 8]
	  BuildMI(MBB, MBBI_post, DebugLoc(), TII->get(X86::CMP64rm))
	    .addReg(X86::RSI)
	    .addReg(/*Base*/ X86::RSP)
	    .addImm(/*Scale*/ 1)
	    .addReg(/*Index*/ X86::NoRegister)
	    .addImm(/*Disp*/ -8)
	    .addReg(/*Segment*/ X86::NoRegister);

	  // cmovne rsp, rdi
	  BuildMI(MBB, MBBI_post, DebugLoc(), TII->get(X86::CMOV64rr), X86::RSP)
	    .addReg(X86::RSP)
	    .addReg(X86::RDI)
	    .addImm(X86::COND_NE);


	  changed = true;

	}
      }


      return changed;
    }
			      
  };
  
}

INITIALIZE_PASS(X86ReturnHardening, "x86-return-hardening-pass", "X86 Return Hardening", false, false)
namespace llvm {
  FunctionPass *createX86ReturnHardeningPass() {
    return new X86ReturnHardening();
  }
}
