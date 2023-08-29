#include "X86MCInstLowerLLSCT.h"
#include "X86LLSCT.h"
#include "MCTargetDesc/X86BaseInfo.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/IR/DataLayout.h"
#include "llvm/CodeGen/MachineBasicBlock.h"
#include "llvm/CodeGen/MachineFunction.h"
#include "llvm/IR/Function.h"
#include "llvm/Analysis/ValueTracking.h"
#include "llvm/Support/WithColor.h"
#include "llvm/IR/Instructions.h"

using namespace llvm;

namespace llsct {

  static int verbose = false; // TODO: 

  static cl::opt<bool> EnableLLSCTIndAddr {
    "llsct-indaddr",
    cl::desc("Enable LLSCT Indirect Addressibility Annotations"),
    cl::init(true),
  };

  void X86MCInstLowerLLSCT(const MachineInstr *MI, MCInst& OutMI) {
    if (!EnableLLSCT)
      return;
    
    const auto addFlag = [&OutMI] (auto f) {
      const auto flags = OutMI.getFlags();
      assert((flags & f) == 0);
      OutMI.setFlags(flags | f);
    };
    
    // Check if the MI has a memory operand flagged as SSBD.
    for (const MachineMemOperand *MMO : MI->memoperands()) {
      if ((MMO->getFlags() & X86::AcSsbd)) {
	addFlag(X86::IP_HAS_SSBD);
      }
    }

    // Check if we should mark it INDADDR.
    if (EnableLLSCTIndAddr && MI->mayLoadOrStore()) {
      switch (MI->getNumMemOperands()) {
      case 0: {
	if (X86::getMemRefBeginIdx(*MI) >= 0) {
	  if (verbose) 
	    WithColor::warning() << __FILE__ << ":" << __LINE__ << ": instruction missing memory operand: " << *MI;
	  break;
	}
	if (!MI->hasRegisterImplicitUseOperand(X86::RSP)) {
	  if (verbose)
	    WithColor::warning() << __FILE__ << ":" << __LINE__ << ": skipping instruction: " << *MI;
	  break;
	}
	break;
      }

      case 1: {
	const MachineMemOperand *MMO = MI->memoperands()[0];
	const Value *Ptr = MMO->getValue();
	if (!Ptr)
	  break;
	int64_t AllocOffset;
	const DataLayout DL(MI->getParent()->getParent()->getFunction().getParent());
	const Value *BasePtr = GetPointerBaseWithConstantOffset(Ptr, AllocOffset, DL);
	assert(BasePtr);
	if (!isa<AllocaInst>(BasePtr))
	  break;
	addFlag(X86::IP_HAS_INDADDR);
	break;
      }
      
      default:
	if (verbose)
	  WithColor::warning() << __FILE__ << ":" << __LINE__ << ": not handling instruction with >1 memory operand: " << *MI;
	break;
      }
    }

    // Declassify flag
    if (MI->getFlag(MachineInstr::LLSCTDeclassify)) {
      addFlag(X86::IP_LLSCT_DECLASSIFY);
    }
  }
  
}
