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
#include "llvm/TPE.h"

using namespace llvm;

namespace tpe {

  static cl::opt<bool> EnablePrivMem {
    "tpe-privm",
    cl::init(true),
    cl::desc("[TPE] Enable insertion of PRIVM prefixes"),
  };

  void X86MCInstLowerTPE(const MachineInstr *MI, MCInst& OutMI) {
    if (!(llsct::EnableLLSCT && EnablePrivMem))
      return;
    
    const auto addFlag = [&OutMI] (auto f) {
      const auto flags = OutMI.getFlags();
      assert((flags & f) == 0);
      OutMI.setFlags(flags | f);
    };
    
    // Declassify flag
    bool privty = MI->getFlag(MachineInstr::TPEPrivM);
    bool pubty = MI->getFlag(MachineInstr::TPEPubM);
    assert(!(privty && pubty));
    if (MI->mayLoadOrStore()) {
      if (!(privty || pubty))  {
	switch (tpe::PrivacyPolicyOpt) {
	case tpe::ct:
	  privty = true;
	  // errs() << "warning: converting untyped access to private: " << *MI;
	  break;
	case tpe::sandbox:
	  pubty = true;
	  break;
	default:
	  llvm_unreachable("Unsupported threat model");
	}
      }
      if (privty) {
	addFlag(X86::IP_TPE_PRIVM);
	// errs() << "[lower] privately-typed access: " << *MI;
      } else {
	// errs() << "[lower] publicly-typed access: " << *MI;
      }
    } else {
      assert(!(privty || pubty));
    }
  }
  
}
