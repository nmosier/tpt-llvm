#pragma once

#include "llvm/CodeGen/MachineInstr.h"
#include "llvm/MC/MCInst.h"

namespace llsct {

  void X86MCInstLowerLLSCT(const llvm::MachineInstr *MI, llvm::MCInst& OutMI);
  
}
