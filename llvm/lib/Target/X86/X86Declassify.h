#pragma once

#include "llvm/CodeGen/MachineFunction.h"
#include "llvm/Analysis/AliasAnalysis.h"

namespace llvm::X86 {

  void runDeclassificationPass(MachineFunction& MF);
  
}
