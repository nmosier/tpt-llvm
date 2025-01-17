#pragma once

#include "llvm/CodeGen/TargetRegisterInfo.h"
#include "PTeX/PTeXInfo.h"

namespace llvm::X86 {

class StackAnalysis {
  MachineFunction &MF;
  const TargetRegisterInfo *TRI;
  const PTeXInfo &PTI;
public:
  StackAnalysis(MachineFunction &MF, const PTeXInfo &PTI):
      MF(MF), TRI(PTI.TRI), PTI(PTI) {}

  bool run();
};

}
