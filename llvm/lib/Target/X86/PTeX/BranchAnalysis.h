#pragma once

#include "PTeX/PTeXAnalysis.h"

namespace llvm::X86 {

class BranchAnalysis {
  MachineFunction &MF;
  const TargetInstrInfo *TII;
  const TargetRegisterInfo *TRI;
  PTeXAnalysis &PTI;

public:
  BranchAnalysis(PTeXAnalysis &PTI):
      MF(PTI.MF), TII(PTI.TII), TRI(PTI.TRI), PTI(PTI) {}

  bool run();

private:
  bool analyzeBlock(MachineBasicBlock &MBB);
};

}
