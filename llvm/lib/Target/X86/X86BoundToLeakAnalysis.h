#pragma once

#include <unordered_map>

#include <llvm/CodeGen/MachineFunction.h>
#include "X86PrivacyTypeAnalysis2.h"

namespace llvm::X86 {

class BoundToLeakAnalysis {
public:
  // TODO: Share with PrivacyTypeAnalysis.
  using PubMap = std::unordered_map<MachineBasicBlock *, PublicPhysRegs>;

  BoundToLeakAnalysis(MachineFunction &MF) : MF(MF) {}

  bool run();

  const PublicPhysRegs &getIn(MachineBasicBlock *MBB) const { return In.at(MBB); }
  const PublicPhysRegs &getOut(MachineBasicBlock *MBB) const { return Out.at(MBB); }
  
private:
  MachineFunction &MF;
  PubMap In;
  PubMap Out;

  void init();
  bool backward();
  bool block(MachineBasicBlock &MBB);
  bool instruction(MachineInstr &MI, PublicPhysRegs &PubRegs);
};

}
