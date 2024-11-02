#pragma once

#include "llvm/CodeGen/LivePhysRegs.h"

namespace llvm::X86 {

// Akin to LivePhys regs, but also tracks what registers are public.
// (All non-live registers are considered private).
class PublicPhysRegs {
  const TargetRegisterInfo *TRI = nullptr;
  LivePhysRegs LPR;

public:
  PublicPhysRegs() = default;
  PublicPhysRegs(const TargetRegisterInfo *TRI) { init(TRI); }

  using const_iterator = LivePhysRegs::const_iterator;

  void init(const TargetRegisterInfo *TRI);
  void addLiveIns(const MachineBasicBlock &MBB) { LPR.addLiveIns(MBB); }
  void addLiveOuts(const MachineBasicBlock &MBB) { LPR.addLiveOuts(MBB); }
  void clear() { LPR.clear(); }
  bool addReg(MCPhysReg PubReg);
  bool addRegs(const PublicPhysRegs &From);

  // Returns whether the set changed.
  bool intersect(const PublicPhysRegs &Other);

  void stepForward(const MachineInstr &MI);
  void stepBackward(const MachineInstr &MI);
  void removeAllDefs(const MachineInstr &MI);
  void updateDefs(const MachineInstr &MI);

  // NOTE: Needs to check AlwaysPublicRegisters.
  bool isPublic(MCPhysReg Reg) const;

  const_iterator begin() const { return LPR.begin(); }
  const_iterator end() const { return LPR.end(); }

  void print(raw_ostream &OS) const { LPR.print(OS); } 
  void dump() const;

  PublicPhysRegs(const PublicPhysRegs &Other);
  PublicPhysRegs &operator=(const PublicPhysRegs &Other);

  void addPublicUses(const MachineInstr &MI);

  static bool regAlwaysPublic(Register Reg, const TargetRegisterInfo &TRI);
};

}
