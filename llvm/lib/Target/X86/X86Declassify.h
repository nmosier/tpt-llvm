#pragma once

#include "llvm/CodeGen/MachineFunction.h"
#include "llvm/Analysis/AliasAnalysis.h"
#include "llvm/ADT/STLExtras.h"
#include "X86.h"
#include "X86RegisterInfo.h"
#include "X86InstrInfo.h"

#include <bitset>

// PTEX-TODO: Change to namespace X86 {
namespace llvm::X86 {

class PrivacyMask {
private:
  std::bitset<NUM_TARGET_REGS> PubRegs;

public:
  static Register canonicalizeRegister(Register Reg);

private:
  static bool registerIsAlwaysPublic(Register Reg);
  void removeClobberedRegisters(const MachineInstr& MI);

public:
  bool allInputsPublic(const MachineInstr& MI) const;
  bool anyOutputPublic(const MachineInstr& MI) const;

  bool operator==(const Value& o) const { return PubRegs == o.PubRegs; }
  bool operator!=(const Value& o) const { return !(*this == o); }

  void addPubReg(Register Reg);
  void delPubReg(Register Reg);
  bool hasPubReg(Register Reg) const;

  bool setAllInstrInputsPublic(const MachineInstr& MI);

  void transferForward(const MachineInstr& MI);
  void transferBackward(const MachineInstr& MI);

  // LLSCT-FIXME: meetForward and meetBackward should return new copies, to avoid mistakenly not setting changed correctly.
  void meetForward(const Value& o);
  void meetBackward(const Value& o);
  [[nodiscard]] bool set_union(const Value& o);

  void print(llvm::raw_ostream& os, const llvm::TargetRegisterInfo *TRI) const;

  static llvm::SmallVector<Register> getDeclassifiedRegisters(const PrivacyMask& pre, const PrivacyMask& post);
};

struct PrivacyNode {
  PrivacyMask pre;
  PrivacyMask post;

private:
  auto tuple() const { return std::make_tuple(pre, post); }

public:
  bool operator==(const Node& o) const { return tuple() == o.tuple(); }
  bool operator!=(const Node& o) const { return tuple() != o.tuple(); }
};


using PrivacyTypes = std::unordered_map<MachineInstr *, PrivacyNode>;
PrivacyTypes runTaintAnalysis(MachineFunction &MF);
llvm::SmallVector<MachineBasicBlock *> getNonemptyPredecessors(MachineBasicBlock& MBB);
  
}
