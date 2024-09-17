#pragma once

#include <unordered_map>
#include <bitset>

#include "llvm/CodeGen/MachineFunctionPass.h"
#include "llvm/CodeGen/MachineBasicBlock.h"
#include "llvm/CodeGen/MachineInstr.h"
#include "llvm/ADT/SmallSet.h"
#include "X86.h"
#include "X86Subtarget.h"

namespace llvm {

namespace X86 {

enum PrivacyType {
  PrivatelyTyped,
  PubliclyTyped,
};

class PrivacyMask {
public:
  using Bitset = std::bitset<NUM_TARGET_REGS>;

private:
  Bitset PubRegs;

public:
  static Register canonicalizeRegister(Register Reg);
  static bool isCanonicalRegister(Register Reg);

  void set(Register Reg, PrivacyType Ty);
  PrivacyType get(Register Reg) const;

  [[nodiscard]] bool inheritPublic(const PrivacyMask &o, PrivacyMask *diff);
  void inheritPrivate(const PrivacyMask &o);

  void setRegMask(const uint32_t *RegMask, PrivacyType Ty, bool invert);

  void print(raw_ostream& os, const TargetRegisterInfo *TRI) const;

  bool operator==(const PrivacyMask& o) const { return PubRegs == o.PubRegs; }

  template <typename OutputIt>
  OutputIt getPublicRegs(OutputIt out) const;

  bool allPrivate() const;

  Bitset getPrivateBitset() const;
  Bitset getPublicBitset() const;

  static Bitset regmaskToBitset(const uint32_t *mask);
};

struct PrivacyNode {
  PrivacyMask in, out;
};

int getJumpTableIndex(const MachineInstr &MI, const MachineFunction &MF);
int getMemRefBeginIdx(const MachineInstr &MI);

}

class X86PrivacyTypeAnalysis final : public MachineFunctionPass {
public:
  using PrivacyType = X86::PrivacyType;
  using PrivacyMask = X86::PrivacyMask;
  using PrivacyNode = X86::PrivacyNode;
  
  static char ID;

  X86PrivacyTypeAnalysis();

  void getAnalysisUsage(AnalysisUsage& AU) const override;
  bool runOnMachineFunction(MachineFunction &F) override;

  using BasicBlockSet = llvm::SmallSet<MachineBasicBlock *, 2>;
  const BasicBlockSet &getBlockPredecessors(MachineBasicBlock *MBB);
  const BasicBlockSet &getBlockSuccessors(MachineBasicBlock *MBB);

private:

  template <typename T>
  using PrivacyTypes = std::unordered_map<T *, PrivacyNode>;
  PrivacyTypes<MachineBasicBlock> BlockPrivacy;
  PrivacyTypes<MachineInstr> InstrPrivacy;

  using ControlFlowGraph = std::unordered_map<MachineBasicBlock *, BasicBlockSet>;
  ControlFlowGraph BlockSuccessors;
  ControlFlowGraph BlockPredecessors;

  void addBlockEdge(MachineBasicBlock *Src, MachineBasicBlock *Dst);

  void clear();

public:
  PrivacyNode &getBlockPrivacy(MachineBasicBlock *MBB);
  PrivacyMask &getBlockPrivacyIn(MachineBasicBlock *MBB);
  PrivacyMask &getBlockPrivacyOut(MachineBasicBlock *MBB);

  PrivacyNode &getInstrPrivacy(MachineInstr *MI);
  PrivacyMask &getInstrPrivacyIn(MachineInstr *MI);
  PrivacyMask &getInstrPrivacyOut(MachineInstr *MI);

private:
  void dumpResults(raw_ostream &os, MachineFunction &MF);
  void validate(MachineFunction &MF);

  void transferInstrForward(MachineInstr &MI, PrivacyMask &Privacy);
};

namespace X86 {

bool registerIsAlwaysPublic(Register Reg);

template <typename OutputIt>
OutputIt PrivacyMask::getPublicRegs(OutputIt out) const {
  for (unsigned Reg = 0; Reg < PubRegs.size(); ++Reg) {
    if (!PubRegs.test(Reg))
      continue;
    assert(canonicalizeRegister(Reg) == Reg);
    *out++ = Reg;
  }
  return out;
}

}

}
