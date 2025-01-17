#pragma once

#include <unordered_map>
#include <unordered_set>

#include "llvm/CodeGen/MachineBasicBlock.h"
#include "llvm/CodeGen/MachineInstr.h"
#include "PTeX/PublicPhysRegs.h"
#include "llvm/CodeGen/TargetInstrInfo.h"
#include "llvm/CodeGen/TargetRegisterInfo.h"
#include "llvm/CodeGen/MachineOperand.h"
#include "llvm/Support/raw_ostream.h"

namespace llvm::X86 {

struct PTeXInfo {
  using Map = std::unordered_map<MachineBasicBlock *, PublicPhysRegs>;
  using Set = std::unordered_set<MachineOperand *>;

  MachineFunction &MF;
  const TargetInstrInfo *TII;
  const TargetRegisterInfo *TRI;
  Map In;
  Map Out;

  PTeXInfo(MachineFunction &MF);

  bool merge(const PTeXInfo &Other);

  void print(raw_ostream &OS) const;

private:
  static bool mergeMap(Map &a, const Map &b);
};

}
