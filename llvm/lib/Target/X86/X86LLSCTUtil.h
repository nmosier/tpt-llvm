#pragma once

#include "X86RegisterInfo.h"
#include "MCTargetDesc/X86MCTargetDesc.h"

#include <bitset>
#include <map>

namespace llvm::X86::util {
  std::bitset<NUM_TARGET_REGS> regmask_to_bitset(const uint32_t *mask);
  std::bitset<NUM_TARGET_REGS> get_call_regmask(const MachineInstr& MI);
  std::map<const Argument *, MCPhysReg> irargs_to_mcargs(const MachineFunction& MF);
}
