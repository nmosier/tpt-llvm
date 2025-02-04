#pragma once

#include "llvm/CodeGen/MachineFunction.h"
#include "PTeX/PTeXInfo.h"
#include "llvm/CodeGen/MachineFunctionPass.h"

namespace llvm::X86 {
bool rotateLoops(MachineFunction &MF, X86::PTeXInfo &PTI, MachineFunctionPass &P, bool rotate_all);
}
