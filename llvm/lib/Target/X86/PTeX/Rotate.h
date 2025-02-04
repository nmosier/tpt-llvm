#pragma once

#include "llvm/CodeGen/MachineFunction.h"
#include "PTeX/PTeXInfo.h"

namespace llvm::X86 {
bool rotateLoops(MachineFunction &MF, X86::PTeXInfo &PTI);
}
