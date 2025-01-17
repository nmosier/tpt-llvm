#pragma once

#include "llvm/CodeGen/MachineFunction.h"
#include "PTeX/PTeXInfo.h"

namespace llvm::X86 {

bool unprotectFlags(MachineFunction &MF, const PTeXInfo &PTI);

}
