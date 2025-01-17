#pragma once

#include "llvm/CodeGen/MachineFunction.h"
#include "PTeX/PTeXInfo.h"
#include "llvm/Pass.h"

namespace llvm::X86 {
bool hoistProtectedUses(MachineFunction &MF, const X86::PTeXInfo &PTI, Pass &P);
}
