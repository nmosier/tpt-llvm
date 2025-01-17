#pragma once

#include "llvm/CodeGen/MachineFunction.h"
#include "PTeX/PTeXAnalysis.h"

namespace llvm::X86 {

bool reloadUnprotectedMem(MachineFunction &MF, const PTeXAnalysis &PA);

}
