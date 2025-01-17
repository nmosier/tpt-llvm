#pragma once

#include "PTeX/PTeXAnalysis.h"

#include "llvm/CodeGen/MachineFunction.h"
#include "llvm/Pass.h"

namespace llvm::X86 {

bool sinkProtectedDefs(MachineFunction &MF, const PTeXAnalysis &PA, Pass &P);

}
