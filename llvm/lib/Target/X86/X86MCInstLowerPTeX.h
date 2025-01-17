#pragma once

#include "llvm/CodeGen/MachineInstr.h"
#include "llvm/MC/MCInst.h"

namespace llvm::X86 {

  void X86MCInstLowerTPE(const llvm::MachineInstr *MI, llvm::MCInst& OutMI);

}
