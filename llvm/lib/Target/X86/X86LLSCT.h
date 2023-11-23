#pragma once

#include <cstdint>

#include "llvm/CodeGen/MachineInstr.h"
#include "llvm/CodeGen/MachineMemOperand.h"
#include "llvm/Support/CommandLine.h"

#warning "Should move this to TPE.h"

// TODO: Move to llsct namespace?
namespace llsct {
  extern bool EnableLLSCT;

  bool NoCalleeSavedRegs();
}

namespace llvm::X86 {

  // TOOD: Gonna have to figure out a workaround to only having 3 flags...
  enum AccessFlags: uint16_t {
    AcSsbd = MachineMemOperand::MOTargetFlag2,
  };

  int getMemRefBeginIdx(const MCInstrDesc& Desc);
  int getMemRefBeginIdx(const MachineInstr& MI);

}



