#pragma once

#include <cstdint>
#include <optional>

#include "llvm/CodeGen/MachineInstr.h"
#include "llvm/CodeGen/MachineMemOperand.h"
#include "llvm/Support/CommandLine.h"

namespace llvm::X86 {

bool EnablePTeX();
extern cl::opt<bool> PrefixProtectedStores;

enum PTeXMode {
  wSNI,
  SCT,
  sSNI,
};

PTeXMode getPTeXMode();

}
