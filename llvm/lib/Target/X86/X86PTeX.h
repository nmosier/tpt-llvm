#pragma once

#include <cstdint>
#include <optional>

#include "llvm/CodeGen/MachineInstr.h"
#include "llvm/CodeGen/MachineMemOperand.h"
#include "llvm/Support/CommandLine.h"

namespace llvm {

enum PrivacyType : uint8_t;

namespace X86 {

bool EnablePTeX();
extern cl::opt<bool> PrefixProtectedStores;
std::optional<PrivacyType> getInstrPrivacy(const MachineInstr &MI);
void setInstrPrivacy(MachineInstr &MI, PrivacyType PrivTy);

}

}
