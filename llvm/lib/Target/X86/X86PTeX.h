#pragma once

#include <cstdint>
#include <optional>

#include "llvm/CodeGen/MachineInstr.h"
#include "llvm/CodeGen/MachineMemOperand.h"
#include "llvm/Support/CommandLine.h"

namespace llvm::X86 {

enum PrivacyType : uint8_t;

bool EnablePTeX();
std::optional<PrivacyType> getInstrPrivacy(const MachineInstr &MI);
void setInstrPrivacy(MachineInstr &MI, PrivacyType PrivTy);

}



