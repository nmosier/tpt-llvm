#pragma once

#include "llvm/CodeGen/MachineFunction.h"
#include "llvm/Analysis/AliasAnalysis.h"
#include "llvm/ADT/STLExtras.h"
#include "X86.h"
#include "X86RegisterInfo.h"
#include "X86InstrInfo.h"

#include <bitset>

namespace llvm::X86 {

  void runDeclassifyAnnotationPass(MachineFunction& MF);  
  void runDeclassifyCFIPass(MachineFunction& MF);
  void runSavePublicCSRsPass(MachineFunction& MF);
  
  class GPRBitMask {
  public:
    uint16_t getValue() const {
      const auto value = bv.to_ulong();
      assert(value <= std::numeric_limits<uint16_t>::max());
      return static_cast<uint16_t>(value);
    }

    void add(MCRegister reg) {
      const auto it = reg2idx.find(reg);
      assert(it != reg2idx.end());
      bv.set(it->second);
    }

    static auto gprs() {
      return llvm::make_first_range(reg2idx);
    }
    
  private:
    std::bitset<16> bv;

    static inline const std::map<MCRegister, size_t> reg2idx = {
      {X86::RAX,  0},
      {X86::RBX,  1},
      {X86::RCX,  2},
      {X86::RDX,  3},
      {X86::RSI,  4},
      {X86::RDI,  5},
      {X86::RBP,  6},
      {X86::EFLAGS, 7},
      // {X86::RSP,  7}, // This is always public anyway.
      {X86::R8,   8},
      {X86::R9,   9},
      {X86::R10, 10},
      {X86::R11, 11},
      {X86::R12, 12},
      {X86::R13, 13},
      {X86::R14, 14},
      {X86::R15, 15},
    };
  };
  
}
