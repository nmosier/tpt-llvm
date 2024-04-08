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
  // void runSavePublicCSRsPass(MachineFunction& MF);
  
  class GPRBitMask {
  public:
    uint64_t getValue() const {
      const auto value = bv.to_ulong();
      assert(value <= std::numeric_limits<uint32_t>::max());
      return static_cast<uint32_t>(value);
    }

    void add(MCRegister reg) {
      const auto it = reg2idx.find(reg);
      assert(it != reg2idx.end());
      bv.set(it->second);
    }

    static auto gprs() {
      return llvm::make_first_range(reg2idx);
    }

    void addAll() {
      for (MCRegister gpr : gprs())
	add(gpr);
    }
    
  private:
    std::bitset<32> bv;

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

      // XMMs
      {X86::XMM0, 16},
      {X86::XMM1, 17},
      {X86::XMM2, 18},
      {X86::XMM3, 19},
      {X86::XMM4, 20},
      {X86::XMM5, 21},
      {X86::XMM6, 22},
      {X86::XMM7, 23},
      {X86::XMM8, 24},
      {X86::XMM9, 25},
      {X86::XMM10, 26},
      {X86::XMM11, 27},
      {X86::XMM12, 28},
      {X86::XMM13, 29},
      {X86::XMM14, 30},
      {X86::XMM15, 31},
    };
  };
  
}
