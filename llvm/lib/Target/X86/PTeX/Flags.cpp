#include "PTeX/Flags.h"

#include "llvm/CodeGen/MachineInstr.h"
#include "X86Subtarget.h"

#define DEBUG_TYPE "x86-ptex-flags"

// TODO: Share this.
#define PTEX_DEBUG(...) LLVM_DEBUG(dbgs() << DEBUG_TYPE << ": "; __VA_ARGS__);

using namespace llvm;
using X86::PTeXInfo;

static bool unprotectFlagsInstr(MachineInstr &MI) {
  if (MI.getNumOperands() != 3) {
    PTEX_DEBUG(dbgs() << "skipping because doesn't have exactly 3 operands: " << MI);
    return false;
  }

  static const std::map<int, int> OpcodeMap = {
    {X86::INC64r, X86::ADD64ri8},
    {X86::INC32r, X86::ADD32ri8},
    {X86::DEC64r, X86::SUB64ri8},
    {X86::DEC32r, X86::SUB32ri8},
  };
  const auto OpcodeIt = OpcodeMap.find(MI.getOpcode());
  if (OpcodeIt == OpcodeMap.end()) {
    PTEX_DEBUG(dbgs() << "skip: unsupported opcode: " << MI);
    return false;
  }

  MachineFunction &MF = *MI.getParent()->getParent();
  const TargetInstrInfo *TII = MF.getSubtarget().getInstrInfo();
  MI.setDesc(TII->get(OpcodeIt->second));
  MI.addOperand(MF, MachineOperand::CreateImm(1));

  PTEX_DEBUG(dbgs() << "success: transformed into: " << MI);
  return true;
}

bool X86::unprotectFlags(MachineFunction &MF, const PTeXInfo &PTI) {
  bool Changed = false;
  for (MachineBasicBlock &MBB : MF) {
    PublicPhysRegs PubRegs = PTI.In.at(&MBB);
    for (MachineInstr &MI : MBB) {
      const bool ProtIn = !PubRegs.isPublic(X86::EFLAGS);
      PubRegs.stepForward(MI);
      const bool PubOut = PubRegs.isPublic(X86::EFLAGS);
      if (ProtIn && PubOut)
        Changed |= unprotectFlagsInstr(MI);
    }
  }
  // TODO: Actually, shouldn't say anything changed, since we're not adding any new instructions...
  return Changed;
}
