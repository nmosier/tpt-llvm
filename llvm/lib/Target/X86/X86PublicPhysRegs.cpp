#include "X86PublicPhysRegs.h"

#include "X86Subtarget.h"

namespace llvm::X86 {

// TODO: Should be able to remove NoRegister from this set.
static std::array<Register, 5> AlwaysPublicRegisters = {
  X86::NoRegister, X86::RSP, X86::RIP, X86::SSP, X86::MXCSR,
};

bool PublicPhysRegs::regAlwaysPublic(Register Reg, const TargetRegisterInfo &TRI) {
  if (Reg.isVirtual())
    return false;
  if (!Reg.isValid())
    return true;
  for (Register PubReg : AlwaysPublicRegisters)
    if (PubReg != X86::NoRegister && TRI.isSubRegisterEq(PubReg, Reg))
      return true;
  return false;
}


PublicPhysRegs::PublicPhysRegs(const PublicPhysRegs &Other) {
  TRI = Other.TRI;
  assert(TRI);
  LPR.init(*TRI);
  addRegs(Other);
}

void PublicPhysRegs::dump() const {
  print(errs());
}

PublicPhysRegs &PublicPhysRegs::operator=(const PublicPhysRegs &Other) {
  TRI = Other.TRI;
  assert(TRI);
  LPR.init(*TRI);
  clear();
  addRegs(Other);
  return *this;
}

void PublicPhysRegs::init(const TargetRegisterInfo *TRI) {
  this->TRI = TRI;
  LPR.init(*TRI);
}

bool PublicPhysRegs::intersect(const PublicPhysRegs &Other) {
  SmallVector<MCPhysReg> RemoveRegs;
  for (MCPhysReg MyPubReg : *this)
    if (!Other.isPublic(MyPubReg))
      RemoveRegs.push_back(MyPubReg);
  for (MCPhysReg Reg : RemoveRegs)
    LPR.removeReg(Reg); // TODO: Call PublicPhysReg's version if we add one.
  return !RemoveRegs.empty();
}

void PublicPhysRegs::addPublicUses(const MachineInstr &MI) {
  for (const MachineOperand &MO : MI.operands())
    if (MO.isReg() && MO.isUse() && MO.isPublic())
      addReg(MO.getReg());
}

void PublicPhysRegs::stepForward(const MachineInstr &MI) {
  // First, add in any operands that are marked public.
  addPublicUses(MI);

  // Then update defs.
  updateDefs(MI);
}

void PublicPhysRegs::stepBackward(const MachineInstr &MI) {
  // Remove defined registers and regmask kills from the set.
  removeAllDefs(MI);

  // Add any public uses.
  addPublicUses(MI);
}

void PublicPhysRegs::removeAllDefs(const MachineInstr &MI) {
  LPR.removeDefs(MI);
}

void PublicPhysRegs::updateDefs(const MachineInstr &MI) {
  // First, remove all defs.
  LPR.removeDefs(MI);

  // Add back in any public defs.
  for (const MachineOperand &MO : MI.operands())
    if (MO.isReg() && MO.isDef() && MO.isPublic())
      addReg(MO.getReg());
}

bool PublicPhysRegs::addReg(MCPhysReg PubReg) {
  if (LPR.contains(PubReg) || regAlwaysPublic(PubReg, *TRI))
    return false;

  LPR.addReg(PubReg);
  return true;
}

bool PublicPhysRegs::addRegs(const PublicPhysRegs &From) {
  bool Changed = false;
  for (MCPhysReg PubReg : From)
    Changed |= addReg(PubReg);
  return Changed;
}

bool PublicPhysRegs::isPublic(MCPhysReg Reg) const {
  // First, check if this register is always public.
  if (regAlwaysPublic(Reg, *TRI))
    return true;

  // Otherwise, check if the entire register is in the pub-reg set.
  // Note that this requires being conservative in the opposite direction
  // of LivePhysRegs::contains(), so we can't use that.
  for (MCPhysReg PubReg : *this)
    if (TRI->isSubRegisterEq(PubReg, Reg))
      return true;

  // Otherwise, it's private.
  return false;
}

}


