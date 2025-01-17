#include "PTeX/PublicPhysRegs.h"

#include "X86Subtarget.h"

namespace llvm::X86 {

static MCPhysReg ProtectableRegisters[] = {
  X86::RAX, X86::RBX, X86::RCX, X86::RDX,
  X86::RBP, X86::RDI, X86::RSI,
  X86::R8, X86::R9, X86::R10, X86::R11,
  X86::R12, X86::R13, X86::R14, X86::R15,
  X86::EFLAGS,
  X86::YMM0, X86::YMM1, X86::YMM2, X86::YMM3,
  X86::YMM4, X86::YMM5, X86::YMM6, X86::YMM7,
  X86::YMM8, X86::YMM9, X86::YMM10, X86::YMM11,
  X86::YMM12, X86::YMM13, X86::YMM14, X86::YMM15,
};

bool PublicPhysRegs::regAlwaysPublic(Register Reg, const TargetRegisterInfo &TRI) {
  if (Reg.isVirtual())
    return false;
  if (!Reg.isValid())
    return true;
  for (Register ProtectableReg : ProtectableRegisters)
    if (TRI.isSubRegisterEq(ProtectableReg, Reg))
      return false;
  return true;
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
    LPR.removeRegOnly(Reg); // TODO: Call PublicPhysReg's version if we add one.
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

bool PublicPhysRegs::isPublic(const MachineOperand &MO) const {
  if (MO.isReg())
    return isPublic(MO.getReg());
  return true;
}

bool PublicPhysRegs::operator==(const PublicPhysRegs &Other) const {
  for (MCPhysReg Reg : *this)
    if (!Other.isPublic(Reg))
      return false;
  for (MCPhysReg Reg : Other)
    if (!isPublic(Reg))
      return false;
  return true;
}

void PublicPhysRegs::removeReg(MCPhysReg Reg) {
  if (Reg != X86::NoRegister)
    LPR.removeReg(Reg);
}

void PublicPhysRegs::removeRegs(const PublicPhysRegs &Other) {
  for (MCPhysReg Reg : Other)
    removeReg(Reg);
}

}
