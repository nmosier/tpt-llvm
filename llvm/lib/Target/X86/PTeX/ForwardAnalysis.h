#pragma once

#include <unordered_set>

#include "PTeX/PublicPhysRegs.h"
#include "PTeX/PTeXInfo.h"

namespace llvm::X86 {

class ForwardAnalysis : public PTeXInfo {
private:
  PTeXInfo &Parent;

public:
  ForwardAnalysis(PTeXInfo &Parent):
      PTeXInfo(Parent.MF), Parent(Parent) {}

  bool run();

private:
  std::unordered_set<MachineOperand *> PubOps;

  void init();
  bool block(MachineBasicBlock &MBB);
  bool instruction(MachineInstr &MI, PublicPhysRegs &PubRegs);
  bool dataUsesPublic(const MachineInstr &MI, const PublicPhysRegs &PubRegs) const;
};

#if 0
// TODO: Make abstract class, 'UnidirectionalPrivacyTypeAnalysis'.
// Then have two concerete subclasses: ForwardPrivacyTypeAnalysis,
// BackwardPrivacyTypeAnalysis.
class ForwardPrivacyTypeAnalysis final : public DirectionalPrivacyTypeAnalysis<ForwardPrivacyTypeAnalysis> {
  friend class DirectionalPrivacyTypeAnalysis<ForwardPrivacyTypeAnalysis>;
  void init() override;
  bool block(MachineBasicBlock &MBB) override;
  void instruction(MachineInstr &MI, PublicPhysRegs &PubRegs);
  bool dataUsesPublic(const MachineInstr &MI, const PublicPhysRegs &PubRegs) const;
  StringRef getName() const override { return "fwd-privacy"; }

public:
  ForwardPrivacyTypeAnalysis(MachineFunction &MF, PubMap &ParentIn, PubMap &ParentOut) :
      DirectionalPrivacyTypeAnalysis(MF, ParentIn, ParentOut) {}

protected:
  auto blocks() const { return ReversePostOrderTraversal<MachineFunction *>(&MF); }
};
#endif

}
