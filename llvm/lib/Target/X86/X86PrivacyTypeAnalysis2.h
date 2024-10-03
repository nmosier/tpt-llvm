#pragma once

#include <unordered_map>
#include <unordered_set>
#include <set>

#include "llvm/CodeGen/MachineFunction.h"
#include "llvm/CodeGen/MachineBasicBlock.h"
#include "llvm/CodeGen/LivePhysRegs.h"

namespace llvm {

enum PrivacyType : uint8_t;

// Akin to LivePhys regs, but also tracks what registers are public.
// (All non-live registers are considered private).
class PublicPhysRegs {
  const TargetRegisterInfo *TRI = nullptr;
  LivePhysRegs LPR;

public:
  PublicPhysRegs() = default;
  PublicPhysRegs(const TargetRegisterInfo *TRI) { init(TRI); }

  using const_iterator = LivePhysRegs::const_iterator;

  void init(const TargetRegisterInfo *TRI);
  void addLiveIns(const MachineBasicBlock &MBB) { LPR.addLiveIns(MBB); }
  void addLiveOuts(const MachineBasicBlock &MBB) { LPR.addLiveOuts(MBB); }
  void clear() { LPR.clear(); }
  bool addReg(MCPhysReg PubReg);
  bool addRegs(const PublicPhysRegs &From);

  // Returns whether the set changed.
  bool intersect(const PublicPhysRegs &Other);

  void stepForward(const MachineInstr &MI);

  // NOTE: Needs to check AlwaysPublicRegisters.
  bool isPublic(MCPhysReg Reg) const;

  const_iterator begin() const { return LPR.begin(); }
  const_iterator end() const { return LPR.end(); }

  void print(raw_ostream &OS) const { LPR.print(OS); } 
  void dump() const { LPR.dump(); }

  PublicPhysRegs(const PublicPhysRegs &Other);
  PublicPhysRegs &operator=(const PublicPhysRegs &Other);
};

inline raw_ostream &operator<<(raw_ostream &OS, const PublicPhysRegs &PubRegs) {
  PubRegs.print(OS);
  return OS;
}

namespace X86 {

// TODO: Rename to 'BidirectionalPrivacyTypeAnalysis'.
class PrivacyTypeAnalysis {
public:
  using PubMap = std::unordered_map<MachineBasicBlock *, PublicPhysRegs>;

  PrivacyTypeAnalysis(MachineFunction &MF) : MF(MF) {}

  bool run();
  void print(raw_ostream &OS) const;

private:
  MachineFunction &MF;
  PubMap In;
  PubMap Out;

  void init();

  void initTransmittedUses(MachineInstr &MI);
  void initPointerLoadsOrStores(MachineInstr &MI);
  void initAlwaysPublicRegs(MachineInstr &MI);
  void initFrameSetupAndDestroy(MachineInstr &MI);
  void initPointerCallArgs(MachineInstr &MI);
  void initPointerTypes(MachineInstr &MI);
  void initPointerReturnValue(MachineInstr &MI);

  bool forward();
  bool backward();
};

// TODO: Make abstract class, 'UnidirectionalPrivacyTypeAnalysis'.
// Then have two concerete subclasses: ForwardPrivacyTypeAnalysis,
// BackwardPrivacyTypeAnalysis.
class ForwardPrivacyTypeAnalysis {
  using PubMap = PrivacyTypeAnalysis::PubMap;

  MachineFunction &MF;
  PubMap &ParentIn;
  PubMap &ParentOut;
  PubMap In;
  PubMap Out;

  // Whether we have newly marked any machine operands to public or
  // have marked new registers as public in the ParentIn or ParentOut.
  bool ParentChanged = false;

public:
  ForwardPrivacyTypeAnalysis(MachineFunction &MF, PubMap &ParentIn, PubMap &ParentOut) :
      MF(MF), ParentIn(ParentIn), ParentOut(ParentOut) {}

  // Run the forward iterative data-flow analysis.
  bool run();

private:
  // Initialize In, Out.
  void init();

  bool block(MachineBasicBlock &MBB);
  bool instruction(MachineInstr &MI, PublicPhysRegs &PubRegs);
  void mergeIntoParent();
  bool dataUsesPublic(const MachineInstr &MI, const PublicPhysRegs &PubRegs) const;
};


}

}
