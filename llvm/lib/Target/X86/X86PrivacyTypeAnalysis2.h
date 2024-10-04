#pragma once

#include <unordered_map>
#include <unordered_set>
#include <set>

#include "llvm/CodeGen/MachineFunction.h"
#include "llvm/CodeGen/MachineBasicBlock.h"
#include "llvm/CodeGen/LivePhysRegs.h"
#include "llvm/ADT/PostOrderIterator.h"

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
  void stepBackward(const MachineInstr &MI);
  void removeDefs(const MachineInstr &MI);

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

namespace impl {
void addRegToCover(MCPhysReg Reg, SmallVectorImpl<MCPhysReg> &Out,
                   const TargetRegisterInfo *TRI);
}

template <class InputIt>
void getRegisterCover(InputIt first, InputIt last, SmallVectorImpl<MCPhysReg> &Out,
                      const TargetRegisterInfo *TRI) {
  assert(Out.empty());
  for (InputIt it = first; it != last; ++it)
    impl::addRegToCover(*it, Out, TRI);
  assert((first == last) == Out.empty());
}

template <class Container>
void getRegisterCover(const Container &C, SmallVectorImpl<MCPhysReg> &Out,
                      const TargetRegisterInfo *TRI) {
  getRegisterCover(C.begin(), C.end(), Out, TRI);
}


namespace X86 {

bool regAlwaysPublic(Register Reg, const TargetRegisterInfo &TRI);

// TODO: Rename to 'BidirectionalPrivacyTypeAnalysis'.
class PrivacyTypeAnalysis {
public:
  using PubMap = std::unordered_map<MachineBasicBlock *, PublicPhysRegs>;

  PrivacyTypeAnalysis(MachineFunction &MF) : MF(MF) {}

  bool run();
  void print(raw_ostream &OS) const;
  void dump() const { print(errs()); }
  const PublicPhysRegs &getIn(MachineBasicBlock *MBB) const { return In.at(MBB); }
  const PublicPhysRegs &getOut(MachineBasicBlock *MBB) const { return Out.at(MBB); }

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

template <class Base>
class DirectionalPrivacyTypeAnalysis {
protected:
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
  DirectionalPrivacyTypeAnalysis(MachineFunction &MF, PubMap &ParentIn, PubMap &ParentOut) :
      MF(MF), ParentIn(ParentIn), ParentOut(ParentOut) {}

  bool run();

protected:
  // Initialize In, Out.
  // TODO: Can actually use some shared code here.
  // TODO: Make this per-block as well?
  virtual void init() = 0;

  // Process each block, returning whether a change occurred.
  virtual bool block(MachineBasicBlock &MBB) = 0;

private:
  void mergeIntoParent();

  const Base *base() const { return static_cast<const Base *>(this); }
  Base *base() { return static_cast<Base *>(this); }
};

// TODO: Make abstract class, 'UnidirectionalPrivacyTypeAnalysis'.
// Then have two concerete subclasses: ForwardPrivacyTypeAnalysis,
// BackwardPrivacyTypeAnalysis.
class ForwardPrivacyTypeAnalysis final : public DirectionalPrivacyTypeAnalysis<ForwardPrivacyTypeAnalysis> {
  friend class DirectionalPrivacyTypeAnalysis<ForwardPrivacyTypeAnalysis>;
  void init() override;
  bool block(MachineBasicBlock &MBB) override;
  bool instruction(MachineInstr &MI, PublicPhysRegs &PubRegs);
  bool dataUsesPublic(const MachineInstr &MI, const PublicPhysRegs &PubRegs) const;

public:
  ForwardPrivacyTypeAnalysis(MachineFunction &MF, PubMap &ParentIn, PubMap &ParentOut) :
      DirectionalPrivacyTypeAnalysis(MF, ParentIn, ParentOut) {}

protected:
  auto blocks() const { return llvm::inverse_post_order(&MF); }
};

class BackwardPrivacyTypeAnalysis final : public DirectionalPrivacyTypeAnalysis<BackwardPrivacyTypeAnalysis> {
  friend class DirectionalPrivacyTypeAnalysis<BackwardPrivacyTypeAnalysis>;
  void init() override;
  bool block(MachineBasicBlock &MBB) override;
  bool instruction(MachineInstr &MI, PublicPhysRegs &PubRegs);
  bool dataDefsPublic(const MachineInstr &MI) const; // TODO: Make this static instead.
  auto blocks() const { return llvm::post_order(&MF); }
  
public:
  BackwardPrivacyTypeAnalysis(MachineFunction &MF, PubMap &ParentIn, PubMap &ParentOut) :
      DirectionalPrivacyTypeAnalysis(MF, ParentIn, ParentOut) {}

};


}

}
