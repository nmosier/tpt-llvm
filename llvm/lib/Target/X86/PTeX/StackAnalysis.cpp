#include "PTeX/StackAnalysis.h"

#include <variant>
#include <map>

#include "llvm/CodeGen/MachineFrameInfo.h"
#include "PTeX/Util.h"
#include "PTeX/PublicPhysRegs.h"
#include "llvm/ADT/PostOrderIterator.h"

#define DEBUG_TYPE "x86-ptex-stack"

#define PTEX_DEBUG(...) LLVM_DEBUG(dbgs() << DEBUG_TYPE << ": "; __VA_ARGS__)

#define PTEX_DEBUG_MF(...) PTEX_DEBUG(dbgs() << MF.getName() << ": "; __VA_ARGS__)

using namespace llvm;
using X86::StackAnalysis;
using X86::PublicPhysRegs;

static MachineOperand *isEligibleStackLoad(MachineInstr &MI, int &FI);

namespace {

template <typename T>
class PhysRegMap {
private:
  using Map = std::map<MCPhysReg, T>;

public:
  PhysRegMap() = default;
  PhysRegMap(const TargetRegisterInfo *TRI): TRI(TRI) {}

  void add(MCPhysReg Reg, const T &Value) {
    remove(Reg);
    [[maybe_unused]] const bool inserted = map.emplace(Reg, Value).second;
    assert(inserted);
  }

  void remove(MCPhysReg Reg) {
    for (MCRegAliasIterator Alias(Reg, TRI, true); Alias.isValid(); ++Alias)
      map.erase(*Alias);
  }

  void clear() {
    map.clear();
  }

  bool intersect(const PhysRegMap &Other, std::function<T (const T &, const T &)> Meet) {
    bool Changed = false;

    for (auto it = map.begin(); it != map.end(); ) {
      const auto other_it = Other.map.find(it->first);

      // If the register doesn't have an entry in the other map, then erase the entry
      // in this map.
      if (other_it == Other.map.end()) {
        it = map.erase(it);
      } else {
        // Otherwise, meet the two.
        const T New = Meet(it->second, other_it->second);
        Changed |= it->second != New;
        it->second = New;
        ++it;
      }
    }

    return Changed;
  }

  using iterator = typename Map::iterator;
  using const_iterator = typename Map::const_iterator;

  iterator begin() { return map.begin(); }
  iterator end() { return map.end(); }
  iterator erase(iterator it) { return map.erase(it); }

  const_iterator begin() const { return map.begin(); }
  const_iterator end() const { return map.end(); }

private:
  const TargetRegisterInfo *TRI = nullptr;
  Map map;
};

struct All {
  bool operator!=(const All &) const { return false; }
};

struct None {
  bool operator!=(const None &) const { return false; }
};

using FrameIndex = std::variant<All, int, None>;
using FrameRegs = PhysRegMap<FrameIndex>;
using FrameRegMap = std::unordered_map<const MachineBasicBlock *, FrameRegs>;

using PublicFrameSet = std::set<int>;
using PublicFrameMap = std::map<MachineBasicBlock *, PublicFrameSet>;

struct FrameIndexVisitor {
  template <typename _>
  FrameIndex operator()(None, _) const { return None(); }
  FrameIndex operator()(int FI, None) const { return None(); }
  FrameIndex operator()(int FI, All) const { return FI; }
  FrameIndex operator()(int FI_A, int FI_B) const {
    if (FI_A == FI_B) {
      return FI_A;
    } else {
      return None();
    }
  }
  template <typename _>
  FrameIndex operator()(All, _ B) const { return B; }
};

struct FrameIndexToString {
  std::string operator()(None) const { return "none"; }
  std::string operator()(int FI) const { return std::to_string(FI); }
  std::string operator()(All) const { return "all"; }
};

}

static FrameIndex meetFrameIndex(const FrameIndex &A, const FrameIndex &B) {
  return std::visit(FrameIndexVisitor(), A, B);
}

static void computeFrameRegMap_INIT(MachineFunction &MF, FrameRegMap &In, FrameRegMap &Out) {
  const TargetRegisterInfo *TRI = MF.getSubtarget().getRegisterInfo();

  // Find all registers used in the function as destinations of loads.
  std::set<MCPhysReg> Regs;
  for (MachineBasicBlock &MBB : MF) {
    for (MachineInstr &MI : MBB) {
      int FI;
      if (MachineOperand *Def = isEligibleStackLoad(MI, FI))
        Regs.insert(Def->getReg());
    }
  }

  // Now, compute top.
  FrameRegs Top(TRI);
  for (MCPhysReg Reg : Regs)
    Top.add(Reg, All());
  FrameRegs Bot(TRI);

  PTEX_DEBUG_MF(dbgs() << "top:");
  for (const auto &[Reg, Val] : Top)
    LLVM_DEBUG(dbgs() << " " << TRI->getRegAsmName(Reg) << "->" << std::visit(FrameIndexToString(), Val));
  LLVM_DEBUG(dbgs() << "\n");

  // Set ins and outs.
  for (const MachineBasicBlock &MBB : MF) {
    In[&MBB] = Top;
    Out[&MBB] = Top;

    if (MBB.pred_size() == 0)
      In[&MBB] = Bot;
  }
}

static MachineOperand *isEligibleStackLoad(MachineInstr &MI, int &FI) {
  const MachineFunction &MF = *MI.getParent()->getParent();

  unsigned Bytes;
  const TargetInstrInfo *TII = MF.getSubtarget().getInstrInfo();
  if (!TII->isLoadFromStackSlot(MI, FI, Bytes))
    return nullptr;

  const MachineFrameInfo &MFI = MF.getFrameInfo();
  if (MFI.getObjectSize(FI) != Bytes) {
    PTEX_DEBUG_MF(dbgs() << "ineligible: bad object size: " << MI);
    return nullptr;
  }

  // FIXME: Need to check if fixed frame index has address taken.
  if (!MFI.isSpillSlotObjectIndex(FI) && !MFI.isFixedObjectIndex(FI)) {
    PTEX_DEBUG_MF(dbgs() << "ineligible: bad object index size: " << MI);
    return nullptr;
  }

  // Expect there to be only one non-address operand.
  if (X86::getMemRefBeginIdx(MI) != 1) {
    PTEX_DEBUG_MF(dbgs() << "ineligible: mem ref begin idx != 1: " << MI);
    return nullptr;
  }

  // Expect 6 operands.
  if (MI.getNumOperands() != 6) {
    PTEX_DEBUG_MF(dbgs() << "ineligible: not 6 operands: " << MI);
    return nullptr;
  }

  MachineOperand &Def = MI.getOperand(0);
  assert(Def.isReg() && Def.isDef());
  PTEX_DEBUG_MF(dbgs() << "eligible: " << MI);
  return &Def;
}

static void computeFrameRegMap_TRANSFER(const MachineInstr &MI, FrameRegs &FR) {
  // Remove instruction clobbers.
  if (MI.isCall()) {
    FR.clear();
    return;
  }
  for (const MachineOperand &MO : MI.operands()) {
    if (MO.isRegMask()) {
      FR.clear();
      return;
    } else if (MO.isReg() && MO.isDef()) {
      FR.remove(MO.getReg());
    }
  }

  int FI;
  const MachineOperand *Def = isEligibleStackLoad(const_cast<MachineInstr &>(MI), FI);
  if (!Def)
    return;

  FR.add(Def->getReg(), FI);
  PTEX_DEBUG(dbgs() << "success: detected stack load into \"" << *Def << "\": " << MI);
}

static void computeFrameRegMap(MachineFunction &MF, FrameRegMap &In, FrameRegMap &Out) {
  computeFrameRegMap_INIT(MF, In, Out);

  // Run forward dataflow loop.
  bool Changed;
  do {
    Changed = false;

    for (const MachineBasicBlock &MBB : MF) {
      // Compute meet-in for MBB.
      for (const MachineBasicBlock *Pred : MBB.predecessors())
        Changed |= In[&MBB].intersect(Out[Pred], meetFrameIndex);

      // Transfer across instructions.
      FrameRegs FR = In[&MBB];
      for (const MachineInstr &MI : MBB)
        computeFrameRegMap_TRANSFER(MI, FR);

      // Set meet-out for MBB.
      Changed |= Out[&MBB].intersect(FR, meetFrameIndex);
    }

  } while (Changed);
}

static void filterFrameRegs(const FrameRegs &FR, const PublicPhysRegs &PR, PublicFrameSet &PF) {
  for (const auto &[Reg, FI] : FR)
    if (std::holds_alternative<int>(FI) && PR.isPublic(Reg))
      PF.insert(std::get<int>(FI));
}

static bool stackBackwardsPass(MachineFunction &MF, const PublicFrameMap &ParentIn, PublicFrameMap &ParentOut) {
  // Collect full set of frame indices?
  // Should just be 'universe'.
  PublicFrameSet Top;
  for (MachineBasicBlock &MBB : MF) {
    llvm::copy(ParentIn.at(&MBB), std::inserter(Top, Top.end()));
    llvm::copy(ParentOut.at(&MBB), std::inserter(Top, Top.end()));
  }

  std::unordered_set<MachineBasicBlock *> ExitReachingBlocks;
  getExitReachingBlocks(MF, ExitReachingBlocks);

  PublicFrameMap In, Out;
  // Initialize.
  for (MachineBasicBlock &MBB : MF) {
    In[&MBB] = Top;
    Out[&MBB] = Top;

    if (MBB.succ_empty())
      Out[&MBB] = ParentOut.at(&MBB);
    if (!ExitReachingBlocks.count(&MBB)) {
      In[&MBB] = ParentIn.at(&MBB);
      Out[&MBB] = ParentOut.at(&MBB);
    }
  }

  std::set<MachineOperand *> PubLoads;
  for (MachineBasicBlock &MBB : MF) {
    for (MachineInstr &MI : MBB) {
      int FI;
      if (MachineOperand *Def = isEligibleStackLoad(MI, FI))
        if (!Def->isPublic())
          PubLoads.insert(Def);
    }
  }

  // Iterative data-flow analysis.
  bool Changed;
  do {
    Changed = false;

    for (MachineBasicBlock *MBB : llvm::post_order(&MF)) {
      // Compute meet-out for MBB.
      const size_t OldOutSize = Out[MBB].size();

      const auto MeetOutSingle = [&] (int FI) -> bool {
        if (!ParentOut.at(MBB).count(FI))
          for (MachineBasicBlock *Succ : MBB->successors())
            if (!In[Succ].count(FI))
              return false;
        return true;
      };

      for (auto it = Out[MBB].begin(); it != Out[MBB].end(); ) {
        if (MeetOutSingle(*it)) {
          ++it;
        } else {
          it = Out[MBB].erase(it);
        }
      }

      const size_t NewOutSize = Out[MBB].size();

      Changed |= (OldOutSize != NewOutSize);
      assert(NewOutSize <= OldOutSize);


      // Transfer.
      PublicFrameSet PFS;
      for (MachineInstr &MI : llvm::reverse(*MBB)) {
        // Nuke any frame indices that may be stored to.
        if (!MI.mayStore())
          continue;
        for (const MachineOperand &MO : MI.operands())
          if (MO.isFI())
            PFS.erase(MO.getIndex());

        // Is this a stack load?
        {
          int FI;
          if (MachineOperand *Def = isEligibleStackLoad(MI, FI)) {
            if (!PFS.count(FI))
              PubLoads.erase(Def);
          }
        }
      }

      // Set block-in.
      const size_t OldInSize = In[MBB].size();
      for (auto it = In[MBB].begin(); it != In[MBB].end(); ) {
        if (ParentIn.at(MBB).count(*it) || PFS.count(*it)) {
          ++it;
        } else {
          it = In[MBB].erase(it);
        }
      }
      const size_t NewInSize = In[MBB].size();
      Changed |= (OldInSize != NewInSize);
      assert(NewInSize <= OldInSize);
    }
  } while (Changed);

  // Are there any stack loads that can be marked public now?
  bool OverallChanged = false;
  for (MachineOperand *Def : PubLoads) {
    assert(!Def->isPublic());
    Def->setIsPublic();
    OverallChanged = true;
  }
  return OverallChanged;
}

bool StackAnalysis::run() {
  // First, do forward pass to find (frame-index, register) pairs.
  FrameRegMap FRIn;
  FrameRegMap FROut;
  computeFrameRegMap(MF, FRIn, FROut);

  // DEBUG: Dump results.
  if (MF.getName() == "get_ref") {
    errs() << "===== StackAnalysis.FrameRegs.get_ref =====\n";
    const auto PrintFrameRegs = [&] (const FrameRegs &FR) {
      for (const auto &[Reg, Val] : FR) {
        errs() << " " << TRI->getRegAsmName(Reg) << "->";
        if (std::holds_alternative<None>(Val)) {
          errs() << "none";
        } else if (std::holds_alternative<All>(Val)) {
          errs() << "all";
        } else {
          errs() << std::get<int>(Val);
        }
      }
    };
    for (const MachineBasicBlock &MBB : MF) {
      errs() << "\nIN:";
      PrintFrameRegs(FRIn.at(&MBB));
      errs() << "\n";
      errs() << MBB;
      errs() << "OUT:";
      PrintFrameRegs(FROut.at(&MBB));
      errs() << "\n";
    }
  }

  // Then, identify the set of public frame indices at each block in and out.
  PublicFrameMap PFIn;
  PublicFrameMap PFOut;
  for (MachineBasicBlock &MBB : MF) {
    filterFrameRegs(FRIn[&MBB], PTI.In.at(&MBB), PFIn[&MBB]);
    filterFrameRegs(FROut[&MBB], PTI.Out.at(&MBB), PFOut[&MBB]);
  }

  // Finally, do backward pass to mark frame accesses public.
  return stackBackwardsPass(MF, PFIn, PFOut);
}
