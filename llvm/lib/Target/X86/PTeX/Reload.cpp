#include "PTeX/Reload.h"

#include <map>
#include <set>

#include "X86InstrInfo.h"
#include "PTeX/Util.h"
#include "PTeX/DataFlowAnalysis.h"

#define DEBUG_TYPE "x86-ptex-reload"


using namespace llvm;
using X86::PTeXAnalysis;


// A load is eligible for reloading if it has a memory operand, doesn't store,
// and has a protected output.
static bool eligibleLoad(const MachineInstr &MI, MCPhysReg &Reg) {
  [[maybe_unused]] const MachineFunction &MF = *MI.getParent()->getParent();

  if (!MI.mayLoad())
    return false;

  switch (MI.getOpcode()) {
  case X86::MOV64rm:
  case X86::MOV32rm:
  case X86::MOVZX32rm8:
    break;

  default:
    PTEX_DEBUG_MF(dbgs() << "ineligible opcode: " << MI);
    return false;
  }

  // Only include non-volatile loads.
  if (MI.hasOrderedMemoryRef())
    return false;
  assert(!MI.hasUnmodeledSideEffects());

  const int MemIdx = X86::getMemRefBeginIdx(MI);
  if (MemIdx < 0)
    return false;

  // Try to find single explicit protected def.
  const MachineOperand *Def = nullptr;
  for (const MachineOperand &MO : MI.operands())
    if (MO.isReg() && MO.isDef() && !MO.isImplicit() && !MO.isPublic())
      Def = &MO;
  if (!Def) {
    PTEX_DEBUG_MF(dbgs() << "found no explicit protected defs: " << MI);
    return false;
  }

  // Does the instruction have uses and defs that alias?
  const TargetRegisterInfo *TRI = MI.getParent()->getParent()->getSubtarget().getRegisterInfo();
  for (const MachineOperand &Def : MI.operands())
    if (Def.isReg() && Def.isDef())
      for (const MachineOperand &Use : MI.operands())
        if (Use.isReg() && Use.isUse())
          if (TRI->regsOverlap(Def.getReg(), Use.getReg()))
            return false;

  Reg = Def->getReg();

  return true;
}

namespace {

// TODO: rename to ReloadAnalysis, ReloadValue.
using RegLoadValue = std::set<MachineInstr *>;

class RegLoadAnalysis final : public ForwardDataFlowAnalysis<RegLoadValue> {
public:
  RegLoadAnalysis(MachineFunction &MF): ForwardDataFlowAnalysis(MF), TRI(MF.getSubtarget().getRegisterInfo()) {}

private:
  const TargetRegisterInfo *TRI;

  void meet(RegLoadValue &A, const RegLoadValue &B) override;
  void combine(RegLoadValue &A, const RegLoadValue &B) override;
  void transfer(MachineInstr &MI, RegLoadValue &A) override;
  RegLoadValue top() override;
  RegLoadValue botIn(MachineBasicBlock &MBB) override { return {}; }
  RegLoadValue botOut(MachineBasicBlock &MBB) override { return {}; }

  void removeDefs(const MachineInstr &MI, RegLoadValue &A) const;
  bool killsUse(const MachineInstr &MI1, const MachineInstr &MI2) const;

  StringRef getName() const override { return "reload"; }
  void printValue(raw_ostream &os, const RegLoadValue &A) const override {
    llvm::interleave(A,
                     [&os] (const MachineInstr *MI) { os << MI; },
                     [&os] () { os << " "; });
  }
  void printEpilogue(raw_ostream &os) const override {
    os << " >>>> Eligible Load Map <<<<\n";
    for (const MachineBasicBlock &MBB : MF) {
      for (const MachineInstr &MI : MBB) {
        MCPhysReg Reg;
        if (eligibleLoad(MI, Reg))
          os << &MI << ": " << MI;
      }
    }
  }
};


}

void RegLoadAnalysis::meet(RegLoadValue &A, const RegLoadValue &B) {
  RegLoadValue Result;
  std::set_intersection(A.begin(), A.end(), B.begin(), B.end(),
                        std::inserter(Result, Result.end()));
  A = std::move(Result);
}

void RegLoadAnalysis::combine(RegLoadValue &A, const RegLoadValue &B) {
  RegLoadValue Result;
  std::set_union(A.begin(), A.end(), B.begin(), B.end(),
                 std::inserter(Result, Result.end()));
  A = std::move(Result);
}

bool RegLoadAnalysis::killsUse(const MachineInstr &MI1, const MachineInstr &MI2) const {
  for (const MachineOperand &Use1 : MI1.operands())
    if (Use1.isReg() && Use1.isUse())
      for (const MachineOperand &Use2 : MI2.operands())
        if (Use2.isReg() && Use2.isUse() && Use2.isKill() &&
            TRI->regsOverlap(Use1.getReg(), Use2.getReg()))
          return true;
  return false;
}

void RegLoadAnalysis::removeDefs(const MachineInstr &MI, RegLoadValue &Loads) const {
  // Check whether the instruction's uses or defs alias with each load's uses.
  for (auto LoadIt = Loads.begin(); LoadIt != Loads.end(); ) {
    [[maybe_unused]] bool RegHazard = false;
    [[maybe_unused]] bool MemHazard = false;
    [[maybe_unused]] bool KillHazard = false;
    if ((RegHazard = hasRegisterHazard(**LoadIt, MI)) ||
        (MemHazard = hasMemoryHazard(**LoadIt, MI)) ||
        (KillHazard = killsUse(**LoadIt, MI))) {

      [[maybe_unused]] const MachineFunction &MF = *MI.getParent()->getParent();
      if (debugMF(MF)) {
        PTEX_DEBUG_MF(dbgs() << "detected hazard:");
        if (RegHazard)
          LLVM_DEBUG(dbgs() << " reg");
        if (MemHazard)
          LLVM_DEBUG(dbgs() << " mem");
        if (KillHazard)
          LLVM_DEBUG(dbgs() << " kill");
        LLVM_DEBUG(dbgs() << ":\n  candidate load: " << **LoadIt
                   << "  hazard instr: " << MI);
      }

      LoadIt = Loads.erase(LoadIt);
    } else {
      ++LoadIt;
    }
  }
}

void RegLoadAnalysis::transfer(MachineInstr &MI, RegLoadValue &A) {
  // Remove defined or clobbered regs.
  removeDefs(MI, A);

  // Is this an eligible load instruction?
  // If so, add it to the map.
  // TODO: Could also add subregisters to the map, if necessary.
  MCPhysReg Reg;
  if (eligibleLoad(MI, Reg))
    A.insert(&MI);
}

RegLoadValue RegLoadAnalysis::top() {
  RegLoadValue Loads;
  for (MachineBasicBlock &MBB : MF) {
    for (MachineInstr &MI : MBB) {
      MCPhysReg Reg;
      if (eligibleLoad(MI, Reg))
        Loads.insert(&MI);
    }
  }
  return Loads;
}

static void reloadInstrAt(MachineFunction &MF, MachineInstr *MI, MachineBasicBlock &MBB) {
  MachineInstr *NewMI = MF.CloneMachineInstr(MI);
  MBB.insert(MBB.begin(), NewMI);

  // Mark any original uses as non-kill.
  for (MachineOperand &Use : MI->operands())
    if (Use.isReg() && Use.isUse())
      Use.setIsKill(false);

  // Update live-ins of successor.
  // TODO: Can actually remove the data reg live-in-ness.
  for (const MachineOperand &MO : NewMI->operands())
    if (MO.isReg() && MO.isUse() && MO.getReg())
      MBB.addLiveIn(MO.getReg());

  PTEX_DEBUG_MF(dbgs() << "reloaded instruction ";
                MI->getParent()->printName(dbgs());
                dbgs() << " -> ";
                MBB.printName(dbgs());
                dbgs() << ": " << *MI);
}

bool X86::reloadUnprotectedMem(MachineFunction &MF, const PTeXAnalysis &PA) {
  bool Changed = false;

  // Compute which registers depend on which loads at each point in the program.
  RegLoadAnalysis RLA(MF);
  RLA.run();

  PTEX_DEBUG_MF(RLA.print(dbgs()));

  // Find blocks for which a register is in-unprotected but out-protected at a predecessor.
  for (MachineBasicBlock &MBB : MF) {
    if (MBB.pred_size() != 1)
      continue;

    MachineBasicBlock *Pred = *MBB.pred_begin();
    PublicPhysRegs PubRegs = PA.In.at(&MBB);
    PubRegs.removeRegs(PA.Out.at(Pred));

    const RegLoadValue &Loads = RLA.In.at(&MBB);

    // Try to find a register that maps to an instruction.
    for (MCPhysReg PubReg : PubRegs) {
      // Try to find load to this register.
      const auto LoadIt = llvm::find_if(Loads, [PubReg] (const MachineInstr *Load) -> bool {
        MCPhysReg LoadReg;
        eligibleLoad(*Load, LoadReg);
        return LoadReg == PubReg;
      });
      if (LoadIt == Loads.end())
        continue;

      reloadInstrAt(MF, *LoadIt, MBB);
      Changed = true;
    }
  }

  return Changed;
}
