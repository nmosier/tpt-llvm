#include "X86PTeX.h"

#include <optional>
#include <set>
#include <sstream>

// PTEX-TODO: Cull these includes.
#include "X86.h"
#include "X86InstrBuilder.h"
#include "X86Subtarget.h"
#include "llvm/CodeGen/MachineBasicBlock.h"
#include "llvm/CodeGen/MachineFunction.h"
#include "llvm/CodeGen/MachineInstr.h"
#include "llvm/CodeGen/MachineFunctionPass.h"
#include "llvm/CodeGen/MachineModuleInfo.h"
#include "llvm/Pass.h"
#include "llvm/CodeGen/LivePhysRegs.h"
#include "llvm/Support/WithColor.h"
#include "llvm/IR/Value.h"
#include "llvm/Analysis/ValueTracking.h"
#include "X86PrivacyTypeAnalysis.h"
#include "X86PTeXAnalysis.h"
#include "X86LLSCTUtil.h"
#include "X86PublicPhysRegs.h"

#define PTEX_DEBUG 1

using namespace llvm;

using X86::PrivacyMask;
using X86::PublicPhysRegs;

#define PASS_KEY "x86-ptex"
#define DEBUG_TYPE PASS_KEY

namespace llvm::X86 {

static cl::opt<bool> EnablePTeXOpt {
  PASS_KEY,
  cl::desc("Enable PTeX"),
  cl::init(false),
  cl::Hidden,
};

static cl::opt<bool> EnablePTeXDump {
  PASS_KEY "-dump",
  cl::desc("Dump PTeX before/after"),
  cl::init(false),
  cl::Hidden,
};

cl::opt<bool> PrefixProtectedStores {
  PASS_KEY "-stores",
  cl::desc("Add PROT prefix for stores"),
  cl::init(false),
  cl::Hidden,
};

static cl::opt<bool> EliminatePrivateCSRs {
  PASS_KEY "-csrs",
  cl::desc("[PTeX] Eliminate private CSRs"),
  cl::init(true),
  cl::Hidden,
};

static cl::opt<std::string> DumpDir {
  PASS_KEY "-dump-dir",
  cl::desc("[PTeX] Dump directory"),
  cl::init(""),
  cl::Hidden,
};

static cl::opt<bool> DeclassifyBlockEntries {
  PASS_KEY "-block-regs",
  cl::desc("[PTeX] Insert dummy register moves to mark newly registers public on basic block entry"),
  cl::init(true),
  cl::Hidden,
};

bool EnablePTeX() {
  return static_cast<bool>(EnablePTeXOpt);
}

static bool DumpPTeX(const MachineFunction &MF) {
  return EnablePTeXDump && X86::DumpCheckFilter(MF);
}

}

// PTEX-TODO: Rename.

namespace {


class X86PTeX final : public MachineFunctionPass {
public:
  static char ID;
  X86PTeX(bool Instrument) : MachineFunctionPass(ID), Instrument(Instrument) {}

  void getAnalysisUsage(AnalysisUsage& AU) const override {
    AU.setPreservesCFG();
    MachineFunctionPass::getAnalysisUsage(AU);
  }

  bool runOnMachineFunction(MachineFunction& MF) override;

private:
  const bool Instrument;
  const TargetRegisterInfo *TRI = nullptr;
  
  // TODO: Make another object that has MF and PrivTys as member.
  [[nodiscard]] bool instrumentPublicArguments(MachineFunction &MF, const X86::PTeXAnalysis &PTA);
  [[nodiscard]] bool instrumentPublicCalleeReturnValues(MachineFunction &MF);
  [[nodiscard]] bool eliminatePrivateCSRs(MachineFunction &MF, const X86::PTeXAnalysis &PTA);
  [[nodiscard]] bool avoidPartialUpdatesOfPrivateEFLAGS(MachineFunction &MF, X86PrivacyTypeAnalysis &PrivTys);
  [[nodiscard]] bool declassifyBlockEntries(MachineBasicBlock &MBB, const X86::PTeXAnalysis &PTA);
  std::optional<PrivacyType> computeInstrPrivacy(MachineInstr &MI, X86PrivacyTypeAnalysis &PrivTys);
  void annotateVirtualPointers(MachineFunction &MF);

  [[nodiscard]] bool eliminatePrivateCSRsForCall(MachineInstr &MI, PublicPhysRegs &PubRegs,
                                                 auto GetSpillInfo);
  void computePrivateCSRsToSpill(const MachineInstr &MI, const PublicPhysRegs &PubRegs,
                                 SmallVectorImpl<MCPhysReg> &ToSpill);
  MCPhysReg spillPrivateCSR(MCPhysReg SpillReg, MachineInstr &MI, auto GetSpillInfo);

  void validate(MachineFunction &MF, const X86::PTeXAnalysis &PTA);
  void validateInstr(const MachineInstr &MI);
  void validateOperand(const MachineOperand &MO);
  void validateBlock(MachineBasicBlock &MBB, const X86::PTeXAnalysis &PTA);
};

}

char X86PTeX::ID = 0;

bool X86PTeX::runOnMachineFunction(MachineFunction& MF) {
  LLVM_DEBUG(dbgs() << "===== " << getPassName() << " on " << MF.getName() << " =====\n");

  if (!X86::EnablePTeX())
    return false;

  TRI = MF.getSubtarget().getRegisterInfo();

  if (MF.getRegInfo().isSSA()) {
    assert(!Instrument && "Cannot instrument SSA machine IR!");
    annotateVirtualPointers(MF);
    return false;
  }

  const TargetRegisterInfo *TRI = MF.getSubtarget().getRegisterInfo();

  // Run physreg privacy analysis.
  X86::PTeXAnalysis PTA(MF);
  PTA.run();
  if (X86::DumpPTeX(MF))
    PTA.print(errs());

  // Validate
  validate(MF, PTA);

  // If we're not instrumenting the code, then just return.
  if (!Instrument)
    return false;
  
  MF.verify();

  if (X86::DumpPTeX(MF)) {
    errs() << "===== X86PTeX BEFORE: " << MF.getName() << " =====\n";
    MF.print(errs());
    errs() << "===========================================\n";
  }

  bool Changed = false;

  Changed |= instrumentPublicArguments(MF, PTA);
  Changed |= instrumentPublicCalleeReturnValues(MF);
  for (MachineBasicBlock &MBB : MF)
    Changed |= declassifyBlockEntries(MBB, PTA);
  if (X86::EliminatePrivateCSRs)
    Changed |= eliminatePrivateCSRs(MF, PTA);

  if (!X86::DumpDir.getValue().empty()) {
    std::string path;
    raw_string_ostream path_ss(path);
    path_ss << X86::DumpDir.getValue() << "/" << MF.getName().take_front(128) << ".mir";
    std::error_code EC;
    raw_fd_ostream os(path, EC);
    assert(!EC);
    MF.print(os);
  }  
  
  // TODO: Verify some properties, like that there are no privately-typed callee-saved registers.

  if (X86::DumpPTeX(MF)) {
    errs() << "===== X86PTeX AFTER: " << MF.getName() << " =====\n";
    PTA.print(errs());
    errs() << "============================================\n";
  }

  MF.verify();

  return Changed;
}

bool X86PTeX::instrumentPublicArguments(MachineFunction &MF, const X86::PTeXAnalysis &PTA) {
  const TargetInstrInfo *TII = MF.getSubtarget().getInstrInfo();
  const TargetRegisterInfo *TRI = MF.getSubtarget().getRegisterInfo();
  const MachineRegisterInfo &MRI = MF.getRegInfo();
  MachineBasicBlock &MBB = MF.front();
  auto MBBI = MBB.begin();

  auto IsCalleeSaved = [&MRI] (MCPhysReg Reg) -> bool {
    for (const auto *CSR = MRI.getCalleeSavedRegs(); *CSR != X86::NoRegister; ++CSR)
      if (*CSR == Reg)
        return true;
    return false;
  };

  SmallVector<MCPhysReg> PubRegs;
  getRegisterCover(PTA.getIn(&MBB), PubRegs, TRI);

#ifndef NDEBUG
  LLVM_DEBUG(dbgs() << "cover:");
  for (const MCPhysReg Reg : PubRegs)
    LLVM_DEBUG(dbgs() << " " << TRI->getRegAsmName(Reg));
  LLVM_DEBUG(dbgs() << "\n");
#endif

  // Remove any registers from the cover that have live superregs.
  // TODO: Share code with declassifyBlockEntries.
  {
    LivePhysRegs LPR(*TRI);
    LPR.addLiveIns(MBB);
    for (auto it = PubRegs.begin(); it != PubRegs.end(); ) {
      const bool SuperLive = llvm::any_of(TRI->superregs(*it), [&LPR] (MCPhysReg SuperReg) -> bool {
        return LPR.contains(SuperReg);
      });
      if (SuperLive) {
        it = PubRegs.erase(it);
      } else {
        ++it;
      }
    }
  }
  
  for (MCPhysReg PubReg : PubRegs) {
    // Is this a callee-saved register?
    // If so, skip.
    if (IsCalleeSaved(PubReg))
      continue;

    // Is this register live?

    // Insert dummy copy.
    LLVM_DEBUG(dbgs() << "Marking pub-in argument public: "
               << MF.getSubtarget().getRegisterInfo()->getRegAsmName(PubReg) << "\n");
    TII->copyPhysReg(MBB, MBBI, DebugLoc(), PubReg, PubReg, /*KillSrc*/true);

    // PTEX-TODO: We can reduce code size overhead by only inserting copies if the first use of
    // this register will not be a public instruction or will be a store.
  }

  // Mark all operands of inserted instructions as public.
  for (auto MBBI2 = MBB.begin(); MBBI2 != MBBI; ++MBBI2)
    for (MachineOperand &MO : MBBI2->operands())
      if (MO.isReg())
        MO.setIsPublic();

  return MBB.begin() != MBBI;
}

bool X86PTeX::instrumentPublicCalleeReturnValues(MachineFunction &MF) {
  bool Changed = false;
  const TargetInstrInfo *TII = MF.getSubtarget().getInstrInfo();
  const TargetRegisterInfo *TRI = MF.getSubtarget().getRegisterInfo();

  for (MachineBasicBlock &MBB : MF) {
    for (MachineInstr &MI : MBB) {
      if (MI.isCall()) {

        const auto MBBIEnd = std::next(MI.getIterator());
        for (const MachineOperand &MO : MI.operands()) {
          if (MO.isReg() && MO.isDef() && MO.isImplicit() && !MO.isDead() &&
              MO.isPublic() && !X86::regAlwaysPublic(MO.getReg(), *TRI)) {
            TII->copyPhysReg(MBB, MBBIEnd, DebugLoc(), MO.getReg(), MO.getReg(), /*KillSrc*/true);
          }
        }

        const auto MBBIBegin = std::next(MI.getIterator());
        for (auto MBBI = MBBIBegin; MBBI != MBBIEnd; ++MBBI)
          for (MachineOperand &MO : MBBI->operands())
            if (MO.isReg())
              MO.setIsPublic();

        Changed = MBBIBegin != MBBIEnd;

      }
    }
  }

  return Changed;
}

class PrivateSpillInfo {
  std::map<Register, int> Map;

  bool checkNoOverlaps(Register Reg, const TargetRegisterInfo *TRI) const;
public:
  int getOrAllocateSpillSlot(Register Reg, MachineFunction &MF);

  auto begin() const { return Map.begin(); }
  auto end() const { return Map.end(); }
};

bool PrivateSpillInfo::checkNoOverlaps(Register Reg, const TargetRegisterInfo *TRI) const {
  for (const auto &[OtherReg, _] : Map) {
    if (TRI->regsOverlap(Reg, OtherReg)) {
      LLVM_DEBUG(dbgs() << "Register " << TRI->getRegAsmName(Reg)
                 << " overlaps with " << TRI->getRegAsmName(OtherReg) << "\n");
      return false;
    }
  }
  return true;
}
  

// TODO: Make MF class member, not function argument.
int PrivateSpillInfo::getOrAllocateSpillSlot(Register Reg, MachineFunction &MF) {
  // Try to retrieve existing spill slot.
  {
    const auto MapIt = Map.find(Reg);
    if (MapIt != Map.end())
      return MapIt->second;
  }

  const auto *TRI = MF.getSubtarget().getRegisterInfo();
  MachineFrameInfo &MFI = MF.getFrameInfo();

  // Otherwise, ensure no overlapping register has already been allocated.
  assert(checkNoOverlaps(Reg, TRI) && "Found overlap!");

  // Allocate new frame index.
  const auto *RegClass = TRI->getMinimalPhysRegClass(Reg);
  const unsigned SpillSize = TRI->getSpillSize(*RegClass);
  const Align SpillAlign = TRI->getSpillAlign(*RegClass);
  const int FrameIndex = MFI.CreateSpillStackObject(SpillSize, SpillAlign);
  Map[Reg] = FrameIndex;
  return FrameIndex;
}

void X86PTeX::computePrivateCSRsToSpill(const MachineInstr &MI, const PublicPhysRegs &PubRegs,
                                         SmallVectorImpl<MCPhysReg> &ToSpill) {
  assert(MI.isCall());  

  const MachineFunction &MF = *MI.getParent()->getParent();
  const MachineFrameInfo &MFI = MF.getFrameInfo();
  const auto *TRI = MF.getSubtarget<X86Subtarget>().getRegisterInfo();

  // Private registers that require spilling are those that meet the following criteria:
  //   - They are not pristine (see MachineFrameInfo::getPristineRegs()).
  //   - They are private (i.e., not in PubRegs).
  //   - They are callee-saved (i.e., they are in the MO_RegMask operand of the call).

  // To start, let's generate the set of private registers to spill.
  std::set<MCPhysReg> PrivateCSRs; // TODO: Should probably be bitset.
  const auto CSRs = X86::util::get_call_regmask(MI);
  for (MCPhysReg CSR = 0; CSR < CSRs.size(); ++CSR)
    if (CSRs[CSR])
      PrivateCSRs.insert(CSR);
  // At this point, criterion 3 is met.
  // Now, remove public CSRs.
  for (MCPhysReg PubReg : PubRegs) 
    if (auto FullPubReg = getX86SubSuperRegisterOrZero(PubReg, 64))
      for (MCPhysReg SubPubReg : TRI->subregs_inclusive(FullPubReg))
        PrivateCSRs.erase(SubPubReg);
  // Remove the frame pointer.
  if (const Register Reg = TRI->getFrameRegister(MF))
    for (MCPhysReg SubReg : TRI->subregs_inclusive(Reg))
      PrivateCSRs.erase(SubReg);
  // Remove the base pointer.
  if (TRI->hasBasePointer(MF))
    for (MCPhysReg SubReg : TRI->subregs_inclusive(TRI->getBaseRegister()))
      PrivateCSRs.erase(SubReg);
  
  // Now, criterion 2 and 3 are met.
  // Finally, remove pristine registers.
#if 0
  const auto PristineRegs = MFI.getPristineRegs(MF);
  for (MCPhysReg PristineReg = 0; PristineReg < PristineRegs.size(); ++PristineReg)
    if (PristineRegs[PristineReg])
      PrivateCSRs.erase(PristineReg);
#elif 0
  // TODO: Communicate this in argument.
  LivePhysRegs LPR(*TRI);
  LPR.addLiveInsNoPristines(*MI.getParent());
  for (auto MBBI = MI.getParent()->begin(); MBBI != MI.getIterator(); ++MBBI) {
    SmallVector<std::pair<MCPhysReg, const MachineOperand *>> Clobbers;
    LPR.stepForward(*MBBI, Clobbers);
  }
  for (auto PrivateCSRIt = PrivateCSRs.begin(); PrivateCSRIt != PrivateCSRs.end(); ){
    if (LPR.contains(*PrivateCSRIt)) {
      ++PrivateCSRIt;
    } else {
      PrivateCSRIt = PrivateCSRs.erase(PrivateCSRIt);
    }
  }
  // FIXME: This is not conservative. We need to also protect dead registers potentially.
  // We might need to do a reaching def analysis or something like that.
#endif

  // Finally, compute the maximal cover.
  getRegisterCover(PrivateCSRs, ToSpill, TRI);

  // If we have any weird upper-half registers in there, just throw them out.
  

#if 0
  // But agh, we might have some funky non-standard registers in there now, like
  // the upper word of EAX.
  static const TargetRegisterClass *GoldenRCs[] = {
    &X86::GR8RegClass, &X86::GR16RegClass, &X86::GR32RegClass, &X86::GR64RegClass,
  };
  // For each register, 

  
  assert(llvm::any_of(GoldenRCs, [&] (const TargetRegisterClass *GoldenRC) -> bool {
    return GoldenRC->hasSubclassEq(RegClass);
  }));
  
  
  
  // Find the minimal register that
#endif
}

// TODO: Change GetSpillInfo to std::function, at least.
MCPhysReg X86PTeX::spillPrivateCSR(MCPhysReg SpillReg, MachineInstr &MI, auto GetSpillInfo) {
  const auto PreMBBI = MI.getIterator();
  const auto PostMBBI = std::next(PreMBBI);
  MachineBasicBlock &MBB = *MI.getParent();
  MachineFunction &MF = *MBB.getParent();
  const auto &Subtarget = MF.getSubtarget();
  const TargetRegisterInfo *TRI = Subtarget.getRegisterInfo();
  const TargetInstrInfo *TII = Subtarget.getInstrInfo();
  const auto *RegClass = TRI->getMinimalPhysRegClass(SpillReg);
  // TODO: Rephrase debug message -- we won't always spill here.
  LLVM_DEBUG(dbgs() << "Spilling private CSR " << TRI->getRegAsmName(SpillReg) << "\n");

  // Allocate or get spill slot for register.
  PrivateSpillInfo &PSI = *GetSpillInfo(&MI, SpillReg);
  // TODO: Allocate spill slot only if we're going to actually store it.
  const int FrameIndex = PSI.getOrAllocateSpillSlot(SpillReg, MF);

  // Is this register live before the call?
  bool CSRLive = false;
  {
    LivePhysRegs LPR(*TRI);
    LPR.addLiveIns(MBB);
    for (auto MBBI = MBB.begin(); MBBI != MI.getIterator(); ++MBBI) {
      SmallVector<std::pair<MCPhysReg, const MachineOperand *>> Clobbers;
      LPR.stepForward(*MBBI, Clobbers);
    }
    CSRLive = !LPR.available(MF.getRegInfo(), SpillReg);
  }

  // Store to spill slot before call.
  // TODO: Should also check if it's live, once we start spilling dead registers.
  // TODO: Actually, once we check if it's live, then we don't need to check ...
  // TODO: Actually, isn't this impossible? We should only have public CSRs on return.
  if (!MI.isReturn() && CSRLive) {
    // Insert store instruction.
    TII->storeRegToStackSlot(MBB, PreMBBI, SpillReg, /*isKill*/true, FrameIndex, RegClass, TRI, X86::NoRegister);
  }

  // Then zero out the register.
#ifndef NDEBUG
  // Make sure that we don't have any weird overlapping live registers.
  {
    LivePhysRegs LPR(*TRI);
    LPR.addLiveIns(MBB);
    const MachineRegisterInfo &MRI = MF.getRegInfo();
    for (auto it = MBB.begin(); it != MI.getIterator(); ++it) {
      SmallVector<std::pair<MCPhysReg, const MachineOperand *>> Clobbers;
      LPR.stepForward(*it, Clobbers);
    }
    LPR.removeReg(SpillReg);
    assert(LPR.available(MRI, SpillReg));
  }
#endif
  MachineInstr *ZeroMI =
      BuildMI(MBB, PreMBBI, DebugLoc(), TII->get(X86::MOV32r0))
      .addDef(getX86SubSuperRegister(SpillReg, 32), RegState::Dead)
      .addDef(X86::EFLAGS, RegState::Implicit | RegState::Dead)
      .addDef(getX86SubSuperRegister(SpillReg, 64), RegState::Implicit | RegState::Dead)
      .getInstr();
  for (MachineOperand &MO : ZeroMI->operands())
    if (MO.isDef())
      MO.setIsPublic();

  // Load from spill slot after call.
  // TODO: Shouldn't MI.isReturn() be impossible?
  if (!MI.isReturn() && CSRLive) {
    // Insert load instruction.
    TII->loadRegFromStackSlot(MBB, PostMBBI, SpillReg, FrameIndex, RegClass, TRI, X86::NoRegister);
  }

  return getX86SubSuperRegister(SpillReg, 64);
}

bool X86PTeX::eliminatePrivateCSRsForCall(MachineInstr &MI, PublicPhysRegs &PubRegs, auto GetSpillInfo) {
  assert(MI.isCall());

  // Collect registers to spill.
  SmallVector<MCPhysReg> ToSpill;
  computePrivateCSRsToSpill(MI, PubRegs, ToSpill);
  if (!ToSpill.empty()) {
    LLVM_DEBUG(dbgs() << "Spilling private CSRs");
    for (MCPhysReg Reg : ToSpill)
      LLVM_DEBUG(dbgs() << " " << MI.getParent()->getParent()->getSubtarget().getRegisterInfo()->getRegAsmName(Reg));
    LLVM_DEBUG(dbgs() << " for call: " << MI);
  }

  for (MCPhysReg PrivateCSR : ToSpill) {
    const MCPhysReg ZeroReg = spillPrivateCSR(PrivateCSR, MI, GetSpillInfo);
#if 0
    PubRegs.addReg(ZeroReg);
#endif
  }

  return !ToSpill.empty();
}

bool X86PTeX::eliminatePrivateCSRs(MachineFunction &MF, const X86::PTeXAnalysis &PTA) {
  bool Changed = false;
  const TargetInstrInfo *TII = MF.getSubtarget().getInstrInfo();
  const TargetRegisterInfo *TRI = MF.getSubtarget().getRegisterInfo();
  const MachineRegisterInfo &MRI = MF.getRegInfo();

  // TODO: This assertion really needs to be made much earlier on. Along with !isSSA().
  assert(MF.getRegInfo().tracksLiveness());

  std::map<const LandingPadInfo *, PrivateSpillInfo> InvokePrivateSpillInfo;
  std::map<MachineInstr *, PrivateSpillInfo> CallPrivateSpillInfo;

  // Precompute EH_LABELs for function.
  std::map<const MCSymbol *, MachineInstr *> Labels;
  for (MachineBasicBlock &MBB : MF) {
    for (MachineInstr &MI : MBB) {
      if (MI.isEHLabel()) {
        assert(MI.getNumOperands() == 1);
        const MachineOperand &MO = MI.getOperand(0);
        assert(MO.isMCSymbol());
        Labels[MO.getMCSymbol()] = &MI;
      }
    }
  }

  auto HasLabel = [&] (const MCSymbol *Sym) -> bool {
    return Labels.count(Sym) > 0;
  };
  auto IsPhantomLPI = [&] (const LandingPadInfo &LPI) -> bool {
    const bool NotPhantom = HasLabel(LPI.LandingPadLabel);
    for (const MCSymbol *BeginLabel : LPI.BeginLabels)
      assert(HasLabel(BeginLabel) == NotPhantom);
    for (const MCSymbol *EndLabel : LPI.EndLabels)
      assert(HasLabel(EndLabel) == NotPhantom);
    return !NotPhantom;
  };

  // Precompute invokes.
  std::map<MachineInstr *, const LandingPadInfo *> InvokeToLandingPad;
  for (const LandingPadInfo &LPI : MF.getLandingPads()) {
    assert(LPI.BeginLabels.size() == LPI.EndLabels.size());

    // Skip over any phantom LPIs.
    if (IsPhantomLPI(LPI))
      continue;

    for (const auto &[BeginLabel, EndLabel] : llvm::zip_equal(LPI.BeginLabels, LPI.EndLabels)) {
      const auto BeginMBBI = std::next(Labels.at(BeginLabel)->getIterator());
      const auto EndMBBI = Labels.at(EndLabel)->getIterator();
      const auto InvokeMBBI =
          std::find_if(BeginMBBI, EndMBBI, [] (const MachineInstr &MI) -> bool { return MI.isCall(); });
      assert(InvokeMBBI != EndMBBI);
      InvokeToLandingPad[&*InvokeMBBI] = &LPI;
    }
  }

  // TODO: It's super messy doing it this way.
  auto GetSpillInfo = [&] (MachineInstr *MI, Register Reg) -> PrivateSpillInfo * {
    const auto InvokeToLandingPadIt = InvokeToLandingPad.find(MI);
    if (InvokeToLandingPadIt == InvokeToLandingPad.end()) {
      // Regular call.
      LLVM_DEBUG(dbgs() << "Call: " << *MI);
      return &CallPrivateSpillInfo[MI];
    }

    // Invoke-style instruction.
    // However, treat it as a call if the register isn't live at landingpad entry.

    // Is the register live at the landingpad entry?
    const LandingPadInfo *LPI = InvokeToLandingPadIt->second;
    {
      LivePhysRegs LPR(*TRI);
      LPR.addLiveIns(*LPI->LandingPadBlock);
      if (!LPR.available(MRI, Reg))
        return &InvokePrivateSpillInfo[LPI];
    }

#ifndef NDEBUG
    // Make sure no registers errantly overlap.
    for (const auto &p : LPI->LandingPadBlock->liveins()) {
      if (TRI->regsOverlap(p.PhysReg, Reg)) {
        errs() << "registers overlap: " << TRI->getRegAsmName(p.PhysReg) << " "
               << TRI->getRegAsmName(Reg) << "\n";
        errs() << "pub-ins to block: " << PTA.getIn(MI->getParent()) << "\n";
        errs() << *MI->getParent() << "\n";
      }
      assert(!TRI->regsOverlap(p.PhysReg, Reg));
    }
#endif

    // Treat as call.
    return &CallPrivateSpillInfo[MI];
  };

  bool IterChanged;
  for (MachineBasicBlock &MBB : MF) {
    PublicPhysRegs PubRegs = PTA.getIn(&MBB);
    for (auto MBBI = MBB.begin(); MBBI != MBB.end(); ) {
      MachineInstr &MI = *MBBI;
      if (MI.isCall()) {
        std::optional<MachineBasicBlock::iterator> PreMBBI;
        if (MBBI != MBB.begin())
          PreMBBI = std::prev(MBBI);
        const auto PostMBBI = std::next(MBBI);

        const bool LocalChange = eliminatePrivateCSRsForCall(MI, PubRegs, GetSpillInfo);
        Changed |= LocalChange;

        // If we inserted instructions, then we stutter.
        if (LocalChange) {
          MBBI = PreMBBI ? std::next(*PreMBBI) : MBB.begin();
          continue;
        }
      }

      // In this case, we didn't add any new instructions, so advance.
      PubRegs.stepForward(MI);
      ++MBBI;
    }
  }

  // Restore at each landingpad.
  for (const auto &[LPI, SpillInfo] : InvokePrivateSpillInfo) {
    MachineBasicBlock &MBB = *LPI->LandingPadBlock;
    auto MBBI = MBB.begin();
    for (const auto &[Reg, FrameIndex] : SpillInfo) {
      const auto *RegClass = TRI->getMinimalPhysRegClass(Reg);
      TII->loadRegFromStackSlot(MBB, MBBI, Reg, FrameIndex, RegClass, TRI, X86::NoRegister);
      Changed = true;
    }
  }  
  
  return Changed;

  // =====================================================================

#if 0 



    
    LivePhysRegs LPR(*TRI);
    LPR.addLiveInsNoPristines(MBB);
    
    for (MachineInstr &MI : MBB) {
      if (MI.isCall()) {
        LLVM_DEBUG(dbgs() << __func__ << ": processing call: " << MI);
        
        PrivacyMask &CallPrivacyIn = PrivTys.getInstrPrivacyIn(&MI);
        PrivacyMask &CallPrivacyOut = PrivTys.getInstrPrivacyOut(&MI);
        // Recall that the call's regmask marks which registers are preserved.
        // We'll want to ensure that any registers that are preserved are publicly-typed, not privately-typed.

        const auto PreMBBI = MI.getIterator();
        const auto PostMBBI = [&] () -> MachineBasicBlock::iterator {
          return std::next(PreMBBI);
        };
        
        const PrivacyMask::Bitset PrivateRegs = CallPrivacyIn.getPrivateBitset();
        const auto RegMaskIt = llvm::find_if(MI.operands(), [] (const MachineOperand &MO) -> bool {
          return MO.isRegMask();
        });
        assert(RegMaskIt != MI.operands_end());
        const PrivacyMask::Bitset CalleeSavedRegs = PrivacyMask::regmaskToBitset(RegMaskIt->getRegMask());
        const PrivacyMask::Bitset PrivateCalleeSaves = (PrivateRegs & CalleeSavedRegs);
        for (Register Reg : LPR) {

          // If the register has a live parent, then skip.
          if (llvm::any_of(TRI->superregs(Reg), [&] (Register SuperReg) -> bool {
            return LPR.contains(SuperReg);
          })) {
            continue;
          }

          // FIXME: Don't want to spill canonicalized live register. Only want to spill live subreg.
          const Register CanonicalReg = PrivacyMask::canonicalizeRegister(Reg);

          // If the canonicalize register isn't a GPR, then it's not callee-saved anyway.
          if (!X86::GR64RegClass.contains(CanonicalReg))
            continue;

          // If it's not a callee-saved register, skip.
          if (!PrivateCalleeSaves.test(CanonicalReg))
            continue;

          // We shouldn't've already handled it.

#if 0
          if (!(debug_min <= debug_cur && debug_cur <= debug_max)) {
            ++debug_cur;
            continue;
          }
#endif

          const auto *RegClass = TRI->getMinimalPhysRegClass(Reg);

          static const TargetRegisterClass *GoldenRCs[] = {
            &X86::GR8RegClass, &X86::GR16RegClass, &X86::GR32RegClass, &X86::GR64RegClass,
          };
          if (llvm::none_of(GoldenRCs, [&] (const TargetRegisterClass *GoldenRC) -> bool {
            return GoldenRC->hasSubClassEq(RegClass);
          })) {
            LLVM_DEBUG(dbgs() << "Not spilling private callee-saved register "
                       "because it has an unsupported register class: " << TRI->getRegAsmName(Reg) << "\n");
            continue;
          }

          LLVM_DEBUG(dbgs() << "Spilling private callee-saved register " << TRI->getRegAsmName(Reg) << "\n");

          // Allocate new stack spill slot.
          PrivateSpillInfo &PSI = *getSpillInfo(&MI, Reg);
          const int FrameIndex = PSI.getOrAllocateSpillSlot(Reg, MF);

          // Store to spill slot before call.
          if (!MI.isReturn()) {

            // Insert store instruction.
            TII->storeRegToStackSlot(MBB, PreMBBI, Reg, /*isKill*/true, FrameIndex, RegClass, TRI, X86::NoRegister);
            MachineInstr *StoreMI = &*std::prev(PreMBBI);
            assert(StoreMI->mayStore());

            // Set in- and out-privacy for StoreMI (unchanged).
            PrivTys.getInstrPrivacyIn(StoreMI) = CallPrivacyIn;
            PrivTys.getInstrPrivacyOut(StoreMI) = CallPrivacyIn;
          }

          // Then zero out the register.
          {

            // Insert zero instruction.
            const Register SubReg = getX86SubSuperRegister(Reg, 32);
            MachineInstr *ZeroMI = BuildMI(MBB, PreMBBI, DebugLoc(), TII->get(X86::MOV32r0), SubReg)
                                       .addDef(X86::EFLAGS, RegState::Implicit)
                                       .getInstr();
              
            // Set in-privacy for ZeroMI (unchanged).
            PrivTys.getInstrPrivacyIn(ZeroMI) = CallPrivacyIn;
              
            // Mark register as now publicly-typed.
            // TODO: Create function to mark all outputs public.
            CallPrivacyIn.markAllInstrOutsPublic(*ZeroMI);
            
            // Set out-privacy for ZeroMI.
            PrivTys.getInstrPrivacyOut(ZeroMI) = CallPrivacyIn;
          }

          // Load from spill slot after call.
          if (!MI.isReturn()) {

            // Insert load instruction.
            TII->loadRegFromStackSlot(MBB, PostMBBI(), Reg, FrameIndex, RegClass, TRI, X86::NoRegister);
            MachineInstr *LoadMI = &*PostMBBI();
            assert(LoadMI->mayLoad());

            // Set out-privacy for LoadMI (unchanged).
            PrivTys.getInstrPrivacyOut(LoadMI) = CallPrivacyOut;

            // Mark register as publicly-typed before load.
            CallPrivacyOut.set(Reg, PubliclyTyped);

            // Set in-privacy for LoadMI.
            PrivTys.getInstrPrivacyIn(LoadMI) = CallPrivacyOut;
          }

          Changed = true;

          ++debug_cur;
        }
      }

      SmallVector<std::pair<MCPhysReg, const MachineOperand *>> Clobbers;
      LPR.stepForward(MI, Clobbers);
    }
  }

  // Restore at each landingpad.
  for (const auto &[LPI, SpillInfo] : InvokePrivateSpillInfo) {
    MachineBasicBlock &MBB = *LPI->LandingPadBlock;
    auto MBBI = MBB.begin();
    for (const auto &[Reg, FrameIndex] : SpillInfo) {
      const auto *RegClass = TRI->getMinimalPhysRegClass(Reg);
      TII->loadRegFromStackSlot(MBB, MBBI, Reg, FrameIndex, RegClass, TRI, X86::NoRegister);
      Changed = true;
    }
  }

  return Changed;

#endif
}

bool X86PTeX::avoidPartialUpdatesOfPrivateEFLAGS(MachineFunction &MF, X86PrivacyTypeAnalysis &PrivTys) {
  bool Changed = false;

  const TargetRegisterInfo *TRI = MF.getSubtarget().getRegisterInfo();
  const X86InstrInfo *TII = MF.getSubtarget<X86Subtarget>().getInstrInfo();

  // We'll just do this on an intra-block basis.
  // If privately-typed EFLAGS are live across multiple blocks, god help us.
  // (Actually, it's fine for security, just not performance.)
  for (MachineBasicBlock &MBB : MF) {
    LivePhysRegs LPR(*TRI);
    LPR.addLiveIns(MBB);
    for (MachineInstr &MI : MBB) {
#if 0
      // We insert a dummy no-op to reset private EFLAGS if:
      //   i.   the EFLAGS are private before MI (duh)
      //   ii.  EFLAGS is not live before MI
      //   iii. MI defs EFLAGS
      //   iv.  MI partially updates EFLAGS
      const bool EFLAGSPrivateIn = (PrivTys.getInstrPrivacyIn(&MI).get(X86::EFLAGS) == PrivatelyTyped);
      const bool EFLAGSPrivateOut = (PrivTys.getInstrPrivacyOut(&MI).get(X86::EFLAGS) == PrivatelyTyped);
      const bool EFLAGSLiveIn = LPR.contains(X86::EFLAGS);
      SmallVector<std::pair<MCPhysReg, const MachineOperand *>> Clobbers;
      LPR.stepForward(MI, Clobbers);
      const bool EFLAGSDef = llvm::count_if(Clobbers, [] (const auto &Pair) -> bool {
        return Pair.first == X86::EFLAGS;
      }) > 0;
      if (EFLAGSPrivateIn && !EFLAGSPrivateOut && !EFLAGSLiveIn && EFLAGSDef && TII->partiallyUpdatesEFLAGS(MI)) {
        MachineInstr *ZeroFlagsMI = BuildMI(MBB, MI.getIterator(), DebugLoc(), TII->get(X86::OR32rr), X86::ESP)
                                        .addReg(X86::ESP)
                                        .addReg(X86::ESP)
                                        .getInstr();
        auto &Privacy = PrivTys.getInstrPrivacyIn(&MI);
        PrivTys.getInstrPrivacyIn(ZeroFlagsMI) = Privacy;
        Privacy.set(X86::EFLAGS, PubliclyTyped);
        PrivTys.getInstrPrivacyOut(ZeroFlagsMI) = Privacy;
        Changed = true;
        LLVM_DEBUG(dbgs() << "Cleaned private EFLAGS before instruction: " << MI);
        // PTEX-TODO: An even better approach would be to just transform the instruction itself.
        // But this might take more engineering work.
        // Just adding a new instruction is easiest for now.
      }
#elif 0
      // PTEX-FIXME: Re-enable.
      if (PrivTys.getInstrPrivacyIn(&MI).get(X86::EFLAGS) == PrivatelyTyped &&
          PrivTys.getInstrPrivacyOut(&MI).get(X86::EFLAGS) == PubliclyTyped &&
          mayPartiallyUpdateEFLAGS(MI)) {

        assert(llvm::any_of(MI.operands(), [] (const auto &MO) {
          return MO.isReg() && MO.getReg() == X86::EFLAGS && MO.isDef();
        }));
        assert(llvm::none_of(MI.operands(), [] (const auto &MO) {
          return MO.isReg() && MO.getReg() == X86::EFLAGS && MO.isUse();
        }));

        MachineInstr *CleanFlagsMI = BuildMI(MBB, MI.getIterator(), DebugLoc(), TII->get(X86::OR32rr), X86::ESP)
                                         .addReg(X86::ESP)
                                         .addReg(X86::ESP)
                                         .getInstr();
        auto &Privacy = PrivTys.getInstrPrivacyIn(&MI);
        PrivTys.getInstrPrivacyIn(CleanFlagsMI) = Privacy;
        Privacy.set(X86::EFLAGS, PubliclyTyped);
        PrivTys.getInstrPrivacyOut(CleanFlagsMI) = Privacy;
        Changed = true;
        LLVM_DEBUG(dbgs() << "Cleaned private EFLAGS before instruction: " << MI);
      }
#endif
    }
  }

  return Changed;
}

// TODO: Unify with `get/setInstrPublic`
std::optional<PrivacyType> X86::getInstrPrivacy(const MachineInstr &MI) {
  const bool Pub = MI.getFlag(MachineInstr::TPEPubM);
  const bool Priv = MI.getFlag(MachineInstr::TPEPrivM);
  if (Pub && !Priv) {
    return PubliclyTyped;
  } else if (!Pub && Priv) {
    return PrivatelyTyped;
  } else if (!Pub && !Priv) {
    return std::nullopt;
  } else {
    MI.print(errs());
    llvm_unreachable("both pub and priv are set for machine instr!");
  }
}

void X86::setInstrPrivacy(MachineInstr &MI, PrivacyType PrivTy) {
  const std::optional<PrivacyType> OrigInstrTy = getInstrPrivacy(MI);
  assert(!(OrigInstrTy == PubliclyTyped && PrivTy == PrivatelyTyped) &&
         "Attempting to change instruction privacy from public to private!");
  if (OrigInstrTy)
    MI.clearFlag(MachineInstr::TPEPrivM);
  switch (PrivTy) {
  case PubliclyTyped:
    MI.setFlag(MachineInstr::TPEPubM);
    break;
  case PrivatelyTyped:
    MI.setFlag(MachineInstr::TPEPrivM);
    break;
  default:
    llvm_unreachable("Bad privacy type!");
  }
}

std::optional<PrivacyType> X86PTeX::computeInstrPrivacy(MachineInstr &MI, X86PrivacyTypeAnalysis &PrivTys) {
  // Calls never get privacy prefixes.
  if (MI.isCall())
    return std::nullopt;
  
  SmallVector<const MachineOperand *, 2> OutRegs;
  X86::getInstrDataOutputs(MI, OutRegs);

  SmallVector<PrivacyType, 2> OutPrivs;
  for (const MachineOperand *MO : OutRegs)
    OutPrivs.push_back(PrivTys.getInstrPrivacyOut(&MI).get(MO->getReg()));

  // If there are any output registers, use that
  if (!OutPrivs.empty()) {
    assert(llvm::all_equal(llvm::make_range(OutPrivs.begin(), OutPrivs.end())));
    return OutPrivs[0];
  }

  // If the instruction has a load, then default to privately-typed.
  if (MI.mayLoad()) {
    std::optional<PrivacyType> InstrPrivacy = X86::getInstrPrivacy(MI);
    if (!InstrPrivacy) {
      InstrPrivacy = PrivatelyTyped;
      LLVM_DEBUG(dbgs() << "Defaulting load with no output to privately-typed: " << MI);
    }
    return InstrPrivacy;
  }

  // Check if we're inserting protection prefixes for stores.
  if (X86::PrefixProtectedStores && MI.mayStore()) {
    std::optional<PrivacyType> InstrPrivacy = X86::getInstrPrivacy(MI);
    if (InstrPrivacy) {
      LLVM_DEBUG(dbgs() << "Store has explicit privacy " << (int) *InstrPrivacy << ": " << MI);
      return InstrPrivacy;
    } else {
      for (const MachineOperand &MO : MI.operands())
        if (MO.isReg() && MO.isUse() && !MO.isUndef() &&
            PrivTys.getInstrPrivacyIn(&MI).get(MO.getReg()) == PrivatelyTyped)
          return PrivatelyTyped;
      return PubliclyTyped;
    }
  }

  // Otherwise, no need to insert prefix.
  LLVM_DEBUG(dbgs() << "Instruction does not require privacy type: " << MI);
  return std::nullopt;
}

static void annotateVirtualPointersInstr(MachineInstr &MI, const MachineRegisterInfo &MRI) {
  // Check if this instruction has any pointer-typed data operands.
  auto IsVirtPtrData = [&] (const MachineOperand &MO) -> bool {
    // Is it a pointer-typed virtual register?
    if (!(MO.isReg() && MRI.getType(MO.getReg()).isPointer()))
      return false;

    // Is this an address operand, not a data operand?
    if (MI.mayLoadOrStore())
      if (const int MemIdx = X86::getMemRefBeginIdx(MI); MemIdx >= 0)
        for (int i = MemIdx; i < MemIdx + X86::AddrNumOperands; ++i)
          if (&MO == &MI.getOperand(i))
            return false;

    // It's a data operand.
    return true;
  };

  // Does this instruction have any pointer-typed data operands?
  if (!llvm::any_of(MI.operands(), IsVirtPtrData))
    return;

  // Yes, it does. Mark instruction public.
  setInstrPublic(MI, "vptr");
  LLVM_DEBUG(dbgs() << "PTeX.LLT: marking instruction public: " << MI);
}

void X86PTeX::annotateVirtualPointers(MachineFunction &MF) {
  const MachineRegisterInfo &MRI = MF.getRegInfo();
  for (MachineBasicBlock &MBB : MF)
    for (MachineInstr &MI : MBB)
      annotateVirtualPointersInstr(MI, MRI);
  MF.getRegInfo().clearVirtRegTypes();
}

void X86PTeX::validate(MachineFunction &MF, const X86::PTeXAnalysis &PTA) {
  const TargetRegisterInfo *TRI = MF.getSubtarget().getRegisterInfo();
  
  // If an explicit output is public, then all implicit outputs should be public.
  for (MachineBasicBlock &MBB : MF) {
    for (MachineInstr &MI : MBB) {
      const bool ExplicitOutputPublic = llvm::any_of(MI.operands(), [] (const MachineOperand &MO) -> bool {
        return MO.isReg() && MO.isDef() && !MO.isImplicit() && MO.isPublic();
      });
      if (ExplicitOutputPublic) {
        for (const MachineOperand &MO : MI.operands()) {
          if (MO.isReg() && MO.isDef() && MO.isImplicit() && !MO.isPublic()) {
#if 0
            assert(MO.isPublic());
#else
            LLVM_DEBUG(dbgs() << "warning: implicit output protected despite explicit output being unprotected: " << MI);
#endif
          }
        }
      }
    }
  }

  // Our PublicPhysRegs iterator should be precise.
  for (MachineBasicBlock &MBB : MF) {
    PublicPhysRegs PubRegs = PTA.getIn(&MBB);

    // FIXME: Should re-enable this in some capacity.
    // The issue is that block live-ins are imperfect themselves.
#if 0
    for (const MachineInstr &MI : MBB) {
      // Ensure that all public uses are marked public in PubRegs.
      for (const MachineOperand &MO : MI.operands())
        if (MO.isReg() && MO.isUse() && MO.isPublic())
          assert(PubRegs.isPublic(MO.getReg())
                 && "Public register use is not marked public in PublicPhysRegs");
      PubRegs.stepForward(MI);
    }
#endif

    // FIXME: Re-enable later.
#if 0
    PubRegs = PTA.getOut(&MBB);
    for (const MachineInstr &MI : llvm::reverse(MBB)) {
      // Ensure that all public defs are marked public in PubRegs.
      for (const MachineOperand &MO : MI.operands())
        if (MO.isReg() && MO.isDef() && MO.isPublic() && !MO.isDead())
          assert(PubRegs.isPublic(MO.getReg())
                 && "Public register def is not marked public in PublicPhysRegs");
      PubRegs.stepBackward(MI);
    }
#endif

    validateBlock(MBB, PTA);
    
    for (const MachineInstr &MI : MBB)
      validateInstr(MI);
  }
}

void X86PTeX::validateBlock(MachineBasicBlock &MBB, const X86::PTeXAnalysis &PTA) {
  const PublicPhysRegs &PubRegs = PTA.getIn(&MBB);

#if 0
  // Quick check that any public uses at the front of the MBB are marked public in PTA.
  if (!MBB.empty())
    for (const MachineOperand &MO : MBB.front().operands())
      if (MO.isReg() && MO.isUse() && MO.isPublic())
        assert(PubRegs.isPublic(MO.getReg()) &&
               "Public use of first instruction in block is not marked pub-in in block!");
#endif
}

void X86PTeX::validateInstr(const MachineInstr &MI) {
  // Validate operands.
  for (const MachineOperand &MO : MI.operands())
    validateOperand(MO);
}

void X86PTeX::validateOperand(const MachineOperand &MO) {
  assert(!(MO.isReg() && MO.isUndef() && MO.isPublic()) && "Found an undef+public operand!");

  if (MO.isReg() && X86::regAlwaysPublic(MO.getReg(), *TRI))
    assert(MO.isPublic() && "Operand with always-public register was not marked public!");
}

bool X86PTeX::declassifyBlockEntries(MachineBasicBlock &MBB, const X86::PTeXAnalysis &PTA) {
  // TODO: Make TRI, TII members.
  const TargetRegisterInfo *TRI = MBB.getParent()->getSubtarget().getRegisterInfo();
  const TargetInstrInfo *TII = MBB.getParent()->getSubtarget().getInstrInfo();

  // Find any registers that are private in a predecessor but public-in to this block.
  // Essentially, take the intersection of this block's pub-ins and all predecessor's pub-outs.
  // Then insert a dummy move for each register in the block's pub-ins but not in this intersection.
  const PublicPhysRegs &OurPubRegs = PTA.getIn(&MBB);
  PublicPhysRegs TheirPubRegs = OurPubRegs;
  for (MachineBasicBlock *PredMBB : MBB.predecessors())
    TheirPubRegs.intersect(PTA.getOut(PredMBB));
  SmallVector<MCPhysReg> NewPubRegsRaw;
  for (MCPhysReg OurPubReg : OurPubRegs)
    if (!TheirPubRegs.isPublic(OurPubReg))
      NewPubRegsRaw.push_back(OurPubReg);

  // Get cover for newly public registers.
  SmallVector<MCPhysReg> NewPubRegs;
  getRegisterCover(NewPubRegsRaw, NewPubRegs, TRI);

  // Erase those that aren't live.
  {
    LivePhysRegs LPR(*TRI);
    LPR.addLiveIns(MBB);
    for (auto it = NewPubRegs.begin(); it != NewPubRegs.end(); ) {
      if (LPR.contains(*it)) {
        ++it;
      } else {
        LLVM_DEBUG(dbgs() << __func__ << ": skipping dead public register " << TRI->getRegAsmName(*it) << "\n");
        it = NewPubRegs.erase(it);
      }
    }
  }

  // Erase those that have a live super-register.
  // TODO: Combine with above.
  {
    LivePhysRegs LPR(*TRI);
    LPR.addLiveIns(MBB);
    for (auto it = NewPubRegs.begin(); it != NewPubRegs.end(); ) {
      const bool SuperLive = llvm::any_of(TRI->superregs(*it), [&LPR] (MCPhysReg SuperReg) -> bool {
        return LPR.contains(SuperReg);
      });
      if (SuperLive) {
        LLVM_DEBUG(dbgs() << __func__ << ": skipping register " << TRI->getRegAsmName(*it) << " because super is live\n");
        it = NewPubRegs.erase(it);
      } else {
        ++it;
      }
    }
  }

  // Now, insert dummy moves.
  const auto MBBI = MBB.begin();
  for (MCPhysReg Reg : NewPubRegs)
    TII->copyPhysReg(MBB, MBBI, DebugLoc(), Reg, Reg, /*KillSrc*/true);

  // Mark newly inserted instructions public.
  for (auto MBBI2 = MBB.begin(); MBBI2 != MBBI; ++MBBI2)
    setInstrPublic(*MBBI2, __func__);

  return !NewPubRegs.empty();
}

INITIALIZE_PASS_BEGIN(X86PTeX, PASS_KEY "-pass",
		      "X86 LLSCT pass", false, false)
INITIALIZE_PASS_END(X86PTeX, PASS_KEY "-pass",
		    "X86 LLSCT pass", false, false)

FunctionPass *llvm::createX86PTeXPass(bool Instrument) {
  return new X86PTeX(Instrument);
}
