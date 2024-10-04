#include "X86PTeX.h"

#include <optional>

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
#include "X86PrivacyTypeAnalysis2.h"

#define PTEX_DEBUG 1

using namespace llvm;

using X86::PrivacyMask;

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

bool EnablePTeX() {
  return static_cast<bool>(EnablePTeXOpt);
}

static bool DumpPTeX(const MachineFunction &MF) {
  return EnablePTeXDump && X86::DumpCheckFilter(MF);
}

}

// PTEX-TODO: Rename.

namespace {


class X86LLSCT final : public MachineFunctionPass {
public:
  static char ID;
  X86LLSCT(bool Instrument) : MachineFunctionPass(ID), Instrument(Instrument) {}

  void getAnalysisUsage(AnalysisUsage& AU) const override {
    AU.setPreservesCFG();
    MachineFunctionPass::getAnalysisUsage(AU);
  }

  bool runOnMachineFunction(MachineFunction& MF) override;

private:
  const bool Instrument;
  
  // Ensures that register types only transition from private->public
  // if the register is the output of an instruction.
  // Achieves this by inserting register moves around any violations.
  // Returns whether any instructions were inserted, i.e., whether it
  // changed the function.
  void validatePrivacyTypes(MachineFunction &MF, const X86PrivacyTypeAnalysis &PTA);


  // TODO: Make another object that has MF and PrivTys as member.
  [[nodiscard]] bool instrumentPublicArguments(MachineFunction &MF, X86::PrivacyTypeAnalysis &PTA);
  [[nodiscard]] bool instrumentPublicCalleeReturnValues(MachineFunction &MF);
  [[nodiscard]] bool eliminatePrivateCalleeSavedRegisters(MachineFunction &MF, X86PrivacyTypeAnalysis &PrivTys);
  [[nodiscard]] bool avoidPartialUpdatesOfPrivateEFLAGS(MachineFunction &MF, X86PrivacyTypeAnalysis &PrivTys);
  void addPrivacyPrefixes(MachineFunction &MF, X86PrivacyTypeAnalysis &PrivTys);
  std::optional<PrivacyType> computeInstrPrivacy(MachineInstr &MI, X86PrivacyTypeAnalysis &PrivTys);
  void annotateVirtualPointers(MachineFunction &MF);
};

}

char X86LLSCT::ID = 0;

bool X86LLSCT::runOnMachineFunction(MachineFunction& MF) {
  LLVM_DEBUG(dbgs() << "===== " << getPassName() << " on " << MF.getName() << " =====\n");
    
  if (!X86::EnablePTeX())
    return false;

  if (MF.getRegInfo().isSSA()) {
    assert(!Instrument && "Cannot instrument SSA machine IR!");
    annotateVirtualPointers(MF);
    return false;
  }

  // Run physreg privacy analysis.
  X86::PrivacyTypeAnalysis PTA(MF);
  PTA.run();
  if (X86::DumpPTeX(MF))
    PTA.print(errs());

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

#if 0
  if (Instrument) {

    // TODO: Remove debugging envvar guards.

    // Step 2: Insert publicly-typed register copies for all publicly-typed, live-in, non-callee-saved registers.
    if (!skip("PUBARGS"))
      Changed |= instrumentPublicArguments(MF, PrivacyTypes);

    // Step 3: Insert publicly-typed register copies for all publicly-typed callee return values.
    if (!skip("PUBRETS"))
      Changed |= instrumentPublicCalleeReturnValues(MF, PrivacyTypes);

    // Step 4: Eliminate all privately-typed callee-saved registers.
    if (!skip("CSRS"))
      Changed |= eliminatePrivateCalleeSavedRegisters(MF, PrivacyTypes);

    // Step 5: Heuristically avoid partial updates of privately-typed EFLAGS.
    Changed |= avoidPartialUpdatesOfPrivateEFLAGS(MF, PrivacyTypes);
  }

  // Mark instructions as public/private.
  addPrivacyPrefixes(MF, PrivacyTypes);  
  
  // TODO: Verify some properties, like that there are no privately-typed callee-saved registers.
#endif

  if (X86::DumpPTeX(MF)) {
    errs() << "===== X86PTeX AFTER: " << MF.getName() << " =====\n";
    PTA.dump();
    errs() << "============================================\n";
  }

  MF.verify();

  return Changed;
}

#if 0
static bool unfoldLoads(MachineFunction &MF) {
  for (MachineBasicBlock &MBB : MF) {
    for (MachineInstr &MI : MBB) {
      
    }
  }
}
#endif

bool X86LLSCT::instrumentPublicArguments(MachineFunction &MF, X86::PrivacyTypeAnalysis &PTA) {
  const TargetInstrInfo *TII = MF.getSubtarget().getInstrInfo();
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
  PTA.getIn(&MBB).getCover(PubRegs);
  
  for (MCPhysReg PubReg : PubRegs) {
    // Is this a callee-saved register?
    // If so, skip.
    if (IsCalleeSaved(PubReg))
      continue;

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

bool X86LLSCT::instrumentPublicCalleeReturnValues(MachineFunction &MF) {
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

bool X86LLSCT::eliminatePrivateCalleeSavedRegisters(MachineFunction &MF, X86PrivacyTypeAnalysis &PrivTys) {
  bool Changed = false;
  const auto *TII = MF.getSubtarget().getInstrInfo();
  const auto *TRI = MF.getSubtarget().getRegisterInfo();

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

  auto getSpillInfo = [&] (MachineInstr *MI, Register Reg) -> PrivateSpillInfo * {
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
    if (LPI->LandingPadBlock->isLiveIn(Reg)) {
      return &InvokePrivateSpillInfo[LPI];
    }

    // Make sure no registers errantly overlap.
    assert(llvm::none_of(LPI->LandingPadBlock->liveins(), [&] (const auto &p) -> bool {
      return TRI->regsOverlap(p.PhysReg, Reg);
    }));

    // Treat as call.
    return &CallPrivateSpillInfo[MI];
  };

  // DEBUG
  static int debug_min = -1;
  static int debug_max = -1;
  if (debug_min < 0) {
    if (const char *s = std::getenv("MIN"))
      debug_min = std::atoi(s);
    else
      debug_min = 0;
  }
  if (debug_max < 0) {
    if (const char *s = std::getenv("MAX"))
      debug_max = std::atoi(s);
    else
      debug_max = INT_MAX;
  }
  static int debug_cur = 0;

  for (MachineBasicBlock &MBB : MF) {
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
}

bool X86LLSCT::avoidPartialUpdatesOfPrivateEFLAGS(MachineFunction &MF, X86PrivacyTypeAnalysis &PrivTys) {
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

std::optional<PrivacyType> X86LLSCT::computeInstrPrivacy(MachineInstr &MI, X86PrivacyTypeAnalysis &PrivTys) {
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

void X86LLSCT::addPrivacyPrefixes(MachineFunction &MF, X86PrivacyTypeAnalysis &PrivTys) {
  for (MachineBasicBlock &MBB : MF) {
    for (MachineInstr &MI : MBB) {
      const std::optional<PrivacyType> InstrPrivTy = computeInstrPrivacy(MI, PrivTys);
      if (!InstrPrivTy)
        continue;
      X86::setInstrPrivacy(MI, *InstrPrivTy);
    }
  }
}

static bool mayPartiallyUpdateEFLAGS(const MachineInstr &MI) {
#if 0
  // Consider calls and returns to partially update EFLAGS.
  if (MI.isCall() || MI.isReturn())
    return true;
#endif
  
  // If EFLAGS is not def'ed, then it doesn't update EFLAGS, period.
  if (llvm::none_of(MI.operands(), [] (const MachineOperand &MO) -> bool {
    return MO.isReg() && MO.getReg() == X86::EFLAGS && MO.isDef();
  })) {
    return false;
  }

  switch (MI.getOpcode()) {
#define CASE(s) case X86::s:
#define SHIFT_SUFFIX(s) CASE(s##1) CASE(s##CL) CASE(s##i)
#define SHIFT_DST(s) SHIFT_SUFFIX(s##m) SHIFT_SUFFIX(s##r)
#define SHIFT(s) SHIFT_DST(s##8) SHIFT_DST(s##16) SHIFT_DST(s##32) SHIFT_DST(s##64)
    SHIFT(SAR);
    SHIFT(SHL);
    SHIFT(SHR);
    return true;

  case X86::DEC8r:
  case X86::DEC16r:
  case X86::DEC32r:
  case X86::DEC64r:
  case X86::INC8r:
  case X86::INC16r:
  case X86::INC32r:
  case X86::INC64r:
    return true;

  default:
    return false;
  }
}

void X86LLSCT::annotateVirtualPointers(MachineFunction &MF) {
  const MachineRegisterInfo &MRI = MF.getRegInfo();
  for (MachineBasicBlock &MBB : MF) {
    for (MachineInstr &MI : MBB) {
      for (MachineOperand &MO : MI.operands()) {
        // PTEX-FIXME: MI.mayLoadOrStore() is too aggressive.
        // We do care about stores that have a pointer operand.
        if (MO.isReg() && !MO.isImplicit() && MRI.getType(MO.getReg()).isPointer() &&
            (MO.isDef() || (MO.isUse() && !MI.mayLoadOrStore()))) {
          MO.setIsPublic();
          LLVM_DEBUG(dbgs() << "PTeX.LLT: marking instruction operand '" << MO << "' public: " << MI);
        }
      }
    }
  }
  MF.getRegInfo().clearVirtRegTypes();
}

INITIALIZE_PASS_BEGIN(X86LLSCT, PASS_KEY "-pass",
		      "X86 LLSCT pass", false, false)
INITIALIZE_PASS_END(X86LLSCT, PASS_KEY "-pass",
		    "X86 LLSCT pass", false, false)

FunctionPass *llvm::createX86LLSCTPass(bool Instrument) {
  return new X86LLSCT(Instrument);
}
