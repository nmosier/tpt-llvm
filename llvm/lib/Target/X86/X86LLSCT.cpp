#include "X86LLSCT.h"

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

#define PTEX_DEBUG 1

using namespace llvm;

using X86::PrivacyMask;
using X86::PubliclyTyped;
using X86::PrivatelyTyped;

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
    AU.addRequired<X86PrivacyTypeAnalysis>();
    MachineFunctionPass::getAnalysisUsage(AU);
  }

  bool runOnMachineFunction(MachineFunction& MF) override;

private:
  bool Instrument;
  
  // Ensures that register types only transition from private->public
  // if the register is the output of an instruction.
  // Achieves this by inserting register moves around any violations.
  // Returns whether any instructions were inserted, i.e., whether it
  // changed the function.
  void validatePrivacyTypes(MachineFunction &MF, const X86PrivacyTypeAnalysis &PTA);

  [[nodiscard]] bool instrumentPublicArguments(MachineFunction &MF, X86PrivacyTypeAnalysis &PrivTys);
  [[nodiscard]] bool instrumentPublicCalleeReturnValues(MachineFunction &MF, X86PrivacyTypeAnalysis &PrivTys);
  [[nodiscard]] bool eliminatePrivateCalleeSavedRegisters(MachineFunction &MF, X86PrivacyTypeAnalysis &PrivTys);
};

}

char X86LLSCT::ID = 0;

bool X86LLSCT::runOnMachineFunction(MachineFunction& MF) {
  MF.verify();
  
  if (!X86::EnablePTeX())
    return false;

  bool Changed = false;

  if (X86::DumpPTeX(MF)) {
    errs() << "===== X86PTeX BEFORE: " << MF.getName() << " =====\n";
    MF.print(errs());
    errs() << "===========================================\n";
  }
 
  // Step 1: Infer privacy types for the function.
  auto &PrivacyTypes = getAnalysis<X86PrivacyTypeAnalysis>();

#if 1
  if (const char *s = std::getenv("INSTRUMENT"); s && !atoi(s))
    return false;
#endif

  auto skip = [] (const char *key) -> bool {
    if (!PTEX_DEBUG)
      return false;
    if (const char *value = std::getenv(key); value && !atoi(value))
      return true;
    return false;
  };

#if 0
  // DEBUG: Print landing pad stuff.
  for (const auto &LPI : MF.getLandingPads()) {
    errs() << "LandingPadBlock:\n" << *LPI.LandingPadBlock;
    auto PrintLabels = [] (const auto& Labels) {
      for (const MCSymbol *Sym : Labels) {
        errs() << "  " << Sym << "\n";
      }
    };
    errs() << "BeginLabels:\n"; PrintLabels(LPI.BeginLabels);
    errs() << "EndLabels:\n"; PrintLabels(LPI.EndLabels);
    errs() << "LandingPadLabel: " << LandingPadLabel << "\n";
  }
#endif
  
  if (Instrument) {

    // Step 2: Insert publicly-typed register copies for all publicly-typed, live-in, non-callee-saved registers.
    if (!skip("PUBARGS"))
      Changed |= instrumentPublicArguments(MF, PrivacyTypes);

    // Step 3: Insert publicly-typed register copies for all publicly-typed callee return values.
    if (!skip("PUBRETS"))
      Changed |= instrumentPublicCalleeReturnValues(MF, PrivacyTypes);

    // Step 4: Eliminate all privately-typed callee-saved registers.
    if (!skip("CSRS"))
      Changed |= eliminatePrivateCalleeSavedRegisters(MF, PrivacyTypes);
  }

  // TODO: Verify some properties, like that there are no privately-typed callee-saved registers.

  if (X86::DumpPTeX(MF)) {
    errs() << "===== X86PTeX AFTER: " << MF.getName() << " =====\n";
    MF.print(errs());
    errs() << "============================================\n";
  }

  MF.verify();

  return Changed;
}

bool X86LLSCT::instrumentPublicArguments(MachineFunction &MF, X86PrivacyTypeAnalysis &PrivTys) {
  // Task:
  // Insert (publicly-typed) register copies for each live function argument.
  
  MachineBasicBlock &MBB = MF.front();
  auto MBBI = MBB.begin();
  const PrivacyMask &Privacy = PrivTys.getBlockPrivacyIn(&MBB);
  const auto *TII = MF.getSubtarget().getInstrInfo();
  const auto *TRI = MF.getSubtarget().getRegisterInfo();
  const MachineRegisterInfo &MRI = MF.getRegInfo();

  auto IsCalleeSaved = [&] (Register Reg) -> bool {
    for (const auto *CSR = MRI.getCalleeSavedRegs(); *CSR != X86::NoRegister; ++CSR) {
      if (*CSR == Reg) {
        return true;
      } else {
        assert(!TRI->regsOverlap(Reg, *CSR));
      }
    }
    return false;
  };

  // Insert publicly-typed register copies.
  for (const auto &[Reg, _] : MRI.liveins()) {

    // No superregs should be live in.
    assert(llvm::none_of(TRI->superregs(Reg), [&] (Register SuperReg) -> bool {
      return MRI.isLiveIn(SuperReg);
    }));
    
    const Register CanonicalReg = PrivacyMask::canonicalizeRegister(Reg);
    
    // Skip if canonical register is not public.
    if (Privacy.get(CanonicalReg) != PubliclyTyped)
      continue;

    // Skip if canonical register is always public.
    if (X86::registerIsAlwaysPublic(CanonicalReg))
      continue;

    // Skip if it's a callee-saved register.
    if (IsCalleeSaved(Reg))
      continue;

    // Do copy.
    TII->copyPhysReg(MBB, MBBI, DebugLoc(), Reg, Reg, /*KillSrc*/true);
  }
  
  // Add privacy type info.
  for (auto MBBI2 = MBB.begin(); MBBI2 != MBBI; ++MBBI2) {
    MachineInstr *MI = &*MBBI2;
    PrivTys.getInstrPrivacyIn(MI) = Privacy;
    PrivTys.getInstrPrivacyOut(MI) = Privacy;
  }

  return MBBI != MBB.begin();
}

bool X86LLSCT::instrumentPublicCalleeReturnValues(MachineFunction &MF, X86PrivacyTypeAnalysis &PrivTys) {
  bool Changed = false;
  const auto *TII = MF.getSubtarget().getInstrInfo();
  
  for (MachineBasicBlock &MBB : MF) {
    for (MachineInstr &MI : MBB) {
      if (MI.isCall()) {
        const PrivacyMask &Privacy = PrivTys.getInstrPrivacyOut(&MI);
        const auto CallMBBI = MI.getIterator();
        auto NewMBBI_begin = [&] () {
          return std::next(CallMBBI);
        };
        const auto NewMBBI_end = NewMBBI_begin();
        llvm::SmallSet<Register, 1> ReturnRegs; // So we don't protect any registers twice.
        for (const MachineOperand &MO : MI.operands()) {
          if (MO.isReg() && MO.isDef()) {
            const Register Reg = MO.getReg();
            if (!X86::registerIsAlwaysPublic(Reg) && Privacy.get(Reg) == X86::PubliclyTyped) {
              if (ReturnRegs.insert(Reg).second) {
                // The callee's return value is publicly-typed.
                TII->copyPhysReg(MBB, NewMBBI_end, DebugLoc(), Reg, Reg, /*KillSrc*/true);
              }
            }
          }
        }

        // Update privacy for newly inserted instructions.
        for (auto MBBI = NewMBBI_begin(); MBBI != NewMBBI_end; ++MBBI) {
          MachineInstr *MI = &*MBBI;
          PrivTys.getInstrPrivacyIn(MI) = Privacy;
          PrivTys.getInstrPrivacyOut(MI) = Privacy;
        }

        Changed = (NewMBBI_begin() != NewMBBI_end);
      }
    }
  }

  return Changed;
}

bool X86LLSCT::eliminatePrivateCalleeSavedRegisters(MachineFunction &MF, X86PrivacyTypeAnalysis &PrivTys) {
  bool Changed = false;
  MachineFrameInfo &MFI = MF.getFrameInfo();
  const auto *TII = MF.getSubtarget().getInstrInfo();
  const auto *TRI = MF.getSubtarget().getRegisterInfo();

  assert(MF.getRegInfo().tracksLiveness());

#if 0
  // Make sure we don't have any landingpads with more than one invoke-style call.
  // NOTE: This is actually present in some programs.
  for (const LandingPadInfo &LPI : MF.getLandingPads()) {
    assert(LPI.BeginLabels.size() == 1);
    assert(LPI.EndLabels.size() == 1);
  }
#endif

  using PrivateSpillInfo = std::map<Register, int>;
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

  // Precompute invokes.
  std::map<MachineInstr *, const LandingPadInfo *> InvokeToLandingPad;
  for (const LandingPadInfo &LPI : MF.getLandingPads()) {
    assert(LPI.BeginLabels.size() == LPI.EndLabels.size());
    for (const auto &[BeginLabel, EndLabel] : llvm::zip_equal(LPI.BeginLabels, LPI.EndLabels)) {
      const auto BeginMBBI = std::next(Labels.at(BeginLabel)->getIterator());
      const auto EndMBBI = Labels.at(EndLabel)->getIterator();
      const auto InvokeMBBI =
          std::find_if(BeginMBBI, EndMBBI, [] (const MachineInstr &MI) -> bool { return MI.isCall(); });
      assert(InvokeMBBI != EndMBBI);
      InvokeToLandingPad[&*InvokeMBBI] = &LPI;
    }
  }

  auto getSpillInfo = [&] (MachineInstr *MI) -> PrivateSpillInfo * {
    const auto InvokeToLandingPadIt = InvokeToLandingPad.find(MI);
    if (InvokeToLandingPadIt == InvokeToLandingPad.end()) {
      // Regular call.
      return &CallPrivateSpillInfo[MI];
    } else {
      return &InvokePrivateSpillInfo[InvokeToLandingPadIt->second];
    }
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
        // TODO: Need canonical iterator over bitset.
        llvm::SmallSet<Register, 4> HandledRegs;
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
          assert(!HandledRegs.contains(CanonicalReg));

#if 0
          if (!(debug_min <= debug_cur && debug_cur <= debug_max)) {
            ++debug_cur;
            continue;
          }
#endif

          HandledRegs.insert(CanonicalReg);

#if 0
          errs() << debug_cur << " : " << MF.getName() << " : " << TRI->getRegAsmName(Reg) << " : "; MI.dump();
#endif

          const auto *RegClass = TRI->getMinimalPhysRegClass(Reg);

#if 0
          // Allocate new stack spill slot.
          // TODO: Can revert this to using 'official' methods.
          const unsigned SpillSize = TRI->getRegSizeInBits(Reg, MRI);
          const Align SpillAlign = Align(SpillSize);
          const int FrameIndex = MFI.CreateSpillStackObject(SpillSize, SpillAlign);
#else
          const unsigned SpillSize = TRI->getSpillSize(*RegClass);
          const Align SpillAlign = TRI->getSpillAlign(*RegClass);
          PrivateSpillInfo &PSI = *getSpillInfo(&MI);
          auto PSI_it = PSI.find(Reg);
          if (PSI_it == PSI.end()) {
            const int FrameIndex = MFI.CreateSpillStackObject(SpillSize, SpillAlign);
            PSI_it = PSI.emplace(Reg, FrameIndex).first;
          }
          const int FrameIndex = PSI_it->second;
#endif

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
            MachineInstr *ZeroMI = BuildMI(MBB, PreMBBI, DebugLoc(), TII->get(X86::MOV32r0), SubReg).getInstr();
              
            // Set in-privacy for ZeroMI (unchanged).
            PrivTys.getInstrPrivacyIn(ZeroMI) = CallPrivacyIn;
              
            // Mark register as now publicly-typed.
            CallPrivacyIn.set(Reg, PubliclyTyped);
              
            // Set out-privacy for ZeroMI.
            PrivTys.getInstrPrivacyOut(ZeroMI) = CallPrivacyOut;
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

    // Just insert before the landingpad's EH_LABEL for now.
#if 0
    if (LPI->LandingPadLabel) {
      assert(MBBI == Labels.at(LPI->LandingPadLabel)->getIterator());
      ++MBBI;
    }
#endif

    for (const auto &[Reg, FrameIndex] : SpillInfo) {
      const auto *RegClass = TRI->getMinimalPhysRegClass(Reg);
      TII->loadRegFromStackSlot(MBB, MBBI, Reg, FrameIndex, RegClass, TRI, X86::NoRegister);
      Changed = true;
    }
  }

  return Changed;
}

INITIALIZE_PASS_BEGIN(X86LLSCT, PASS_KEY "-pass",
		      "X86 LLSCT pass", false, false)
INITIALIZE_PASS_END(X86LLSCT, PASS_KEY "-pass",
		    "X86 LLSCT pass", false, false)

FunctionPass *llvm::createX86LLSCTPass(bool Instrument) {
  return new X86LLSCT(Instrument);
}
