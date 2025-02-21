#pragma once

#include <unordered_set>

#include "llvm/ADT/SmallVector.h"
#include "llvm/CodeGen/TargetRegisterInfo.h"
#include "PTeX/PublicPhysRegs.h"
#include "llvm/CodeGen/MachineLoopInfo.h"

namespace llvm {

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

int getMemRefBeginIdx(const MachineInstr &MI);

PublicPhysRegs computeTop(MachineFunction &MF);

void getInstrDataOutputs(const MachineInstr &MI, SmallVectorImpl<const MachineOperand *> &Outs);

bool registerIsAlwaysPublic(Register Reg);

}

bool unpeelSingleMachineLoopIteration(MachineLoop *L);

void getExitReachingBlocks(MachineFunction &MF, std::unordered_set<MachineBasicBlock *> &ExitReachingBlocks);

bool hasRegisterHazard(const MachineInstr &MI1, const MachineInstr &MI2);
bool hasMemoryHazard(const MachineInstr &MI1, const MachineInstr &MI2);

#define PTEX_DEBUG(...) LLVM_DEBUG(dbgs() << DEBUG_TYPE << ": "; __VA_ARGS__);

bool debugMF(const MachineFunction &MF);
#define PTEX_DEBUG_MF(...) do { if (debugMF(MF)) { PTEX_DEBUG(__VA_ARGS__); } } while (0)

bool hasFoldedLoad(const MachineInstr &MI);
bool hasFoldedStore(const MachineInstr &MI);

}
