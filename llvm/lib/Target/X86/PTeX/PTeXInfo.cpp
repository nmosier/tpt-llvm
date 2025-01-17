#include "PTeX/PTeXInfo.h"

#include "llvm/Support/WithColor.h"

using namespace llvm;
using llvm::X86::PTeXInfo;

PTeXInfo::PTeXInfo(MachineFunction &MF):
    MF(MF), TII(MF.getSubtarget().getInstrInfo()), TRI(MF.getSubtarget().getRegisterInfo())
{}

bool PTeXInfo::mergeMap(Map &a, const Map &b) {
  bool Changed = false;
  assert(a.size() == b.size());
  for (const auto &[key, b_value] : b) {
    Changed |= a[key].addRegs(b_value);
  }
  return Changed;
}

bool PTeXInfo::merge(const PTeXInfo &Other) {
  bool Changed = false;
  Changed |= mergeMap(In, Other.In);
  Changed |= mergeMap(Out, Other.Out);
  return Changed;
}

void PTeXInfo::print(raw_ostream &os) const {
  os << "===== Privacy Types for Function \"" << MF.getName() << "\" =====\n\n";

  const auto meta_os = [&] () {
    return WithColor(os, raw_ostream::Colors::GREEN);
  };

  const auto pub_os = [&] () {
    return WithColor(os, raw_ostream::Colors::BLUE);
  };

  auto PrintBlockNames = [&] (const auto &range) {
    auto os = meta_os();
    for (auto it = range.begin(); it != range.end(); ++it) {
      if (it != range.begin())
        os << " ";
      (*it)->printName(os);
    }
  };

  for (MachineBasicBlock &MBB : MF) {
    MBB.printName(os);
    os << ":\n";
    meta_os() << "    // preds: "; PrintBlockNames(MBB.predecessors()); os << "\n";
    pub_os() << "    // pub-in: " << In.at(&MBB);

    for (MachineInstr &MI : MBB)
      os << MI;

    pub_os() << "    // pub-out: " << Out.at(&MBB);
    meta_os() << "    // succs: "; PrintBlockNames(MBB.successors()); meta_os() << "\n";
    os << "\n";
  }
}
