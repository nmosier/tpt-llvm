#pragma once

#include <map>

#include "llvm/CodeGen/MachineFunction.h"
#include "llvm/CodeGen/MachineBasicBlock.h"
#include "llvm/CodeGen/MachineInstr.h"
#include "llvm/Support/WithColor.h"

namespace llvm {

template <typename T>
class ForwardDataFlowAnalysis {
public:
  using Value = T;
  using Map = std::map<MachineBasicBlock *, T>;

  ForwardDataFlowAnalysis(MachineFunction &MF): MF(MF) {}

  // Fixed across the data-flow.
  MachineFunction &MF;

  // Data-flow state.
  Map In;
  Map Out;

  void run();

  T predOuts(MachineBasicBlock &MBB) const;

  void print(raw_ostream &OS) const;

  virtual StringRef getName() const = 0;

protected:
  virtual void meet(T &a, const T& b) = 0;
  virtual void combine(T &a, const T &b) = 0;
  virtual void transfer(MachineInstr &MI, T &a) = 0;
  virtual T top() = 0;
  virtual T botIn(MachineBasicBlock &MBB) = 0;
  virtual T botOut(MachineBasicBlock &MBB) = 0;
  virtual void printValue(raw_ostream &OS, const T &a) const = 0;
  virtual void printEpilogue(raw_ostream &OS) const {}

private:
  void init();
  bool iteration();
};

template <typename T>
void ForwardDataFlowAnalysis<T>::init() {
  const T Top = top();
  for (MachineBasicBlock &MBB : MF) {
    if (MBB.pred_empty()) {
      In[&MBB] = botIn(MBB);
    } else {
      In[&MBB] = Top;
    }
    Out[&MBB] = Top;
  }
}

template <typename T>
bool ForwardDataFlowAnalysis<T>::iteration() {
  bool Changed = false;
  for (MachineBasicBlock &MBB : MF) {
    // Compute block in.
    const T OldIn = In[&MBB];
    for (MachineBasicBlock *Pred : MBB.predecessors())
      meet(In[&MBB], Out[Pred]);
    combine(In[&MBB], botIn(MBB));
    Changed |= (OldIn != In[&MBB]);

    // Transfer.
    T value = In[&MBB];
    for (MachineInstr &MI : MBB)
      transfer(MI, value);

    // Copy into block-out.
    const T OldOut = Out[&MBB];
    Out[&MBB] = value;
    combine(Out[&MBB], botOut(MBB));
    Changed |= (OldOut != Out[&MBB]);
  }

  return Changed;
}

template <typename T>
void ForwardDataFlowAnalysis<T>::run() {
  // Initialize In, Out.
  init();
  while (iteration()) {}
}

template <typename T>
T ForwardDataFlowAnalysis<T>::predOuts(MachineBasicBlock &MBB) const {
  if (MBB.pred_empty())
    return botIn(MBB);
  auto succ_it = MBB.succ_begin();
  T Result = Out.at(*succ_it++);
  for (; succ_it != MBB.succ_end(); ++succ_it)
    meet(Result, Out.at(*succ_it++));
  return Result;
}

template <typename T>
void ForwardDataFlowAnalysis<T>::print(raw_ostream &os) const {
  os << "===== BEGIN " << getName() << " Results for " << MF.getName() << " =====\n";

  const auto meta_os = [&] () {
    return WithColor(os, raw_ostream::Colors::GREEN);
  };

  const auto value_os = [&] () {
    return WithColor(os, raw_ostream::Colors::BLUE);
  };

  auto PrintBlockNames = [&] (const auto &range) {
    auto os = meta_os();
    for (const MachineBasicBlock *MBB : range) {
      os << " ";
      MBB->printName(os);
    }
  };

  for (MachineBasicBlock &MBB : MF) {
    MBB.printName(os);
    os << ":\n";
    meta_os() << "  // preds: ";
    PrintBlockNames(MBB.predecessors());
    os << "\n";
    value_os() << " // value-in: ";
    printValue(value_os(), In.at(&MBB));
    os << "\n";

    for (MachineInstr &MI : MBB)
      os << "    " << MI;

    value_os() << "  // value-out: ";
    printValue(value_os(), Out.at(&MBB));
    os << "\n";
    meta_os() << "  // succs: ";
    PrintBlockNames(MBB.successors());
    os << "\n\n\n";
  }

  os << "===== EPILOG " << getName() << " Results for " << MF.getName() << " =====\n";
  printEpilogue(os);

  os << "===== END " << getName() << " Results for " << MF.getName() << " =====\n";
}

}
