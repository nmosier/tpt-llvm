#include "X86LLSCTUtil.h"
#include "llvm/CodeGen/MachineFunction.h"
#include "llvm/IR/Function.h"
#include "llvm/Support/WithColor.h"
#include "llvm/IR/IntrinsicInst.h"

namespace llvm::X86::util {

  std::bitset<NUM_TARGET_REGS> regmask_to_bitset(const uint32_t *mask) {
    std::bitset<NUM_TARGET_REGS> bitset;
    for (unsigned Reg = 0; Reg < NUM_TARGET_REGS; ++Reg)
      if ((mask[Reg / 32] & (1u << (Reg % 32))) != 0)
	bitset.set(Reg);
    return bitset;
  }

  std::bitset<NUM_TARGET_REGS> get_call_regmask(const MachineInstr& MI) {
    const auto it = llvm::find_if(MI.operands(), std::mem_fn(&MachineOperand::isRegMask));
    assert(it != MI.operands_end());
    return regmask_to_bitset(it->getRegMask());
  }

  std::map<const Argument *, MCPhysReg> irargs_to_mcargs(const MachineFunction& MF) {
    std::map<const Argument *, MCPhysReg> map;

    for (const CCValAssign& VA : MF.FormalArgLocs) {
      const Argument *ir_arg = MF.getFunction().getArg(VA.getValNo());
      if (VA.isRegLoc()) {
	const MCRegister mc_reg = VA.getLocReg().asMCReg();
	map[ir_arg] = mc_reg;
      } else {
	WithColor::warning() << "unhandled argument mapping for " << *ir_arg << "\n";
      }
    }

    return map;
  }

  const CallBase *mircall_to_ircall(const MachineInstr& MI) {
    assert(MI.isCall());
    const MachineBasicBlock& MBB = *MI.getParent();
    const BasicBlock *BB = MBB.getBasicBlock();
    if (!BB)
      return nullptr;
    SmallVector<const CallBase *> ir_calls;
    SmallVector<const MachineInstr *> mir_calls;
    for (const MachineInstr& MI : MBB)
      if (MI.isCall())
	mir_calls.push_back(&MI);
    for (const Instruction& I : *BB)
      if (const CallBase *C = dyn_cast<CallBase>(&I))
	if (!isa<IntrinsicInst>(C))
	  ir_calls.push_back(C);
    if (ir_calls.size() != mir_calls.size())
      return nullptr;

    const auto mir_it = llvm::find(mir_calls, &MI);
    assert(mir_it != mir_calls.end());
    return ir_calls[mir_it - mir_calls.begin()];
  }
}
