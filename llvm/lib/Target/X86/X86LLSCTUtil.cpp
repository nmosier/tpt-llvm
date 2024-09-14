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
  const Function& F = MF.getFunction();
    
  // FIXME: hotfix for i128 argument LLVM bug
  if (llvm::any_of(F.args(), [] (const Argument& A) -> bool {
    return A.getType()->isIntegerTy(128);
  })) {
    return {};
  }
    
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



}

