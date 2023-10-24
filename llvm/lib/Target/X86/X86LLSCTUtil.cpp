#include "X86LLSCTUtil.h"
#include "llvm/CodeGen/MachineFunction.h"
#include "llvm/IR/Function.h"
#include "llvm/Support/WithColor.h"

namespace llvm::X86::util {

  std::bitset<NUM_TARGET_REGS> regmask_to_bitset(const uint32_t *mask) {
    std::bitset<NUM_TARGET_REGS> bitset;
    for (unsigned Reg = 0; Reg < NUM_TARGET_REGS; ++Reg)
      if ((mask[Reg / 32] & (1u << (Reg % 32))) != 0)
	bitset.set(Reg);
    return bitset;
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
}
