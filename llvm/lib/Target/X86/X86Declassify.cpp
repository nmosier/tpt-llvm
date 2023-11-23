#include "X86.h"
#include "X86InstrInfo.h"
#include "X86Declassify.h"
#include "X86LLSCT.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Constants.h"
#include "../lib/IR/ConstantsContext.h"
#include "llvm/IR/IntrinsicInst.h"
#include "llvm/CodeGen/MachineJumpTableInfo.h"
#include "llvm/Support/WithColor.h"
#include "llvm/CodeGen/MachineFrameInfo.h"
#include "llvm/CodeGen/LivePhysRegs.h"
#include "X86Subtarget.h"
#include <set>
#include <queue>
#include <bitset>
#include "X86LLSCTUtil.h"
#include "llvm/TPE.h"

using namespace tpe;

namespace llvm::X86 {

  namespace {
    class Node;
  }

  std::map<MachineInstr *, Node> runTaintAnalysis(MachineFunction& MF);

}

namespace tpe {

  static llvm::cl::opt<bool> EnablePrivRegs {
    "tpe-privr",
    llvm::cl::init(true),
    llvm::cl::desc("[TPE] Enable privr instruction insertion"),
  };
  
  llvm::cl::opt<PrivacyPolicy> PrivacyPolicyOpt {
    "tpe-privacy-policy",
    llvm::cl::desc("TPE's Privacy Policy"),
    llvm::cl::values(clEnumVal(sandbox, "sandbox privacy policy (all registers always public)"),
	       clEnumVal(ct,      "constant-time privacy policy (without declassification)"),
	       clEnumVal(ctdecl,  "constant-time privacy policy (with declassification)")),
    llvm::cl::init(PrivacyPolicyNone),
  };
  
  using namespace llvm::X86;
  bool allowDeclassify() {
    switch (PrivacyPolicyOpt) {
    case ct: return false;
    case ctdecl: return true;
    default:
      llvm_unreachable("Should not be called for non-CT threat models!");
    }
  }
}

using tpe::allowDeclassify;
  
namespace llvm::X86 {
  namespace {
    template <class Range>
    auto FilterRegMask(const MachineInstr *MI, Range&& range) {
      const uint32_t *RegMask = nullptr;
      if (MI) {
	for (const MachineOperand& MO : MI->operands()) {
	  if (MO.isRegMask()) {
	    assert(!RegMask);
	    RegMask = MO.getRegMask();
	  }
	}
      }
      return llvm::make_filter_range(range, [RegMask] (MCRegister Reg) {
	return !(RegMask && (RegMask[Reg / 32] & (1u << (Reg % 32))) != 0);
      });
    }

    static const std::set<MCRegister> csrs = {X86::RBP, X86::RBX, X86::R12, X86::R13, X86::R14, X86::R15};
    
    struct FrameLocation {
      int Index;
      uint64_t Offset;

      auto tuple() const { return std::make_tuple(Index, Offset); }
      bool operator<(const FrameLocation& o) const { return tuple() < o.tuple(); }
      bool operator==(const FrameLocation& o) const { return tuple() == o.tuple(); }
    };

    class Value {
    private:
      std::bitset<NUM_TARGET_REGS> PubRegs;

    public:
      static Register canonicalizeRegister(Register Reg) {
	if (Reg == X86::EFLAGS)
	  return Reg;
	return getX86SubSuperRegisterOrZero(Reg, 64);
      }

    private:
      static bool registerIsAlwaysPublic(Register Reg) {
	return Reg == X86::NoRegister || Reg == X86::RSP || Reg == X86::RIP;
      }

      void removeClobberedRegisters(const MachineInstr& MI);

    public:
      bool allInputsPublic(const MachineInstr& MI) const;
      bool anyOutputPublic(const MachineInstr& MI) const;

      // bool operator<(const Value& o) const { return PubRegs < o.PubRegs; }
      bool operator==(const Value& o) const { return PubRegs == o.PubRegs; }
      bool operator!=(const Value& o) const { return !(*this == o); }
      
      void addPubReg(Register Reg) {
	Reg = canonicalizeRegister(Reg);
	if (!registerIsAlwaysPublic(Reg))
	  PubRegs.set(Reg);
      }

      void delPubReg(Register Reg) {
	Reg = canonicalizeRegister(Reg);
	PubRegs.reset(Reg);
      }

      bool hasPubReg(Register Reg) const {
	Reg = canonicalizeRegister(Reg);
	if (registerIsAlwaysPublic(Reg))
	  return true;
	return PubRegs.test(Reg);
      }

      bool setAllInstrInputsPublic(const MachineInstr& MI);

      void transferForward(const MachineInstr& MI);
      void transferBackward(const MachineInstr& MI);

      // LLSCT-FIXME: meetForward and meetBackward should return new copies, to avoid mistakenly not setting changed correctly.
      void meetForward(const Value& o);
      void meetBackward(const Value& o);
      [[nodiscard]] bool set_union(const Value& o);

      void print(llvm::raw_ostream& os, const llvm::TargetRegisterInfo *TRI) const {
	os << "{";
	for (unsigned Reg = 0; Reg < NUM_TARGET_REGS; ++Reg) {
	  if (PubRegs[Reg]) {
	    os << TRI->getRegAsmName(Reg) << " ";
	  }
	}
	os << "}";
      }
	
    };

    struct Node {
      Value pre;
      Value post;

      auto tuple() const { return std::make_tuple(pre, post); }
      // bool operator<(const Node& o) const { return tuple() < o.tuple(); }
      bool operator==(const Node& o) const { return tuple() == o.tuple(); }
      bool operator!=(const Node& o) const { return tuple() != o.tuple(); }
    };


    template <class Range>
    auto FilterLiveRegsBefore(const MachineInstr& MI, Range&& range) {
      const MachineBasicBlock& MBB = *MI.getParent();
      const auto *TRI = MBB.getParent()->getSubtarget().getRegisterInfo();
      LivePhysRegs live_regs(*TRI);
      live_regs.addLiveIns(MBB);
      for (const MachineInstr *it = &MBB.front(); it != &MI; it = it->getNextNode()) {
	SmallVector<std::pair<MCPhysReg, const MachineOperand *>> clobbers;
	live_regs.stepForward(*it, clobbers);
      }
      std::set<MCRegister> canonical_live_regs;
      llvm::transform(live_regs, std::inserter(canonical_live_regs, canonical_live_regs.end()),
		      [] (MCRegister live_reg) -> MCRegister {
			return Value::canonicalizeRegister(live_reg);
		      });
      return llvm::make_filter_range(range, [canonical_live_regs, TRI] (MCRegister reg) -> bool {
	// errs() << "check: " << TRI->getRegAsmName(reg) << ", returning " << (canonical_live_regs.find(reg) != canonical_live_regs.end()) << "\n";
	return canonical_live_regs.find(reg) != canonical_live_regs.end();
      });
    }


    
    bool pointeeHasPublicType(const llvm::Value *Ptr, std::set<const llvm::Value *>& seen) {
      assert(Ptr->getType()->isPointerTy() && "Require pointer value");
      if (!seen.insert(Ptr).second)
	return false;
      const auto rec = [&seen] (const llvm::Value *V) {
	return pointeeHasPublicType(V, seen);
      };
      Type *Ty;
      if (const AllocaInst *AI = dyn_cast<AllocaInst>(Ptr)) {
	Ty = AI->getAllocatedType();
      } else if (const GetElementPtrInst *GEP = dyn_cast<GetElementPtrInst>(Ptr)) {
	Ty = GEP->getResultElementType();
      } else if (const GlobalValue *GV = dyn_cast<GlobalValue>(Ptr)) {
	Ty = GV->getValueType();
      } else if (const PHINode *Phi = dyn_cast<PHINode>(Ptr)) {
	// Check if any of the incoming values have public pointee type.
	return llvm::any_of(Phi->incoming_values(), rec);
      } else if (const GetElementPtrConstantExpr *GEP = dyn_cast<GetElementPtrConstantExpr>(Ptr)) {
	Ty = GEP->getResultElementType();
      } else if (const SelectInst *Select = dyn_cast<SelectInst>(Ptr)) {
	return rec(Select->getTrueValue()) || rec(Select->getFalseValue());
      } else if (isa<IntToPtrInst, LoadInst, Argument, CallBase, UndefValue, CastConstantExpr, ExtractValueInst, ExtractElementInst>(Ptr)) {
	// TODO: Can be more intelligent with load instructions if using alias analysis.
	return false;
      } else if (isa<ConstantPointerNull>(Ptr)) {
	return true;
      } else if (const FreezeInst *Freeze = dyn_cast<FreezeInst>(Ptr)) {
	return rec(Freeze->getOperand(0));
      } else {
	Ptr->dump();
	report_fatal_error("Unhandled pointer");
      }
      return Ty->isPointerTy();
    }

    bool pointeeHasPublicType(const llvm::Value *Ptr) {
      std::set<const llvm::Value *> seen;
      return pointeeHasPublicType(Ptr, seen);
    }

    void Value::removeClobberedRegisters(const MachineInstr& MI) {
      if (MI.isCall()) {
	// Remove all registers not in regmask.
	const auto regmask = util::get_call_regmask(MI);
	PubRegs &= ~regmask;
      }
      
      for (const MachineOperand& MO : MI.operands()) {
	if (MO.isReg()) {
	  if (MO.isKill() || MO.isDef() || MO.isUndef())
	    PubRegs.reset(canonicalizeRegister(MO.getReg()));
	} else if (MO.isRegMask()) {
	  PubRegs &= util::regmask_to_bitset(MO.getRegMask());
	}
      }
    }

    bool Value::allInputsPublic(const MachineInstr& MI) const {
      // TODO: IS it okay that memory accesses may come here?

      // If all register operands are undef, then assume we have XOR eax, eax primitive.
      if (llvm::all_of(MI.operands(), [] (const MachineOperand& MO) -> bool {
	if (MO.isReg() && MO.isUse()) {
	  return MO.isUndef();
	} else {
	  return true;
	}
      })) {
	return true;
      }
      
      for (const MachineOperand& MO : MI.operands())
	if (MO.isReg() && MO.isUse() && !hasPubReg(MO.getReg()))
	  return false;
      return true;
    }

    bool Value::anyOutputPublic(const MachineInstr& MI) const {
      for (const MachineOperand& MO : MI.operands())
	if (MO.isReg() && MO.isDef() && hasPubReg(MO.getReg()))
	  return true;
      return false;
    }
    
    void Value::transferForward(const MachineInstr& MI) {
      // FIXME: Should handle memory accesses specially, rather than just saying !MI.mayLoad().
      const bool all_inputs_public = !MI.mayLoad() && !MI.isCall() && allInputsPublic(MI);
      removeClobberedRegisters(MI);
      if (all_inputs_public)
	for (const MachineOperand& MO : MI.operands())
	  if (MO.isReg() && MO.isDef())
	    addPubReg(MO.getReg());

      // If the instruction is the end of the block, then remove any dead registers.
#if 0
      if (!MI.getNextNode()) {
	const MachineBasicBlock& MBB = *MI.getParent();
	std::set<MCRegister> live_regs;
	llvm::transform(MBB.liveouts(), std::inserter(live_regs, live_regs.end()),
			[] (const auto& live_pair) -> MCRegister {
			  return canonicalizeRegister(live_pair.PhysReg);
			});
	for (unsigned pub_reg = 0; pub_reg < PubRegs.size(); ++pub_reg)
	  if (PubRegs[pub_reg] && live_regs.find(pub_reg) == live_regs.end())
	    PubRegs.reset(pub_reg);
      }
#endif
    }

    static bool isPush(const MachineInstr& MI) {
      switch (MI.getOpcode()) {
      case X86::PUSH64r:
      case X86::PUSH64i32:
      case X86::PUSH64i8:
      case X86::PUSH64rmm:
	return true;
      case X86::ADJCALLSTACKDOWN64:
      case X86::ADJCALLSTACKUP64:
	return false;
      default: break;
      }

      if (MI.isCall() || MI.isReturn())
	return false;

      if (!MI.mayStore())
	return false;

      if (llvm::none_of(MI.operands(), [] (const MachineOperand& MO) {
	return MO.isReg() && MO.isUse() && MO.isImplicit() && MO.getReg() == X86::RSP;
      }))
	return false;

      if (llvm::none_of(MI.operands(), [] (const MachineOperand& MO) {
	return MO.isReg() && MO.isDef() && MO.isImplicit() && MO.getReg() == X86::RSP;
      }))
	return false;

      errs() << "isPush: unhandled instruction: " << MI;
      abort();
    }

    void Value::transferBackward(const MachineInstr& MI) {
      bool any_output_public = !MI.isCall() && !isPush(MI) && anyOutputPublic(MI);
      size_t num_private_ins = 0;
      removeClobberedRegisters(MI);
      if (allowDeclassify()) {
	// Also check that all but one input is public, i.e., at most one input is private.
	num_private_ins = llvm::count_if(MI.operands(), [&] (const MachineOperand& MO) -> bool {
	  return MO.isReg() && MO.isUse() && !hasPubReg(MO.getReg());
	});
	if (num_private_ins > 1)
	  any_output_public = false;
      }
      if (any_output_public)
	for (const MachineOperand& MO : MI.operands())
	  if (MO.isReg() && MO.isUse() && !MO.isUndef())
	    addPubReg(MO.getReg());

      // If the instruction is the beginning of the block, then remove any dead registers.
#if 0
      if (!MI.getPrevNode()) {
	std::set<MCRegister> live_regs;
	llvm::transform(MI.getParent()->liveins(), std::inserter(live_regs, live_regs.end()),
			[] (const auto& live_pair) -> MCRegister {
			  return canonicalizeRegister(live_pair.PhysReg);
			});
	for (unsigned pub_reg = 0; pub_reg < PubRegs.size(); ++pub_reg)
	  if (PubRegs[pub_reg] && live_regs.find(pub_reg) == live_regs.end())
	    PubRegs.reset(pub_reg);
      }
#endif
    }

    bool Value::setAllInstrInputsPublic(const MachineInstr& MI) {
      const auto orig_size = PubRegs.count();
      for (const MachineOperand& MO : MI.operands())
	if (MO.isReg() && MO.isUse())
	  addPubReg(MO.getReg());
      return orig_size != PubRegs.count();
    }

    void Value::meetForward(const Value& o) {
      // set intersection
      PubRegs &= o.PubRegs;
    }

    void Value::meetBackward(const Value& o) {
      (void) set_union(o);
    }

    bool Value::set_union(const Value& o) {
      const auto orig_size = PubRegs.count();
      PubRegs |= o.PubRegs;
      return PubRegs.count() != orig_size;
    }

    bool getFrameAccess(const MachineInstr& MI, FrameLocation& FL) {
      const int MemIdx = X86::getMemRefBeginIdx(MI);
      if (MemIdx < 0)
	return false;
      const MachineOperand& BaseOp = MI.getOperand(MemIdx + X86::AddrBaseReg);
      const MachineOperand& IndexOp = MI.getOperand(MemIdx + X86::AddrIndexReg);
      const MachineOperand& DispOp = MI.getOperand(MemIdx + X86::AddrDisp);
      const MachineOperand& SegOp = MI.getOperand(MemIdx + X86::AddrSegmentReg);
      if (!(BaseOp.isFI() &&
	    IndexOp.isReg() && IndexOp.getReg() == X86::NoRegister &&
	    SegOp.isReg() && SegOp.getReg() == X86::NoRegister))
	return false;
      FL.Index = BaseOp.getIndex();
      FL.Offset = DispOp.getImm();
      return true;
    }
    
  }

  template <typename Func>
  void getNonemptySuccessors(MachineBasicBlock& MBB, llvm::SmallVectorImpl<MachineBasicBlock *>& out, Func get_successors, bool inclusive) {
    std::set<MachineBasicBlock *> seen;
    std::queue<MachineBasicBlock *> todo;

    const auto add_succs = [&] (MachineBasicBlock *MBB) {
      for (auto *succ : get_successors(MBB))
	todo.push(succ);
    };

    // Add successors of starting block to queue.
    if (inclusive) {
      todo.push(&MBB);
    } else {
      assert(!MBB.empty());
      add_succs(&MBB);
    }
    
    while (!todo.empty()) {
      MachineBasicBlock *cur = todo.front();
      todo.pop();

      // If we have already processed this block, then ignore -- we are in a loop.
      if (!seen.insert(cur).second)
	continue;

      // If the block is non-empty, then we are done.
      if (!cur->empty()) {
	out.push_back(cur);
	continue;
      }

      // Otherwise, we need to add its successors as well.
      add_succs(cur);
    }
  }

  auto getNonemptySuccessors(MachineBasicBlock& MBB) {
    llvm::SmallVector<MachineBasicBlock *> succs;
    getNonemptySuccessors(MBB, succs, [] (MachineBasicBlock *MBB) { return MBB->successors(); }, false);
    return succs;
  }

  auto getNonemptyPredecessors(MachineBasicBlock& MBB) {
    llvm::SmallVector<MachineBasicBlock *> preds;
    getNonemptySuccessors(MBB, preds, [] (MachineBasicBlock *MBB) { return MBB->predecessors(); }, false);
    return preds;
  }

  auto getNonemptyEntrypoints(MachineFunction& MF) {
    assert(!MF.empty());
    llvm::SmallVector<MachineBasicBlock *> entrypoints;
    getNonemptySuccessors(MF.front(), entrypoints, [] (MachineBasicBlock *MBB) { return MBB->successors(); }, true);
    return entrypoints;
  }

  void BuildCFILabel(MachineBasicBlock& MBB, MachineBasicBlock::iterator MBBI,
		     uint32_t CFILabel_, MCRegister BaseReg) {
    if (!tpe::EnablePrivRegs)
      return;
    
    int64_t CFILabel = CFILabel_;
#if 0
    // HACK: Force labels < 256 to use 1-byte encoding.
    if (CFILabel < 256)
      CFILabel = (int8_t) CFILabel;
#endif
    const auto *TII = MBB.getParent()->getSubtarget<X86Subtarget>().getInstrInfo();
    BuildMI(MBB, MBBI, DebugLoc(), TII->get(X86::CFILBL))
      .addReg(BaseReg)
      .addImm(1)
      .addReg(X86::NoRegister)
      .addImm(CFILabel)
      .addReg(X86::NoRegister);
  }

  void BuildCFILabel_Dst(MachineBasicBlock& MBB, MachineBasicBlock::iterator MBBI, uint32_t CFILabel) {
    BuildCFILabel(MBB, MBBI, CFILabel, X86::RDI);
  }

  void BuildCFILabel_Src(MachineBasicBlock& MBB, MachineBasicBlock::iterator MBBI, uint32_t CFILabel) {
    BuildCFILabel(MBB, MBBI, CFILabel, X86::RSI);
  }


  static void ValidateDeclassifyMap(MachineFunction& MF, const std::map<MachineInstr *, Node>& Map, StringRef msg) {
#if 0
    bool valid = true;
    
    for (MachineBasicBlock& MBB : MF) {
#if 0
      if (!MBB.empty()) {
	for (MCRegister gpr : GPRBitMask::gprs()) {
	  if (gpr == X86::RSP)
	    continue;
	  const Value& pre = Map.at(&MBB.front()).pre;
	  const auto is_live_in = [&MBB] (MCRegister Reg) {
	    return llvm::any_of(MBB.liveins(), [Reg] (const auto& p) {
	      return getX86SubSuperRegisterOrZero(p.PhysReg, 64) == Reg;
	    });
	  };
	  if (pre.hasPubReg(gpr) && !is_live_in(gpr)) {
	    errs() << "REG IS NOT LIVE: " << MF.getSubtarget().getRegisterInfo()->getRegAsmName(gpr) << "\n";
	    errs() << MBB << "\n\n";
	    valid = false;
	  }
	}
      }
#endif

#if 0
      // Check liveness vs. public registers.
      const auto *TRI = MF.getSubtarget().getRegisterInfo();
      LivePhysRegs live_regs(*TRI);
      live_regs.addLiveIns(MBB);
      for (MachineInstr& MI : MBB) {
	const Node& node = Map.at(&MI);

	// Check all public registers are livein.
	const auto is_live_in = [&live_regs] (MCRegister reg) {
	  return llvm::any_of(live_regs, [reg] (MCRegister live_reg) {
	    return getX86SubSuperRegisterOrZero(live_reg, 64) == reg;
	  });
	};
	
	for (MCRegister gpr : GPRBitMask::gprs()) {
	  if (gpr == X86::RSP)
	    continue;
	  if (node.pre.hasPubReg(gpr) && !is_live_in(gpr)) {
	    errs() << "\n\n";
	    errs() << "REG IS NOT LIVE BEFORE: " << TRI->getRegAsmName(gpr) << "\n";
	    errs() << "Instruction: " << MI;
	    errs() << "Block:\n" << MBB;
	    errs() << "Live regs:";
	    for (MCRegister live_reg : live_regs)
	      errs() << " " << TRI->getRegAsmName(live_reg);
	    errs() << "\n\n";
	    valid = false;
	  }
	}

	SmallVector<std::pair<MCPhysReg, const MachineOperand *>> clobbers;
	live_regs.stepForward(MI, clobbers);

	for (MCRegister gpr : GPRBitMask::gprs()) {
	  if (gpr == X86::RSP)
	    continue;
	  if (node.post.hasPubReg(gpr) && !is_live_in(gpr)) {
	    errs() << "\n\n";
	    errs() << "REG IS NOT LIVE AFTER: " << MF.getSubtarget().getRegisterInfo()->getRegAsmName(gpr) << "\n";
	    errs() << "Instruction: " << MI;
	    errs() << "Block:\n" << MBB;
	    errs() << "\n\n";
	    valid = false;
	  }
	}
      }
#endif 
      
      for (MachineInstr& MI : MBB) {
	if (MI.isCall()) {
	  const Value& value = Map.at(&MI).post;
	  for (const MCRegister Reg : std::initializer_list<MCRegister> {X86::RDI, X86::RSI, X86::RDX, X86::RCX, X86::R8, X86::R9}) {
	    if (value.hasPubReg(Reg)) {
	      errs() << "FOUND PUBLIC ARG REGISTER FOLLOWING CALL: " << msg << "\n";
	      errs() << "Call: " << MI << "\n";
	      errs() << "Reg: " << MF.getSubtarget().getRegisterInfo()->getRegAsmName(Reg) << "\n";
	      errs() << "Block:\n";
	      errs() << MBB;
	      std::error_code EC;
	      llvm::raw_fd_ostream f("pubarg.mf", EC);
	      MF.print(f);
	      exit(1);
	    }

	  }
	}
      }
    }

    if (!valid) {
      {
	std::error_code EC;
	llvm::raw_fd_ostream f("invalid.mf", EC);
	MF.print(f);
      }
      exit(1);
    }
#endif
  }

  std::map<MachineInstr *, Node> runConstantTimePrivacyAnalysis(MachineFunction& MF) {
    assert(PrivacyPolicyOpt == ct || PrivacyPolicyOpt == ctdecl);
    
    const Function& F = MF.getFunction();
    
    std::set<MachineMemOperand *> Declassified;

    std::map<MachineInstr *, Node> Map, Bak;

    // Add the inputs/outputs of explicitly declassified load/stores via the MIFlag LLSCTDeclassify.
    for (MachineBasicBlock& MBB : MF) {
      for (MachineInstr& MI : MBB) {
	if (MI.getFlag(MI.TPEPubM)) {
	  if (MI.mayStore())
	    for (const MachineOperand& MO : MI.operands())
	      if (MO.isReg() && MO.isUse())
		Map[&MI].pre.addPubReg(MO.getReg());
	  if (MI.mayLoad())
	    for (const MachineOperand& MO : MI.operands())
	      if (MO.isReg() && MO.isDef())
		Map[&MI].post.addPubReg(MO.getReg());
	}
      }
    }

    // Add explicitly declassified arguments.
    {
      const auto argmap = util::irargs_to_mcargs(MF);
      for (const Argument& irarg : F.args()) {
	if (irarg.hasAttribute(Attribute::Declassified)) {
	  const auto argit = argmap.find(&irarg);
	  if (argit != argmap.end()) {
	    const auto phys_reg = argit->second;
	    for (MachineBasicBlock *entrypoint : getNonemptyEntrypoints(MF))
	      Map[&entrypoint->front()].pre.addPubReg(phys_reg);
	  } else {
	    WithColor::warning() << F.getName() << ": argument missing from mapping: " << irarg << "\n";
	  }
	}
      }
    }

    // Add explicitly declassified return values.
    if (F.hasRetAttribute(Attribute::Declassified)) {
      for (MachineBasicBlock& MBB : MF) {
	for (MachineInstr& MI : MBB) {
	  if (MI.isReturn() && !MI.isCall()) {
	    Map[&MI].pre.setAllInstrInputsPublic(MI);
	  }
	}
      }
    }

    // Add explicitly declassified call arguments and return values.
    for (MachineBasicBlock& MBB : MF) {
      for (MachineInstr& MI : MBB) {
	if (MI.isCall()) {
	  const auto call_sites_info_it = MF.getCallSitesInfo().find(&MI);
	  if (call_sites_info_it != MF.getCallSitesInfo().end()) {
	    const auto call_sites_info = call_sites_info_it->second;
	    if (const CallBase *I = call_sites_info.Call) {
	      for (const auto& ArgReg : call_sites_info.ArgRegPairs) {
		if (I->paramHasAttr(ArgReg.ArgNo, Attribute::Declassified)) {
		  Map[&MI].pre.addPubReg(ArgReg.Reg);
		}
	      }
	    
	      if (I->hasRetAttr(Attribute::Declassified)) {
		for (const MachineOperand& MO : MI.operands()) {
		  if (MO.isReg() && MO.isDef() && MO.isImplicit()) {
		    Map[&MI].post.addPubReg(MO.getReg());
		  }
		}
	      }
	    } else {
	      errs() << F.getName() << ": failed to get IR call for: " << MI;
	    }
	  }
	}
      }
    }
    
    // declassify the value operands / results of all memory accesses that were
    // flagged as declassified in our IR pass.
    for (MachineBasicBlock& MBB : MF) {
      for (MachineInstr& MI : MBB) {
	const bool should_declassify =
	  any_of(MI.memoperands(), [] (const MachineMemOperand *MemOp) -> bool {
	    // Is the memory operand's data type implicitly public?
	    auto *II = dyn_cast_or_null<IntrinsicInst>(MemOp->getValue());
	    if (!II)
	      return false;
	    if (II->getIntrinsicID() != Intrinsic::ptr_annotation)
	      return false;
	    GlobalVariable *Global = dyn_cast<GlobalVariable>(II->getOperand(1));
	    if (!Global)
	      return false;
	    if (!Global->hasInitializer())
	      return false;
	    auto *ConstArr = dyn_cast<ConstantDataArray>(Global->getInitializer());
	    if (!ConstArr->isCString())
	      return false;
	    if (ConstArr->getAsCString() != "llsct.declassify.mem")
	      return false;
	    return true;
	  });

	if (!should_declassify)
	  continue;

	// FIXME: Just do it for the ones that are really declassified?
	for (MachineMemOperand *MemOp : MI.memoperands())
	  Declassified.insert(MemOp);

	auto& Val = Map[&MI];

	if (MI.isCall()) {
	  // FIXME: These should always be declassified anyway, so we should ignore it.
	} else if (MI.mayLoad()) {
	  // All outputs are declassified.
	  for (MachineOperand& MO : MI.operands())
	    if (MO.isReg() && MO.isDef())
	      Val.post.addPubReg(MO.getReg());
	} else if (MI.mayStore()) {
	  // All inputs are declassified.
	  for (MachineOperand& MO : MI.operands())
	    if (MO.isReg() && MO.isUse())
	      Val.pre.addPubReg(MO.getReg());
	}
      }
    }
      
    // All sensitive operands of transmitters are assumed to be public.
    // For now, we will just consider (a) the address operands of memory accesses,
    // (b) the operands of control-flow instructions, and (c) the operands of
    // division instructions to be sensitive.
    for (MachineBasicBlock& MBB : MF) {
      for (MachineInstr& MI : MBB) {
	auto& Val = Map[&MI];

	// Declassify operands of control-flow instructions
	if (MI.isCall()) {
	  const MachineOperand& MO = MI.getOperand(0);
	  if (MO.isReg()) {
	    assert(MO.isUse());
	    Val.pre.addPubReg(MO.getReg());
	  }
	} else if (MI.isBranch()) {
	  for (MachineOperand& MO : MI.operands())
	    if (MO.isReg() && MO.isUse())
	      Val.pre.addPubReg(MO.getReg());
	}

	// Declassify operands of division instructions
	switch (MI.getOpcode()) {
	case X86::DIV64r:
	case X86::DIV64m:
	case X86::DIV32r:
	case X86::DIV32m:
	case X86::IDIV64r:
	case X86::IDIV64m:
	case X86::IDIV32r:
	case X86::IDIV32m:
	  for (MachineOperand& MO : MI.operands())
	    if (MO.isReg() && MO.isUse())
	      Val.pre.addPubReg(MO.getReg());
	  break;
	}

	// Declassify address operands
	int MemIdx = getMemRefBeginIdx(MI);
	if (MI.mayLoadOrStore() && MemIdx >= 0) {
	  assert(MI.getOpcode() != X86::LEA64r);
	  const MachineOperand& BaseOp = MI.getOperand(MemIdx + X86::AddrBaseReg);
	  const MachineOperand& IndexOp = MI.getOperand(MemIdx + X86::AddrIndexReg);
	  if (BaseOp.isReg())
	    Val.pre.addPubReg(BaseOp.getReg());
	  if (IndexOp.isReg())
	    Val.pre.addPubReg(IndexOp.getReg());
	}

	// If a memory access accesses a pointer value, then declassify *all* operands.
	for (MachineMemOperand *MMO : MI.memoperands()) {
	  if (const llvm::Value *Ptr = MMO->getValue()) {
	    if (pointeeHasPublicType(Ptr)) {
	      for (const MachineOperand& MO : MI.operands()) {
		if (MO.isReg()) {
		  Val.pre.addPubReg(MO.getReg());
		  if (!MI.isCall())
		    Val.post.addPubReg(MO.getReg());
		}
	      }
	    }
	  }
	}
      }
    }


    // DEBUG ONLY
    [[maybe_unused]] const auto dump_taint = [&] (llvm::raw_ostream& os) {
      os << "TAINT FOR FUNCTION " << MF.getFunction().getName() << "\n";
      for (auto& MBB : MF) {

	os << "LIVEINS:";
	for (const auto& p : MBB.liveins()) {
	  os << " " << MF.getSubtarget().getRegisterInfo()->getRegAsmName(p.PhysReg);
	}
	os << "\n";
	
	for (auto& MI : MBB) {
	  const auto *TRI = MF.getSubtarget().getRegisterInfo();
	  const auto& node = Map[&MI];
	  os << "\t";
	  node.pre.print(os, TRI);

	  os << "\n";
	  os << MI;
	  os << "\t";
	  node.post.print(os, TRI);
	  os << "\n";
	}
      }
    };

    ValidateDeclassifyMap(MF, Map, "pre-df");

    bool changed;
    do {
      changed = false;

      // Transfer function for each machine instruction
      for (MachineBasicBlock& MBB : MF) {
	for (MachineInstr& MI : MBB) {
	  auto& Node = Map[&MI];
	  {
	    Value Fwd = Node.pre;
	    Fwd.transferForward(MI);
	    changed |= Node.post.set_union(Fwd);
	  }
	  {
	    Value Bwd = Node.post;
	    Bwd.transferBackward(MI);
	    changed |= Node.pre.set_union(Bwd);
	  }
	}
      }

      // Global consistency of frame accesses
      std::set<FrameLocation> PubFrameLocs;
      for (MachineBasicBlock& MBB : MF) {
	for (MachineInstr& MI : MBB) {
	  FrameLocation FL;
	  if (MI.mayLoad() && getFrameAccess(MI, FL) && Map[&MI].post.anyOutputPublic(MI))
	    PubFrameLocs.insert(FL);
	}
      }
      for (MachineBasicBlock& MBB : MF) {
	for (MachineInstr& MI : MBB) {
	  FrameLocation FL;
	  if (MI.mayStore() && getFrameAccess(MI, FL) && PubFrameLocs.find(FL) != PubFrameLocs.end())
	    changed |= Map[&MI].pre.setAllInstrInputsPublic(MI);
	}
      }

      // Meet (forward and backward)
      for (MachineBasicBlock& MBB : MF) {
	if (MBB.empty())
	  continue;
	
	// Meet forward
	std::optional<Value> Fwd;
	for (MachineBasicBlock *PredMBB : getNonemptyPredecessors(MBB)) {
	  auto& In = Map[&PredMBB->back()].post;
	  if (Fwd) {
	    Fwd->meetForward(In);
	  } else {
	    Fwd = In;
	  }
	}
	if (Fwd) {
	  changed |= Map[&MBB.front()].pre.set_union(*Fwd);
	}

	// Meet backward
	if (!allowDeclassify()) {
	  std::optional<Value> Bwd;
	  for (MachineBasicBlock *SuccMBB : getNonemptySuccessors(MBB)) {
	    auto& In = Map[&SuccMBB->front()].pre;
	    if (Bwd) {
	      Bwd->meetBackward(In);
	    } else {
	      Bwd = In;
	    }
	  }
	  if (Bwd) {
	    changed |= Map[&MBB.back()].post.set_union(*Bwd);
	  }
	} 

	// Within same block
	for (auto it1 = MBB.begin(), it2 = std::next(it1); it2 != MBB.end(); ++it1, ++it2) {
	  auto& Val1 = Map[&*it1].post;
	  auto& Val2 = Map[&*it2].pre;
	  changed |= (Val1 != Val2);
	  changed |= Val1.set_union(Val2);
	  Val2 = Val1;
	}
      }

#if 0
      ValidateDeclassifyMap(MF, Map, "pre-df");
#endif
      
    } while (changed);


#if 0
    if (MF.getFunction().getName() == "walk_tree_1") {
      std::error_code EC;
      llvm::raw_fd_ostream f("taint.out", EC);
      dump_taint(f);

      llvm::raw_fd_ostream f2("ir.out", EC);
      MF.getFunction().print(f2);

      llvm::raw_fd_ostream f3("mf.out", EC);
      MF.print(f3);
    }
#endif
    ValidateDeclassifyMap(MF, Map, "post-df");
    
    return Map;
  }

  void runDeclassifyAnnotationPass(MachineFunction& MF) {

    auto Map = runTaintAnalysis(MF);

    // Mark loads/stores as declassified iff their value operand is public.
    for (MachineBasicBlock& MBB : MF) {
      for (MachineInstr& MI : MBB) {
	if (!MI.mayLoadOrStore())
	  continue;

	if (PrivacyPolicyOpt == PrivacyPolicy::sandbox) {
	  MI.setFlag(MachineInstr::TPEPubM);
	  continue;
	}
	
	const int MemIdx = getMemRefBeginIdx(MI);
	if (MemIdx < 0)
	  continue;

	bool AllInputsPublic = true;
	bool AnyOutputPublic = false;
	for (int OpIdx = 0; OpIdx < (int) MI.getNumOperands(); ++OpIdx) {
	  if (MemIdx <= OpIdx && OpIdx < MemIdx + X86::AddrNumOperands)
	    continue;
	  const MachineOperand& MO = MI.getOperand(OpIdx);
	  if (!MO.isReg())
	    continue;
	  const Register Reg = MO.getReg();
	  auto& Node = Map[&MI];
	  if (MO.isUse()) {
	    AllInputsPublic &= Node.pre.hasPubReg(Reg);
	  } else if (MO.isDef()) {
	    AnyOutputPublic |= Node.post.hasPubReg(Reg);
	  }
	}

	if ((MI.mayLoad() && AnyOutputPublic) || (MI.mayStore() && AllInputsPublic)) {
	  MI.setFlag(MachineInstr::TPEPubM);
	} else {
	  MI.setFlag(MachineInstr::TPEPrivM);
	}
      }
    }

#if 0
    dump_taint();
#endif

  }

#if 0
  void runSavePublicCSRsPass(MachineFunction& MF) {
    // Don't need to do this for sandbox isolation because any callee pushes/pops will be publicly typed as well.
    if (PrivacyPolicyOpt == PrivacyPolicy::sandbox)
      return;
    
    auto Map = runTaintAnalysis(MF);

    const auto *TII = MF.getSubtarget().getInstrInfo();

    for (MachineBasicBlock& MBB : MF) {
      for (MachineInstr& MI : MBB) {
	if (MI.isCall() && !MI.isTerminator()) {
	  assert(MI.getNextNode());

	  // The set of callee-saved registers we need to save before and restore after the call are
	  // exactly the set of GPRs that are (1) in the call's regmask and (2) public on return
	  // from the call.
	  const auto call_regmask = util::get_call_regmask(MI);
	  for (MCRegister csr : GPRBitMask::gprs()) {
	    if (!call_regmask[csr]) // (1)
	      continue;
	    if (!Map[&MI].post.hasPubReg(csr)) // (2)
	      continue;
	    
	    // Create a new frame location for this.
	    MachineFrameInfo& MFI = MF.getFrameInfo();
	    const auto FrameIdx = MFI.CreateSpillStackObject(8, Align(8));

	    // Save to slot before call.
	    auto SaveMBBI = MI.getIterator();
	    for (; SaveMBBI != MBB.begin() && std::prev(SaveMBBI)->getOpcode() == X86::ADJCALLSTACKDOWN64;
		 --SaveMBBI)
	      ;
	    MachineInstr& SaveInst =
	      *BuildMI(MBB, SaveMBBI, DebugLoc(), TII->get(X86::MOV64mr))
	      .addFrameIndex(FrameIdx)
	      .addImm(1)
	      .addReg(X86::NoRegister)
	      .addImm(0)
	      .addReg(X86::NoRegister)
	      .addReg(csr);
	    SaveInst.setFlag(MachineInstr::TPEPubM);

	    // Restore from slot after call.
	    auto RestoreMBBI = std::next(MI.getIterator());
	    for (; RestoreMBBI != MBB.end() && RestoreMBBI->getOpcode() == X86::ADJCALLSTACKUP64; ++RestoreMBBI)
	      ;
	    MachineInstr& RestoreInst =
	      *BuildMI(MBB, RestoreMBBI, DebugLoc(), TII->get(X86::MOV64rm), csr)
	      .addFrameIndex(FrameIdx)
	      .addImm(1)
	      .addReg(X86::NoRegister)
	      .addImm(0)
	      .addReg(X86::NoRegister);
	    RestoreInst.setFlag(MachineInstr::TPEPubM);
	  }
	  
	}
      }
    }
  }
#endif

  // TODO: Rename.
  void runDeclassifyCFIPass(MachineFunction& MF) {
    auto Map = runTaintAnalysis(MF);

    std::set<const MachineBasicBlock *> indirect_entrypoints = {&MF.front()};
    if (const MachineJumpTableInfo *JTI = MF.getJumpTableInfo())
      for (const auto& JTE : JTI->getJumpTables())
	llvm::copy(JTE.MBBs, std::inserter(indirect_entrypoints, indirect_entrypoints.end()));
    
    for (MachineBasicBlock& MBB : MF) {
      for (MachineInstr& MI : MBB) {
	if (MachineInstr *Prev = MI.getPrevNode())
	  if (Prev->isTerminator())
	    continue;
	
	const Value& value = Map[&MI].pre;

	const auto get_label = [&] (const Value& value) -> uint32_t {
	  GPRBitMask label;
	  for (MCRegister gpr : FilterRegMask(&MI, label.gprs()))
	    if (value.hasPubReg(gpr))
	      label.add(gpr);
	  return label.getValue();
	};

	const auto declassifies = [&] (const uint32_t label1, const uint32_t label2) {
	  if ((label1 & label2) == label2) {
	    return false;
	  } else {
	    // In constant-time w/o declassification, this should never occur
	    assert(allowDeclassify());
	    return true;
	  }
	};

	const auto deviates = [&] (MachineInstr& MI) -> bool {
	  if (MI.isCall() || MI.isReturn() || MI.isTerminator() || isPush(MI)) {
	    return false;
	  } else {
	    // Check if any input is private.
	    const bool any_input_private = llvm::any_of(MI.operands(), [&] (const MachineOperand& MO) -> bool {
	      return MO.isReg() && MO.isUse() && !MO.isUndef() && !Map[&MI].pre.hasPubReg(MO.getReg());
	    });
	    if (any_input_private) {
	      const bool any_output_public = llvm::any_of(MI.operands(), [&] (const MachineOperand& MO) -> bool {
		return MO.isReg() && MO.isDef() && Map[&MI].post.hasPubReg(MO.getReg());
	      });
	      if (any_output_public) {
		assert(allowDeclassify());
		return true;
	      }
	    }
	    return false;
	  }
	};

	// Check if there is a privacy type mismatch if MI is not an indirect control-flow instruction.
	const bool guard_src = [&] () {
	  if (MI.isCall() || MI.isReturn()) {
	    return true;
	  } else if (MI.getNextNode()) {
	    return declassifies(get_label(Map[&MI].post), get_label(Map[MI.getNextNode()].pre))
	      || deviates(MI);
	  } else {
	    return llvm::any_of(MBB.successors(), [&] (MachineBasicBlock *Succ) -> bool {
	      if (Succ->empty()) {
		return true;
	      } else {
		return declassifies(get_label(Map[&MI].post), get_label(Map[&Succ->front()].pre));
	      }
	    });
	  }
	}();

	const auto guard_dst = [&] () {
	  if (MBB.getIterator() == MF.begin() && MI.getIterator() == MBB.begin()) {
	    return true;
	  } else if (MI.getIterator() == MBB.begin() && indirect_entrypoints.find(&MBB) != indirect_entrypoints.end()) {
	    return true;
	  } else if (MI.getPrevNode() && MI.getPrevNode()->isCall() && !MI.getPrevNode()->isReturn()) {
	    return true;
	  } else if (MI.getPrevNode()) {
	    return declassifies(get_label(Map[MI.getPrevNode()].post), get_label(Map[&MI].pre))
	      || deviates(*MI.getPrevNode());
	  } else {
	    return llvm::any_of(MBB.predecessors(), [&] (MachineBasicBlock *Pred) -> bool {
	      if (Pred->empty()) {
		return true;
	      } else {
		return declassifies(get_label(Map[&Pred->back()].post), get_label(Map[&MI].pre));
	      }
	    });
	  }
	}();

	if (guard_src || guard_dst) {
	  if (MachineInstr *Prev = MI.getPrevNode()) {
	    assert(!Prev->isTerminator());
	  }
	}

	// Source CFI labels.
	if (guard_src) {
	  //	  llvm::errs() << "src: " << MI << "\n";
	  
	  GPRBitMask label;

	  // Add to the mask any remaining GPRs that are public.
	  for (MCRegister gpr : FilterRegMask(&MI, label.gprs()))
	    if (value.hasPubReg(gpr))
	      label.add(gpr);

	  if (PrivacyPolicyOpt == tpe::sandbox)
	    label.addAll();
	  
	  BuildCFILabel_Src(MBB, MI.getIterator(), label.getValue());
	}


	// Destination CFI labels.
	if (guard_dst) {

	  GPRBitMask label;

	  const MachineInstr *Prev = MI.getPrevNode();

	  for (MCRegister gpr : FilterLiveRegsBefore(MI, FilterRegMask(Prev, label.gprs())))
	    if (value.hasPubReg(gpr))
	      label.add(gpr);

	  if (PrivacyPolicyOpt == tpe::sandbox)
	    label.addAll();
	  
	  BuildCFILabel_Dst(MBB, MI.getIterator(), label.getValue());
	}
	
      }
    }

  }




  std::map<MachineInstr *, Node> runSandboxPrivacyAnalysis(MachineFunction& MF) {
    assert(PrivacyPolicyOpt == sandbox);

    std::map<MachineInstr *, Node> Map;
    for (MachineBasicBlock& MBB : MF) {
      for (MachineInstr& MI : MBB) {
	Value value;
	for (MCRegister Reg : GPRBitMask::gprs())
	  value.addPubReg(Reg);
	Map[&MI].pre = Map[&MI].post = value;
      }
    }

    return Map;
  }

  std::map<MachineInstr *, Node> runTaintAnalysis(MachineFunction& MF) {
    switch (PrivacyPolicyOpt) {
    case PrivacyPolicyNone:
      WithColor::error() << "no threat model specified, refusing to compile\n";
      std::exit(1);
    case sandbox:
      return runSandboxPrivacyAnalysis(MF);
    case ct:
    case ctdecl:
      return runConstantTimePrivacyAnalysis(MF);
    default:
      llvm_unreachable("unexpected privacy policy enum");
    }
  }
  
}
