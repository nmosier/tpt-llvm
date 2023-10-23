#include "X86.h"
#include "X86InstrInfo.h"
#include "X86Declassify.h"
#include "X86LLSCT.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Constants.h"
#include "../lib/IR/ConstantsContext.h"
#include "llvm/IR/IntrinsicInst.h"
#include "llvm/CodeGen/MachineJumpTableInfo.h"
#include "X86Subtarget.h"
#include <set>
#include <queue>
#include <bitset>

namespace llvm::X86 {

  namespace {

    bool IsIndirectControlFlow(const MachineInstr& MI) {
      if (MI.isIndirectBranch() || MI.isReturn()) {
	return true;
      } else if (MI.isCall()) {
	switch (MI.getOpcode()) {
	case X86::CALL64pcrel32:
	  return false;
	case X86::CALL64r:
	case X86::CALL64m:
	  return true;
	default:
	  errs() << __FILE__ << ":" << __LINE__ << ": unhandled opcode: " << MI << "\n";
	  report_fatal_error("exiting");
	}
      } else {
	return false;
      }
    }

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

      static Register canonicalizeRegister(Register Reg) {
	if (Reg == X86::EFLAGS)
	  return Reg;
	return getX86SubSuperRegisterOrZero(Reg, 64);
      }

      static bool registerIsAlwaysPublic(Register Reg) {
	return Reg == X86::NoRegister || Reg == X86::RSP || Reg == X86::RIP;
      }

      void delPubReg(Register Reg) {
	Reg = canonicalizeRegister(Reg);
	PubRegs.reset(Reg);
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

      bool hasPubReg(Register Reg) const {
	Reg = canonicalizeRegister(Reg);
	if (registerIsAlwaysPublic(Reg))
	  return true;
	return PubRegs.test(Reg);
      }

      [[nodiscard]] bool setAllInstrInputsPublic(const MachineInstr& MI);

      void transferForward(const MachineInstr& MI);
      void transferBackward(const MachineInstr& MI);

      // LLSCT-FIXME: meetForward and meetBackward should return new copies, to avoid mistakenly not setting changed correctly.
      void meetForward(const Value& o);
      void meetBackward(const Value& o);
      [[nodiscard]] bool set_union(const Value& o);
    };

    struct Node {
      Value pre;
      Value post;

      auto tuple() const { return std::make_tuple(pre, post); }
      // bool operator<(const Node& o) const { return tuple() < o.tuple(); }
      bool operator==(const Node& o) const { return tuple() == o.tuple(); }
      bool operator!=(const Node& o) const { return tuple() != o.tuple(); }
    };

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
      for (const MachineOperand& MO : MI.operands()) {
	if (MO.isReg() && ((MO.isUse() && MO.isKill()) || MO.isDef())) {
	  PubRegs.reset(canonicalizeRegister(MO.getReg()));
	}
      }
    }

    bool Value::allInputsPublic(const MachineInstr& MI) const {
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
      removeClobberedRegisters(MI);

      // If all inputs are public, then mark all outputs as public.
      if (!MI.mayLoad() && allInputsPublic(MI))
	for (const MachineOperand& MO : MI.operands())
	  if (MO.isReg() && MO.isDef())
	    addPubReg(MO.getReg());
    }

    void Value::transferBackward(const MachineInstr& MI) {
      removeClobberedRegisters(MI);

      // If all outputs are public, then mark all inputs as public.
      if (!MI.mayLoad() && anyOutputPublic(MI))
	for (const MachineOperand& MO : MI.operands())
	  if (MO.isReg() && MO.isUse())
	    addPubReg(MO.getReg());
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
		     uint32_t CFILabel, MCRegister BaseReg) {
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
  
  void runDeclassificationPass(MachineFunction& MF) {
    std::set<MachineMemOperand *> Declassified;

    std::map<MachineInstr *, Node> Map, Bak;

    // All input registers are assumed to be public.
    // FIXME: No longer make this assumption.
    {
      for (MachineBasicBlock *EntryMBB : getNonemptyEntrypoints(MF)) {
	auto& Entry = Map[&EntryMBB->front()].pre;
	for (const auto& [MCReg, Reg] : MF.getRegInfo().liveins()) {
	  Entry.addPubReg(MCReg);
	}
      }
    }

    // Declassify the value operands / results of all memory accesses that were
    // flagged as declassified in our IR pass.
    for (MachineBasicBlock& MBB : MF) {
      for (MachineInstr& MI : MBB) {
	const bool should_declassify =
	  any_of(MI.memoperands(), [] (const MachineMemOperand *MemOp) -> bool {
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
	    if (ConstArr->getAsCString() != "llsct.declassify")
	      return false;
	    return true;
	  });
	
	if (!should_declassify)
	  continue;

	// FIXME: Just do it for the ones that are really declassified?
	for (MachineMemOperand *MemOp : MI.memoperands())
	  Declassified.insert(MemOp);

	auto& Val = Map[&MI];
	
	if (MI.mayLoad()) {
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
	if (MI.isCall() || MI.isBranch() || MI.isReturn()) {
	  for (MachineOperand& MO : MI.operands())
	    if (MO.isReg() && MO.isUse())
	      Val.pre.addPubReg(MO.getReg());
	}

	// Declassify call arguments.
	if (MI.isCall() || MI.isReturn()) {
	  // Look for implicit kills and implicit defs.
	  for (const MachineOperand& MO : MI.operands()) {
	    if (MO.isReg() && MO.isImplicit()) {
	      const Register Reg = MO.getReg();
	      if (MO.isUse() && MO.isKill()) {
		Val.pre.addPubReg(Reg);
	      } else if (MO.isDef()) {
		Val.post.addPubReg(Reg);
	      }
	      // llvm_unreachable("implicit machine register operand must be kill or def");
	    }
	  }
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
		  Val.post.addPubReg(MO.getReg());
		}
	      }
	    }
	  }
	}
      }
    }

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

	// Within same block
	for (auto it1 = MBB.begin(), it2 = std::next(it1); it2 != MBB.end(); ++it1, ++it2) {
	  auto& Val1 = Map[&*it1].post;
	  auto& Val2 = Map[&*it2].pre;
	  changed |= (Val1 != Val2);
	  changed |= Val1.set_union(Val2);
	  Val2 = Val1;
	}
      }

    } while (changed);

    // Mark loads/stores as declassified iff their value operand is public.
    for (MachineBasicBlock& MBB : MF) {
      for (MachineInstr& MI : MBB) {
	if (!MI.mayLoadOrStore())
	  continue;
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
	  MI.setFlag(MachineInstr::LLSCTDeclassify);
	}
      }
    }
    

    std::set<const MachineBasicBlock *> indirect_entrypoints = {&MF.front()};
    if (const MachineJumpTableInfo *JTI = MF.getJumpTableInfo ())
      for (const auto& JTE : JTI->getJumpTables())
	llvm::copy(JTE.MBBs, std::inserter(indirect_entrypoints, indirect_entrypoints.end()));

    

    for (MachineBasicBlock& MBB : MF) {
      for (MachineInstr& MI : MBB) {
	const Value& value = Map[&MI].pre;

	// Source CFI labels.
	if (IsIndirectControlFlow(MI)) {
	  llvm::errs() << "src: " << MI << "\n";
	  
	  GPRBitMask label;

	  // Add to the mask any remaining GPRs that are public.
	  for (MCRegister gpr : FilterRegMask(&MI, label.gprs()))
	    if (value.hasPubReg(gpr))
	      label.add(gpr);
	  
	  BuildCFILabel_Src(MBB, MI.getIterator(), label.getValue());
	}


	// Destination CFI labels.
	if ((!MI.getPrevNode() && indirect_entrypoints.find(&MBB) != indirect_entrypoints.end()) ||
	    (MI.getPrevNode() && MI.getPrevNode()->isCall() && !MI.getPrevNode()->isReturn())) {
	  llvm::errs() << "dst: " << MI << "\n";

	  GPRBitMask label;

	  const MachineInstr *Prev = MI.getPrevNode();

	  for (MCRegister gpr : FilterRegMask(Prev, label.gprs()))
	    if (value.hasPubReg(gpr))
	      label.add(gpr);
	  
	  BuildCFILabel_Dst(MBB, MI.getIterator(), label.getValue());
	}
	
      }
    }

    // Destination CFI Labels.
    
	

# if 0
    // Collect stats on what fraction of callee-saved registers are public.
    {
      const auto *TII = MF.getSubtarget<X86Subtarget>().getInstrInfo();
      for (MachineBasicBlock& MBB : MF) {
	for (MachineInstr& MI : MBB) {
	  if (MI.isCall() || MI.isReturn()) {
	    for (MCRegister csr : csrs) {
	      const Value& value = Map[&MI].pre;
	      if (value.hasPubReg(csr)) {
		BuildMI(MBB, MI.getIterator(), DebugLoc(), TII->get(X86::INT3));
	      }
	    }
	  }
	}
      }
    }
#endif
    
  }
  
}
