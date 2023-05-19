#ifndef LLVM_LIB_TARGET_X86_X86LLSCT_H
#define LLVM_LIB_TARGET_X86_X86LLSCT_H

#include <cstdint>

#include "llvm/CodeGen/MachineInstr.h"
#include "llvm/CodeGen/MachineMemOperand.h"

namespace llvm {

  namespace X86 {
#if 1
    struct AccessInfo {
      enum AccessMode {
	Load = 1 << 0,
	Store = 1 << 1,
      };
      enum AccessKind: int {
	Nca,
	Stack,
	Global,
      };
  
      AccessMode Mode;
      AccessKind Kind;
      SmallSet<Register, 2> AddrRegs;

      AccessInfo() = default;
      AccessInfo(AccessMode Mode, AccessKind Kind, std::initializer_list<Register> AddrRegs_): Mode(Mode), Kind(Kind) {
	for (Register AddrReg : AddrRegs_)
	  AddrRegs.insert(AddrReg);
      }
    };
    
    void getAccessInfo(const MachineInstr& MI, SmallVectorImpl<AccessInfo>& Info);
#endif


    /*
     */
    struct Access {
      enum AccessMode {
	Load = 1 << 0,
	Store = 1 << 1,
      };
      enum AccessKind {
	Nca,
	Stack,
	Global,
      };
      AccessMode Mode;
      AccessKind Kind;
      Access(AccessMode Mode, AccessKind Kind): Mode(Mode), Kind(Kind) {}
    };
    
    struct MyInstrInfo {
      struct StackSlot {
	int FrameIdx;
	unsigned Bytes;
	unsigned Offset;
      };
      using Location = std::variant<Register, StackSlot>;
      

      SmallVector<Access> Accesses;
      SmallVector<Location> Uses;
      SmallVector<Location> Defs;
      SmallVector<Location> Leaks;

#if 0
      static MyInstrInfo get(const MachineInstr& MI) {
      }
#endif
    };
    
  }

#if 0
  namespace X86 {
    enum AccessFlags: uint16_t {
      AcNca = MachineMemOperand::MOTargetFlag1,
      AcSsbd = MachineMemOperand::MOTargetFlag2,
      AcClass = MachineMemOperand::MOTargetFlag3,
    };
  }

  /// Access flags
  static const MachineMemOperand::Flags MONca = AcNca;
  static const MachineMemOperand::Flags MOSsbd = AcSsbd;
  static const MachineMemOperand::Flags MOClass = AcClass;
  
  namespace X86 {
    AccessFlags getDefaultAccessFlags(const MachineInstr& MI);
  }
#endif

}

#endif
