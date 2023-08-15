#include "X86.h"
#include "X86InstrInfo.h"
#include "llvm/CodeGen/MachineFunctionPass.h"
#include "llvm/CodeGen/MachineInstrBuilder.h"
#include "X86Subtarget.h"
#include "llvm/IR/Module.h"
#include "llvm/CodeGen/MachineFrameInfo.h"
#include "llvm/ADT/PointerUnion.h"
#include "MCTargetDesc/X86IntelInstPrinter.h"
#include "X86TargetMachine.h"
#include "llvm/CodeGen/MachineJumpTableInfo.h"

#include <map>
#include <set>
#include <variant>
#include <queue>
#include <tuple>

using namespace llvm;

namespace {

  cl::opt<bool> EnableProtectPass {
    "x86-protect",
    cl::desc("Enable Serberus' Protect Pass"),
    cl::init(false),
    cl::Hidden,
  };

  static int getMemRefBeginIdx(const MachineInstr& MI) {
    const MCInstrDesc& Desc = MI.getDesc();
    int MemRefBeginIdx = X86II::getMemoryOperandNo(Desc.TSFlags);
    if (MemRefBeginIdx < 0)
      return -1;
    MemRefBeginIdx += X86II::getOperandBias(Desc);
    return MemRefBeginIdx;
  }
  
  static StringRef getMnemonic(const MachineInstr& MI) {
    const auto& target = MI.getParent()->getParent()->getTarget();
    MCInst MCI;
    MCI.setOpcode(MI.getOpcode());
    X86IntelInstPrinter IP(*target.getMCAsmInfo(), *target.getMCInstrInfo(), *target.getMCRegisterInfo());
    StringRef mnemonic = IP.getMnemonic(&MCI).first;
    return mnemonic.rtrim();      
  }  

  struct DFGNode {
    PointerUnion<MachineInstr *, MachineBasicBlock *> Loc;
    enum Point {BEFORE, AFTER} Pt;
    Register Reg;

    DFGNode(MachineInstr *MI, Point Pt, Register Reg): Loc(MI), Pt(Pt), Reg(Reg) {}
    DFGNode(MachineBasicBlock *MBB, Point Pt, Register Reg): Loc(MBB), Pt(Pt), Reg(Reg) {}

    bool isMI() const { return Loc.is<MachineInstr *>(); }
    MachineInstr& getMI() const { assert(isMI()); return *Loc.get<MachineInstr *>(); }
    bool isMBB() const { return Loc.is<MachineBasicBlock *>(); }
    MachineBasicBlock& getMBB() const { assert(isMBB()); return *Loc.get<MachineBasicBlock *>(); }
    
    auto tuple() const { return std::make_tuple(Loc, Pt, Reg); }
    bool operator<(const DFGNode& o) const { return tuple() < o.tuple(); }
    bool operator==(const DFGNode& o) const { return tuple() == o.tuple(); }
    bool operator!=(const DFGNode& o) const { return tuple() != o.tuple(); }

    bool valid() const {
      return Reg != X86::NoRegister;
    }
  };

  class DFG {
  private:
    struct SuperSource {
      bool operator<(const SuperSource&) const { return false; }
      bool operator==(const SuperSource&) const { return true; }
      bool operator!=(const SuperSource&) const { return false; }
    };
    struct SuperSink {
      bool operator<(const SuperSink&) const { return false; }
      bool operator==(const SuperSink&) const { return true; }
      bool operator!=(const SuperSink&) const { return false; }
    };
    struct SplitNode {
      DFGNode node;
      enum Type {IN, OUT} half;
      SplitNode(const DFGNode& node, Type half): node(node), half(half) {}
      auto tuple() const { return std::make_tuple(node, half); }
      bool operator<(const SplitNode& o) const { return tuple() < o.tuple(); }
      bool operator==(const SplitNode& o) const { return tuple() == o.tuple(); }
      bool operator!=(const SplitNode& o) const { return tuple() != o.tuple(); }
    };
    using DFGNode2 = std::variant<SuperSource, SuperSink, SplitNode>;
    using Index = unsigned;
    using Weight = int;
    using Graph = std::vector<std::map<Index, Weight>>;
    // using BitVector = std::vector<uint8_t>;
    using BitVector = std::vector<bool>;
  public:
    void add_edge(const DFGNode& src, const DFGNode& dst) {
      add_node(src);
      add_node(dst);
      add_edge2(SplitNode(src, SplitNode::OUT), SplitNode(dst, SplitNode::IN), INT_MAX);
    }
  private:
    int compute_node_weight(const DFGNode& node) {
      if (node.isMBB())
	return INT_MAX;
      assert(node.isMI());
      if (node.getMI().isTerminator() && node.Pt == DFGNode::AFTER)
	return INT_MAX;
      return 1;
    }
  public:
    void add_node(const DFGNode& node) {
      add_edge2(SplitNode(node, SplitNode::IN),
		SplitNode(node, SplitNode::OUT),
		compute_node_weight(node));
    }
    void add_source(const DFGNode& source) {
      add_edge2(SuperSource(), SplitNode(source, SplitNode::IN), INT_MAX);
    }
    void add_sink(const DFGNode& sink) {
      add_edge2(SplitNode(sink, SplitNode::OUT), SuperSink(), INT_MAX);
    }
  private:
    struct Valid {
      bool operator()(SuperSource) const { return true; }
      bool operator()(SuperSink) const { return true; }
      bool operator()(const SplitNode& node) const { return node.node.valid(); }
    };
    static bool valid(const DFGNode2& node) {
      return std::visit(Valid(), node);
    }

    Graph graph;
    std::map<DFGNode2, Index> node_to_index;
    std::vector<DFGNode2> index_to_node;

    size_t getNumNodes() const {
      return index_to_node.size(); }
    

    Index add_node2(const DFGNode2& node) {
      const auto it = node_to_index.emplace(node, getNumNodes());
      if (it.second) {
	index_to_node.push_back(node);
	graph.emplace_back();
      }
      return it.first->second;
    }

    void add_edge2(const DFGNode2& src, const DFGNode2& dst, int w) {
      const Index src2 = add_node2(src);
      const Index dst2 = add_node2(dst);
      graph[src2][dst2] = w;
    }

    bool bfs(Graph& R, Index s, Index t, std::vector<Index>& parent) {
      parent.clear();
      parent.resize(getNumNodes(), -1);
      BitVector visited(getNumNodes(), false);
      std::queue<Index> q;
      q.push(s);
      visited[s] = true;

      while (!q.empty()) {
	const Index u = q.front();
	q.pop();
	for (const auto& [v, w] : R[u]) {
	  if (!visited[v] && w > 0) {
	    visited[v] = true;
	    q.push(v);
	    parent[v] = u;
	  }
	}
      }

      return visited[t];
    }

    void dfs(Graph& R, Index s, BitVector& visited) {
      visited[s] = true;
      for (const auto& [i, w] : R[s]) {
	if (w > 0 && !visited[i])
	  dfs(R, i, visited);
      }
    }
    
  public:
    void min_cut(std::set<DFGNode>& cut_nodes) {
      errs() << "nodes: " << getNumNodes() << "\n";
      
      auto& G = graph;
      Graph R = G;

      const Index s = add_node2(SuperSource());
      const Index t = add_node2(SuperSink());

      std::vector<Index> parent(getNumNodes(), -1);
      int n = 0;
      while (bfs(R, s, t, parent)) {
	errs() << "\riteration " << ++n;
	int path_flow = INT_MAX;
	for (auto v = t; v != s; v = parent.at(v)) {
	  auto u = parent.at(v);
	  assert(u != (Index) -1);
	  path_flow = std::min(path_flow, R[u][v]);
	}
	for (auto v = t; v != s; v = parent.at(v)) {
	  auto u = parent.at(v);
	  assert(u != (Index) -1);
	  R[u][v] -= path_flow;
	  R[v][u] += path_flow;
	}
      }
      errs() << "\n";

      BitVector visited(getNumNodes(), false);
      dfs(R, s, visited);

      std::set<std::pair<DFGNode2, DFGNode2>> cut_edges;
      for (Index src = 0; src < getNumNodes(); ++src) {
	const auto& dsts = G[src];
	for (const auto& [dst, w] : dsts) {
	  if (G[src][dst] > 0 && visited[src] && !visited[dst]) {
	    cut_edges.emplace(index_to_node.at(src), index_to_node.at(dst));
	  }
	}
      }

      // Map back to original nodes
      for (const auto& [src, dst] : cut_edges) {
	assert(std::holds_alternative<SplitNode>(src) &&
	       std::holds_alternative<SplitNode>(dst));
	auto src_ = std::get<SplitNode>(src);
	auto dst_ = std::get<SplitNode>(dst);
	assert(src_.half != dst_.half && src_.node == dst_.node);
	cut_nodes.insert(src_.node);
      }
    }
  };

  

  class X86Protect final : public MachineFunctionPass {
  public:
    static inline char ID = 0;
    X86RegisterInfo *TRI;

    X86Protect(): MachineFunctionPass(ID) {
      initializeX86ProtectPass(*PassRegistry::getPassRegistry());
    }

    static inline const std::set<Register> regs = {
      X86::RAX, X86::RBX, X86::RCX, X86::RDX,
      X86::RDI, X86::RSI, X86::RSP, X86::RBP,
      X86::R8,  X86::R9,  X86::R10, X86::R11,
      X86::R12, X86::R13, X86::R14, X86::R15,
    };
    

    static iterator_range<std::set<Register>::iterator> getAllRegisters() {
      return regs;
    }

    void getSuccessors(MachineBasicBlock& MBB, SmallVectorImpl<MachineBasicBlock *>& Succs, std::set<MachineBasicBlock *>& seen) {
      if (!seen.insert(&MBB).second)
	return;
      for (MachineBasicBlock *Succ : MBB.successors()) {
	if (Succ->empty()) {
	  getSuccessors(*Succ, Succs, seen);
	} else {
	  Succs.push_back(Succ);
	}
      }
    }

    Register legalizeRegister(Register Reg) const {
      const Register SuperReg = getX86SubSuperRegisterOrZero(Reg, 64);
      if (regs.find(SuperReg) != regs.end()) {
	return SuperReg;
      } else {
	return X86::NoRegister;
      }
    }

    bool isNCA(MachineInstr& MI) const {
      const int MemIdx = getMemRefBeginIdx(MI);
      if (MemIdx < 0)
	return false;
      const MachineOperand& Base = MI.getOperand(MemIdx + X86::AddrBaseReg);
      if (Base.isReg()) {
	const Register BaseReg = Base.getReg();
	if (BaseReg != X86::NoRegister && BaseReg != X86::RIP && BaseReg != X86::RSP)
	  return true;
      }
      const MachineOperand& Index = MI.getOperand(MemIdx + X86::AddrIndexReg);
      if (Index.isReg()) {
	const Register IndexReg = Index.getReg();
	if (IndexReg != X86::NoRegister) {
	  assert(IndexReg != X86::RIP && IndexReg != X86::RSP);
	  return true;
	}
      }
      return false;
    }

    void getSensitiveOperands(MachineInstr& MI, SmallVectorImpl<Register>& Leaks) {
      if (MI.isCopy())
	return;
      
      // First, check for memory operands.
      const int MemIdx = getMemRefBeginIdx(MI);
      if (MemIdx >= 0) {
	const MachineOperand& Base = MI.getOperand(MemIdx + X86::AddrBaseReg);
	if (Base.isReg())
	  Leaks.push_back(Base.getReg());
	const MachineOperand& Index = MI.getOperand(MemIdx + X86::AddrIndexReg);
	if (Index.isReg())
	  Leaks.push_back(Index.getReg());
      }

      // Now, check for leaked input operands.
      static const std::set<std::string> safe_mnemonics = {
	"ADC", "ADCX", "ADD", "ADOX", "AESDEC", "AESDECLAST", "AESENC", "AESENCLAST", "AESIMC", "AESKEYGENASSIST", "AND", "ANDN", "BT", "BTC", "BTR", "BTS", "CMOVB", "CMOVBE", "CMOVL", "CMOVLE", "CMOVNB", "CMOVNBE", "CMOVNL", "CMOVNLE", "CMOVNO", "CMOVNP", "CMOVNS", "CMOVNZ", "CMOVO", "CMOVP", "CMOVS", "CMOVZ", "CMP", "DEC", "GF2P8AFFINEINVQB", "GF2P8AFFINEQB", "GF2P8MULB", "IMUL", "INC", "KADDB", "KADDD", "KADDQ", "KADDW", "KANDB", "KANDD", "KANDNB", "KANDND", "KANDNQ", "KANDNW", "KANDQ", "KANDW", "KMOVB", "KMOVD", "KMOVQ", "KMOVW", "KNOTB", "KNOTD", "KNOTQ", "KNOTW", "KORB", "KORD", "KORQ", "KORTESTB", "KORTESTD", "KORTESTQ", "KORTESTW", "KORW", "KSHIFTLB", "KSHIFTLD", "KSHIFTLQ", "KSHIFTLW", "KSHIFTRB", "KSHIFTRD", "KSHIFTRQ", "KSHIFTRW", "KTESTB", "KTESTD", "KTESTQ", "KTESTW", "KUNPCKBW", "KUNPCKDQ", "KUNPCKWD", "KXNORB", "KXNORD", "KXNORQ", "KXNORW", "KXORB", "KXORD", "KXORQ", "KXORW", "LDDQU", "LEA", "MOV", "MOVD", "MOVDDUP", "MOVDQ2Q", "MOVDQA", "MOVDQU", "MOVNTDQ", "MOVNTDQA", "MOVQ", "MOVSB", "MOVSD", "MOVSHDUP", "MOVSLDUP", "MOVSQ", "MOVSW", "MOVSX", "MOVSXD", "MOVZX", "MPSADBW", "MUL", "MULX", "NEG", "NOT", "OR", "PABSB", "PABSD", "PABSW", "PACKSSDW", "PACKSSWB", "PACKUSDW", "PACKUSWB", "PADDB", "PADDD", "PADDQ", "PADDSB", "PADDSW", "PADDUSB", "PADDUSW", "PADDW", "PALIGNR", "PAND", "PANDN", "PAVGB", "PAVGW", "PBLENDVB", "PBLENDW", "PCLMULQDQ", "PCMPEQB", "PCMPEQD", "PCMPEQQ", "PCMPEQW", "PCMPGTB", "PCMPGTD", "PCMPGTQ", "PCMPGTW", "PEXTRB", "PEXTRD", "PEXTRQ", "PEXTRW", "PHADDD", "PHADDSW", "PHADDW", "PHMINPOSUW", "PHSUBD", "PHSUBSW", "PHSUBW", "PINSRB", "PINSRD", "PINSRQ", "PINSRW", "PMADDUBSW", "PMADDWD", "PMAXSB", "PMAXSW", "PMAXUB", "PMAXUD", "PMAXUW", "PMINSB", "PMINSW", "PMINUB", "PMINUD", "PMINUW", "PMOVMSKB", "PMOVSXBD", "PMOVSXBQ", "PMOVSXBW", "PMOVSXDQ", "PMOVSXWD", "PMOVSXWQ", "PMOVZXBD", "PMOVZXBQ", "PMOVZXBW", "PMOVZXDQ", "PMOVZXWD", "PMOVZXWQ", "PMULDQ", "PMULHRSW", "PMULHUW", "PMULHW", "PMULLD", "PMULLW", "PMULUDQ", "POP", "POR", "PSADBW", "PSHUFB", "PSHUFD", "PSHUFHW", "PSHUFLW", "PSIGNB", "PSIGND", "PSIGNW", "PSLLD", "PSLLDQ", "PSLLQ", "PSLLW", "PSRAD", "PSRAW", "PSRLD", "PSRLDQ", "PSRLQ", "PSRLW", "PSUBB", "PSUBD", "PSUBQ", "PSUBSB", "PSUBSW", "PSUBUSB", "PSUBUSW", "PSUBW", "PTEST", "PUNPCKHBW", "PUNPCKHDQ", "PUNPCKHQDQ", "PUNPCKHWD", "PUNPCKLBW", "PUNPCKLDQ", "PUNPCKLQDQ", "PUNPCKLWD", "PUSH", "PXOR", "REP_MOVSB", "REP_MOVSD", "REP_MOVSW", "REP_STOSB", "REP_STOSD", "REP_STOSW", "SAR", "SBB", "SETB", "SETBE", "SETL", "SETLE", "SETNB", "SETNBE", "SETNL", "SETNLE", "SETNO", "SETNP", "SETNS", "SETNZ", "SETO", "SETP", "SETS", "SETZ", "SHA1MSG1", "SHA1MSG2", "SHA1NEXTE", "SHA1RNDS4", "SHA256MSG1", "SHA256MSG2", "SHA256RNDS2", "SHL", "SHLX", "SHR", "SHRX", "SUB", "TEST", "VAESDEC", "VAESDECLAST", "VAESENC", "VAESENCLAST", "VAESIMC", "VAESKEYGENASSIST", "VALIGND", "VALIGNQ", "VBLENDMPD", "VBLENDMPS", "VBROADCASTF128", "VBROADCASTF32X2", "VBROADCASTF32X4", "VBROADCASTF32X8", "VBROADCASTF64X2", "VBROADCASTF64X4", "VBROADCASTI128", "VBROADCASTI32X2", "VBROADCASTI32X4", "VBROADCASTI32X8", "VBROADCASTI64X2", "VBROADCASTI64X4", "VBROADCASTSD", "VBROADCASTSS", "VCOMPRESSPD", "VCOMPRESSPS", "VDBPSADBW", "VEXPANDPD", "VEXPANDPS", "VEXTRACTF128", "VEXTRACTF32X4", "VEXTRACTF32X8", "VEXTRACTF64X2", "VEXTRACTF64X4", "VEXTRACTI128", "VEXTRACTI32X4", "VEXTRACTI32X8", "VEXTRACTI64X2", "VEXTRACTI64X4", "VGF2P8AFFINEINVQB", "VGF2P8AFFINEQB", "VGF2P8MULB", "VINSERTF128", "VINSERTF32X4", "VINSERTF32X8", "VINSERTF64X2", "VINSERTF64X4", "VINSERTI128", "VINSERTI32X4", "VINSERTI32X8", "VINSERTI64X2", "VINSERTI64X4", "VLDDQU", "VMOVD", "VMOVDDUP", "VMOVDQA", "VMOVDQA32", "VMOVDQA64", "VMOVDQU", "VMOVDQU16", "VMOVDQU32", "VMOVDQU64", "VMOVDQU8", "VMOVNTDQ", "VMOVNTDQA", "VMOVQ", "VMOVSD", "VMOVSHDUP", "VMOVSLDUP", "VMPSADBW", "VPABSB", "VPABSD", "VPABSQ", "VPABSW", "VPACKSSDW", "VPACKSSWB", "VPACKUSDW", "VPACKUSWB", "VPADDB", "VPADDD", "VPADDQ", "VPADDSB", "VPADDSW", "VPADDUSB", "VPADDUSW", "VPADDW", "VPALIGNR", "VPAND", "VPANDD", "VPANDN", "VPANDND", "VPANDNQ", "VPANDQ", "VPAVGB", "VPAVGW", "VPBLENDD", "VPBLENDMB", "VPBLENDMD", "VPBLENDMQ", "VPBLENDMW", "VPBLENDVB", "VPBLENDW", "VPBROADCASTB", "VPBROADCASTD", "VPBROADCASTMB2Q", "VPBROADCASTMW2D", "VPBROADCASTQ", "VPBROADCASTW", "VPCLMULQDQ", "VPCMPB", "VPCMPEQB", "VPCMPEQD", "VPCMPEQQ", "VPCMPEQW", "VPCMPGTB", "VPCMPGTD", "VPCMPGTQ", "VPCMPGTW", "VPCMPQ", "VPCMPUB", "VPCMPUD", "VPCMPUQ", "VPCMPUW", "VPCMPW", "VPERM2F128", "VPERM2I128", "VPERMD", "VPERMI2D", "VPERMI2PD", "VPERMI2PS", "VPERMI2Q", "VPERMI2W", "VPERMILPD", "VPERMILPS", "VPERMPD", "VPERMPS", "VPERMQ", "VPERMT2D", "VPERMT2PD", "VPERMT2PS", "VPERMT2Q", "VPERMT2W", "VPERMW", "VPEXTRB", "VPEXTRD", "VPEXTRQ", "VPEXTRW", "VPHADDD", "VPHADDSW", "VPHADDW", "VPHMINPOSUW", "VPHSUBD", "VPHSUBSW", "VPHSUBW", "VPINSRB", "VPINSRD", "VPINSRQ", "VPINSRW", "VPLZCNTD", "VPLZCNTQ", "VPMADD52HUQ", "VPMADD52LUQ", "VPMADDUBSW", "VPMADDWD", "VPMAXSB", "VPMAXSQ", "VPMAXSW", "VPMAXUB", "VPMAXUD", "VPMAXUQ", "VPMAXUW", "VPMINSB", "VPMINSQ", "VPMINSW", "VPMINUB", "VPMINUD", "VPMINUQ", "VPMINUW", "VPMOVB2M", "VPMOVD2M", "VPMOVDB", "VPMOVDW", "VPMOVM2B", "VPMOVM2D", "VPMOVM2Q", "VPMOVM2W", "VPMOVMSKB", "VPMOVQ2M", "VPMOVQB", "VPMOVQD", "VPMOVQW", "VPMOVSDB", "VPMOVSDW", "VPMOVSQB", "VPMOVSQD", "VPMOVSQW", "VPMOVSWB", "VPMOVSXBD", "VPMOVSXBQ", "VPMOVSXBW", "VPMOVSXDQ", "VPMOVSXWD", "VPMOVSXWQ", "VPMOVUSDB", "VPMOVUSDW", "VPMOVUSQB", "VPMOVUSQD", "VPMOVUSQW", "VPMOVUSWB", "VPMOVW2M", "VPMOVWB", "VPMOVZXBD", "VPMOVZXBQ", "VPMOVZXBW", "VPMOVZXDQ", "VPMOVZXWD", "VPMOVZXWQ", "VPMULDQ", "VPMULHRSW", "VPMULHUW", "VPMULHW", "VPMULLD", "VPMULLQ", "VPMULLW", "VPMULUDQ", "VPOR", "VPORD", "VPORQ", "VPROLD", "VPROLQ", "VPROLVD", "VPROLVQ", "VPRORD", "VPRORQ", "VPRORVD", "VPRORVQ", "VPSADBW", "VPSHLDD", "VPSHLDQ", "VPSHLDVD", "VPSHLDVQ", "VPSHLDVW", "VPSHLDW", "VPSHRDD", "VPSHRDQ", "VPSHRDVD", "VPSHRDVQ", "VPSHRDVW", "VPSHRDW", "VPSHUFB", "VPSHUFD", "VPSHUFHW", "VPSHUFLW", "VPSIGNB", "VPSIGND", "VPSIGNW", "VPSLLD", "VPSLLDQ", "VPSLLQ", "VPSLLVD", "VPSLLVQ", "VPSLLVW", "VPSLLW", "VPSRAD", "VPSRAQ", "VPSRAVD", "VPSRAVQ", "VPSRAVW", "VPSRAW", "VPSRLD", "VPSRLDQ", "VPSRLQ", "VPSRLVD", "VPSRLVQ", "VPSRLVW", "VPSRLW", "VPSUBB", "VPSUBD", "VPSUBQ", "VPSUBSB", "VPSUBSW", "VPSUBUSB", "VPSUBUSW", "VPSUBW", "VPTERNLOGD", "VPTERNLOGQ", "VPTEST", "VPTESTMB", "VPTESTMD", "VPTESTMQ", "VPTESTMW", "VPTESTNMB", "VPTESTNMD", "VPTESTNMQ", "VPTESTNMW", "VPUNPCKHBW", "VPUNPCKHDQ", "VPUNPCKHQDQ", "VPUNPCKHWD", "VPUNPCKLBW", "VPUNPCKLDQ", "VPUNPCKLQDQ", "VPUNPCKLWD", "VPXOR", "VPXORD", "VPXORQ", "VSHUFF32X4", "VSHUFF64X2", "VSHUFI32X4", "VSHUFI64X2", "VZEROALL", "VZEROUPPER", "XOR",
      };

      if (safe_mnemonics.find(std::string(getMnemonic(MI))) == safe_mnemonics.end()) {
	// Add all input operands (explicit and implicit)
	for (const MachineOperand& MO : MI.operands())
	  if (MO.isReg() && MO.isUse())
	    Leaks.push_back(MO.getReg());
      }
      
    }

    bool runOnMachineFunction(MachineFunction& MF) override {
      if (!EnableProtectPass)
	return false;

      errs() << "Running Protect on " << MF.getName() << " (" << MF.getInstructionCount() << ")\n";

      if (auto *JTI = MF.getJumpTableInfo()) {
	for (const auto& JTE : JTI->getJumpTables()) {
	  errs() << "Jump table: "  << JTE.MBBs.size() << "\n";
	}
      }

      auto *TII = MF.getSubtarget().getInstrInfo();
      
      DFG dfg;

      Register LegalReg;

      // Add taint primitives
      {
      
	/// Add arguments as sources
	for (const auto& [Reg, _] : MF.front().liveins())
	  if ((LegalReg = legalizeRegister(Reg)) != X86::NoRegister)
	    dfg.add_source(DFGNode(&MF.front(), DFGNode::BEFORE, LegalReg));

	/// Add NCA loads as sources
	for (MachineBasicBlock& MBB : MF)
	  for (MachineInstr& MI : MBB)
	    if (MI.mayLoad() && isNCA(MI))
	      for (MachineOperand& MO : MI.operands())
		if (MO.isReg() && MO.isUse() && (LegalReg = legalizeRegister(MO.getReg())) != X86::NoRegister)
		  dfg.add_source(DFGNode(&MI, DFGNode::AFTER, LegalReg));

      }

      // Add transmitters
      {
	// True transmitters
	for (MachineBasicBlock& MBB : MF) {
	  for (MachineInstr& MI : MBB) {
	    SmallVector<Register> LeakedRegs;
	    getSensitiveOperands(MI, LeakedRegs);
	    for (Register Reg : LeakedRegs)
	      if ((LegalReg = legalizeRegister(Reg)) != X86::NoRegister)
		dfg.add_sink(DFGNode(&MI, DFGNode::BEFORE, LegalReg));
	  }
	}

	// Pseudo-transmitters (CA stores)
	for (MachineBasicBlock& MBB : MF)
	  for (MachineInstr& MI : MBB)
	    if (MI.mayStore() && !isNCA(MI))
	      for (const MachineOperand& MO : MI.operands())
		if (MO.isReg() && MO.isUse() && (LegalReg = legalizeRegister(MO.getReg())) != X86::NoRegister)
		  dfg.add_sink(DFGNode(&MI, DFGNode::BEFORE, LegalReg));
      }

      // Add inter-instruction data-flow edges
      {
	for (Register Reg : getAllRegisters()) {
	  for (MachineBasicBlock& MBB : MF) {
	    if (MBB.empty())
	      continue;
	    
	    // Intra-block edges
	    for (auto MBBI = MBB.begin(); std::next(MBBI) != MBB.end(); ++MBBI) {
	      dfg.add_edge(DFGNode(&*MBBI, DFGNode::AFTER, Reg),
			   DFGNode(&*std::next(MBBI), DFGNode::BEFORE, Reg));
	    }

	    // Entry-to-front edge
	    dfg.add_edge(DFGNode(&MBB, DFGNode::BEFORE, Reg),
			 DFGNode(&MBB.front(), DFGNode::BEFORE, Reg));

	    // Back-to-exit edge
	    dfg.add_edge(DFGNode(&MBB.back(), DFGNode::AFTER, Reg),
			 DFGNode(&MBB, DFGNode::AFTER, Reg));
	    
	    // Inter-block edges
	    for (MachineBasicBlock *SuccMBB : MBB.successors()) {
	      dfg.add_edge(DFGNode(&MBB, DFGNode::AFTER, Reg),
			   DFGNode(SuccMBB, DFGNode::BEFORE, Reg));
	    }
	  }
	}
      }

      // Add intra-instruction data-flow edges
      {
	for (MachineBasicBlock& MBB : MF) {
	  for (MachineInstr& MI : MBB) {
	    std::set<Register> Uses;
	    for (const MachineOperand& MO : MI.operands())
	      if (MO.isReg() && MO.isUse() && (LegalReg = legalizeRegister(MO.getReg())) != X86::NoRegister)
		Uses.insert(LegalReg);
	    
	    std::set<Register> Defs;
	    for (const MachineOperand& MO : MI.defs())
	      if (MO.isReg() && MO.isDef() && (LegalReg = legalizeRegister(MO.getReg())) != X86::NoRegister)
		Defs.insert(LegalReg);
	    
	    for (Register Def : getAllRegisters()) {
	      if (Defs.find(Def) != Defs.end()) {
		for (Register Use : Uses) {
		  dfg.add_edge(DFGNode(&MI, DFGNode::BEFORE, Use),
			       DFGNode(&MI, DFGNode::AFTER, Def));
		}
	      } else {
		dfg.add_edge(DFGNode(&MI, DFGNode::BEFORE, Def),
			     DFGNode(&MI, DFGNode::AFTER, Def));
	      }
	    }
	  }
	}
      }


      // Now, do min cut.
      std::set<DFGNode> cut_nodes;
      // dfg.prune();
      dfg.min_cut(cut_nodes);

      bool changed = false;

      for (const DFGNode& node : cut_nodes) {
	assert(node.isMI());
	MachineInstr& MI = node.getMI();
	MachineBasicBlock::iterator MBBI;
	switch (node.Pt) {
	case DFGNode::BEFORE:
	  MBBI = MI.getIterator();
	  break;
	case DFGNode::AFTER:
	  MBBI = std::next(MI.getIterator());
	  break;
	}
	BuildMI(*MI.getParent(), MBBI, DebugLoc(), TII->get(X86::PROTECT64rr), node.Reg)
	  .addReg(node.Reg);
	changed = true;
      }

      return changed;
    }
  };
  
}

  INITIALIZE_PASS(X86Protect, "x86-protect-pass", "X86 Protect Pass", false, false)

  namespace llvm {
    FunctionPass *createX86ProtectPass() { return new X86Protect(); }
  }
