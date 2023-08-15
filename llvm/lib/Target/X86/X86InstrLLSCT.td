def SDTX86Protect : SDTypeProfile<1, 1, []>;

// def int_x86_protect : SDNode<"X86ISD::PROTECT", SDTX86Protect>;
// def X86protect : SDNode<"X86ISD::PROTECT", SDTX86Protect>;

let SchedRW = [WriteMove], isCodeGenOnly = 1 in {
// let isMoveReg = 1 in {

def PROTECT8rr  : I<0x88, MRMDestReg, (outs GR8 :$dst), (ins GR8 :$src),
                "mov{b}\t{$src, $dst|$dst, $src}", [(set GR8:$dst, (int_x86_protect GR8:$src))]>, NOSPEC;
def PROTECT16rr : I<0x89, MRMDestReg, (outs GR16:$dst), (ins GR16:$src),
                "mov{w}\t{$src, $dst|$dst, $src}", [(set GR16:$dst, (int_x86_protect GR16:$src))]>, OpSize16, NOSPEC;
def PROTECT32rr : I<0x89, MRMDestReg, (outs GR32:$dst), (ins GR32:$src),
                "mov{l}\t{$src, $dst|$dst, $src}", [(set GR32:$dst, (int_x86_protect GR32:$src))]>, OpSize32, NOSPEC;
def PROTECT64rr : RI<0x89, MRMDestReg, (outs GR64:$dst), (ins GR64:$src),
                 "mov{q}\t{$src, $dst|$dst, $src}", [(set GR64:$dst, (int_x86_protect GR64:$src))]>, NOSPEC;

// }
}

// // let Constraints = "$src = $dst", SchedRW = [WriteMove] in {
// let SchedRW = [WriteMove] in {
// let hasSideEffects = 0, isMoveReg = 1 in {
// 
// def PROTECT8r: I<0x88, MRMDestReg, (outs GR8:$dst), (ins GR8:$src), "protect{b}\t$dst, $src", []>;
// def PROTECT16r: I<0x89, MRMDestReg, (outs GR16:$dst), (ins GR16:$src), "protect{w}\t$dst", []>;
// def PROTECT32r: I<0x89, MRMDestReg, (outs GR32:$dst), (ins GR32:$src), "protect{d}\t$dst", []>;
// def PROTECT64r: RI<0x89, MRMDestReg, (outs GR64:$dst), (ins GR64:$src), "protect{q}\t$dst", []>;
// 
// /*
// def PROTECT64r : RI<0x1f, MRM1r, (outs GR64:$dst), (ins GR64:$src), "protect{q}\t$dst",
//                   [(set GR64:$dst, (int_x86_protect GR64:$src))]>, XS;
//   */                 
// }
// }
