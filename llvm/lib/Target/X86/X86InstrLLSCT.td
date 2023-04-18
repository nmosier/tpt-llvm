let Constraints = "$src = $dst", SchedRW = [WriteMove] in {
def PROTECT : RI<0x1f, MRM1r, (outs GR64:$dst), (ins GR64:$src), "protect{q}\t$dst",
                 [(set GR64:$dst, (int_x86_protect GR64:$src))]>, XS;
                   
}
