; RUN: llc -O1 %s --x86-ptex --x86-ptex-type=cts -o %t.o -filetype=obj && objdump -d --no-show-raw-insn --no-addresses -Mintel %t.o | FileCheck %s

; CHECK-LABEL: <S_reghop4>:
; CHECK-NOT: mov rax,rax
; CHECK: {{^ *}} ret
define internal fastcc ptr @S_reghop4(ptr %s, i64 %off, ptr %llim, ptr %rlim) unnamed_addr #0 {
entry:
  %cmp = icmp sgt i64 %off, -1
  br i1 %cmp, label %while.body, label %while.cond2.preheader

while.cond2.preheader:                            ; preds = %entry
  br label %if.end25

while.body:                                       ; preds = %while.body, %entry
  br i1 poison, label %while.body, label %if.end25

if.end25:                                         ; preds = %while.body, %while.cond2.preheader
  ret ptr poison
}
