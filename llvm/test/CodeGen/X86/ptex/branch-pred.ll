; RUN: llc %s --x86-ptex=sni --filetype=obj -o %t.o; objdump -d -Mintel --no-show-raw-insn --no-addresses %t.o | FileCheck --check-prefixes=ALL,NST %s
; RUN: llc %s --x86-ptex=sct --filetype=obj -o %t.o; objdump -d -Mintel --no-show-raw-insn --no-addresses %t.o | FileCheck --check-prefixes=ALL,CT  %s

; ALL-LABEL: <foo>:
; NST-NOT: {{^ *}} inc
; CT: {{^ *}} inc
; ALL: ret
define void @foo(i32 %n, ptr %p, i64 %stride) {
entry:
  br label %loop

loop:
  %i = phi i32 [ %n, %entry ], [ %inext, %loop ]
  %ptr = phi ptr [ %p, %entry ], [ %pnext, %loop ]
  %pnext = getelementptr i8, ptr %ptr, i64 %stride
  %inext = add i32 %i, 1
  %done = icmp eq i32 %inext, 0
  br i1 %done, label %exit, label %loop

exit:
  ret void
}
