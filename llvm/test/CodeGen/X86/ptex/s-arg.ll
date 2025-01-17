; RUN: clang %s -mllvm --x86-ptex=ct  -o %t.o -c; objdump --disassemble=foo -Mintel %t.o | FileCheck %s
; RUN: clang %s -mllvm --x86-ptex=nst -o %t.o -c; objdump --disassemble=foo -Mintel %t.o | FileCheck %s

; CHECK-LABEL: <foo>:
; CHECK: ss mov rax,rdi
define i64 @foo(i64 %n) {
  ret i64 %n
}
