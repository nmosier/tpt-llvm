; RUN: clang %s -mllvm --x86-ptex=ct  -o %t.o -c; objdump -d -Mintel --no-show-raw-insn --no-addresses %t.o | FileCheck %s
; RUN: clang %s -mllvm --x86-ptex=nst -o %t.o -c; objdump -d -Mintel --no-show-raw-insn --no-addresses %t.o | FileCheck %s

; CHECK-LABEL: <foo>:
; CHECK: {{^ *}} mov rdi,rdi
; CHECK: ret
define ptr @foo(ptr %p) {
  ret ptr %p
}
