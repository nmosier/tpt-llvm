; RUN: clang %s -mllvm --x86-ptex -mllvm --x86-ptex-type=cts -o %t.o -c; objdump --disassemble=foo -Mintel %t.o | FileCheck %s
; RUN: clang %s -mllvm --x86-ptex -mllvm --x86-ptex-type=ct -o %t.o -c; objdump --disassemble=foo -Mintel %t.o | FileCheck %s
; RUN: clang %s -mllvm --x86-ptex -mllvm --x86-ptex-type=ctd -o %t.o -c; objdump --disassemble=foo -Mintel %t.o | FileCheck %s
; CHECK: ss mov rax,rdi

define i64 @foo(i64 %n) {
  ret i64 %n
}
