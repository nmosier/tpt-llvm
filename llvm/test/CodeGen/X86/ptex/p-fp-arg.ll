; RUN: clang %s -mllvm --x86-ptex -mllvm --x86-ptex-type=cts -o %t.o -c; objdump --disassemble=foo -Mintel %t.o | FileCheck %s
; RUN: clang %s -mllvm --x86-ptex -mllvm --x86-ptex-type=ct -o %t.o -c; objdump --disassemble=foo -Mintel %t.o | FileCheck %s
; RUN: clang %s -mllvm --x86-ptex -mllvm --x86-ptex-type=ctd -o %t.o -c; objdump --disassemble=foo -Mintel %t.o | FileCheck %s
; CHECK-NOT: {{ }}ss{{ }}
; CHECK: fld

define x86_fp80 @foo(x86_fp80 %fp) {
  ret x86_fp80 %fp
}
