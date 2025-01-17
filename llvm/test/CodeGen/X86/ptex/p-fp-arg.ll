; RUN: clang %s -mllvm --x86-ptex=ct  -o %t.o -c; objdump --disassemble=foo -Mintel %t.o | FileCheck %s
; RUN: clang %s -mllvm --x86-ptex=nst -o %t.o -c; objdump --disassemble=foo -Mintel %t.o | FileCheck %s
; CHECK-NOT: {{ }}ss{{ }}
; CHECK: fld

define x86_fp80 @foo(x86_fp80 %fp) {
  ret x86_fp80 %fp
}
