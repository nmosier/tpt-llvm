// RUN: clang -O1 %s -mllvm --x86-ptex=sct -o %t.o -c && objdump -d --no-show-raw-insn --no-addresses -Mintel %t.o | FileCheck --check-prefixes=CHECK %s
// RUN: clang -O1 %s -mllvm --x86-ptex=sni -o %t.o -c && objdump -d --no-show-raw-insn --no-addresses -Mintel %t.o | FileCheck --check-prefixes=CHECK %s

#include "util.h"

// CHECK-LABEL: <test_i32>:
// CHECK: {{^ *}} mov edi,edi
// CHECK: {{^ *}} movsxd rdi,edi
// CHECK: jmp
void test_i32(int x) {
  leak(x);
}
