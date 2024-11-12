// RUN: clang -O1 %s -mllvm --x86-ptex -mllvm --x86-ptex-type=cts    -o %t.o -c && objdump -d --no-show-raw-insn --no-addresses -Mintel %t.o | FileCheck --check-prefixes=CHECK %s
// RUN: clang -O1 %s -mllvm --x86-ptex -mllvm --x86-ptex-type=ct     -o %t.o -c && objdump -d --no-show-raw-insn --no-addresses -Mintel %t.o | FileCheck --check-prefixes=CHECK %s
// RUN: clang -O1 %s -mllvm --x86-ptex -mllvm --x86-ptex-type=ctdecl -o %t.o -c && objdump -d --no-show-raw-insn --no-addresses -Mintel %t.o | FileCheck --check-prefixes=CHECK %s

#include "util.h"

int pred;

// CHECK-LABEL: <test_i32>:
// CHECK: {{^ *}} mov edi,edi
// CHECK: {{^ *}} movsxd rdi,edi
// CHECK: jmp
void test_i32(int x) {
  leak(x);
}
