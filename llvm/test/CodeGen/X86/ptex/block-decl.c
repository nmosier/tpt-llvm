// RUN: clang -O1 %s -mllvm --x86-ptex -mllvm --x86-ptex-type=cts    -o %t.o -c && objdump -d --no-show-raw-insn --no-addresses -Mintel %t.o | FileCheck --check-prefixes=CHECK %s
// RUN: clang -O1 %s -mllvm --x86-ptex -mllvm --x86-ptex-type=ct     -o %t.o -c && objdump -d --no-show-raw-insn --no-addresses -Mintel %t.o | FileCheck --check-prefixes=CHECK %s
// RUN: clang -O1 %s -mllvm --x86-ptex -mllvm --x86-ptex-type=ctdecl -o %t.o -c && objdump -d --no-show-raw-insn --no-addresses -Mintel %t.o | FileCheck --check-prefixes=CHECK,CHECK-CTD %s

#include "util.h"
int pred;

// CHECK-LABEL: <test1>:
// CHECK-CTD: cmp
// CHECK-CTD: je
// CHECK-CTD: {{^ *}} mov rdi,rdi
void test1(long x) {
  if (pred) {
    leak(x);
  }
}

void test2(int x) {
  if (pred) {
    asm volatile ("" :: "r"(x));
    leak(x);
  }
}
