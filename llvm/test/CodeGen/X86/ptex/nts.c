// RUN: clang -O1 %s -mllvm --x86-ptex -mllvm --x86-ptex-type=nst    -o %t.o -c && objdump -d --no-show-raw-insn --no-addresses -Mintel %t.o | FileCheck --check-prefixes=CHECK %s

#include "util.h"

// CHECK-LABEL: <test_direct_leak>:
// CHECK: {{^ *}} mov rdi,rdi
int test_direct_leak(long x) {
  leak(x);
}

// CHECK-LABEL: <test_add_leak>:
// CHECK-NOT: mov rdi,rdi
// CHECK: {{^ *}} inc rdi
int test_add_leak(long x) {
  leak(x + 1);
}
