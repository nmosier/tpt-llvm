// RUN: clang -O1 %s -mllvm --x86-ptex=sct -o %t.o -c && objdump -d --no-show-raw-insn --no-addresses -Mintel %t.o | FileCheck --check-prefixes=CHECK,CHECK-P %s
// RUN: clang -O1 %s -mllvm --x86-ptex=sni -o %t.o -c && objdump -d --no-show-raw-insn --no-addresses -Mintel %t.o | FileCheck --check-prefixes=CHECK,CHECK-S %s

#include "util.h"

// CHECK-LABEL: <test_lea_one>:
// CHECK-P: {{^ *}} mov rsi,rsi
// CHECK-S-NOT: mov rsi,rsi
// CHECK: {{^ *}} lea rdi,[rsi*8+0x0]
void test_lea_one(int _, long x) {
  leak(x * 8);
}

// CHECK-LABEL: <test_lea_two>:
// CHECK-S-NOT: mov rdi,rdi
// CHECK-S-NOT: mov rsi,rsi
// CHECK-P-DAG: {{^ *}} mov rdi,rdi
// CHECK-P-DAG: {{^ *}} mov rsi,rsi
// CHECK: {{^ *}} lea rdi,[rdi+rsi*8]
void test_lea_two(long x, long y) {
  leak(x + y * 8);
}

// CHECK-LABEL: <test_lea_two_decl>:
// CHECK-DAG: {{^ *}} mov rdi,rdi
// CHECK-DAG: {{^ *}} mov rsi,rsi
// CHECK: {{^ *}} lea rdi,[r14+rbx*8]
void test_lea_two_decl(long x, long y) {
  leak(y);
  leak(x + y * 8);
}
