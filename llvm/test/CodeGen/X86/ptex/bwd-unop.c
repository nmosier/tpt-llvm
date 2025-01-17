// RUN: clang -O1 %s -mllvm --x86-ptex=ct  -o %t.o -c && objdump -d --no-show-raw-insn --no-addresses -Mintel %t.o | FileCheck %s
// RUN: clang -O1 %s -mllvm --x86-ptex=nst -o %t.o -c && objdump -d --no-show-raw-insn --no-addresses -Mintel %t.o | FileCheck %s

#include "util.h"

// CHECK-LABEL: <test_not>:
// CHECK: {{^ *}} mov rdi,rdi
// CHECK: {{^ *}} not rdi
void test_not(long x) {
  leak(~x);
}

// CHECK-LABEL: <test_neg>:
// CHECK: {{^ *}} mov rdi,rdi
// CHECK: {{^ *}} neg rdi
void test_neg(long x) {
  leak(-x);
}

// CHECK-LABEL: <test_copy>:
// CHECK: {{^ *}} mov rdi,rdi
// CHECK: {{^ *}} mov rax,rdi
void test_copy(long x) {
  asm volatile ("" ::: "rdi");
  leak(x);
}

// CHECK-LABEL: <test_lea>:
// CHECK: {{^ *}} mov rsi,rsi
// CHECK: {{^ *}} lea rdi,[rsi+0x64]
void test_lea(int _, long x) {
  leak(x + 0x64);
}

// CHECK-LABEL: <test_inc>:
// CHECK: {{^ *}} mov rdi,rdi
// CHECK: {{^ *}} inc rdi
void test_inc(long x) {
  leak(x + 1);
}

// CHECK-LABEL: <test_dec>:
// CHECK: {{^ *}} mov rdi,rdi
// CHECK: {{^ *}} dec rdi
void test_dec(long x) {
  leak(x - 1);
}
