// RUN: clang -O1 %s -mllvm --x86-ptex=nst -o %t.o -c && objdump -d --no-show-raw-insn --no-addresses -Mintel %t.o | FileCheck --check-prefixes=CHECK %s

#include "util.h"

#define TEST(name, T)                        \
  void name(T x, T y) {                      \
    leak(x);                                 \
    leak(x * y);                             \
  }

// CHECK-LABEL: <mul_signed_32>:
// CHECK-DAG: {{^ *}} mov esi,esi
// CHECK-DAG: {{^ *}} mov edi,edi
// CHECK: imul
TEST(mul_signed_32, int);

// CHECK-LABEL: <mul_signed_64>:
// CHECK-DAG: {{^ *}} mov rsi,rsi
// CHECK-DAG: {{^ *}} mov rdi,rdi
// CHECK: imul
TEST(mul_signed_64, long);

// CHECK-LABEL: <mul_unsigned_32>:
// CHECK-NOT: mov esi,esi
// CHECK: mul
TEST(mul_unsigned_32, unsigned);

// CHECK-LABEL: <mul_unsigned_64>:
// CHECK-NOT: mov rsi,rsi
// CHECK: mul
TEST(mul_unsigned_64, unsigned long);
