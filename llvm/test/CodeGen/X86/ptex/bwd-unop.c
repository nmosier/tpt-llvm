// RUN: clang -O1 %s -mllvm --x86-ptex -mllvm --x86-ptex-type=ctdecl -o %t.o -c && objdump -d --no-show-raw-insn --no-addresses -Mintel %t.o | FileCheck %s
// RUN: clang -O1 %s -mllvm --x86-ptex -mllvm --x86-ptex-type=cts    -o %t.o -c && objdump -d --no-show-raw-insn --no-addresses -Mintel %t.o | FileCheck %s
// RUN: clang -O1 %s -mllvm --x86-ptex -mllvm --x86-ptex-type=ct     -o %t.o -c && objdump -d --no-show-raw-insn --no-addresses -Mintel %t.o | FileCheck %s

#include "util.h"

// CHECK-LABEL: <test_not>:
// CHECK-DAG: {{^ *}} mov rdi,rdi
// CHECK-DAG: {{^ *}} mov rsi,rsi
// CHECK: {{^ *}} not rsi
// CHECK: ss mov eax,DWORD PTR [rdi+rsi*4]
int test_not(int A[], long x) {
  return A[~x];
}

// CHECK-LABEL: <test_neg>:
// CHECK-DAG: {{^ *}} mov rdi,rdi
// CHECK: {{^ *}} neg rdi
// CHECK: ss mov eax,DWORD PTR [rdi]
int test_neg(long p) {
  return * (const int *) -p;
}

// CHECK-LABEL: <test_copy>:
// CHECK-DAG: {{^ *}} mov rdi,rdi
// CHECK-DAG: {{^ *}} mov rsi,rsi
// CHECK: {{^ *}} mov rax,rsi
// CHECK: ss mov eax,DWORD PTR [rdi+rax*4]
int test_copy(int A[], long x) {
  asm volatile ("" ::: "rsi");
  return A[x];
}

// CHECK-LABEL: <test_lea>:
// CHECK: {{^ *}} mov rsi,rsi
// CHECK: {{^ *}} lea rdi,[rsi*8+0x0]
void test_lea(int, long x) {
  leak(x * 8);
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
