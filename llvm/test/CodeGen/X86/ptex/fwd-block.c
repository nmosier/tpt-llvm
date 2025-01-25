// RUN: clang -O1 %s -mllvm --x86-ptex=sct    -o %t.o -c && objdump -d --no-show-raw-insn --no-addresses -Mintel %t.o | FileCheck %s
// RUN: clang -O1 %s -mllvm --x86-ptex=sni    -o %t.o -c && objdump -d --no-show-raw-insn --no-addresses -Mintel %t.o | FileCheck %s

#include "util.h"

long pred;
extern void do_something(void);

// CHECK-LABEL: <test1>:
// CHECK: {{^ *}} mov rdi,rdi
// CHECK: call
// CHECK: {{^ *}} inc rbx
// CHECK: ret
long test1(long x) {
  leak(x);
  return x + 1;
}

// CHECK-LABEL: <test2>:
// CHECK: xor eax,eax
// CHECK-NOT: mov eax,eax
// CHECK: ret
int test2(int *x) {
  int sum = 0;
  for (long i = 0; i < 128; ++i)
    sum += x[i];
  return sum;
}
