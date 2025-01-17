// RUN: clang -O1 %s -mllvm --x86-ptex=ct  -o %t.o -c && objdump -d --no-show-raw-insn --no-addresses -Mintel %t.o | FileCheck --check-prefixes=CHECK %s
// RUN: clang -O1 %s -mllvm --x86-ptex=nst -o %t.o -c && objdump -d --no-show-raw-insn --no-addresses -Mintel %t.o | FileCheck --check-prefixes=CHECK %s

#include "util.h"

void do_something(void);

// CHECK-LABEL: <test1>:
// CHECK: ss mov rbx,rdi
// CHECK: mov QWORD PTR [rsp+0x8],rbx
// CHECK: xor ebx,ebx
// CHECK: call
// CHECK: ss mov rbx,QWORD PTR [rsp+0x8]
// CHECK: ss mov rax,rbx
// CHECK: ret
long test1(long x) {
  do_something();
  return x;
}

// CHECK-LABEL: <test2>:
// CHECK: mov rdi,rdi
// CHECK: mov rbx,rdi
// CHECK: call
// CHECK: mov rax,rbx
// CHECK: ret
void *test2(void *p) {
  do_something();
  return p;
}
