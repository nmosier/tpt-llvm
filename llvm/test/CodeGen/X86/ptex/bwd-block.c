// RUN: clang -O1 %s -mllvm --x86-ptex=sct  -o %t.o -c && objdump -d --no-show-raw-insn --no-addresses -Mintel %t.o | FileCheck --check-prefixes=CHECK,CHECK-S %s
// RUN: clang -O1 %s -mllvm --x86-ptex=sni -o %t.o -c && objdump -d --no-show-raw-insn --no-addresses -Mintel %t.o | FileCheck --check-prefixes=CHECK,CHECK-S %s

#include "util.h"

long pred;
extern void do_something(void);
extern void do_something_else(void);

// CHECK-LABEL: <test_leak_any_path>:
// CHECK-S-NOT: mov rdi,rdi
// CHECK: cmp
void test_leak_any_path(long x) {
  if (pred)
    leak(x);
}

// CHECK-LABEL: <test_leak_all_paths_post_if>:
// CHECK: {{^ *}} mov rdi,rdi
// CHECK: cmp
void test_leak_all_paths_post_if(long x) {
  if (pred)
    do_something();
  leak(x);
}

// CHECK-LABEL: <test_leak_all_paths_in_if>:
// CHECK: {{^ *}} mov rdi,rdi
// CHECK: cmp
void test_leak_all_paths_in_if(long x) {
  if (pred) {
    leak(x);
  } else {
    leak2(x);
  }
}

// CHECK-LABEL: <test_leak_any_path_switch>:
// CHECK-NOT-S: mov rdi,rdi
// CHECK: jmp rax
int test_leak_any_path_switch(long x) {
  switch (pred) {
  case 1:
    leak(x);
    break;
  case 2:
    do_something();
    break;
  case 3:
    do_something_else();
    break;
  case 4:
    x = x + 1;
  default:
    break;
  }
  return x;
}

// CHECK-LABEL: <test_leak_all_paths_switch>:
// CHECK: mov rdi,rdi
// CHECK: jmp rax
void test_leak_all_paths_switch(long x) {
  switch (pred) {
  case 1:
    leak(x);
    break;
  case 2:
    leak2(x);
    break;
  case 3:
    leak(x);
    break;
  case 4:
    do_something();
    leak(x);
    break;
  default:
    leak2(x);
    break;
  }
}
