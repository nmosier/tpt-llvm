// RUN: clang -O1 %s -mllvm --x86-ptex=sct -o %t.o -c && objdump -d --no-show-raw-insn --no-addresses -Mintel %t.o | FileCheck --check-prefixes=CHECK,CHECK-P %s
// RUN: clang -O1 %s -mllvm --x86-ptex=sni -o %t.o -c && objdump -d --no-show-raw-insn --no-addresses -Mintel %t.o | FileCheck --check-prefixes=CHECK,CHECK-S %s

#define leak(x) bar((void *) (x))

extern void bar(void *);

// CHECK-LABEL: <test_add>:
// CHECK-DAG: mov rdi,rdi
// CHECK-DAG: mov rsi,rsi
// CHECK: add r14,rbx
void test_add(long x, long y) {
  leak(y);
  leak(x + y);
}

// CHECK-LABEL: <test_or>:
// CHECK-S-NOT: mov rdi,rdi
// CHECK-P-DAG: mov rdi,rdi
// CHECK-DAG: mov rsi,rsi
// CHECK: or r14,rbx
void test_or(long x, long y) {
  leak(y);
  leak(x | y);
}
