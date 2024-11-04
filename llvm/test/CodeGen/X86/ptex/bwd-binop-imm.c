// RUN: clang -O1 %s -mllvm --x86-ptex -mllvm --x86-ptex-type=cts    -o %t.o -c && objdump -d --no-show-raw-insn --no-addresses -Mintel %t.o | FileCheck --check-prefixes=CHECK,CHECK-P %s
// RUN: clang -O1 %s -mllvm --x86-ptex -mllvm --x86-ptex-type=ct     -o %t.o -c && objdump -d --no-show-raw-insn --no-addresses -Mintel %t.o | FileCheck --check-prefixes=CHECK,CHECK-P %s
// RUN: clang -O1 %s -mllvm --x86-ptex -mllvm --x86-ptex-type=ctdecl -o %t.o -c && objdump -d --no-show-raw-insn --no-addresses -Mintel %t.o | FileCheck --check-prefixes=CHECK,CHECK-S %s

#define leak(x) bar((void *) (x))

extern void bar(void *);

// CHECK-LABEL: <test_add>:
// CHECK-DAG: {{^ *}} mov rdi,rdi
// CHECK: {{^ *}} add rdi,0x2
void test_add(long x) {
  leak(x + 2);
}

// CHECK-LABEL: <test_or>:
// CHECK-S-NOT: mov rsi,rsi
// CHECK-DAG: {{^ *}} mov rdi,rdi
// CHECK-P-DAG: {{^ *}} mov rsi,rsi
// CHECK: {{^ *}} or rsi,0x4
// CHECK: ss mov eax,DWORD PTR [rdi+rsi*1]
int test_or(int A[], long x) {
  return A[x | 1];
}
