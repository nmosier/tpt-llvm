// RUN: clang -O1 %s -mllvm --x86-ptex=nst -mllvm --x86-ptex-reload -o %t.o -c && objdump -d --no-show-raw-insn --no-addresses -Mintel %t.o | FileCheck %s

// CHECK-LABEL: <test>:
// CHECK: js
// CHECK-NEXT: {{^ *}} mov rax,rax
// CHECK-NEXT: {{^ *}} mov rsi,rsi
// CHECK-NEXT: {{^ *}} mov rax,QWORD PTR [rdi]
void test(long *p, int A[]) {
  const long x = *p;
  if (x >= 0)
    A[x] = 0;
}
