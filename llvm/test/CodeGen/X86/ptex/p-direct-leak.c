// RUN: clang -O1 %s -mllvm --x86-ptex=ct  -o %t.o -c; objdump --disassemble=foo -Mintel %t.o | FileCheck %s
// RUN: clang -O1 %s -mllvm --x86-ptex=nst -o %t.o -c; objdump --disassemble=foo -Mintel %t.o | FileCheck %s

// CHECK-LABEL: <foo>:
// CHECK-NOT: {{ }}ss{{ }}
// CHECK: mov rdi,rdi
// CHECK-NOT: {{ }}ss{{ }}
// CHECK: mov rsi,rsi
// CHECK-NOT: {{ }}ss{{ }}
// CHECK: ss mov eax,DWORD PTR [rdi+rsi*4]
int foo(int A[], long p) {
  return A[p];
}
