// RUN: clang -O1 %s -mllvm --x86-ptex -mllvm --x86-ptex-type=cts -o %t.o -c; objdump --disassemble=foo -Mintel %t.o | FileCheck %s
// RUN: clang -O1 %s -mllvm --x86-ptex -mllvm --x86-ptex-type=ct -o %t.o -c; objdump --disassemble=foo -Mintel %t.o | FileCheck %s
// RUN: clang -O1 %s -mllvm --x86-ptex -mllvm --x86-ptex-type=ctd -o %t.o -c; objdump --disassemble=foo -Mintel %t.o | FileCheck %s
// CHECK-NOT: {{ }}ss{{ }}
// CHECK: mov rdi,rdi
// CHECK-NOT: {{ }}ss{{ }}
// CHECK: mov rsi,rsi
// CHECK-NOT: {{ }}ss{{ }}
// CHECK: ss mov eax,DWORD PTR [rdi+rsi*4]

int foo(int A[], long p) {
  return A[p];
}
