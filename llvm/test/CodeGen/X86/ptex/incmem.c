// RUN: clang -O1 %s -mllvm --x86-ptex=nst -o %t.o -c && objdump -d --no-show-raw-insn --no-addresses -Mintel %t.o | FileCheck %s

// CHECK-LABEL: <test>:
// CHECK-NEXT: mov rdi,rdi
// CHECK-NEXT: ss inc DWORD PTR [rdi]
// CHECK-NEXT: ret
void test(int *p) {
  ++*p;
}
