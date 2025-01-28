// RUN: clang -O1 %s -mllvm --x86-ptex=sni -o %t.o -c && objdump -d --no-show-raw-insn --no-addresses -Mintel %t.o | FileCheck %s

// CHECK-LABEL: <foo>:
// CHECK-NEXT: {{^ *}} xor ecx,ecx
// CHECK-NEXT: ss cmp DWORD PTR [rsp+0x8],0x3
int foo(int, int, int, int, int, int, int x) {
  if (x > 2) {
    return 42;
  } else {
    return 0;
  }
}
