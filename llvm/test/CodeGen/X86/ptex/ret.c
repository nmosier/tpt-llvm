// RUN: clang -O1 %s -mllvm --x86-ptex=sni -o %t.o -c && objdump -d --no-show-raw-insn --no-addresses -Mintel %t.o | FileCheck %s

int bar(void);

// CHECK-LABEL: <foo>:
// CHECK-NEXT: push rax
// CHECK-NEXT: call
// CHECK-NEXT: ss inc eax
// CHECK-NEXT: pop rcx
// CHECK-NEXT: ret
int foo(void) {
  return bar() + 1;
}
