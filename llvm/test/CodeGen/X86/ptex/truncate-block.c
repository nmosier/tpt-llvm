// RUN: clang -O1 %s -mllvm --x86-ptex=sni    -o %t.o -c && objdump -d --no-show-raw-insn --no-addresses -Mintel %t.o | FileCheck %s
// RUN: clang -O1 %s -mllvm --x86-ptex=sct    -o %t.o -c && objdump -d --no-show-raw-insn --no-addresses -Mintel %t.o | FileCheck %s

// CHECK-LABEL: <foo>:
// CHECK-NOT: mov edi,edi
void foo(int *dst, unsigned a) {
  if (a)
    return;
  if ((unsigned) (unsigned long) dst + a)
    *dst = 0;
}
