// RUN: clang -O1 %s -mllvm --x86-ptex=sni -mllvm --x86-ptex-analyze-branches -o %t.o -c && objdump -d --no-show-raw-insn --no-addresses -Mintel %t.o | FileCheck %s

// CHECK-LABEL: <test>:
// CHECK: {{^ *}} dec edi
// CHECK-NEXT: jne
void test(int n) {
  for (int i = 0; i < n; ++i) {
    volatile int x = 0;
  }
}
