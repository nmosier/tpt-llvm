// RUN: clang -O1 %s -mllvm --x86-ptex=sni -mllvm --x86-ptex-hoist -o %t.o -c && objdump -d --no-show-raw-insn --no-addresses -Mintel %t.o | FileCheck %s

#define leak(n) (* (char *) (n) = 0)

// CHECK-LABEL: <test>:
// CHECK: {{^ *}} lea rax,[rdi*8+0x0]
// CHECK-NEXT: {{^ *}} sub rax,rdi
// CHECK-NEXT: {{^ *}} add rax,0x7
long test(long n, long a) {
  if (a)
    leak(n);
  return (n + 1) * 7;
}
