// RUN: clang -O1 %s -mllvm --x86-ptex=sct -o %t.o -c && objdump -d --no-show-raw-insn --no-addresses -Mintel %t.o | FileCheck %s
// RUN: clang -O1 %s -mllvm --x86-ptex=sni -o %t.o -c && objdump -d --no-show-raw-insn --no-addresses -Mintel %t.o | FileCheck %s

void bar(void);
void baz(void);

// CHECK-LABEL: <foo>:
// CHECK: {{^ *}} lea rdx,[rip+0x0]
// CHECK: {{^ *}} movsxd rcx,DWORD PTR [rdx+rcx*4]
// CHECK: {{^ *}} add rcx,rdx
// CHECK: {{^ *}} jmp rcx
int foo(int x) {
  switch (x) {
  case 0:
    bar();
    return 1;
  case 1:
    baz();
    return 2;
  case 2:
    return 0;
  case 3:
    return 1;
  case 4:
    return 2;
  default:
    return 0;
  }
}
