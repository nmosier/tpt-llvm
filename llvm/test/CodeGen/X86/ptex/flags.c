// RUN: clang -O1 %s -mllvm --x86-ptex=ct                          -o %t.o -c && objdump -d --no-show-raw-insn --no-addresses -Mintel %t.o | FileCheck --check-prefixes=SHARED,NOFLAGS %s
// RUN: clang -O1 %s -mllvm --x86-ptex=nst                         -o %t.o -c && objdump -d --no-show-raw-insn --no-addresses -Mintel %t.o | FileCheck --check-prefixes=SHARED,NOFLAGS %s
// RUN: clang -O1 %s -mllvm --x86-ptex=ct  -mllvm --x86-ptex-flags -o %t.o -c && objdump -d --no-show-raw-insn --no-addresses -Mintel %t.o | FileCheck --check-prefixes=SHARED,FLAGS   %s
// RUN: clang -O1 %s -mllvm --x86-ptex=nst -mllvm --x86-ptex-flags -o %t.o -c && objdump -d --no-show-raw-insn --no-addresses -Mintel %t.o | FileCheck --check-prefixes=SHARED,FLAGS   %s

// SHARED-LABEL: <test_inc_64>:
// NOFLAGS: inc rcx
// FLAGS: add rcx,0x1
int test_inc_64(int A[], long n) {
  int sum = 0;
  for (int i = 0; i < n; ++i)
    sum += A[i];
  return sum;
}
