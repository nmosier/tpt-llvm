// RUN: clang -O1 %s -mllvm --x86-ptex=sni -mllvm --x86-ptex-analyze-branches -o %t.o -c && objdump -d --no-show-raw-insn --no-addresses -Mintel %t.o | FileCheck --check-prefixes=CHECK,PUBLIC %s
// RUN: clang -O1 %s -mllvm --x86-ptex=sct -mllvm --x86-ptex-analyze-branches -o %t.o -c && objdump -d --no-show-raw-insn --no-addresses -Mintel %t.o | FileCheck --check-prefixes=CHECK,PUBLIC %s
// RUN: clang -O1 %s -mllvm --x86-ptex=sni                                    -o %t.o -c && objdump -d --no-show-raw-insn --no-addresses -Mintel %t.o | FileCheck --check-prefixes=CHECK,SECRET %s
// RUN: clang -O1 %s -mllvm --x86-ptex=sct                                    -o %t.o -c && objdump -d --no-show-raw-insn --no-addresses -Mintel %t.o | FileCheck --check-prefixes=CHECK,PUBLIC %s

#include "util.h"

// CHECK-LABEL: <test_ne_long>:
// PUBLIC-NEXT: {{^ *}} mov rsi,rsi
// SECRET-NEXT: test rsi,rsi
void test_ne_long(volatile int A[], long n) {
  for (long i = 0; i != n; ++i)
    A[i] = 0;
}

// CHECK-LABEL: <test_ne_int>:
// PUBLIC-NEXT: {{^ *}} mov esi,esi
// SECRET-NEXT: test esi,esi
void test_ne_int(volatile int A[], int n) {
  for (int i = 0; i != n; ++i)
    A[i] = 0;
}
