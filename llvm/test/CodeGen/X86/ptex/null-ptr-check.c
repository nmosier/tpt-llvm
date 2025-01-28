// RUN: clang -O1 %s -mllvm --x86-ptex=sni -mllvm --x86-ptex-analyze-branches -o %t.o -c && objdump -d --no-show-raw-insn --no-addresses -Mintel %t.o | FileCheck --check-prefixes=CHECK,PUBLIC %s
// RUN: clang -O1 %s -mllvm --x86-ptex=sct -mllvm --x86-ptex-analyze-branches -o %t.o -c && objdump -d --no-show-raw-insn --no-addresses -Mintel %t.o | FileCheck --check-prefixes=CHECK,PUBLIC %s
// RUN: clang -O1 %s -mllvm --x86-ptex=sni                                    -o %t.o -c && objdump -d --no-show-raw-insn --no-addresses -Mintel %t.o | FileCheck --check-prefixes=CHECK,SECRET %s
// RUN: clang -O1 %s -mllvm --x86-ptex=sct                                    -o %t.o -c && objdump -d --no-show-raw-insn --no-addresses -Mintel %t.o | FileCheck --check-prefixes=CHECK,PUBLIC %s

#include "util.h"

// CHECK-LABEL: <foo>:
// PUBLIC-NEXT: {{^ *}} mov rdi,rdi
// PUBLIC-NEXT: test rdi,rdi
// SECRET-NEXT: test rdi,rdi
int foo(long p) {
  if (p) {
    return * (int *) p;
  } else {
    return 0;
  }
}
