// RUN: clang -O1 %s -mllvm --x86-ptex -mllvm --x86-ptex-type=cts    -o %t.o -c && objdump -d --no-show-raw-insn --no-addresses -Mintel %t.o | FileCheck --check-prefixes=CHECK,CHECK-P %s
// RUN: clang -O1 %s -mllvm --x86-ptex -mllvm --x86-ptex-type=ct     -o %t.o -c && objdump -d --no-show-raw-insn --no-addresses -Mintel %t.o | FileCheck --check-prefixes=CHECK,CHECK-P %s
// RUN: clang -O1 %s -mllvm --x86-ptex -mllvm --x86-ptex-type=ctdecl -o %t.o -c && objdump -d --no-show-raw-insn --no-addresses -Mintel %t.o | FileCheck --check-prefixes=CHECK,CHECK-S %s

// CHECK-LABEL: <test_or>:
// CHECK-S-NOT: mov rsi,rsi
// CHECK-S-NOT: mov rdx,rdx
// CHECK-DAG: {{^ *}} mov rdi,rdi
// CHECK-P-DAG: {{^ *}} mov rsi,rsi
// CHECK-P-DAG: {{^ *}} mov rdx,rdx
// CHECK: {{^ *}} or rsi,rdx
// CHECK: ss mov eax,DWORD PTR [rdi+rsi*4]
int test_or(int A[], long x, long y) {
  return A[x | y];
}

// CHECK-LABEL: <test_and>:
// CHECK-S-NOT: mov rsi,rsi
// CHECK-S-NOT: mov rdx,rdx
// CHECK-DAG: {{^ *}} mov rdi,rdi
// CHECK-P-DAG: {{^ *}} mov rsi,rsi
// CHECK-P-DAG: {{^ *}} mov rdx,rdx
// CHECK: {{^ *}} and rsi,rdx
// CHECK: ss mov eax,DWORD PTR [rdi+rsi*4]
int test_and(int A[], long x, long y) {
  return A[x & y];
}

// CHECK-LABEL: <test_shl>:
// CHECK-S-NOT: mov rsi,rsi
// CHECK-S-NOT: mov rdx,rdx
// CHECK-DAG: {{^ *}} mov rdi,rdi
// CHECK-P-DAG: {{^ *}} mov rsi,rsi
// CHECK-P-DAG: {{^ *}} mov rdx,rdx
// CHECK: {{^ *}} shl rsi,cl
// CHECK: ss mov eax,DWORD PTR [rdi+rsi*4]
int test_shl(int A[], long x, long y) {
  return A[x << y];
}

// CHECK-LABEL: <test_shr>:
// CHECK-S-NOT: mov rsi,rsi
// CHECK-S-NOT: mov rdx,rdx
// CHECK-DAG: {{^ *}} mov rdi,rdi
// CHECK-P-DAG: {{^ *}} mov rsi,rsi
// CHECK-P-DAG: {{^ *}} mov rdx,rdx
// CHECK: {{^ *}} shr rsi,cl
// CHECK: ss mov eax,DWORD PTR [rdi+rsi*4]
int test_shr(int A[], unsigned long x, long y) {
  return A[x >> y];
}

// CHECK-LABEL: <test_mul>:
// CHECK-S-NOT: mov rsi,rsi
// CHECK-S-NOT: mov rdx,rdx
// CHECK-DAG: {{^ *}} mov rdi,rdi
// CHECK-P-DAG: {{^ *}} mov rsi,rsi
// CHECK-P-DAG: {{^ *}} mov rdx,rdx
// CHECK: {{^ *}} imul rsi,rdx
// CHECK: ss mov eax,DWORD PTR [rdi+rsi*4]
int test_mul(int A[], long x, long y) {
  return A[x * y];
}

// CHECK-LABEL: <test_xor>:
// CHECK-S-NOT: mov rsi,rsi
// CHECK-S-NOT: mov rdx,rdx
// CHECK-DAG: {{^ *}} mov rdi,rdi
// CHECK-P-DAG: {{^ *}} mov rsi,rsi
// CHECK-P-DAG: {{^ *}} mov rdx,rdx
// CHECK: {{^ *}} xor rsi,rdx
// CHECK: ss mov eax,DWORD PTR [rdi+rsi*4]
int test_xor(int A[], long x, long y) {
  return A[x ^ y];
}

// CHECK-LABEL: <test_add>:
// CHECK-S-NOT: mov rsi,rsi
// CHECK-S-NOT: mov rdx,rdx
// CHECK-DAG: {{^ *}} mov rdi,rdi
// CHECK-P-DAG: {{^ *}} mov rsi,rsi
// CHECK-P-DAG: {{^ *}} mov rdx,rdx
// CHECK: {{^ *}} add rsi,rdx
// CHECK: ss mov eax,DWORD PTR [rdi+rsi*4]
int test_add(int A[], long x, long y) {
  return A[x + y];
}

// CHECK-LABEL: <test_sub>:
// CHECK-S-NOT: mov rsi,rsi
// CHECK-S-NOT: mov rdx,rdx
// CHECK-DAG: {{^ *}} mov rdi,rdi
// CHECK-P-DAG: {{^ *}} mov rsi,rsi
// CHECK-P-DAG: {{^ *}} mov rdx,rdx
// CHECK: {{^ *}} sub rsi,rdx
// CHECK: ss mov eax,DWORD PTR [rdi+rsi*4]
int test_sub(int A[], long x, long y) {
  return A[x - y];
}
