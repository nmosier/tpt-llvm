; RUN: clang %s -mllvm --x86-ptex=ct  -o %t.o -c; objdump -d -Mintel --no-show-raw-insn --no-addresses %t.o | FileCheck %s
; RUN: clang %s -mllvm --x86-ptex=nst -o %t.o -c; objdump -d -Mintel --no-show-raw-insn --no-addresses %t.o | FileCheck %s

declare void @leak(ptr %x)

; CHECK-LABEL: <test_zeroext>:
; CHECK: {{^ *}} mov dil,dil
define void @test_zeroext(i8 %x) {
  %y = zext i8 %x to i64
  %z = inttoptr i64 %y to ptr
  %rv = tail call i32(ptr) @leak(ptr %z)
  ret void
}

; CHECK-LABEL: <test_signext>:
; CHECK: {{^ *}} mov dil,dil
define void @test_signext(i8 %x) {
  %y = sext i8 %x to i64
  %z = inttoptr i64 %y to ptr
  %rv = tail call i32(ptr) @leak(ptr %z)
  ret void
}
