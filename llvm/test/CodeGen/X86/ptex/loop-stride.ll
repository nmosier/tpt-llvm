; RUN: clang -O1 %s -mllvm --x86-ptex=ct  -mllvm --x86-ptex-sink -o %t.o -c; objdump -d -Mintel --no-show-raw-insn --no-addresses %t.o | FileCheck %s
; RUN: clang -O1 %s -mllvm --x86-ptex=nst -mllvm --x86-ptex-sink -o %t.o -c; objdump -d -Mintel --no-show-raw-insn --no-addresses %t.o | FileCheck %s

; CHECK-LABEL: <test_stride_leak>:
; CHECK-DAG: {{^ *}} mov rsi,rsi
; CHECK-DAG: {{^ *}} mov rdx,rdx
; CHECK: ret
define void @test_stride_leak(i32 %n, ptr %p, i64 %stride) {
entry:
  br label %loop

loop:
  %i = phi i32 [ %n, %entry ], [ %inext, %loop ]
  %ptr = phi ptr [ %p, %entry ], [ %pnext, %loop ]
  %pnext = getelementptr i8, ptr %ptr, i64 %stride
  store i8 0, ptr %pnext
  %inext = add i32 %i, 1
  %done = icmp eq i32 %inext, 0
  br i1 %done, label %exit, label %loop

exit:
  ret void
}

; CHECK-LABEL: <test_leak_stride>:
; CHECK-DAG: {{^ *}} mov rsi,rsi
; CHECK-DAG: {{^ *}} mov rdx,rdx
; CHECK: ret
define void @test_leak_stride(i32 %n, ptr %p, i64 %stride) {
entry:
  br label %loop

loop:
  %i = phi i32 [ %n, %entry ], [ %inext, %loop ]
  %ptr = phi ptr [ %p, %entry ], [ %pnext, %loop ]
  store i8 0, ptr %ptr
  %pnext = getelementptr i8, ptr %ptr, i64 %stride
  %inext = add i32 %i, 1
  %done = icmp eq i32 %inext, 0
  br i1 %done, label %exit, label %loop

exit:
  ret void
}
