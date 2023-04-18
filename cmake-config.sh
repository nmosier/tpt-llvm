#!/bin/bash

script_dir="$(realpath "$(dirname "${BASH_SOURCE[0]}")")"
build_dir="$(realpath .)"

if [[ "$(dirname "$build_dir")" != "$script_dir" ]]; then
    echo 'script should be run from build dir inside llvm, e.g., llvm/build' >&2
    exit 1
fi

flags='-fcf-protection=none'

cmake ../llvm \
      -DCMAKE_BUILD_TYPE=RelWithDebInfo \
      -DCMAKE_C_FLAGS="$flags" \
      -DCMAKE_CXX_FLAGS="$flags" \
      -DLLVM_ENABLE_PROJECTS="clang;lld" \
      -DLLVM_TARGETS_TO_BUILD="X86" \
      -DLLVM_ENABLE_ASSERTIONS=On \
      -DLLVM_USE_LINKER=lld

      

      
