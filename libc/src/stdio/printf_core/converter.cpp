//===-- Format specifier converter implmentation for printf -----*- C++ -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#include "src/stdio/printf_core/converter.h"

#include "src/stdio/printf_core/core_structs.h"
#include "src/stdio/printf_core/writer.h"

// This option allows for replacing all of the conversion functions with custom
// replacements. This allows conversions to be replaced at compile time.
#ifndef LLVM_LIBC_PRINTF_CONV_ATLAS
#include "src/stdio/printf_core/converter_atlas.h"
#else
#include LLVM_LIBC_PRINTF_CONV_ATLAS
#endif

#include <stddef.h>

namespace __llvm_libc {
namespace printf_core {

int convert(Writer *writer, const FormatSection &to_conv) {
  if (!to_conv.has_conv)
    return writer->write(to_conv.raw_string);

  switch (to_conv.conv_name) {
  case '%':
    return writer->write("%");
  case 'c':
    return convert_char(writer, to_conv);
  case 's':
    return convert_string(writer, to_conv);
  case 'd':
  case 'i':
  case 'u':
  case 'o':
  case 'x':
  case 'X':
    return convert_int(writer, to_conv);
#ifndef LLVM_LIBC_PRINTF_DISABLE_FLOAT
  case 'f':
  case 'F':
  case 'g':
  case 'G':
    return convert_float_decimal(writer, to_conv);
  case 'e':
  case 'E':
    return convert_float_dec_exp(writer, to_conv);
  case 'a':
  case 'A':
    return convert_float_hex_exp(writer, to_conv);
    // case 'g':
    // case 'G':
    // return convert_float_mixed(writer, to_conv);
#endif // LLVM_LIBC_PRINTF_DISABLE_FLOAT
#ifndef LLVM_LIBC_PRINTF_DISABLE_WRITE_INT
  case 'n':
    return convert_write_int(writer, to_conv);
#endif // LLVM_LIBC_PRINTF_DISABLE_WRITE_INT
  case 'p':
    return convert_pointer(writer, to_conv);
  default:
    return writer->write(to_conv.raw_string);
  }
  return -1;
}

} // namespace printf_core
} // namespace __llvm_libc
