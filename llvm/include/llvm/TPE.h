#pragma once

#include <llvm/Support/CommandLine.h>

namespace tpe {

#warning Should eliminate this
  bool allowDeclassify();

  enum PrivacyPolicy {
    PrivacyPolicyNone,
    sandbox,
    ct,
    ctdecl,
  };

  extern llvm::cl::opt<PrivacyPolicy> PrivacyPolicyOpt;
  
}
