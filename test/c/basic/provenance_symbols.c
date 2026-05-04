#include "smack.h"
#include <assert.h>

// @expect verified
// @flag --provenance-syms
// @checkbpl grep '{:llvm.func "main"}'
// @checkbpl grep '{:llvm.inst "main:'
// @checkbpl grep '{:llvm.op "store"}'

volatile int g;

int main(void) {
  g = 1;
  assert(g == 1);
  return 0;
}
