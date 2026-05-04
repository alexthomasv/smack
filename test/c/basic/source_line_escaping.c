#include "smack.h"
#include <assert.h>

// @expect verified
// @flag --provenance-syms
// @checkbpl grep '\\"quoted\\"'

volatile int n;

int main(void) {
  n = sizeof("quoted");
  assert(n > 0);
  return 0;
}
