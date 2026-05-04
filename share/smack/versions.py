"""Source-tree fallback for SMACK tool versions.

CMake installs ``bin/versions`` as this module. Keeping the same constants in
the source tree lets ``bin/smack`` run directly in tests before installation.
"""

Z3_VERSION = "4.16.0"
Z3_GLIBC_VERSION = "2.39"
CVC4_VERSION = "1.8"
YICES2_VERSION = "2.6.2"
BOOGIE_VERSION = "3.5.6"
CORRAL_VERSION = "1.1.8"
SYMBOOGLIX_COMMIT = "ccb2e7f2b3"
LOCKPWN_COMMIT = "12ba58f1ec"
LLVM_SHORT_VERSION = "22"
LLVM_FULL_VERSION = "22.1.4"
RUST_VERSION = "nightly-2022-01-01"
