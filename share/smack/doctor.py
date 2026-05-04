#!/usr/bin/env python3
#
# This file is distributed under the MIT License. See LICENSE for details.
#

import os
from subprocess import Popen, PIPE
import sys
import re
import argparse

from .versions import LLVM_SHORT_VERSION


def red(text):
    return '\033[0;31m' + text + '\033[0m'


def green(text):
    return '\033[0;32m' + text + '\033[0m'


def check(text, condition):
    global args
    global count
    if condition:
        if not args.quiet:
            print(green("[X] " + text))
    else:
        print(red("[-] " + text), file=sys.stderr)
        count += 1


def full_path(program):
    for path in os.environ['PATH'].split(os.pathsep):
        path = path.strip('"')
        exe = os.path.join(path, program)
        if os.path.isfile(exe) and os.access(exe, os.X_OK):
            return exe
    return None


def check_command(cmd):
    exe = full_path(cmd)

    check("%s is in the path" % cmd, exe is not None)
    if exe is not None:
        try:
            rc = Popen(cmd, stdout=PIPE, stderr=PIPE).wait()
        except BaseException:
            rc = None
        check("%s is executable" % cmd, rc in [0, 1, 2])


def check_version_command(cmd, version_arg):
    exe = full_path(cmd)

    check("%s is in the path" % cmd, exe is not None)
    if exe is not None:
        try:
            rc = Popen([cmd, version_arg], stdout=PIPE, stderr=PIPE).wait()
        except BaseException:
            rc = None
        check("%s reports a version" % cmd, rc == 0)


def check_verifier(cmd):
    if cmd == "corral" and os.environ.get("SMACK_ENABLE_CORRAL_TESTS") != "1":
        if not args.quiet:
            print("Skipping legacy Corral checks.")
        return

    exe = full_path(cmd)
    var = cmd.upper()

    if exe is not None:
        try:
            with open(exe, encoding='utf-8') as f:
                exe_text = f.read()
        except UnicodeDecodeError:
            exe_text = None
        if exe_text is not None:
            check("%s is a bash script" % cmd, '#!/bin/bash' in exe_text)
            check(
                "%s redirects to %s" %
                (cmd, var), ("$%s \"$@\"" % var) in exe_text)

    if var in os.environ:
        check("%s environment variable is set" % var, True)
        check("%s invokes mono" % var, re.match(r'\Amono', os.environ[var]))
        verifier_exe = os.environ[var].split()[1]
        check("%s verifier executable exists" %
              var, os.path.isfile(verifier_exe))
        solver_exe = os.path.join(os.path.dirname(verifier_exe), "z3.exe")
        check("%s solver executable exists" % var, os.path.isfile(solver_exe))
        check("%s solver is executable" % var, os.access(solver_exe, os.X_OK))

    if cmd == "boogie":
        check_version_command(cmd, "/version")
    else:
        check_command(cmd)


def check_headers(prefix):
    HEADERS = [
        (["share", "smack", "include", "smack.h"], "#define SMACK_H_"),
        (["share", "smack", "lib", "smack.c"], "void __SMACK_decls(void)")
    ]

    for (path, content) in HEADERS:
        file = os.path.join(prefix, *path)
        check("%s exists" % file, os.path.isfile(file))
        if os.path.isfile(file):
            check(
                "%s contains %s" %
                (file, content), content in open(file).read())


def main():
    global args
    global count
    parser = argparse.ArgumentParser(
        description='Diagnose SMACK configuration issues.')
    parser.add_argument(
        '-q',
        '--quiet',
        dest='quiet',
        action="store_true",
        default=False,
        help='only show failed diagnostics')
    parser.add_argument(
        '--prefix',
        metavar='P',
        dest='prefix',
        type=str,
        default='',
        help='point to the installation prefix')
    args = parser.parse_args()
    count = 0

    if not args.quiet:
        print("Checking front-end dependencies...")
    check_version_command("clang-%s" % LLVM_SHORT_VERSION, "--version")
    check_version_command("clang++-%s" % LLVM_SHORT_VERSION, "--version")
    check_version_command("llvm-config-%s" % LLVM_SHORT_VERSION, "--version")
    check_version_command("llvm-link-%s" % LLVM_SHORT_VERSION, "--version")

    if not args.quiet:
        print("Checking back-end dependencies...")
    check_verifier("boogie")
    check_verifier("corral")

    if not args.quiet:
        print("Checking SMACK itself...")
    check_command("llvm2bpl")
    check_command("smack")

    if not args.prefix:
        check_headers(args.prefix)

    exit(count)
