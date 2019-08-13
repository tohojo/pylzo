#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# lzo_test.py
#
# Author:   Toke Høiland-Jørgensen (toke@toke.dk)
# Date:     13 August 2019
# Copyright (c) 2019, Toke Høiland-Jørgensen
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import sys
import subprocess
import shlex

ret = 0


def run_test(command, input, output):
    global ret
    print(f"Trying input {input[:10]}...", end='')
    proc = subprocess.Popen(shlex.split(command),
                            stdin=subprocess.PIPE,
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE)
    out, err = proc.communicate(input=input)

    if proc.returncode != 0:
        if output:
            print(f"Got returncode {proc.returncode} for input {input.hex()}")
            print(err.decode())
            ret = 2
        else:
            print("OK (Expected crash)")
    elif output != out:
        print(f"Got {out} expected {output}")
        ret = 1
    else:
        print("OK")


def run_tests(filename, cmd):
    with open(filename) as fp:
        lines = fp.readlines()

    for l in lines:
        try:
            input, output = l.split(":")
            run_test(cmd, bytes.fromhex(input), bytes.fromhex(output))
        except:
            pass


if __name__ == "__main__":
    if len(sys.argv) < 3:
        sys.stderr.write(f"Usage: {sys.argv[0]} <test vector filename> <decompressor command>\n")
        sys.exit(1)
    testfile = sys.argv[1]
    cmd = sys.argv[2]
    run_tests(testfile, cmd)
    sys.exit(ret)
