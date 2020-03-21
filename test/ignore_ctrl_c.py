#!/usr/bin/env python3
# Because of Windows' limitation, we need to run `ctest`
# under this wrapper to prevent it from being closed by Ctrl-C event.
import ctypes
import sys
import subprocess

ctypes.windll.kernel32.SetConsoleCtrlHandler(None, 1)
subprocess.check_call(sys.argv[1:])
