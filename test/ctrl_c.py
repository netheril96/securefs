#!/usr/bin/env python3
import ctypes
import sys

kernel = ctypes.windll.kernel32


def errcheck(result, func, arguments):
    if result == 0:
        raise ctypes.WinError()


def setup_prototypes():
    kernel.FreeConsole.argtypes = []
    kernel.FreeConsole.errcheck = errcheck
    kernel.AttachConsole.argtypes = [ctypes.c_int32]
    kernel.AttachConsole.errcheck = errcheck
    kernel.SetConsoleCtrlHandler.argtypes = [ctypes.c_void_p, ctypes.c_int32]
    kernel.SetConsoleCtrlHandler.errcheck = errcheck
    kernel.GenerateConsoleCtrlEvent.argtypes = [ctypes.c_int32, ctypes.c_int32]
    kernel.GenerateConsoleCtrlEvent.errcheck = errcheck


def main():
    setup_prototypes()
    pid = int(sys.argv[1])
    kernel.FreeConsole()
    kernel.AttachConsole(pid)
    kernel.SetConsoleCtrlHandler(None, 1)
    kernel.GenerateConsoleCtrlEvent(0, 0)


if __name__ == "__main__":
    main()
