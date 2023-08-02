#!/usr/bin/env python3
import subprocess
import os
import tempfile
import argparse


def check_call(*args):
    print("Executing", args)
    subprocess.check_call(args)


def get_build_root(build_root: str) -> str:
    if build_root:
        os.makedirs(build_root, exist_ok=True)
        return build_root
    base_tmp_dir = None
    if os.path.isdir("/dev/shm"):
        base_tmp_dir = "/dev/shm"
    return tempfile.mkdtemp(prefix="securefs", dir=base_tmp_dir)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--vcpkg_root",
        help="The root of vcpkg repository",
        default=os.path.join(os.environ.get("HOME", "/"), "vcpkg"),
    )
    parser.add_argument(
        "--build_root",
        help="The root of build directory. If unset, a temporary directory will be used.",
        default="",
    )
    parser.add_argument(
        "--enable_test", default=False, help="Enable all tests", action="store_true"
    )
    parser.add_argument(
        "--enable_unit_test",
        default=False,
        help="Run unit test after building to ensure correctness",
        action="store_true",
    )
    parser.add_argument(
        "--enable_integration_test",
        default=False,
        help="Run integration test after building to ensure correctness",
        action="store_true",
    )
    parser.add_argument(
        "--triplet",
        default="" if os.name != "nt" else "x64-windows-static-md",
        help="Override the default vcpkg triplet",
    )
    parser.add_argument(
        "--cmake_defines",
        default=[],
        nargs="*",
        help="Additional CMake definitions. Example: FOO=BAR",
    )
    args = parser.parse_args()
    if not os.path.isdir(args.vcpkg_root):
        raise ValueError(
            "--vcpkg_root must point to a directory. Install from https://vcpkg.io if necessary."
        )

    if args.enable_test:  # For backwards compat
        args.enable_unit_test = True
        args.enable_integration_test = True

    source_dir = os.path.dirname(os.path.realpath(__file__))
    os.chdir(get_build_root(args.build_root))
    configure_args = [
        "cmake",
        "-DCMAKE_BUILD_TYPE=Release",
        f"-DCMAKE_TOOLCHAIN_FILE={args.vcpkg_root}/scripts/buildsystems/vcpkg.cmake",
    ]
    if args.triplet:
        configure_args.append("-DVCPKG_TARGET_TRIPLET=" + args.triplet)
    if not args.enable_unit_test:
        configure_args.append("-DSECUREFS_ENABLE_UNIT_TEST=OFF")
    if not args.enable_integration_test:
        configure_args.append("-DSECUREFS_ENABLE_INTEGRATION_TEST=OFF")
    for pair in args.cmake_defines:
        configure_args.append("-D" + pair)
    configure_args.append(source_dir)

    check_call(*configure_args)
    check_call("cmake", "--build", ".", "--config", "Release")
    if args.enable_unit_test or args.enable_integration_test:
        check_call("ctest", "-V", "-C", "Release")
    print(
        "Build succeeds. Please copy the binary somewhere in your PATH:",
        os.path.realpath("./securefs"),
    )


if __name__ == "__main__":
    main()
