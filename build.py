#!/usr/bin/env python3
import subprocess
import os
import tempfile
import argparse
import shutil
from typing import Optional


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


def _unchecked_get_vcpkg_cmake_file(vcpkg_root: Optional[str]) -> str:
    subpath = "scripts/buildsystems/vcpkg.cmake"
    vcpkg_root = vcpkg_root or os.environ.get("VCPKG_ROOT")
    if vcpkg_root:
        return os.path.join(vcpkg_root, subpath)
    exe_path = shutil.which("vcpkg")
    if exe_path:
        vcpkg_root = os.path.dirname(exe_path)
        return os.path.join(vcpkg_root, subpath)
    vcpkg_root = os.path.expanduser("~/vcpkg")
    return os.path.join(vcpkg_root, subpath)


def get_vcpkg_cmake_file(vcpkg_root: Optional[str]) -> str:
    result = _unchecked_get_vcpkg_cmake_file(vcpkg_root)
    if not os.path.isfile(result):
        raise ValueError(
            "Cannot find vcpkg installation by heuristic. Please specify --vcpkg_root explicitly."
        )
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--vcpkg_root",
        help="The root of vcpkg repository",
        default=None,
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
        "--host_triplet",
        default="" if os.name != "nt" else "x64-windows-static-md",
        help="Override the default vcpkg host triplet",
    )
    parser.add_argument(
        "--cmake_defines",
        default=[],
        nargs="*",
        help="Additional CMake definitions. Example: FOO=BAR",
    )
    parser.add_argument("--build_type", default="Release", help="CMake build type")
    parser.add_argument(
        "--clang_cl", help="Use clang-cl on Windows for building", action="store_true"
    )
    parser.add_argument(
        "--lto",
        help="Build with link time optimization. Only works on some platforms",
        action="store_true",
    )
    parser.add_argument(
        "--test_timeout", help="Test time out in seconds", type=int, default=600
    )
    args = parser.parse_args()

    if args.enable_test:  # For backwards compat
        args.enable_unit_test = True
        args.enable_integration_test = True

    source_dir = os.path.dirname(os.path.realpath(__file__))
    os.chdir(get_build_root(args.build_root))
    configure_args = [
        "cmake",
        "-DCMAKE_BUILD_TYPE=" + args.build_type,
        f"-DCMAKE_TOOLCHAIN_FILE={get_vcpkg_cmake_file(args.vcpkg_root)}",
    ]
    if args.clang_cl:
        configure_args += ["-T", "ClangCL"]
    if args.triplet:
        configure_args.append("-DVCPKG_TARGET_TRIPLET=" + args.triplet)
    if args.host_triplet:
        configure_args.append("-DVCPKG_HOST_TRIPLET=" + args.host_triplet)
    if not args.enable_unit_test:
        configure_args.append("-DSECUREFS_ENABLE_UNIT_TEST=OFF")
    if not args.enable_integration_test:
        configure_args.append("-DSECUREFS_ENABLE_INTEGRATION_TEST=OFF")
    if args.lto:
        configure_args += [
            "-DCMAKE_INTERPROCEDURAL_OPTIMIZATION=ON",
            f"-DVCPKG_OVERLAY_TRIPLETS={os.path.join(source_dir,'overlay_triplets')}",
        ]
    for pair in args.cmake_defines:
        configure_args.append("-D" + pair)
    configure_args.append(source_dir)

    check_call(*configure_args)
    check_call(
        "cmake", "--build", ".", "--config", args.build_type, "-j", str(os.cpu_count())
    )
    if args.enable_unit_test or args.enable_integration_test:
        check_call(
            "ctest", "-V", "-C", args.build_type, "--timeout", str(args.test_timeout)
        )
    print(
        "Build succeeds. Please copy the binary somewhere in your PATH:",
        os.path.realpath("./securefs"),
    )


if __name__ == "__main__":
    main()
