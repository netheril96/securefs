#!/usr/bin/python3
# coding: utf-8
import ctypes
import faulthandler
import itertools
import logging
import os
import inspect
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time
import traceback
import unittest
import uuid
from typing import List, Optional, Sequence
from typing import Set
import enum
import unicodedata
from collections import namedtuple
import multiprocessing
import random
import secrets
import io

faulthandler.enable()


SECUREFS_BINARY = os.environ["SECUREFS_BINARY"]
if not os.path.isfile(SECUREFS_BINARY):
    raise ValueError(f"{repr(SECUREFS_BINARY)} is not a file!")

if sys.platform != "win32":
    try:
        import xattr
    except ImportError:
        if os.getenv("SECUREFS_TEST_FORCE_XATTR") in ("1", "true", "yes", "on"):
            raise ValueError("SECUREFS_TEST_FORCE_XATTR is on but xattr import fails")
        sys.stderr.write(
            'Importing module "xattr" failed. Testing for extended attribute support is skipped\n'
        )
        xattr = None
else:
    xattr = None


if sys.platform == "win32":

    def ismount(path):
        # Not all reparse points are mounts, but in our test, that is close enough
        attribute = ctypes.windll.kernel32.GetFileAttributesW(path.rstrip("/\\"))
        return attribute != -1 and (attribute & 0x400) == 0x400

    def statvfs(path):
        if not ctypes.windll.kernel32.GetDiskFreeSpaceExW(path, None, None, None):
            raise ctypes.WinError()

else:
    ismount = os.path.ismount
    statvfs = os.statvfs


def is_mount_then_statvfs(mount_point: str) -> bool:
    try:
        ismounted: bool = ismount(mount_point)
        if not ismounted:
            return False
        # This forces initialization of FUSE
        statvfs(mount_point)
        return True
    except EnvironmentError:
        traceback.print_exc()
        return False


def securefs_mount(
    data_dir: str,
    mount_point: str,
    password: Optional[str],
    keyfile: Optional[str] = None,
    config_filename: Optional[str] = None,
    plain_text_names: bool = False,
) -> subprocess.Popen:
    command = [
        SECUREFS_BINARY,
        "mount",
        data_dir,
        mount_point,
        "--normalization",
        "none",
    ]
    if password:
        command.append("--pass")
        command.append(password)
    if keyfile:
        command.append("--keyfile")
        command.append(keyfile)
    if config_filename:
        command.append("--config")
        command.append(config_filename)
    if plain_text_names:
        command.append("--plain-text-names")
    logging.info("Start mounting, command:\n%s", " ".join(command))
    p = subprocess.Popen(
        command,
        creationflags=(
            subprocess.CREATE_NEW_PROCESS_GROUP if sys.platform == "win32" else 0
        ),
    )
    try:
        for _ in range(600):
            try:
                p.wait(timeout=0.01)
            except subprocess.TimeoutExpired:
                pass
            if p.returncode:
                raise subprocess.CalledProcessError(p.returncode, p.args)
            if subprocess.call([SECUREFS_BINARY, "ismount", mount_point]) == 0:
                return p

        raise TimeoutError(f"Failed to mount {repr(mount_point)} after many attempts")
    except:
        securefs_unmount(p=p, mount_point=mount_point)
        raise


def securefs_unmount(p: subprocess.Popen, mount_point: str):
    with p:
        subprocess.check_call([SECUREFS_BINARY, "unmount", mount_point])
        p.wait(timeout=5)
        if p.returncode:
            logging.error("securefs exited with non-zero code: %d", p.returncode)


class RepoFormat(enum.Enum):
    LITE = 4
    FULL = 2


class Sensitivity(enum.Enum):
    SENSITIVE = "sensitive"
    INSENSITIVE = "insensitive"


def securefs_create(
    data_dir: str,
    fmt: RepoFormat,
    password: Optional[str],
    keyfile: Optional[str] = None,
    max_padding: int = 0,
    config_destination: Optional[str] = None,
    case: Sensitivity = Sensitivity.SENSITIVE,
    uninorm: Sensitivity = Sensitivity.SENSITIVE,
):
    if config_destination:
        try:
            os.remove(config_destination)
        except FileNotFoundError:
            pass
    command = [
        SECUREFS_BINARY,
        "create",
        data_dir,
        "--max-padding",
        str(max_padding),
        "--argon2-t",
        "2",
        "--argon2-m",
        "16",
        "--argon2-p",
        "2",
        "-f",
        fmt.name,
        "--case",
        case.value,
        "--uninorm",
        uninorm.value,
    ]
    if password:
        command.append("--pass")
        command.append(password)
    if keyfile:
        command.append("--keyfile")
        command.append(keyfile)
    if config_destination:
        command.append("--config")
        command.append(config_destination)
    logging.info("Creating securefs repo with command %s", command)
    subprocess.check_call(command)


def securefs_chpass(
    data_dir,
    old_pass: Optional[str] = None,
    new_pass: Optional[str] = None,
    old_keyfile: Optional[str] = None,
    new_keyfile: Optional[str] = None,
    use_stdin: bool = True,
):
    if not old_pass and not old_keyfile:
        raise ValueError("At least one of old_pass and old_keyfile must be specified")
    if not new_pass and not new_keyfile:
        raise ValueError("At least one of new_pass and new_keyfile must be specified")

    args = [
        SECUREFS_BINARY,
        "chpass",
        data_dir,
        "--argon2-t",
        "3",
        "--argon2-m",
        "16",
        "--argon2-p",
        "2",
    ]
    if old_pass:
        if use_stdin:
            args.append("--askoldpass")
        else:
            args.append("--oldpass")
            args.append(old_pass)
    if new_pass:
        if use_stdin:
            args.append("--asknewpass")
        else:
            args.append("--newpass")
            args.append(new_pass)
    if old_keyfile:
        args.append("--oldkeyfile")
        args.append(old_keyfile)
    if new_keyfile:
        args.append("--newkeyfile")
        args.append(new_keyfile)
    logging.info("Executing command: %s", args)
    with subprocess.Popen(
        args,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        universal_newlines=True,
    ) as p:
        input = ""
        if use_stdin:
            if old_pass:
                input += old_pass + "\n"
            if new_pass:
                input += (new_pass + "\n") * 2
        out, err = p.communicate(input=input, timeout=3)
        if p.returncode:
            raise subprocess.CalledProcessError(p.returncode, args, out, err)


def get_data_dir(fmt: RepoFormat):
    return tempfile.mkdtemp(prefix=f"securefs.{fmt}.data🔐", dir="tmp")


def get_mount_point():
    result = tempfile.mkdtemp(prefix=f"securefs.mount🔓", dir="tmp")
    os.rmdir(result)
    return result


@enum.unique
class SecretInputMode(enum.IntEnum):
    PASSWORD = 0b1
    KEYFILE = 0b10
    PASSWORD_WITH_KEYFILE = PASSWORD | KEYFILE
    KEYFILE2 = KEYFILE | 0b1000
    PASSWORD_WITH_KEYFILE2 = PASSWORD | KEYFILE2


def parametrize(possible_args: Sequence[Sequence]):
    def real_parametrize(func):
        sig = inspect.signature(func)
        for l in possible_args:
            if len(l) != len(sig.parameters):
                raise ValueError(
                    "The possible arguments list does not match the parameters"
                )
        for l in possible_args:
            cls = func(*l)
            if cls is None:
                continue
            assert isinstance(cls, type)
            kwargs = {}
            for l, p in zip(l, sig.parameters.keys()):
                kwargs[p] = l
            cls_name = cls.__name__ + repr(kwargs)
            globals()[cls_name] = type(cls_name, (cls,), {})  # type: ignore
        return func

    return real_parametrize


def is_freebsd():
    return sys.platform.startswith("freebsd")


reference_data_dir = shutil.copytree(
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "reference"),
    f"tmp/{uuid.uuid4()}",
)


def _compare_directory(self: unittest.TestCase, dir1: str, dir2: str):
    listing1 = list_dir_recursive(dir1, relpath=True)
    listing2 = list_dir_recursive(dir2, relpath=True)

    self.assertEqual(
        listing1,
        listing2,
        f"{dir1} and {dir2} differ in file names",
    )

    for fn in listing1:
        fn1 = os.path.join(dir1, fn)
        fn2 = os.path.join(dir2, fn)

        if os.path.isdir(fn1) and os.path.isdir(fn2):
            continue

        with open(fn1, "rb") as f:
            data1 = f.read()
        with open(fn2, "rb") as f:
            data2 = f.read()
        self.assertEqual(data1, data2, f"{fn1} and {fn2} differ in contents")


class PlainTextNamesRegressionTestCase(unittest.TestCase):
    def test_regression(self):
        mount_point = get_mount_point()
        config_filename = os.path.join(
            reference_data_dir, "4", ".securefs.argon2id.KEYFILE2.json"
        )
        p = securefs_mount(
            os.path.join(reference_data_dir, "4-plain-text-names"),
            mount_point,
            password=None,
            keyfile=os.path.join(reference_data_dir, "keyfile"),
            config_filename=config_filename,
            plain_text_names=True,
        )
        try:
            _compare_directory(
                self, os.path.join(reference_data_dir, "plain"), mount_point
            )
        finally:
            securefs_unmount(p, mount_point)


class RepoLockerTestCase(unittest.TestCase):
    def test_locked(self):
        data_dir = get_data_dir(fmt=RepoFormat.FULL)
        securefs_create(data_dir=data_dir, fmt=RepoFormat.FULL, password="123")
        mount_point = get_mount_point()
        with open(os.path.join(data_dir, ".securefs.lock"), "w") as f:
            f.write(str(os.getpid()))
        with self.assertRaises(subprocess.CalledProcessError):
            p = securefs_mount(
                data_dir=data_dir, mount_point=mount_point, password="123"
            )

    def test_locker_died(self):
        data_dir: str = get_data_dir(fmt=RepoFormat.FULL)
        securefs_create(data_dir=data_dir, fmt=RepoFormat.FULL, password="123")
        mount_point = get_mount_point()
        with open(os.path.join(data_dir, ".securefs.lock"), "w") as f:
            f.write(str(2**31 - 1))
        p = securefs_mount(data_dir=data_dir, mount_point=mount_point, password="123")
        try:
            with open(os.path.join(data_dir, ".securefs.lock"), "r") as f:
                self.assertEqual(f.read(), str(p.pid))
        finally:
            securefs_unmount(p, mount_point)


def list_dir_recursive(dirname: str, relpath=False) -> Set[str]:
    # Note: os.walk does not work on Windows when crossing filesystem boundary.
    # So we use this crude version instead.
    try:
        sub_filenames = os.listdir(dirname)
    except OSError:
        return set()
    result = set()
    for fn in sub_filenames:
        fn = os.path.join(dirname, fn)
        result.add(fn)
        result.update(list_dir_recursive(fn))
    if relpath:
        return set(os.path.relpath(f, dirname) for f in result)
    return result


def generate_keyfile():
    with tempfile.NamedTemporaryFile(
        dir="tmp", mode="wb", delete=False, prefix="key"
    ) as f:
        f.write(os.urandom(9))
        return f.name


@parametrize([[1], [2], [3], [4]])
def make_size_test(version):
    """Ensures that padding actually increases the underlying file sizes."""

    class SizeTestBase(unittest.TestCase):
        def test_size(self):
            nonpadded_data_dir = os.path.join(reference_data_dir, str(version))
            padded_data_dir = os.path.join(reference_data_dir, f"{version}-padded")
            nonpadded_fs = compute_file_statistics(
                nonpadded_data_dir, exclude_securefs_json=True
            )
            padded_fs = compute_file_statistics(
                padded_data_dir, exclude_securefs_json=True
            )
            self.assertEqual(nonpadded_fs.count, padded_fs.count)
            self.assertGreater(
                padded_fs.total_size - nonpadded_fs.total_size, padded_fs.count * 32
            )

    return SizeTestBase


FileStatistics = namedtuple("FileStatistics", ("total_size", "count"))


def compute_file_statistics(
    base_dir: str, exclude_securefs_json: bool
) -> FileStatistics:
    size = 0
    count = 0
    with os.scandir(base_dir) as it:
        for entry in it:
            name: str = entry.name
            if entry.is_dir():
                fs = compute_file_statistics(
                    os.path.join(base_dir, name), exclude_securefs_json
                )
                size += fs.total_size
                count += fs.count
            elif (
                entry.is_file()
                and not name.startswith(".securefs")
                and not name.endswith(".json")
            ):
                size += entry.stat().st_size
                count += 1
    return FileStatistics(total_size=size, count=count)


@parametrize(
    tuple(
        itertools.product(
            [None, "abc"],
            [None, "abc"],
            [None, generate_keyfile()],
            [None, generate_keyfile()],
            [True, False],
            [RepoFormat.LITE, RepoFormat.FULL],
            [0, 32],
        )
    )
)
def make_chpass_test(
    old_pass, new_pass, old_keyfile, new_keyfile, use_stdin, fmt, max_padding
):
    if not old_pass and not old_keyfile:
        return
    if not new_pass and not new_keyfile:
        return

    class ChpassTestBase(unittest.TestCase):
        def test_chpass(self):
            data_dir = get_data_dir(fmt)
            mount_point = get_mount_point()
            test_dir_path = os.path.join(mount_point, "test")
            test_file_path = os.path.join(mount_point, "aaa")

            securefs_create(
                data_dir=data_dir,
                password=old_pass,
                keyfile=old_keyfile,
                fmt=fmt,
                max_padding=max_padding,
            )

            self.assertFalse(os.path.exists(test_dir_path))

            p = securefs_mount(data_dir, mount_point, old_pass, old_keyfile)
            try:
                os.mkdir(test_dir_path)
                with open(test_file_path, "xb") as f:
                    f.write(b"x" * 10)
            finally:
                securefs_unmount(p, mount_point)

            self.assertFalse(os.path.exists(test_dir_path))

            securefs_chpass(
                data_dir,
                old_pass=old_pass,
                new_pass=new_pass,
                old_keyfile=old_keyfile,
                new_keyfile=new_keyfile,
                use_stdin=use_stdin,
            )

            p = securefs_mount(data_dir, mount_point, new_pass, new_keyfile)
            try:
                self.assertTrue(
                    os.path.isdir(test_dir_path),
                    msg=f"stat result={os.lstat(test_dir_path)}",
                )
                self.assertEqual(os.lstat(test_file_path).st_size, 10)
                with open(test_file_path, "rb") as f:
                    self.assertEqual(f.read(), b"x" * 10)
            finally:
                securefs_unmount(p, mount_point)

    return ChpassTestBase


def randomly_act_on_file(filename: str, barrier) -> None:
    rng = random.Random(os.urandom(16))

    def run_once(f: io.FileIO):
        action = rng.randrange(0, 5)
        if action == 0:
            f.read(rng.randrange(5000))
        elif action == 1:
            f.write(secrets.token_bytes(rng.randrange(1, 5000)))
        elif action == 2:
            f.seek(rng.randrange(0, 1 << 20))
        elif action == 3:
            os.ftruncate(f.fileno(), rng.randrange(0, 1 << 20))
            f.seek(0)
        elif action == 4:
            os.fsync(f.fileno())

    barrier.wait()
    for _ in range(3):
        with open(filename, "r+b", buffering=0) as f:
            for _ in range(rng.randrange(10, 30)):
                run_once(f)


@parametrize([[RepoFormat.LITE], [RepoFormat.FULL]])
def make_concurrency_test(fmt: RepoFormat):
    class ConcurrencyTestBase(unittest.TestCase):
        def test_concurrent_access(self):
            data_dir = get_data_dir(fmt)
            mount_point = get_mount_point()

            securefs_create(data_dir=data_dir, password="xxxx", fmt=fmt)
            test_filename = os.path.join(mount_point, "a" * 10)
            p = securefs_mount(data_dir, mount_point, "xxxx")
            try:
                with open(test_filename, "xb") as f:
                    pass
                count = multiprocessing.cpu_count()
                barrier = multiprocessing.Barrier(count)
                processes = [
                    multiprocessing.Process(
                        target=randomly_act_on_file, args=(test_filename, barrier)
                    )
                    for _ in range(count)
                ]
                for proc in processes:
                    proc.start()
                for proc in processes:
                    proc.join()
                for proc in processes:
                    if proc.exitcode != 0:
                        raise ValueError(
                            "A process that reads/writes test file has failed"
                        )
            finally:
                securefs_unmount(p, mount_point)

    return ConcurrencyTestBase


if __name__ == "__main__":
    logging.getLogger().setLevel(logging.INFO)
    unittest.main()
