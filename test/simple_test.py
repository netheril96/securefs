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

if sys.platform == "darwin":
    try:
        import xattr
    except ImportError:
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
            time.sleep(0.05)
            if is_mount_then_statvfs(mount_point):
                return p
        raise TimeoutError(f"Failed to mount {repr(mount_point)} after many attempts")
    except:
        p.communicate(timeout=0.1)
        securefs_unmount(p=p, mount_point=mount_point)
        raise


def securefs_unmount(p: subprocess.Popen, mount_point: str):
    statvfs(mount_point)
    with p:
        if sys.platform == "win32":
            p.send_signal(signal.CTRL_BREAK_EVENT)
        else:
            p.send_signal(signal.SIGINT)
        p.wait(timeout=5)
        if p.returncode:
            logging.error("securefs exited with non-zero code: %d", p.returncode)
        if ismount(mount_point):
            raise RuntimeError(f"{mount_point} still mounted")


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


@parametrize(
    list(
        itertools.product(
            [RepoFormat.LITE, RepoFormat.FULL],
            [
                SecretInputMode.PASSWORD,
                SecretInputMode.KEYFILE2,
                SecretInputMode.PASSWORD_WITH_KEYFILE2,
            ],
            [0, 15],
            [False],
            [Sensitivity.SENSITIVE],
            [Sensitivity.SENSITIVE],
        )
    )
    + [
        (
            RepoFormat.LITE,
            SecretInputMode.PASSWORD_WITH_KEYFILE2,
            3,
            True,
            Sensitivity.SENSITIVE,
            Sensitivity.SENSITIVE,
        ),
        (
            RepoFormat.FULL,
            SecretInputMode.PASSWORD_WITH_KEYFILE2,
            3,
            False,
            Sensitivity.INSENSITIVE,
            Sensitivity.SENSITIVE,
        ),
        (
            RepoFormat.FULL,
            SecretInputMode.PASSWORD_WITH_KEYFILE2,
            15,
            False,
            Sensitivity.SENSITIVE,
            Sensitivity.INSENSITIVE,
        ),
    ]
)
def make_test_case(
    fmt: RepoFormat,
    mode: SecretInputMode,
    max_padding: int,
    plain_text_names: bool,
    case: Sensitivity = Sensitivity.SENSITIVE,
    uninorm: Sensitivity = Sensitivity.SENSITIVE,
):
    class SimpleSecureFSTestBase(unittest.TestCase):
        data_dir: str
        password: Optional[str]
        keyfile: Optional[str]
        mount_point: str
        securefs_process: Optional[subprocess.Popen]
        config_file: Optional[str]

        @classmethod
        def setUpClass(cls):
            os.makedirs("tmp", exist_ok=True)
            cls.data_dir = get_data_dir(fmt)
            cls.mount_point = get_mount_point()
            cls.password = "pvj8lRgrrsqzlr" if mode & SecretInputMode.PASSWORD else None
            cls.keyfile = generate_keyfile() if mode & SecretInputMode.KEYFILE else None
            cls.config_file = generate_keyfile() if plain_text_names else None
            securefs_create(
                data_dir=cls.data_dir,
                password=cls.password,
                fmt=fmt,
                keyfile=cls.keyfile,
                max_padding=max_padding,
                config_destination=cls.config_file,
                case=case,
                uninorm=uninorm,
            )
            cls.mount()

        @classmethod
        def tearDownClass(cls):
            cls.unmount()

        @classmethod
        def mount(cls):
            cls.securefs_process = securefs_mount(
                cls.data_dir,
                cls.mount_point,
                password=cls.password,
                keyfile=cls.keyfile,
                config_filename=cls.config_file,
                plain_text_names=plain_text_names,
            )

        @classmethod
        def unmount(cls):
            if cls.securefs_process is None:
                return
            securefs_unmount(cls.securefs_process, cls.mount_point)
            cls.securefs_process = None

        if fmt == RepoFormat.LITE and not plain_text_names and not is_freebsd:

            def test_long_name(self):
                os.mkdir(os.path.join(self.mount_point, "k" * 200))
                with open(
                    os.path.join(self.mount_point, "k" * 200, "✅" * 70), "w"
                ) as f:
                    f.write("test" * 70)
                os.rename(
                    os.path.join(self.mount_point, "k" * 200, "✅" * 70),
                    os.path.join(self.mount_point, "k" * 200, "d" * 222),
                )
                self.assertSetEqual(
                    set(os.listdir(os.path.join(self.mount_point, "k" * 200))),
                    {"d" * 222},
                )
                os.rename(
                    os.path.join(self.mount_point, "k" * 200, "d" * 222),
                    os.path.join(self.mount_point, "🎈" * 70),
                )
                self.assertIn(
                    "🎈" * 70,
                    set(os.listdir(os.path.join(self.mount_point))),
                )
                st = os.stat(os.path.join(self.mount_point, "🎈" * 70))
                self.assertEqual(st.st_size, 4 * 70)
                os.rename(
                    os.path.join(self.mount_point, "🎈" * 70),
                    os.path.join(self.mount_point, "k" * 200, "🎈" * 2),
                )
                self.assertSetEqual(
                    set(os.listdir(os.path.join(self.mount_point, "k" * 200))),
                    {"🎈" * 2},
                )

                if sys.platform != "win32":
                    os.symlink(
                        "b🔼🎈" * 30,
                        os.path.join(self.mount_point, "k" * 200, "🔼" * 64),
                    )
                    self.assertEqual(
                        "b🔼🎈" * 30,
                        os.readlink(
                            os.path.join(self.mount_point, "k" * 200, "🔼" * 64)
                        ),
                    )
                    os.link(
                        os.path.join(self.mount_point, "k" * 200, "🎈" * 2),
                        os.path.join(self.mount_point, "k" * 200, "✅" * 60),
                    )
                    self.assertEqual(
                        os.stat(
                            os.path.join(self.mount_point, "k" * 200, "✅" * 60)
                        ).st_nlink,
                        2,
                    )
                all_names = os.listdir(os.path.join(self.mount_point, "k" * 200))
                if sys.platform != "win32":
                    self.assertIn("b🔼🎈" * 30, all_names)
                    self.assertIn("✅" * 60, all_names)
                    self.assertIn("🎈" * 2, all_names)
                self.assertIn("🔼" * 64, all_names)
                shutil.rmtree(os.path.join(self.mount_point, "k" * 200))

        if xattr is not None:

            def test_xattr(self):
                fn = os.path.join(self.mount_point, str(uuid.uuid4()))
                try:
                    with open(fn, "wt") as f:
                        f.write("hello\n")
                    x = xattr.xattr(fn)
                    x.set("abc", b"def")
                    x.set("123", b"456")
                    self.unmount()
                    self.mount()
                    self.assertEqual(x.get("abc"), b"def")
                    self.assertEqual(set(x.list()), {"abc", "123"})
                    xattr.removexattr(fn, "abc")
                    self.assertEqual(set(x.list()), {"123"})
                finally:
                    try:
                        os.remove(fn)
                    except EnvironmentError:
                        pass

        if sys.platform != "win32" and not is_freebsd:

            def test_hardlink(self):
                data = os.urandom(16)
                source = os.path.join(self.mount_point, str(uuid.uuid4()))
                dest = os.path.join(self.mount_point, str(uuid.uuid4()))
                try:
                    with open(source, "wb") as f:
                        f.write(data)
                    os.link(source, dest)
                    source_stat = os.stat(source)
                    dest_stat = os.stat(dest)
                    self.assertEqual(source_stat.st_mode, dest_stat.st_mode)
                    self.assertEqual(source_stat.st_mtime, dest_stat.st_mtime)
                    self.assertEqual(source_stat.st_size, dest_stat.st_size)
                    self.assertEqual(source_stat.st_nlink, 2)
                    with open(dest, "rb") as f:
                        self.assertEqual(data, f.read())
                    # Moving hard links onto each other is a no-op
                    os.rename(dest, source)
                    self.assertTrue(os.path.isfile(dest) and os.path.isfile(source))
                finally:
                    try:
                        os.remove(source)
                    except EnvironmentError:
                        pass
                    try:
                        os.remove(dest)
                    except EnvironmentError:
                        pass

        if sys.platform != "win32" or fmt == RepoFormat.FULL:

            def test_symlink(self):
                data = os.urandom(16)
                source = str(uuid.uuid4())
                dest = str(uuid.uuid4())
                cwd: str = os.getcwd()
                os.chdir(self.mount_point)
                try:
                    with open(source, "wb") as f:
                        f.write(data)
                    os.symlink(source, dest)
                    dir_entries = list(os.scandir("."))
                    self.assertIn(os.path.basename(dest), [d.name for d in dir_entries])
                    self.assertTrue(
                        next(
                            d for d in dir_entries if d.name == os.path.basename(dest)
                        ).is_symlink()
                    )
                    self.assertEqual(os.readlink(dest), source)
                    with open(dest, "rb") as f:
                        self.assertEqual(data, f.read())

                    os.makedirs("ccc", exist_ok=True)
                    dest2 = "ccc/" + str(uuid.uuid4())
                    os.rename(dest, dest2)
                    dir_entries = list(os.scandir("ccc"))
                    self.assertIn(
                        os.path.basename(dest2), [d.name for d in dir_entries]
                    )
                    self.assertTrue(
                        next(
                            d for d in dir_entries if d.name == os.path.basename(dest2)
                        ).is_symlink()
                    )
                    self.assertEqual(os.readlink(dest2), source)
                    with self.assertRaises(EnvironmentError):
                        with open(dest2, "rb") as f:
                            f.read()
                    os.rename(source, "ccc/" + source)
                    with open(dest2, "rb") as f:
                        self.assertEqual(data, f.read())

                    dest3 = "📚🔐🔓📗😂🤣❤️😍😶‍🌫️"
                    os.symlink("ccc", dest3, target_is_directory=True)
                    dir_entries = list(os.scandir("."))
                    self.assertIn(dest3, [d.name for d in dir_entries])
                    self.assertTrue(
                        next(d for d in dir_entries if d.name == dest3).is_symlink()
                    )
                    self.assertTrue(
                        next(d for d in dir_entries if d.name == dest3).is_dir()
                    )
                    with open(os.path.join(dest3, os.path.basename(dest2)), "rb") as f:
                        self.assertEqual(data, f.read())
                finally:
                    for d in os.scandir("."):
                        shutil.rmtree(d.name, ignore_errors=True)
                    os.chdir(cwd)

        if sys.platform == "win32":

            def test_win_long_path(self):
                long_mount_point = rf"\\?\{os.path.abspath(self.mount_point)}"
                long_dir = os.path.join(long_mount_point, *(["🐋🐳" * 10] * 40))
                os.makedirs(long_dir)
                shutil.rmtree(os.path.join(long_mount_point, "🐋🐳" * 10))

        def test_rename(self):
            data = os.urandom(32)
            source = os.path.join(self.mount_point, str(uuid.uuid4()))
            dest = os.path.join(self.mount_point, str(uuid.uuid4()))
            try:
                with open(source, "wb") as f:
                    f.write(data)
                source_stat = os.stat(source)
                self.assertFalse(os.path.isfile(dest))
                os.rename(source, dest)
                self.assertFalse(os.path.isfile(source))
                self.assertTrue(os.path.isfile(dest))
                dest_stat = os.stat(dest)
                self.assertEqual(source_stat.st_ino, dest_stat.st_ino)
                self.assertEqual(source_stat.st_size, dest_stat.st_size)
            finally:
                try:
                    os.remove(source)
                except EnvironmentError:
                    pass
                try:
                    os.remove(dest)
                except EnvironmentError:
                    pass

        def test_rename_dir(self):
            a = str(uuid.uuid4())
            b = str(uuid.uuid4())
            c = str(uuid.uuid4())
            cwd = os.getcwd()
            os.chdir(self.mount_point)
            try:
                os.mkdir(a)
                os.mkdir(os.path.join(a, b))
                os.mkdir(c)
                os.rename(a, os.path.join(c, a))
                self.assertTrue(os.path.isdir(os.path.join(c, a, b)))
            finally:
                try:
                    shutil.rmtree(a)
                except EnvironmentError:
                    pass
                try:
                    shutil.rmtree(c)
                except EnvironmentError:
                    pass
                os.chdir(cwd)

        def test_read_write_mkdir_listdir_remove(self):
            dir_names = set(str(i) for i in range(3))
            random_data = os.urandom(11111)
            rng_filename = os.path.join(self.mount_point, "rng")
            with open(rng_filename, "wb") as f:
                f.write(random_data)
            self.unmount()

            self.mount()
            st = os.lstat(rng_filename)
            self.assertEqual(st.st_size, len(random_data))
            self.assertEqual(stat.S_IFMT(st.st_mode), stat.S_IFREG)

            with open(rng_filename, "rb") as f:
                self.assertEqual(f.read(), random_data)
                fst = os.fstat(f.fileno())
                self.assertEqual(st.st_ino, fst.st_ino)
                self.assertEqual(st.st_size, fst.st_size)

            if sys.platform != "win32":
                os.chmod(rng_filename, 0o620)
                self.assertEqual(os.lstat(rng_filename).st_mode, 0o100620)

            os.utime(rng_filename, times=(1713274809, 1713274821))
            self.assertEqual(os.lstat(rng_filename).st_mtime, 1713274821)

            now = time.time()
            os.utime(rng_filename)
            tolerance = 0.2  # The timing functions may differ a little bit
            self.assertGreaterEqual(os.lstat(rng_filename).st_mtime + tolerance, now)

            data = b"\0" * len(random_data) + b"0"
            with open(rng_filename, "wb") as f:
                f.write(data)
            with open(rng_filename, "rb") as f:
                self.assertEqual(f.read(), data)
            os.remove(rng_filename)
            for n in dir_names:
                os.mkdir(os.path.join(self.mount_point, n))
                st = os.lstat(os.path.join(self.mount_point, n))
                self.assertEqual(stat.S_IFMT(st.st_mode), stat.S_IFDIR)
            for n in dir_names:
                os.mkdir(os.path.join(self.mount_point, "0", n))
            for n in dir_names:
                os.mkdir(os.path.join(self.mount_point, "0", "1", n))
            self.unmount()

            self.mount()
            self.assertEqual(set(os.listdir(self.mount_point)), dir_names)
            self.assertEqual(
                set(os.listdir(os.path.join(self.mount_point, "0"))), dir_names
            )
            self.assertEqual(
                set(os.listdir(os.path.join(self.mount_point, "0", "1"))), dir_names
            )
            for dn in dir_names:
                try:
                    shutil.rmtree(os.path.join(self.mount_point, dn))
                except EnvironmentError:
                    pass

        if not plain_text_names and case == Sensitivity.INSENSITIVE:

            def test_case_insensitive(self):
                try:
                    os.mkdir(os.path.join(self.mount_point, "AbcDefG"))
                    os.mkdir(os.path.join(self.mount_point, "abcdefg", "777GGg"))
                    os.mkdir(os.path.join(self.mount_point, "aBCdEFG", "888llM"))
                    with open(
                        os.path.join(
                            self.mount_point, "abcDefG", "888LLM", "System.txt"
                        ),
                        "w",
                    ) as f:
                        f.write("hello\n")
                    self.assertSetEqual(
                        frozenset(
                            os.listdir(os.path.join(self.mount_point, "abCdefg"))
                        ),
                        {"777GGg", "888llM"},
                    )
                    with open(
                        os.path.join(
                            self.mount_point, "abcDefg", "888llm", "SYSTEM.txt"
                        ),
                        "r",
                    ) as f:
                        self.assertEqual(f.read(), "hello\n")
                finally:
                    shutil.rmtree(os.path.join(self.mount_point, "AbcDefG"))

        if not plain_text_names and uninorm == Sensitivity.INSENSITIVE and sys.platform != 'darwin':
            # FUSE-T has its own normalization handling so we don't test this
            def test_uninorm_insensitive(self):
                names = ["\u212bABV\u212b", "\u2126666", "333\u1e69", "\u1e0b\u0323..."]

                nfd_names: List[str] = [unicodedata.normalize("NFD", n) for n in names]
                for n, nn in zip(names, nfd_names):
                    self.assertNotEqual(n, nn)

                try:
                    os.mkdir(os.path.join(self.mount_point, names[0]))
                    os.mkdir(os.path.join(self.mount_point, names[0], names[1]))
                    os.mkdir(os.path.join(self.mount_point, nfd_names[0], names[2]))
                    with open(
                        os.path.join(
                            self.mount_point, nfd_names[0], nfd_names[2], names[3]
                        ),
                        "w",
                    ) as f:
                        f.write("hello\n")
                    self.assertSetEqual(
                        frozenset(
                            os.listdir(os.path.join(self.mount_point, nfd_names[0]))
                        ),
                        {names[1], names[2]},
                    )
                    with open(
                        os.path.join(
                            self.mount_point, names[0], nfd_names[2], nfd_names[3]
                        ),
                        "r",
                    ) as f:
                        self.assertEqual(f.read(), "hello\n")
                finally:
                    shutil.rmtree(os.path.join(self.mount_point, names[0]))

    return SimpleSecureFSTestBase


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


@parametrize(
    tuple(
        itertools.product(
            range(1, 5),
            ("scrypt", "pkcs5-pbkdf2-hmac-sha256", "argon2id"),
            SecretInputMode,
            [False, True],
        )
    )
)
def make_regression_test(version: int, pbkdf: str, mode: SecretInputMode, padded: bool):
    class RegressionTestBase(unittest.TestCase):
        """
        Ensures that future versions of securefs can read old versions just fine.
        """

        def test_regression(self):
            mount_point = get_mount_point()
            if padded:
                data_dir = f"{version}-padded"
            else:
                data_dir = str(version)
            config_filename = os.path.join(
                reference_data_dir, data_dir, f".securefs.{pbkdf}.{mode.name}.json"
            )
            p = securefs_mount(
                os.path.join(reference_data_dir, data_dir),
                mount_point,
                password="abc" if mode & SecretInputMode.PASSWORD else None,
                keyfile=(
                    os.path.join(reference_data_dir, "keyfile")
                    if mode & SecretInputMode.KEYFILE
                    else None
                ),
                config_filename=config_filename,
            )
            try:
                _compare_directory(
                    self, os.path.join(reference_data_dir, "plain"), mount_point
                )
            finally:
                securefs_unmount(p, mount_point)

    return RegressionTestBase


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
                self.assertTrue(os.path.isdir(test_dir_path))
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
