#!/usr/bin/python3
# coding: utf-8
import ctypes
import errno
import faulthandler
import itertools
import logging
import os
import platform
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import traceback
import unittest
import uuid
from typing import Optional
from typing import Set
import enum

faulthandler.enable()


def find_securefs_binary():
    for dir_path, _, files in os.walk("."):
        for fn in files:
            if fn == "securefs" or fn == "securefs.exe":
                return os.path.join(dir_path, fn)
    raise RuntimeError("securefs binary not found")


SECUREFS_BINARY = find_securefs_binary()

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

else:
    ismount = os.path.ismount


def securefs_mount(
    data_dir: str,
    mount_point: str,
    password: Optional[str],
    keyfile: Optional[str] = None,
    config_filename: Optional[str] = None,
) -> subprocess.Popen[bytes]:
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
    logging.info("Start mounting, command:\n%s", " ".join(command))
    p = subprocess.Popen(
        command,
        creationflags=subprocess.CREATE_NEW_PROCESS_GROUP
        if sys.platform == "win32"
        else 0,
    )
    try:
        for _ in range(300):
            time.sleep(0.05)
            try:
                if ismount(mount_point):
                    return p
            except EnvironmentError:
                traceback.print_exc()
        raise TimeoutError(f"Failed to mount {repr(mount_point)} after many attempts")
    except:
        p.communicate(timeout=0.1)
        p.kill()
        raise


def securefs_unmount(p: subprocess.Popen, mount_point: str):
    time.sleep(0.005)
    with p:
        if sys.platform == "win32":
            p.send_signal(signal.CTRL_BREAK_EVENT)
        else:
            p.send_signal(signal.SIGINT)
        p.communicate(timeout=5)
        # Ignore error on Apple platforms,
        # as MacFUSE has bugs during unmounting.
        if p.returncode and sys.platform != "darwin":
            raise RuntimeError(f"securefs failed with code {p.returncode}")
        if ismount(mount_point):
            raise RuntimeError(f"{mount_point} still mounted")


def securefs_create(
    data_dir: str,
    version: int,
    pbkdf: str,
    password: Optional[str],
    keyfile: Optional[str] = None,
):
    command = [
        SECUREFS_BINARY,
        "create",
        "--format",
        str(version),
        data_dir,
        "--rounds",
        "2",
        "--pbkdf",
        pbkdf,
    ]
    if password:
        command.append("--pass")
        command.append(password)
    if keyfile:
        command.append("--keyfile")
        command.append(keyfile)
    logging.info("Creating securefs repo with command %s", command)
    subprocess.check_call(command)


def securefs_chpass(
    data_dir,
    pbkdf: str,
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

    args = [SECUREFS_BINARY, "chpass", data_dir, "--rounds", "2", "--pbkdf", pbkdf]
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


def get_data_dir(format_version=4):
    return tempfile.mkdtemp(
        prefix=f"securefs.format{format_version}.data_dir", dir="tmp"
    )


def get_mount_point():
    result = tempfile.mkdtemp(prefix=f"securefs.mount_point", dir="tmp")
    os.rmdir(result)
    return result


@enum.unique
class SecretInputMode(enum.IntEnum):
    PASSWORD = 0b1
    KEYFILE = 0b10
    PASSWORD_WITH_KEYFILE = PASSWORD | KEYFILE
    KEYFILE2 = KEYFILE | 0b1000
    PASSWORD_WITH_KEYFILE2 = PASSWORD | KEYFILE2


def make_test_case(version: int, pbkdf: str, mode: SecretInputMode):
    class SimpleSecureFSTestBase(unittest.TestCase):
        data_dir: str
        password: Optional[str]
        keyfile: Optional[str]
        mount_point: str
        securefs_process: Optional[subprocess.Popen]

        @classmethod
        def setUpClass(cls):
            os.makedirs("tmp", exist_ok=True)
            cls.data_dir = get_data_dir(format_version=version)
            cls.mount_point = get_mount_point()
            cls.password = "pvj8lRgrrsqzlr" if mode & SecretInputMode.PASSWORD else None
            cls.keyfile = generate_keyfile() if mode & SecretInputMode.KEYFILE else None
            securefs_create(
                data_dir=cls.data_dir,
                password=cls.password,
                version=version,
                keyfile=cls.keyfile,
                pbkdf=pbkdf,
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
            )

        @classmethod
        def unmount(cls):
            if cls.securefs_process is None:
                return
            securefs_unmount(cls.securefs_process, cls.mount_point)
            cls.securefs_process = None

        def test_long_name(self):
            with self.assertRaises(EnvironmentError) as context:
                os.mkdir(os.path.join(self.mount_point, "k" * 256))
                self.fail("mkdir should fail")
            if sys.platform != "win32":
                self.assertEqual(context.exception.errno, errno.ENAMETOOLONG)

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

        if version < 4 and sys.platform != "win32":

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

        if sys.platform != "win32":

            def test_symlink(self):
                data = os.urandom(16)
                source = os.path.join(self.mount_point, str(uuid.uuid4()))
                dest = os.path.join(self.mount_point, str(uuid.uuid4()))
                try:
                    with open(source, "wb") as f:
                        f.write(data)
                    os.symlink(source, dest)
                    self.assertEqual(os.readlink(dest), source)
                    os.remove(source)
                    with self.assertRaises(EnvironmentError):
                        with open(dest, "rb") as f:
                            f.read()
                finally:
                    try:
                        os.remove(source)
                    except EnvironmentError:
                        pass
                    try:
                        os.remove(dest)
                    except EnvironmentError:
                        pass

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
            with open(rng_filename, "rb") as f:
                self.assertEqual(f.read(), random_data)
            data = b"\0" * len(random_data) + b"0"
            with open(rng_filename, "wb") as f:
                f.write(data)
            with open(rng_filename, "rb") as f:
                self.assertEqual(f.read(), data)
            os.remove(rng_filename)
            for n in dir_names:
                os.mkdir(os.path.join(self.mount_point, n))
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

        if version == 3:

            def test_time(self):
                rand_dirname = os.path.join(self.mount_point, str(uuid.uuid4()))
                os.mkdir(rand_dirname)
                st = os.stat(rand_dirname)
                self.assertTrue(
                    st.st_atime == st.st_ctime and st.st_ctime == st.st_mtime
                )
                self.assertAlmostEqual(st.st_atime, time.time(), delta=10)
                rand_filename = os.path.join(rand_dirname, "abc")
                with open(rand_filename, "w") as f:
                    f.write("1")
                os.utime(rand_filename, (1000.0, 1000.0))
                st = os.stat(rand_filename)
                self.assertEqual(st.st_mtime, 1000)
                with open(rand_filename, "w") as f:
                    f.write("1")
                st = os.stat(rand_filename)
                self.assertAlmostEqual(st.st_ctime, time.time(), delta=10)

    return SimpleSecureFSTestBase


reference_data_dir = shutil.copytree(
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "reference"),
    f"tmp/{uuid.uuid4()}",
)


def make_regression_test(version: int, pbkdf: str, mode: SecretInputMode):
    class RegressionTestBase(unittest.TestCase):
        """
        Ensures that future versions of securefs can read old versions just fine.
        """

        def test_regression(self):
            mount_point = get_mount_point()
            config_filename = os.path.join(
                reference_data_dir, str(version), f".securefs.{pbkdf}.{mode.name}.json"
            )
            p = securefs_mount(
                os.path.join(reference_data_dir, str(version)),
                mount_point,
                password="abc" if mode & SecretInputMode.PASSWORD else None,
                keyfile=os.path.join(reference_data_dir, "keyfile")
                if mode & SecretInputMode.KEYFILE
                else None,
                config_filename=config_filename,
            )
            try:
                self.compare_directory(
                    os.path.join(reference_data_dir, "plain"), mount_point
                )
            finally:
                securefs_unmount(p, mount_point)

        def compare_directory(self, dir1, dir2):
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

    return RegressionTestBase


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


def make_chpass_test(
    old_pass, new_pass, old_keyfile, new_keyfile, use_stdin, version, pbkdf
):
    class ChpassTestBase(unittest.TestCase):
        def test_chpass(self):
            data_dir = get_data_dir()
            mount_point = get_mount_point()
            test_dir_path = os.path.join(mount_point, "test")

            securefs_create(
                data_dir=data_dir,
                password=old_pass,
                keyfile=old_keyfile,
                version=version,
                pbkdf=pbkdf,
            )

            self.assertFalse(os.path.exists(test_dir_path))

            p = securefs_mount(data_dir, mount_point, old_pass, old_keyfile)
            try:
                os.mkdir(test_dir_path)
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
                pbkdf=pbkdf,
            )

            p = securefs_mount(data_dir, mount_point, new_pass, new_keyfile)
            try:
                self.assertTrue(os.path.isdir(test_dir_path))
            finally:
                securefs_unmount(p, mount_point)

    return ChpassTestBase


def make_all_tests():
    all_pbkdfs = ("scrypt", "pkcs5-pbkdf2-hmac-sha256", "argon2id")

    # `securefs` has two different methods of operating on keyfiles, but on new repos, only one is supported.
    for version, mode, pbkdf in itertools.product(
        range(1, 5),
        [
            SecretInputMode.PASSWORD,
            SecretInputMode.KEYFILE2,
            SecretInputMode.PASSWORD_WITH_KEYFILE2,
        ],
        all_pbkdfs,
    ):
        params = dict(version=version, mode=mode, pbkdf=pbkdf)
        class_name = f"SimpleSecureFSTest{params}"
        globals()[class_name] = type(class_name, (make_test_case(**params),), {})

    # For regression test, however, we need to test all modes.
    for version, mode, pbkdf in itertools.product(
        range(1, 5), SecretInputMode, all_pbkdfs
    ):
        params = dict(version=version, mode=mode, pbkdf=pbkdf)
        class_name = f"RegressionTest{params}"
        globals()[class_name] = type(
            class_name,
            (make_regression_test(**params),),
            {},
        )

    old_passes = [None, "abc"]
    new_passes = [None, "def"]
    old_keyfiles = [None, generate_keyfile()]
    new_keyfiles = [None, generate_keyfile()]

    for (
        old_pass,
        new_pass,
        old_keyfile,
        new_keyfile,
        use_stdin,
        version,
        pbkdf,
    ) in itertools.product(
        old_passes,
        new_passes,
        old_keyfiles,
        new_keyfiles,
        [True, False],
        range(1, 5),
        all_pbkdfs,
    ):
        if not old_pass and not old_keyfile:
            continue
        if not new_pass and not new_keyfile:
            continue
        params = dict(
            old_pass=old_pass,
            new_pass=new_pass,
            old_keyfile=old_keyfile,
            new_keyfile=new_keyfile,
            use_stdin=use_stdin,
            version=version,
            pbkdf=pbkdf,
        )
        class_name = f"ChpassTest{params}"
        globals()[class_name] = type(
            class_name,
            (make_chpass_test(**params),),
            {},
        )


make_all_tests()

if __name__ == "__main__":
    os.environ["SECUREFS_ARGON2_M_COST"] = "16"
    os.environ["SECUREFS_ARGON2_P"] = "2"
    logging.getLogger().setLevel(logging.INFO)
    unittest.main()
