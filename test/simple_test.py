#!/usr/bin/python3
# coding: utf-8
import os
import subprocess
import unittest
import tempfile
import shutil
import errno
import platform
import time
import traceback
import uuid
import sys
import stat
import traceback
import signal


def find_securefs_binary():
    for dir_path, _, files in os.walk("."):
        for fn in files:
            if fn == "securefs" or fn == "securefs.exe":
                return os.path.join(dir_path, fn)
    raise RuntimeError("securefs binary not found")


SECUREFS_BINARY = find_securefs_binary()

IS_WINDOWS = os.name == "nt"

if platform.system() == "Darwin":
    try:
        import xattr
    except ImportError:
        sys.stderr.write(
            'Importing module "xattr" failed. Testing for extended attribute support is skipped\n'
        )
        xattr = None
else:
    xattr = None


class TimeoutException(BaseException):
    def __init__(self):
        BaseException.__init__(self, "Operation timeout")


def securefs_mount(data_dir: str, mount_point: str, password: str) -> subprocess.Popen:
    if mount_point.endswith("\\"):
        mount_point = mount_point.rstrip("\\")
    p = subprocess.Popen(
        [
            SECUREFS_BINARY,
            "mount",
            "--log",
            "XXXX.log",
            "--trace",
            data_dir,
            mount_point,
        ],
        stdin=subprocess.PIPE,
        stderr=subprocess.PIPE,
        encoding="utf-8",
        universal_newlines=True,
        creationflags=0 if not IS_WINDOWS else subprocess.CREATE_NEW_PROCESS_GROUP,
    )
    p.stdin.write(password)
    p.stdin.write("\n")

    for _ in range(100):
        time.sleep(0.1)
        try:
            if os.path.ismount(mount_point):
                return p
        except EnvironmentError:
            traceback.print_exc()
    raise TimeoutException()


def securefs_unmount(p: subprocess.Popen, mount_point: str):
    try:
        p.send_signal(signal.CTRL_C_EVENT)
        code, err = p.communicate(timeout=5)
        if code:
            raise RuntimeError(f"Failed to unmount securefs: {err}")
    except:
        if os.path.ismount(mount_point):
            raise  # Still mounted
        traceback.print_exc()


def securefs_create(data_dir, password, version):
    p = subprocess.Popen(
        [
            SECUREFS_BINARY,
            "create",
            "--format",
            str(version),
            data_dir,
            "--rounds",
            "4",
        ],
        stdin=subprocess.PIPE,
        stderr=subprocess.PIPE,
        encoding="utf-8",
        universal_newlines=True,
    )
    out, err = p.communicate(input=password + "\n" + password + "\n")
    if p.returncode:
        raise RuntimeError(err)


def make_test_case(format_version):
    class SimpleSecureFSTestBase(unittest.TestCase):
        @classmethod
        def setUpClass(cls):
            try:
                os.mkdir("tmp")
            except EnvironmentError as e:
                if e.errno != errno.EEXIST:
                    raise
            cls.data_dir = tempfile.mkdtemp(
                prefix="securefs.format{}.data_dir".format(format_version), dir="tmp"
            )
            if IS_WINDOWS:
                cls.mount_point = "T:\\"
            else:
                cls.mount_point = tempfile.mkdtemp(
                    prefix="securefs.format{}.mount_point".format(format_version),
                    dir="tmp",
                )
            cls.password = "pvj8lRgrrsqzlr"
            securefs_create(cls.data_dir, cls.password, format_version)
            cls.mount()

        @classmethod
        def tearDownClass(cls):
            cls.unmount()

        @classmethod
        def mount(cls):
            cls.securefs_process = securefs_mount(
                cls.data_dir, cls.mount_point, cls.password
            )

        @classmethod
        def unmount(cls):
            if cls.securefs_process is None:
                return
            securefs_unmount(cls.securefs_process, cls.mount_point)
            cls.securefs_process = None

        def test_long_name(self):
            try:
                os.mkdir(os.path.join(self.mount_point, "k" * 256))
                self.fail("mkdir should fail")
            except EnvironmentError as e:
                self.assertEqual(e.errno, errno.ENAMETOOLONG)

        if xattr:

            def test_xattr(self):
                fn = os.path.join(self.mount_point, str(uuid.uuid4()))
                try:
                    with open(fn, "wt") as f:
                        f.write("hello\n")
                    x = xattr.xattr(fn)
                    x.set("abc", "def")
                    x.set("123", "456")
                    self.unmount()
                    self.mount()
                    self.assertEqual(x.get("abc"), "def")
                    self.assertEqual(set(x.list()), {"abc", "123"})
                    xattr.removexattr(fn, "abc")
                    self.assertEqual(set(x.list()), {"123"})
                finally:
                    try:
                        os.remove(fn)
                    except EnvironmentError:
                        pass

        if format_version < 4 and not IS_WINDOWS:

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

        if not IS_WINDOWS:

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
                except:
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
                shutil.rmtree(os.path.join(self.mount_point, dn))

        if format_version == 3:

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


class TestVersion1(make_test_case(1)):
    pass


class TestVersion2(make_test_case(2)):
    pass


class TestVersion3(make_test_case(3)):
    pass


class TestVersion4(make_test_case(4)):
    pass


if __name__ == "__main__":
    unittest.main()
