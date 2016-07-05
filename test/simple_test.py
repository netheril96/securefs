#!/usr/bin/env python
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

SECUREFS_BINARY = './securefs'

if platform.system() == 'Darwin':
    UNMOUNT = ['umount']
else:
    UNMOUNT = ['fusermount', '-u']


def securefs_mount(data_dir, mount_point, password):
    p = subprocess.Popen([SECUREFS_BINARY, 'mount', '--stdinpass', '--background', data_dir, mount_point],
                         stdin=subprocess.PIPE, stderr=subprocess.PIPE)
    out, err = p.communicate(input=password + '\n')
    if p.returncode:
        raise RuntimeError(err)
    while 1:
        time.sleep(0.05)
        try:
            if os.path.ismount(mount_point):
                break
        except EnvironmentError:
            traceback.print_exc()


def securefs_unmount(mount_point):
    p = subprocess.Popen(UNMOUNT + [mount_point], stderr=subprocess.PIPE)
    out, err = p.communicate()
    if p.returncode:
        raise RuntimeError(err)
    while 1:
        time.sleep(0.05)
        try:
            if not os.path.ismount(mount_point):
                break
        except EnvironmentError:
            traceback.print_exc()


def securefs_create(data_dir, password, version):
    p = subprocess.Popen([SECUREFS_BINARY, 'create', '--stdinpass', '--ver', str(version), data_dir, '--rounds', '1'],
                         stdin=subprocess.PIPE, stderr=subprocess.PIPE)
    out, err = p.communicate(input=password + '\n')
    if p.returncode:
        raise RuntimeError(err)


def make_test_case(format_version):
    class SimpleSecureFSTestBase(unittest.TestCase):
        @classmethod
        def setUpClass(cls):
            try:
                os.mkdir('tmp')
            except EnvironmentError as e:
                if e.errno != errno.EEXIST:
                    raise
            cls.data_dir = tempfile.mkdtemp(prefix='securefs.format{}.data_dir'.format(format_version), dir='tmp')
            cls.mount_point = tempfile.mkdtemp(prefix='securefs.format{}.mount_point'.format(format_version), dir='tmp')
            cls.password = 'madoka'
            securefs_create(cls.data_dir, cls.password, format_version)
            securefs_mount(cls.data_dir, cls.mount_point, cls.password)

        @classmethod
        def tearDownClass(cls):
            try:
                securefs_unmount(cls.mount_point)
            except:
                if os.path.ismount(cls.mount_point):
                    raise  # Still mounted
            shutil.rmtree(cls.data_dir)
            shutil.rmtree(cls.mount_point)

        def mount(self):
            securefs_mount(self.data_dir, self.mount_point, self.password)

        def unmount(self):
            securefs_unmount(self.mount_point)

        def test_hardlink(self):
            data = os.urandom(16)
            source = os.path.join(self.mount_point, str(uuid.uuid4()))
            dest = os.path.join(self.mount_point, str(uuid.uuid4()))
            try:
                with open(source, 'wb') as f:
                    f.write(data)
                os.link(source, dest)
                source_stat = os.stat(source)
                dest_stat = os.stat(dest)
                self.assertEqual(source_stat.st_mode, dest_stat.st_mode)
                self.assertEqual(source_stat.st_mtime, dest_stat.st_mtime)
                self.assertEqual(source_stat.st_size, dest_stat.st_size)
                self.assertEqual(source_stat.st_nlink, 2)
                with open(dest, 'rb') as f:
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

        def test_symlink(self):
            data = os.urandom(16)
            source = os.path.join(self.mount_point, str(uuid.uuid4()))
            dest = os.path.join(self.mount_point, str(uuid.uuid4()))
            try:
                with open(source, 'wb') as f:
                    f.write(data)
                os.symlink(source, dest)
                self.assertEqual(os.readlink(dest), source)
                os.remove(source)
                with self.assertRaises(EnvironmentError):
                    with open(dest, 'rb') as f:
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
                with open(source, 'wb') as f:
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

        def test_read_write_mkdir_listdir_remove(self):
            dir_names = set(str(i) for i in xrange(3))
            random_data = os.urandom(1111111)
            rng_filename = os.path.join(self.mount_point, 'rng')
            with open(rng_filename, 'wb') as f:
                f.write(random_data)
            self.unmount()

            self.mount()
            with open(rng_filename, 'rb') as f:
                self.assertEqual(f.read(), random_data)
            os.remove(rng_filename)
            for n in dir_names:
                os.mkdir(os.path.join(self.mount_point, n))
            for n in dir_names:
                os.mkdir(os.path.join(self.mount_point, '0', n))
            for n in dir_names:
                os.mkdir(os.path.join(self.mount_point, '0', '1', n))
            self.unmount()

            self.mount()
            self.assertEqual(set(os.listdir(self.mount_point)), dir_names)
            self.assertEqual(set(os.listdir(os.path.join(self.mount_point, '0'))), dir_names)
            self.assertEqual(set(os.listdir(os.path.join(self.mount_point, '0', '1'))), dir_names)
            for dn in dir_names:
                shutil.rmtree(os.path.join(self.mount_point, dn))

    return SimpleSecureFSTestBase


class TestVersion1(make_test_case(1)):
    pass


class TestVersion2(make_test_case(2)):
    pass


if __name__ == '__main__':
    unittest.main()
