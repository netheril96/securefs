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

        def runTest(self):
            dir_names = set(str(i) for i in xrange(2))
            self.mount()
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
            self.unmount()

    return SimpleSecureFSTestBase


class TestVersion1(make_test_case(1)):
    pass


class TestVersion2(make_test_case(2)):
    pass


if __name__ == '__main__':
    unittest.main()
