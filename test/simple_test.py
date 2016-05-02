#!/usr/bin/env python
# coding: utf-8
import os
import subprocess
import unittest
import tempfile
import shutil
import sys
import platform


SECUREFS_BINARY = './securefs'

if platform.system() == 'Darwin':
    UNMOUNT = ['umount']
else:
    UNMOUNT = ['fusermount', '-u']


def securefs_mount(data_dir, mount_point, password):
    p = subprocess.Popen([SECUREFS_BINARY, 'mount', '--stdinpass', '--background', data_dir, mount_point],
                         stdin=subprocess.PIPE, stderr=subprocess.PIPE)
    out, err = p.communicate(input=password+'\n')
    if p.returncode:
        raise RuntimeError(err)


def securefs_unmount(mount_point):
    p = subprocess.Popen(UNMOUNT + [mount_point], stderr=subprocess.PIPE)
    out, err = p.communicate()
    if p.returncode:
        raise RuntimeError(err)


def securefs_create(data_dir, password, version):
    p = subprocess.Popen([SECUREFS_BINARY, 'create', '--stdinpass', '--ver', str(version), data_dir, '--rounds', '1'],
                         stdin=subprocess.PIPE, stderr=subprocess.PIPE)
    out, err = p.communicate(input=password+'\n')
    if p.returncode:
        raise RuntimeError(err)


class SimpleSecureFSTestBase(object):
    def setUp(self):
        self.data_dir = tempfile.mkdtemp(prefix='securefs.data_dir')
        self.mount_point = tempfile.mkdtemp(prefix='securefs.mount_point')
        self.password = 'madoka'
        securefs_create(self.data_dir, self.password, self.version)
        
    def tearDown(self):
        try:
            securefs_unmount(self.mount_point)
        except:
            pass
        shutil.rmtree(self.data_dir)
        shutil.rmtree(self.mount_point)
        
    def mount(self):
        return securefs_mount(self.data_dir, self.mount_point, self.password)
    
    def unmount(self):
        return securefs_unmount(self.mount_point)
        
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


class TestVersion1(unittest.TestCase, SimpleSecureFSTestBase):
    def setUp(self):
        self.version = 1
        SimpleSecureFSTestBase.setUp(self)


class TestVersion2(unittest.TestCase, SimpleSecureFSTestBase):
    def setUp(self):
        self.version = 2
        SimpleSecureFSTestBase.setUp(self)
        

if __name__ == '__main__':
	unittest.main()

