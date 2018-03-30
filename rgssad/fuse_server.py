#!/usr/bin/env python3
# This file is part of rgssad-fuse.

# rgssad-fuse is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# rgssad-fuse is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with rgssad-fuse.  If not, see <http://www.gnu.org/licenses/>.

import argparse
import errno
import llfuse
import logging
import os
import stat
import threading

from . import core

from collections import deque


class FileHandleTable(object):
    def __init__(self):
        self.logger = logging.getLogger('rgssad_fuse.FileHandleTable')
        self._lock = threading.Lock()
        self._fh = {}
        self._recycled_ids = deque()
        self._last_avaliable_id = 0

    def _check_fh(self, fh):
        if fh >= self._last_avaliable_id or fh not in self._fh:
            raise IndexError('Invalid fh')

    def _islast(self, fh):
        return fh == self._last_avaliable_id - 1

    def alloc(self, data=None):
        self.logger.debug('alloc()')
        try:
            self._lock.acquire()
            if len(self._recycled_ids) == 0:
                fh = self._last_avaliable_id
                self._last_avaliable_id += 1
            else:
                fh = self._recycled_ids.popleft()

            self._fh[fh] = data
        finally:
            self._lock.release()

        self.logger.debug('alloc(): fh=%d', fh)
        return fh

    def free(self, fh):
        self.logger.debug('free(): fh=%d', fh)
        try:
            self._lock.acquire()
            self._check_fh(fh)

            del self._fh[fh]
            self._recycled_ids.append(fh)
        finally:
            self._lock.release()

    def get(self, fh):
        self.logger.debug('get(): fh=%d', fh)
        self._check_fh(fh)
        return self._fh[fh]

    def set(self, fh, data):
        self.logger.debug('set(): fh=%d', fh)
        try:
            self._lock.acquire()
            self._check_fh(fh)
            self._fh[fh] = data
        finally:
            self._lock.release()


class RgssadFuse(llfuse.Operations):
    def __init__(self, arc_filename, uid=None, gid=None, umask=0o022, fmask=0o133, dmask=None):
        super().__init__()
        self.logger = logging.getLogger('rgssad_fuse.RgssadFuse')

        self._fh = FileHandleTable()

        self.archive = core.Archive(arc_filename)
        if uid is not None:
            self.uid = uid
        else:
            self.uid = os.getuid()
        if gid is not None:
            self.gid = gid
        else:
            self.gid = os.getgid()

        assert not (fmask is None and dmask is None and umask is None)
        if fmask is not None:
            self.fmask = fmask
        else:
            self.fmask = umask
        if dmask is not None:
            self.dmask = dmask
        else:
            self.dmask = umask

        # Set atime, ctime, mtime according to the RGSSAD file
        arc_stat = os.stat(self.archive.filename)
        self._arc_atime = arc_stat.st_atime * 1e9
        self._arc_ctime = arc_stat.st_ctime * 1e9
        self._arc_mtime = arc_stat.st_mtime * 1e9

    def _file_perm(self):
        return (~self.fmask) & 0o777

    def _dir_perm(self):
        return (~self.dmask) & 0o777

    def getattr(self, inode, ctx=None):
        self.logger.debug('getattr(): inode=%d', inode)
        entry = llfuse.EntryAttributes()

        try:
            arc_entry = self.archive.read_inode(_if2a(inode))
        except IndexError:
            raise llfuse.FUSEError(errno.ENOENT)
        arc_entry_type = arc_entry['type']

        entry.st_ino = inode

        if arc_entry_type == 'd':
            entry.st_mode = (stat.S_IFDIR | self._dir_perm())
            entry.st_size = 0
        elif arc_entry_type == 'f':
            entry.st_mode = (stat.S_IFREG | self._file_perm())
            entry.st_size = arc_entry['size']
        else:
            assert False, 'Unknown entry type'

        entry.st_atime_ns = self._arc_atime
        entry.st_ctime_ns = self._arc_ctime
        entry.st_mtime_ns = self._arc_mtime

        entry.st_uid = self.uid
        entry.st_gid = self.gid

        return entry

    def lookup(self, parent_inode, name, ctx=None):
        self.logger.debug('lookup(): parent_inode=%d, name=%s', parent_inode, name)
        arc_inode = self.archive.lookup(_if2a(parent_inode), name.decode('utf-8'))
        if arc_inode is None:
            raise llfuse.FUSEError(errno.ENOENT)
        return self.getattr(_ia2f(arc_inode))

    def opendir(self, inode, ctx):
        self.logger.debug('opendir(): inode=%d', inode)
        if not self.archive.exists(_if2a(inode)) or \
                not self.archive.isdir(_if2a(inode)):
            raise llfuse.FUSEError(errno.ENOENT)
        fh = self._fh.alloc({'type': 'd', 'ref': _if2a(inode)})

        return fh

    def readdir(self, fh, off):
        self.logger.debug('readdir(): fh=%d, off=%d', fh, off)
        fhobj = self._fh.get(fh)
        assert fhobj['type'] == 'd', \
            'readdir() with invalid fh'

        for ctr, entry in enumerate(self.archive.readdir(fhobj['ref'], off or None)):
            yield (entry['name'].encode('utf-8'), self.getattr(_ia2f(entry['id'])), ctr + off + 1)

    def open(self, inode, flags, ctx):
        self.logger.debug('open(): inode=%d, flags=%d', inode, flags)
        if self.archive.exists(_if2a(inode)):
            if self.archive.isdir(_if2a(inode)):
                raise llfuse.FUSEError(errno.EISDIR)
        else:
            raise llfuse.FUSEError(errno.ENOENT)

        if flags & os.O_RDWR or flags & os.O_WRONLY:
            raise llfuse.FUSEError(errno.EROFS)

        fh = self._fh.alloc({'type': 'f', 'ref': self.archive.open(_if2a(inode))})
        return fh

    def read(self, fh, off, size):
        self.logger.debug('read(): fh=%d, off=%d, size=%d', fh, off, size)
        fhobj = self._fh.get(fh)
        assert fhobj['type'] == 'f', \
            'read() with invalid fh'

        fhobj['ref'].seek(off)
        return fhobj['ref'].read(size)

    def release(self, fh):
        self.logger.debug('release(): fh=%d', fh)
        fhobj = self._fh.get(fh)
        assert fhobj['type'] == 'f', \
            'release() with invalid fh'
        fhobj['ref'].close()
        self._fh.free(fh)

    def releasedir(self, fh):
        self.logger.debug('releasedir(): fh=%d', fh)
        fhobj = self._fh.get(fh)
        assert fhobj['type'] == 'd', \
            'releasedir() with invalid fh'
        self._fh.free(fh)


def _if2a(inode):
    return inode - llfuse.ROOT_INODE

def _ia2f(inode):
    return llfuse.ROOT_INODE + inode

def parse_args():
    _xmask = lambda n: None if n is None else (int(n, 8) & 0o777)
    p = argparse.ArgumentParser()
    p.add_argument('rgssad', type=str,
                   help='RGSSAD file that needs to be mounted')
    p.add_argument('dir', type=str,
                   help='Target mount point')
    p.add_argument('-v', '--debug',
                   action='store_true',
                   help='Enable debug output')
    p.add_argument('-V', '--debug-fuse',
                   action='store_true',
                   help='Enable debug output from FUSE')
    p.add_argument('-j', '--workers', type=int,
                   default=1,
                   help='Maximum workers')
    p.add_argument('-u', '--uid', type=int,
                   default=None,
                   help='Override UID')
    p.add_argument('-g', '--gid', type=int,
                   default=None,
                   help='Override GID')
    p.add_argument('-U', '--umask', type=_xmask,
                   default=0o022,
                   help='Override umask')
    p.add_argument('-D', '--dmask', type=_xmask,
                   default=None,
                   help='Override dmask')
    p.add_argument('-F', '--fmask', type=_xmask,
                   default=0o133,
                   help='Override fmask')
    p.add_argument('-c', '--crypto-impl', type=str,
                   default='c',
                   help='Implementation of the crypto module (c, py)')
    return p, p.parse_args()

def main():
    p, args = parse_args()
    logging.basicConfig(level=(logging.INFO, logging.DEBUG)[int(args.debug)])
    core.set_crypto_impl(args.crypto_impl)
    svr = RgssadFuse(
        args.rgssad,
        uid=args.uid,
        gid=args.gid,
        umask=args.umask,
        dmask=args.dmask,
        fmask=args.fmask
    )
    fuse_options = set(llfuse.default_options)
    fuse_options.add('ro')
    fuse_options.add('subtype=rgssad-fuse')
    fuse_options.add('fsname={}'.format(args.rgssad.replace(',', r'\,')))
    if args.debug_fuse:
        fuse_options.add('debug')

    llfuse.init(svr, args.dir, fuse_options)

    try:
        llfuse.main(workers=args.workers)
    except:
        llfuse.close(unmount=False)
        raise

    llfuse.close()

if __name__ == '__main__':
    main()
