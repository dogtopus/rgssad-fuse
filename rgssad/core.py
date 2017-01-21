#!/usr/bin/env python3
import os
import ntpath
import io
import struct
import logging

try:
    from . import _crypto as crypto
except ImportError:
    from . import crypto


class Archive(object):
    def __init__(self, arc_filename):
        self.logger = logging.getLogger('rgssad.Archive')
        self.filename = arc_filename
        self.inodes = [{
            'type': 'd',
            'children': [
                {'id': 0, 'name': '.'},
                {'id': 0, 'name': '..'}
            ]
        }]
        self._build_directory_tree()

    def _parse_metadata(self):
        def _parser_v1(arc):
            magickey = crypto.MagicKeyFactory()
            xorer = crypto.XORer(arc, magickey)
            while arc.tell() < arc_size:
                # Extract file paths
                fn_len = xorer.read_32bits(1)[0]
                fn = xorer.read_data_8bit(fn_len)
                f_size = xorer.read_32bits(1)[0]
                self.logger.debug('fn_len=%d fn=%s f_size=%d, key=0x%08x', fn_len, fn, f_size, magickey.get_key())
                yield fn.decode('utf-8'), arc.tell(), f_size, magickey.get_key()
                arc.seek(f_size, io.SEEK_CUR)
            arc_size = os.path.getsize(self.filename)

        def _parser_v3(arc):
            metadata_key_seed = struct.unpack('<I', arc.read(4))[0]
            metadata_key = (metadata_key_seed * 9 + 3) & 0xffffffff
            self.logger.debug('Using metadata_key=0x%08x', metadata_key)
            xorer = crypto.XORer(arc, crypto.StaticMagicKeyFactory(iv=metadata_key))
            while True:
                f_offset, f_size, subkey, fn_len = xorer.read_32bits(4)
                self.logger.debug('fn_len=%d, f_offset=%d, f_size=%d, key=0x%08x', fn_len, f_offset, f_size, subkey)
                if f_offset == 0:
                    break
                fn = xorer.read_32bits_unaligned(fn_len)
                self.logger.debug('fn=%s', fn)
                yield fn.decode('utf-8'), f_offset, f_size, subkey

        with open(self.filename, 'rb') as arc:
            # check magic
            magic, ver = struct.unpack('<6sxB', arc.read(8))
            if magic != b'RGSSAD' or ver not in (1, 2, 3):
                self.logger.error('Invalid magic=%s ver=%d', magic, ver)
                raise RuntimeError('Unsupported file type')
            elif ver in (1, 2):
                yield from _parser_v1(arc)
            elif ver == 3:
                yield from _parser_v3(arc)
            else:
                assert False, 'Something went wrong on version checking'
                yield from tuple()

    def _build_directory_tree(self):
        '''Extract the list of files and build directory tree'''
        def _mknod(parent_inode, name, entry_type):
            self.inodes.append({'type': entry_type})
            inode = len(self.inodes) - 1
            self.inodes[parent_inode]['children'].append({'id': inode, 'name': name})
            return inode

        def _add_file_entry(parent_inode, name, offset, size, magickey):
            inode = _mknod(parent_inode, name, 'f')
            self.inodes[inode].update({
                'offset': offset,
                'size': size,
                'magickey': magickey
            })
            self.logger.debug('new file ent %s under %d (inode=%d)', name, parent_inode, inode)
            self.logger.debug('  size=%d, key=0x%08x', size, magickey)
            return inode

        def _mkdir(parent_inode, name):
            inode = _mknod(parent_inode, name, 'd')
            self.inodes[inode].update({
                'children': [
                    {'id': inode, 'name': '.'},
                    {'id': parent_inode, 'name': '..'},
                ]
            })
            self.logger.debug('mkdir %s under %d (inode=%d)', name, parent_inode, inode)
            return inode

        def _nt_mkdir_p(path):
            cur_inode = 0
            for p in ntpath.normpath(path).split(ntpath.sep):
                next_inode = self.lookup(cur_inode, p)
                if next_inode is not None:
                    self.logger.debug('cd %s (inode %d)', p, next_inode)
                    cur_inode = next_inode
                else:
                    cur_inode = _mkdir(cur_inode, p)
            return cur_inode

        for md_entry in self._parse_metadata():
            dirname, basename = ntpath.split(ntpath.normpath(md_entry[0]))
            inode = _nt_mkdir_p(dirname)
            _add_file_entry(inode, basename, md_entry[1], md_entry[2], md_entry[3])

        # It's probably not possible to have a empty directory in rgssad, so we
        # assume there aren't any of them

    def readdir(self, inode, offset=None):
        if offset is None:
            dirdata = self.inodes[inode]['children']
        else:
            dirdata = self.inodes[inode]['children'][offset:]

        for direntry in dirdata:
            yield direntry

    def lookup(self, parent_inode, name):
        for direntry in self.readdir(parent_inode):
            if name == direntry['name']:
                return direntry['id']
        return None

    def exists(self, inode):
        try:
            return self.inodes[inode] is not None
        except IndexError:
            return False

    def isfile(self, inode):
        '''Check if the specified path in the archive is a file '''
        return self.inodes[inode]['type'] == 'f'

    def isdir(self, inode):
        '''Check if the specified path in the archive is a directory '''
        return self.inodes[inode]['type'] == 'd'

    def read_inode(self, inode):
        return self.inodes[inode]

    def open(self, inode):
        '''Open a file in the archive and return a file-like object'''
        assert self.isfile(inode), 'inode is not a file'
        entry = self.inodes[inode]
        return File(self.filename,
                    entry['offset'],
                    entry['size'],
                    entry['magickey'])


class File(io.FileIO):
    def __init__(self, arc_filename, offset, length, magickey):
        super().__init__(arc_filename, mode='rb')
        self.logger = logging.getLogger('rgssad.File')
        self.vfile_base = offset
        self.vfile_length = length
        self.magickey = crypto.MagicKeyFactory(magickey)
        self.xorer = crypto.XORer(super(), self.magickey)
        super().seek(self.vfile_base)

    def _read_data_32bit(self, count):
        '''
        Reads XORed data into bytes (32-bit unaligned block)
        '''
        if count <= 0:
            return ''

        truncate_bytes = self.tell() % 4
        data = self.xorer.read_32bits_unaligned(count, truncate_bytes)

        return data

    def seek(self, offset, whence=io.SEEK_SET):
        if (whence == io.SEEK_SET and offset < 0) or \
                (whence == io.SEEK_CUR and (offset + self.tell()) < 0) or \
                (whence == io.SEEK_END and (offset + self.vfile_length) < 0):
            raise ValueError('Negative seek position {0}'.format(offset))

        # offsets (in 32-bit blocks)
        block_count = offset // 4
        cur_block = self.tell() // 4

        offset_real = offset
        # crazy magickey stuff
        # TODO: maybe we can get rid of block_count and cur_block?

        # Seek from beginning, offset is larger than or equal to current
        # offset
        # Relative skip (which is faster than reset & skip)
        if whence == io.SEEK_SET and block_count >= cur_block:
            self.magickey.skip(block_count - cur_block)
            offset_real += self.vfile_base

        # Seek from beginning, offset is smaller than current offset
        # Reset & skip as-is
        elif whence == io.SEEK_SET and block_count < cur_block:
            self.magickey.reset()
            self.magickey.skip(block_count)
            offset_real += self.vfile_base

        # Seek from current offset, positive direction
        # Just skip as-is
        elif whence == io.SEEK_CUR and block_count >= 0:
            self.magickey.skip((self.tell() % 4 + offset) // 4)

        # Seek from current offset, negative direction
        # Reset & skip to the absolute block
        elif whence == io.SEEK_CUR and block_count < 0:
            self.magickey.reset()
            self.magickey.skip((self.tell() + offset) // 4)

        # Seek from eof
        # Reset & skip to the absolute block
        elif whence == io.SEEK_END:
            self.magickey.reset()
            self.magickey.skip((self.vfile_length + offset) // 4)

        super().seek(offset_real, whence)
        return self.tell()

    def read(self, size=-1):
        if size < 0 or size > (self.vfile_length - self.tell()):
            return self.readall()
        else:
            return self._read_data_32bit(size)

    def readall(self):
        # size = virtual_len - virtual_pos
        return self._read_data_32bit(self.vfile_length - self.tell())

    def tell(self):
        # virtual_pos = real_pos - base
        return self.tell_real() - self.vfile_base

    def tell_real(self):
        return super().tell()
