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

import logging
from libc.stdio cimport fdopen, fread, fseek, ftell, SEEK_CUR, SEEK_SET, FILE, printf
from libc.stdlib cimport malloc, free
from libc.string cimport memset
from libc.stdint cimport uint32_t
from .crypto import xgcd, lcg_gen, LCG_TABLE


cdef class MagicKeyFactory:
    cdef uint32_t iv
    cdef uint32_t key
    cpdef object logger
    cdef uint32_t _lcg_table[30][3]
    cpdef bool can_rewind

    def __init__(self, uint32_t iv=0xdeadcafe, tuple lcg_table=LCG_TABLE):
        self.can_rewind = True
        self._init_clcg_table(lcg_table)
        self.logger = logging.getLogger('rgssad.MagicKeyFactory')
        self.iv = iv
        self.key = 0
        self.reset()

    cdef inline void _init_clcg_table(self, tuple pylcg):
        # only copy 30x3 numbers
        for i in range(30):
            for j in range(3):
                if not self.can_rewind:
                    continue
                if j == 2 and pylcg[i][j] is None:
                    self.can_rewind = False
                    self._lcg_table[i][j] = 0
                else:
                    # cython should handle other sanity issues
                    self._lcg_table[i][j] = (pylcg[i][j] & 0xffffffffUL)

    cpdef uint32_t get_key(self):
        return self.key

    cpdef uint32_t get_next(self):
        cdef uint32_t key = self.key
        self._transform()
        return key

    cpdef skip(self, unsigned long long count):
        cdef unsigned long long i = 0
        self.logger.debug('skip %d block(s)', count)
        for i in range(count):
            self._transform()

    cpdef rewind(self, unsigned long long count):
        cdef unsigned long long i = 0
        self.logger.debug('rewind %d block(s)', count)
        for i in range(count):
            self._transform_backwards()

    cdef inline void _transform(self):
        self.key *= self._lgc_table[0][0]
        self.key += self._lgc_table[0][1]

    cdef inline void _transform_backwards(self):
        self.key -= self._lgc_table[0][1]
        self.key *= self._lgc_table[0][2]

    cpdef one_step_rollback(self):
        self._transform_backwards()

    cpdef reset(self):
        self.logger.debug('key reset')
        self.key = self.iv


cdef class StaticMagicKeyFactory(MagicKeyFactory):
    def __init__(self, uint32_t iv=0xdeadcafe):
        self.iv = iv

    cpdef uint32_t get_next(self):
        return self.iv

    cpdef skip(self, unsigned long long count):
        pass

    cpdef rewind(self, unsigned long long count):
        pass

    cpdef one_step_rollback(self):
        pass

    cpdef reset(self):
        pass


cdef class XORer:
    cdef object io_obj
    cdef MagicKeyFactory magickey_obj
    # TODO: This won't work on io objects other than a file
    cdef FILE *_io_handle
    cpdef object logger

    def __init__(self, io_obj, MagicKeyFactory magickey_obj):
        self.logger = logging.getLogger('rgssad.XORer')
        self.io_obj = io_obj
        self.magickey_obj = magickey_obj
        self._io_handle = fdopen(io_obj.fileno(), 'rb')
        if self._io_handle == NULL:
            raise MemoryError("Cannot attach to file descriptor")
        self._pull_offset()
        self._push_offset()

    cdef inline void _pull_offset(self):
        self.logger.debug("_pull_offset(): %d -> %d", ftell(self._io_handle), self.io_obj.tell())
        fseek(self._io_handle, self.io_obj.tell(), SEEK_SET)
        #self.logger.debug("_pull_offset(): py: %d, c: %d", ftell(self._io_handle), self.io_obj.tell())

    cdef inline void _push_offset(self):
        self.logger.debug("_push_offset(): %d -> %d", self.io_obj.tell(), ftell(self._io_handle))
        self.io_obj.seek(ftell(self._io_handle))
        #self.logger.debug("_pull_offset(): py: %d, c: %d", ftell(self._io_handle), self.io_obj.tell())

    cdef void _read_8bits(self, unsigned char *buf, size_t count):
        cdef size_t i
        self._pull_offset()
        self.logger.debug("read %d bytes", count)
        fread(<void *>buf, sizeof(unsigned char), count, self._io_handle)
        for i in range(count):
            buf[i] ^= (self.magickey_obj.get_next() & 0xff)
        self._push_offset()

    cdef void _read_32bits(self, uint32_t *buf, size_t count):
        cdef size_t i
        self._pull_offset()
        self.logger.debug("read %d ints", count)
        fread(<void *>buf, sizeof(uint32_t), count, self._io_handle)
        for i in range(count):
            buf[i] ^= self.magickey_obj.get_next()
        self._push_offset()

    cdef void _read_32bits_unaligned(self,
                                     uint32_t *buf,
                                     size_t count,
                                     size_t count_bytes,
                                     char rollback,
                                     unsigned int left_offset):
        cdef size_t i
        self._pull_offset()
        self.logger.debug("read %d bytes (%d int blocks)", count_bytes, count)
        fread(<void *> &((<unsigned char *> buf)[left_offset]), sizeof(unsigned char), count_bytes, self._io_handle)
        for i in range(count):
            buf[i] ^= self.magickey_obj.get_next()

        if rollback != 0:
            self.magickey_obj.one_step_rollback()
        self._push_offset()

    def read_8bits(self, size_t count):
        cdef size_t i
        cdef tuple result
        cdef unsigned char *buf

        try:
            buf = <unsigned char *> malloc(count * sizeof(unsigned char))
            if buf == NULL:
                raise MemoryError("Cannot allocate buffer")
            self._read_8bits(buf, count)
            result = tuple(buf[i] for i in range(count))
        finally:
            if buf != NULL:
                free(buf)

        return result

    def read_data_8bit(self, size_t count):
        cdef bytes result
        cdef unsigned char *buf

        try:
            buf = <unsigned char *> malloc(count * sizeof(unsigned char))
            if buf == NULL:
                raise MemoryError("Cannot allocate buffer")
            memset(<void *> buf, 0, count * sizeof(unsigned char))
            self._read_8bits(buf, count)
            result = buf[:(count * sizeof(unsigned char))]
        finally:
            if buf != NULL:
                free(buf)

        return result

    def read_32bits(self, size_t count):
        cdef size_t i
        cdef tuple result
        cdef uint32_t *buf

        try:
            buf = <uint32_t *> malloc(count * sizeof(uint32_t))
            if buf == NULL:
                raise MemoryError("Cannot allocate buffer")
            memset(<void *> buf, 0, count * sizeof(uint32_t))
            self._read_32bits(buf, count)
            result = tuple(buf[i] for i in range(count))
        finally:
            if buf != NULL:
                free(buf)

        return result

    def read_32bits_unaligned(self, size_t count_bytes, unsigned int left_offset=0):
        cdef uint32_t *buf
        cdef size_t count
        cdef unsigned char rollback
        cdef bytes result

        count = count_bytes + left_offset
        rollback = <char> count % 4
        if count % 4 != 0:
            count /= 4
            count += 1
        else:
            count /= 4

        try:
            buf = <uint32_t *> malloc(count * sizeof(uint32_t))
            if buf == NULL:
                raise MemoryError("Cannot allocate buffer")
            memset(<void *> buf, 0, count * sizeof(uint32_t))
            self._read_32bits_unaligned(buf, count, count_bytes, rollback, left_offset)
            result = (<unsigned char *> buf)[left_offset:left_offset+count_bytes]
        finally:
            if buf != NULL:
                free(buf)

        return result
