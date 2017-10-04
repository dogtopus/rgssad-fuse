# TODO implement a native version of XORer
import logging
from crypto import StaticMagicKeyFactory
from libc.stdio cimport fdopen, fread, fseek, SEEK_CUR, FILE
from libc.stdlib cimport malloc, free

#from crypto import XORer

cdef class MagicKeyFactory:
    cdef unsigned int iv
    cdef unsigned int key
    cpdef object logger

    def __init__(self, unsigned int iv=0xdeadcafe):
        self.logger = logging.getLogger('rgssad.MagicKeyFactory')
        self.iv = iv
        self.key = 0
        self.reset()

    cpdef unsigned int get_key(self):
        return self.key

    cpdef unsigned int get_next(self):
        cdef unsigned int key = self.key
        self._transform()
        return key

    cpdef skip(self, unsigned int count):
        cdef unsigned int i = 0
        self.logger.debug('skip %d block(s)', count)
        for i in range(count):
            self._transform()

    cpdef rewind(self, unsigned int count):
        cdef unsigned int i = 0
        self.logger.debug('rewind %d block(s)', count)
        for i in range(count):
            self._transform_backwards()

    cdef _transform(self):
        self.key *= 7
        self.key += 3

    cdef _transform_backwards(self):
        self.key -= 3
        # 0xb6db6db7 = inv(7) (mod 0x100000000)
        self.key *= <unsigned int> 0xb6db6db7

    cpdef one_step_rollback(self):
        self._transform_backwards()

    cpdef reset(self):
        self.logger.debug('key reset')
        self.key = self.iv


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

    cdef void _read_8bits(self, unsigned char *buf, unsigned int count):
        cdef unsigned int i
        fread(<void *>buf, sizeof(unsigned char), count, self._io_handle)
        for i in range(count):
            buf[i] ^= (self.magickey_obj.get_next() & 0xff)

    cdef void _read_32bits(self, unsigned int *buf, unsigned int count):
        cdef unsigned int i
        fread(<void *>buf, sizeof(unsigned int), count, self._io_handle)
        for i in range(count):
            buf[i] ^= self.magickey_obj.get_next()

    cdef void _read_32bits_unaligned(self,
                                     unsigned int *buf,
                                     unsigned int count,
                                     unsigned int count_bytes,
                                     char rollback,
                                     unsigned int left_offset):
        cdef unsigned int i

        fread(<void *> &((<unsigned char *> buf)[left_offset]), sizeof(unsigned char), count_bytes, self._io_handle)
        for i in range(count):
            buf[i] ^= self.magickey_obj.get_next()

        if rollback != 0:
            self.magickey_obj.one_step_rollback()

    def read_8bits(self, unsigned int count):
        cdef unsigned int i
        cdef object result
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

    def read_data_8bit(self, unsigned int count):
        cdef bytes result
        cdef unsigned char *buf

        try:
            buf = <unsigned char *> malloc(count * sizeof(unsigned char))
            if buf == NULL:
                raise MemoryError("Cannot allocate buffer")
            self._read_8bits(buf, count)
            result = buf[:(count * sizeof(unsigned char))]
        finally:
            if buf != NULL:
                free(buf)

        return result

    def read_32bits(self, unsigned int count):
        cdef unsigned int i
        cdef object result
        cdef unsigned int *buf

        try:
            buf = <unsigned int *> malloc(count * sizeof(unsigned int))
            if buf == NULL:
                raise MemoryError("Cannot allocate buffer")
            self._read_32bits(buf, count)
            result = tuple((<unsigned char *> buf)[i] for i in range(count * sizeof(unsigned int)))
        finally:
            if buf != NULL:
                free(buf)

        return result

    def read_32bits_unaligned(self, unsigned int count_bytes, unsigned int left_offset=0):
        cdef unsigned int *buf
        cdef unsigned int count
        cdef unsigned char rollback

        count = count_bytes + left_offset
        rollback = <char> count % 4
        if count % 4 != 0:
            count /= 4
            count += 1
        else:
            count /= 4

        try:
            buf = <unsigned int *> malloc(count * sizeof(unsigned int))
            if buf == NULL:
                raise MemoryError("Cannot allocate buffer")
            self._read_32bits_unaligned(buf, count, count_bytes, rollback, left_offset)
            result = (<unsigned char *> buf)[left_offset:left_offset+count]
        finally:
            if buf != NULL:
                free(buf)

        return result
