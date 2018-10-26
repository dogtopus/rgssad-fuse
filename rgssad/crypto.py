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

import struct
import logging

# https://en.wikipedia.org/wiki/Extended_Euclidean_algorithm
def xgcd(a, m):
    s, t, old_s, old_t = 0, 1, 1, 0
    r, old_r = m, a
    while r != 0:
        q = old_r // r
        old_r, r = r, old_r - q*r
        old_s, s = s, old_s - q*s
        old_t, t = t, old_t - q*t
    # we don't care about the another half of the Bézout coefficients
    return old_r, old_s

# calculates equivalent LCG constants after 2^n iterations
# WARNING: costly, do not invoke too frequently
def lcg_gen(mul, add, bits):
    gcd, im = xgcd(mul, 1 << 32)
    if gcd != 1:
        im = None
    else:
        im &= 0xffffffff
    yield mul, add, im
    m, a = mul, add
    for i in range(1, bits):
        m2 = m * m
        a2 = a * (m+1)
        m, a = m2 & 0xffffffff, a2 & 0xffffffff
        if im is not None:
            im2 = im * im
            im = im2 & 0xffffffff
        yield m, a, im

# Why 30? Remember that RGSSAD uses 32-bit offset and each block of data is 4
# bytes.
LCG_TABLE = tuple(lcg_gen(7, 3, 30))

class MagicKeyFactory(object):
    def __init__(self, iv=0xdeadcafe, lcg_table=LCG_TABLE):
        self._lcg_table = lcg_table
        self.logger = logging.getLogger('rgssad.MagicKeyFactory')
        self.key = 0
        self.iv = iv
        self.can_rewind = self._lcg_table[0][2] is not None
        self.reset()

    def get_key(self):
        return self.key

    def get_next(self):
        key = self.key
        #self.logger.debug('key: %d', key)
        self._transform()
        return key

    def skip(self, count):
        self.logger.debug('skip %d block(s)', count)
        self._transformn(count)

    def rewind(self, count):
        self.logger.debug('rewind %d block(s)', count)
        self._transformn_backwards(count)

    def _transform(self):
        self.key *= self._lcg_table[0][0]
        self.key += self._lcg_table[0][1]
        self.key &= 0xffffffff

    def _transform_backwards(self):
        if not self.can_rewind:
            raise TypeError('This factory does not support rewind')
        self.key -= self._lcg_table[0][1]
        # 0xb6db6db7 = inv(7) (mod 0x100000000)
        self.key *= self._lcg_table[0][2]
        self.key &= 0xffffffff

    def _transformn_backwards(self, n):
        if not self.can_rewind:
            raise TypeError('This factory does not support rewind')
        bitpos = 0
        while n:
            if n & 1:
                _, a, im = LCG_TABLE[bitpos]
                self.key -= a
                self.key *= im
                self.key &= 0xffffffff
            n >>= 1
            bitpos += 1

    # Transform n times in lg(n) time complexity!
    def _transformn(self, n):
        bitpos = 0
        while n:
            if n & 1:
                m, a, _ = LCG_TABLE[bitpos]
                self.key *= m
                self.key += a
                self.key &= 0xffffffff
            n >>= 1
            bitpos += 1

    def one_step_rollback(self):
        self._transform_backwards()

    def reset(self):
        self.logger.debug('key reset')
        self.key = self.iv


class StaticMagicKeyFactory(object):
    def __init__(self, iv=0xdeadcafe):
        self.logger = logging.getLogger('rgssad.StaticMagicKeyFactory')
        self.key = iv

    def get_next(self):
        return self.key

    def get_key(self):
        return self.key

    def skip(self, count):
        '''Does nothing'''
        pass

    def one_step_rollback(self):
        '''Does nothing'''
        pass

    def reset(self):
        '''Does nothing'''
        pass


class XORer(object):
    '''
    Decrypt XORed data
    Supports block size of 8 and 32-bits, aligned (returns integers) or 
        unaligned (returns blob)
    '''
    def __init__(self, io_obj, magickey_obj):
        self.logger = logging.getLogger('rgssad.XORer')
        self.io_obj = io_obj
        self.magickey_obj = magickey_obj

    def read_8bits(self, count):
        '''
        Reads XORed data into tuple of integers (8-bit block)
        '''
        return tuple(b ^ (self.magickey_obj.get_next() & 0xff) \
                         for b in self.io_obj.read(count))

    def read_32bits(self, count):
        '''
        Reads XORed data into tuple of integers (32-bit aligned block)
        NOTE: The `count` parameter needs to be the amount of 32-bit blocks, not
              total bytes of XORed data
        '''
        length = 4 * count
        buf = bytearray(length)

        # TODO underrun caused by eof (fixed?)
        actual_length = self.io_obj.readinto(buf)
        self.logger.debug('read_32bits(): expecting %d bytes, got %d bytes',
                      length, actual_length)
        assert actual_length % 4 == 0
        if actual_length != length:
            count = -(-(actual_length // 4))

        fmt = struct.Struct('<{:d}I'.format(count))
        return tuple(i ^ self.magickey_obj.get_next() \
                  for i in fmt.unpack(buf))

    def read_32bits_unaligned(self, count_bytes, left_offset=0):
        '''
        Reads XORed data into bytes (32-bit unaligned block)
        '''
        self.logger.debug('read unaligned data with offset=%d, len=%d', 
                      left_offset, count_bytes)
        assert left_offset in range(0,4)

        # # of blocks to read = ceil(bytes / 4)
        # Taken from https://stackoverflow.com/questions/14822184/
        count = -(-(count_bytes + left_offset) // 4)
        self.logger.debug('count=%d', count)
        fmt = struct.Struct('<{:d}I'.format(count))
        # create buffer
        self.logger.debug('create buffer (%d blocks)', count)
        buf = bytearray(4 * count)
        # create a memoryview to write data into specific area of buf
        buf2 = memoryview(buf)
        buf_result = memoryview(bytearray(4 * count))

        
        bytes_read = self.io_obj.readinto(
            buf2[left_offset : left_offset+count_bytes]
        )
        #self.logger.debug('%s', repr(buf))
        self.logger.debug('read %d bytes (expecting %d)', bytes_read, count_bytes)

        fmt.pack_into(buf_result, 0, *(i ^ self.magickey_obj.get_next() \
                      for i in fmt.unpack(buf)))

        #self.logger.debug('%s', repr(buf_result.tobytes()))
        # right unaligned data
        if len(buf_result) != (left_offset + count_bytes):
            # HACK fix magic key
            self.magickey_obj.one_step_rollback()

        return buf_result[left_offset : left_offset+count_bytes].tobytes()

    def read_data_8bit(self, count):
        '''
        Reads XORed data into bytes (8-bit block)
        '''
        return bytes(self.read_8bits(count))
