#!/usr/bin/env python3
import struct
import logging

class MagicKeyFactory(object):
    def __init__(self, iv=0xdeadcafe):
        self.logger = logging.getLogger('rgssad.MagicKeyFactory')
        self.iv = iv
        # HACK
        self.prev_key = 0
        self.reset()

    def get_key(self):
        return self.key

    def get_next(self):
        key = self.key
        #self.logger.debug('key: %d', key)
        self.prev_key = self.key
        self._transform()
        return key

    def skip(self, count):
        self.logger.debug('skip %d block(s)', count)
        # Transform 4 times in 1 multiplication and 1 addition to save some time
        if count >= 4:
            t4_count = count // 4
            t_count = count % 4
            
            for i in range(t4_count):
                self._transform4()
            for i in range(t_count):
                self._transform()
        else:
            for i in range(count):
                self._transform()

    def _transform(self):
        self.key *= 7
        self.key += 3
        self.key &= 0xffffffff

    def _transform4(self):
        self.key *= 2401
        self.key += 1200
        self.key &= 0xffffffff

    # HACK
    def one_step_rollback(self):
        self.logger.debug('rolling key back (%d -> %d)', self.key, self.prev_key)
        self.key = self.prev_key

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
