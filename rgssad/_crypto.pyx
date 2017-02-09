# TODO implement a native version of XORer
from crypto import StaticMagicKeyFactory
from crypto import XORer

cdef class MagicKeyFactory:
    cdef unsigned int iv
    cdef unsigned int key

    def __init__(self, unsigned int iv=0xdeadcafe):
        self.iv = iv
        self.key = 0
        self.reset()

    cpdef get_key(self):
        return self.key

    cpdef get_next(self):
        cdef unsigned int key = self.key
        self._transform()
        return key

    cpdef skip(self, unsigned int count):
        cdef unsigned int i = 0
        for i in range(count):
            self.get_next()

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
        self.key = self.iv

