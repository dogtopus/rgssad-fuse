# TODO implement a native version of XORer
from crypto import XORer

cdef class MagicKeyFactory:
    cdef unsigned int iv
    cdef unsigned int prev_key
    cdef unsigned int key

    def __init__(self, unsigned int iv=0xdeadcafe):
        self.iv = iv
        self.prev_key = 0
        self.key = 0
        # HACK
        self.reset()

    cpdef get_key(self):
        return self.key

    cpdef get_next(self):
        cdef unsigned int key = self.key
        self.prev_key = self.key
        self._transform()
        return key

    cpdef skip(self, unsigned int count):
        cdef int i = 0
        for i in range(count):
            self.get_next()
        
    cdef _transform(self):
        self.key *= 7
        self.key += 3

    # HACK
    cpdef one_step_rollback(self):
        self.key = self.prev_key

    cpdef reset(self):
        self.key = self.iv

