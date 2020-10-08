import struct

class Zip7ByteStream(object):
    _cursor = 0
    _stream = b''
    _length = 0

    def __init__(self, data=b''):
        self._stream = data
        self._length = len(data)

    def read(self, count=1, dont_advance_cursor=False):
        data = self._stream[self._cursor: self._cursor + count]
        if not dont_advance_cursor:
            self._cursor += count
        return data

    # 7z uses little endian for its packed integers
    def read_int(self, count=1, endian='little'):
        if count == 0:
            # There are algorithmic reasons why read_int(0) might be called, so just return 0 for them
            return 0

        data = self.read(count)
        if count not in [i+1 for i in range(8)]:
            raise Exception("Valid integer lengths: 1-8")

        padding = (8 - count) * b'\x00'
        if endian == 'big':
            data = padding + data
            return struct.unpack('>Q', data)[0]
        elif endian == 'little':
            data += padding
            return struct.unpack('<Q', data)[0]
        else:
            raise Exception('Valid endian choices: big, little')

    def read_bool(self):
        data = self.read()
        return struct.unpack('?', data)[0]

    # 7zip determines 'numbers' byte length based on bitmasking within the first byte
    def read_number(self):
        # This is impossible to explain in comments
        # Read the docs: https://py7zr.readthedocs.io/en/stable/archive_format.html
        test_byte = self.read_int()
        for i in range(8):
            if (test_byte >> (7 - i) & 1) == 0:
                return ((test_byte & (0xFF >> (1+i))) << (8 * i)) + self.read_int(i)
        return self.read_int(8)

    def eof(self):
        return self._cursor == self._length
