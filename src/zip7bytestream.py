# I could probably just use some normal I/O stream for this in retrospect, but I just wanted something quick lol

class Zip7ByteStream(object):
    _position = 0
    _stream = b''
    _length = 0

    def __init__(self, data):
        self._stream = data
        self._length = len(data)

    def read(self, count=1):
        data = self._stream[self._position: self._position + count]
        self._position += count
        return data

    def eof(self):
        return self._position == self._length
