class Buffer:
    buf: bytes
    len: int
    cur: int

    def __init__(self, buf: bytes):
        self.buf = buf
        self.len = len(self.buf)
        self.cur = 0

    def __bytes__(self) -> bytes:
        return self.buf[self.cur:self.cur + self.len]

    def __str__(self) -> str:
        return str(bytes(self))

    def __repr__(self) -> str:
        return repr(bytes(self))

    def __len__(self) -> int:
        return self.len

    def empty(self) -> bool:
        return self.len == 0

    def narrow(self, n: int):
        self.len = min(self.len, n)
        assert self.len >= 0

    def widden(self):
        self.len = len(self.buf) - self.cur
        assert self.len >= 0

    def pop(self, n: int) -> bytes:
        if n > self.len:
            raise OverflowError
        buf = self.buf[self.cur:self.cur + n]
        self.cur += n
        self.len -= n
        return buf

    def pop_all(self) -> bytes:
        return self.pop(self.len)

    def pop_int(self, n: int) -> int:
        buf = self.pop(n)
        return int.from_bytes(buf, 'big')

    def copy(self) -> 'Buffer':
        return Buffer(bytes(self))
