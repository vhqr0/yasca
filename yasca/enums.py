from enum import IntEnum

from .buffer import Buffer


class BaseIntEnum(IntEnum):
    len: int

    def __bytes__(self) -> bytes:
        return self.int2bytes(self)

    def __repr__(self) -> str:
        return str(self)

    @classmethod
    def int2bytes(cls, i: int) -> bytes:
        return i.to_bytes(cls.len, 'big')

    @classmethod
    def wrap(cls, i: int) -> int:
        try:
            return cls(i)
        except ValueError:
            return i

    @classmethod
    def pop_from_buffer(cls, buffer: Buffer) -> int:
        i = buffer.pop_int(cls.len)
        return cls.wrap(i)


class U8EnumMixin:
    len = 1


class U8Enum(U8EnumMixin, BaseIntEnum):
    pass


class U16EnumMixin:
    len = 2


class U16Enum(U16EnumMixin, BaseIntEnum):
    pass
