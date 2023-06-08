import socket
from abc import abstractmethod
from functools import cache
from typing import Optional, Union

from typing_extensions import Self

from .buffer import Buffer


class Address:
    data: bytes
    len: int

    def __init__(
        self,
        addr: Optional[Union['Address', str, int, bytes]] = None,
    ):
        if addr is None:
            addr = bytes(self.len)
        if isinstance(addr, Address):
            addr = bytes(addr)
        if isinstance(addr, str):
            addr = self.str2bytes(addr)
        if isinstance(addr, int):
            addr = addr.to_bytes(self.len, 'big')
        if len(addr) != self.len:
            raise ValueError
        self.data = addr

    def __bytes__(self) -> bytes:
        return self.data

    def __len__(self) -> int:
        return self.len

    @cache
    def __int__(self) -> int:
        return int.from_bytes(self.data, 'big')

    @cache
    def __str__(self) -> str:
        return self.bytes2str(self.data)

    def __repr__(self) -> str:
        return '{}({})'.format(self.__class__.__name__, repr(str(self)))

    @classmethod
    def pop_from_buffer(cls, buffer: Buffer) -> Self:
        addr = buffer.pop(cls.len)
        return cls(addr)

    @abstractmethod
    def str2bytes(self, s: str) -> bytes:
        raise NotImplementedError

    @abstractmethod
    def bytes2str(self, b: bytes) -> str:
        raise NotImplementedError


class MACAddress(Address):
    len = 6

    def str2bytes(self, s: str) -> bytes:
        s = s.replace('-', ':')
        hexes = s.split(':')
        if len(hexes) != self.len:
            raise ValueError
        return bytes(int(h, 16) for h in hexes)

    def bytes2str(self, b: bytes) -> str:
        hexes = list()
        for c in b:
            hexes.append(f'{c:02x}')
        return ':'.join(hexes)


class IPAddress(Address):
    family: socket.AddressFamily

    def str2bytes(self, s: str) -> bytes:
        return socket.inet_pton(self.family, s)

    def bytes2str(self, b: bytes) -> str:
        return socket.inet_ntop(self.family, b)


class IPv4Address(IPAddress):
    len = 4
    family = socket.AF_INET


class IPv6Address(IPAddress):
    len = 16
    family = socket.AF_INET6
