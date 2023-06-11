from ctypes import c_ushort
from typing import Optional, Union

from .addr import IPAddress
from .buffer import Buffer
from .enums import U8Enum
from .packet import Packet, PacketBuildCtx, PacketParseCtx


class IPVersion(U8Enum):
    V4 = 4
    V6 = 6


class IPProto(U8Enum):
    HopByHopOption = 0
    DestinationOption = 60
    Fragment = 44
    Routing = 43
    Encapsulating = 50
    Authentication = 51
    NoNext = 59
    ICMPv4 = 1
    ICMPv6 = 58
    TCP = 6
    UDP = 17


_IPVersion = Union[IPVersion, int]
_IPProto = Union[IPProto, int]


class IPProtoHeader(Packet):
    proto: _IPProto

    proto_dict: dict[int, type['IPProtoHeader']] = dict()

    def __init_subclass__(cls, **kwargs):
        super().__init_subclass__(**kwargs)
        if hasattr(cls, 'proto') and cls.proto not in cls.proto_dict:
            cls.proto_dict[cls.proto] = cls


class IPChainedHeader(Packet):
    nh: Optional[_IPProto]

    def __init__(self, nh: Optional[_IPProto] = None, **kwargs):
        super().__init__(**kwargs)
        self.nh = nh

    def resolve_nh(self, ctx: PacketBuildCtx):
        nh: Optional[int] = None
        if isinstance(self.payload, IPProtoHeader):
            nh = self.payload.proto
        self.nh = ctx.conflict_act.resolve(self.nh, nh, IPProto.NoNext)

    @classmethod
    def parse_nh_from_buffer(
        cls,
        buffer: Buffer,
        ctx: PacketParseCtx,
    ) -> int:
        return IPProto.pop_from_buffer(buffer)

    def guess_payload_cls(self, ctx) -> Optional[type['Packet']]:
        if self.nh is not None:
            return IPProtoHeader.proto_dict.get(self.nh)
        return super().guess_payload_cls(ctx)


def ip_sum(buf: bytes) -> int:
    s = 0
    buffer = Buffer(buf)
    while len(buffer) >= 2:
        s += buffer.pop_int(2)
    if len(buffer) == 1:
        s += buffer.pop_int(1) << 8
    s = ((s & 0xffff0000) >> 16) + (s & 0xffff)
    s = ((s & 0xffff0000) >> 16) + (s & 0xffff)
    s &= 0xffff
    return s


def ip_checksum(buf: bytes) -> int:
    s = ip_sum(buf)
    s = c_ushort(-s - 1).value  # invert
    return s


def ipproto_checksum(
    buf: bytes,
    src: IPAddress,
    dst: IPAddress,
    proto: _IPProto,
) -> int:
    buf = bytes(src) + \
        bytes(dst) + \
        len(buf).to_bytes(4, 'big') + \
        proto.to_bytes(4, 'big') + \
        buf
    return ip_checksum(buf)
