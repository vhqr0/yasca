from typing import Optional, Union

from typing_extensions import Self

from .addr import MACAddress
from .buffer import Buffer
from .enums import U16Enum
from .packet import Packet, PacketBuildCtx, PacketParseCtx


class EtherType(U16Enum):
    Ether = 0x0001


class EtherProto(U16Enum):
    ALL = 0x0003
    ARP = 0x0806
    IPv4 = 0x0800
    IPv6 = 0x86dd


_MACAddress = Union[MACAddress, str, int, bytes]
_EtherProto = Union[EtherProto, int]


class EtherProtoHeader(Packet):
    proto: _EtherProto

    proto_dict: dict[int, type['EtherProtoHeader']] = dict()

    def __init_subclass__(cls, **kwargs):
        super().__init_subclass__(**kwargs)
        if hasattr(cls, 'proto') and cls.proto not in cls.proto_dict:
            cls.proto_dict[cls.proto] = cls


class EtherChainedHeader(Packet):
    nh: Optional[_EtherProto]

    def __init__(self, nh: Optional[_EtherProto] = None, **kwargs):
        super().__init__(**kwargs)
        self.nh = nh

    def resolve_nh(self, ctx: PacketBuildCtx):
        nh: Optional[int] = None
        if isinstance(self.payload, EtherProtoHeader):
            nh = self.payload.proto
        self.nh = ctx.conflict_act.resolve(self.nh, nh, EtherProto.ALL)

    @classmethod
    def parse_nh_from_buffer(
        cls,
        buffer: Buffer,
        ctx: PacketParseCtx,
    ) -> int:
        return EtherProto.pop_from_buffer(buffer)

    def guess_payload_cls(self, ctx) -> Optional[type['Packet']]:
        if self.nh is not None:
            return EtherProtoHeader.proto_dict.get(self.nh)
        return super().guess_payload_cls(ctx)


class Ether(EtherChainedHeader):
    src: MACAddress
    dst: MACAddress

    def __init__(
        self,
        src: Optional[_MACAddress] = None,
        dst: Optional[_MACAddress] = None,
        **kwargs,
    ):
        super().__init__(**kwargs)
        if not isinstance(src, MACAddress):
            src = MACAddress(src)
        if not isinstance(dst, MACAddress):
            dst = MACAddress(dst)
        self.src = src
        self.dst = dst

    def build_with_payload(self, payload: bytes, ctx: PacketBuildCtx) -> bytes:
        self.resolve_nh(ctx)
        assert isinstance(self.nh, int)
        return bytes(self.dst) + \
            bytes(self.src) + \
            EtherProto.int2bytes(self.nh) + \
            payload

    @classmethod
    def parse_header_from_buffer(
        cls,
        buffer: Buffer,
        ctx: PacketParseCtx,
    ) -> Self:
        dst = MACAddress.pop_from_buffer(buffer)
        src = MACAddress.pop_from_buffer(buffer)
        nh = cls.parse_nh_from_buffer(buffer, ctx)
        return cls(
            nh=nh,
            src=src,
            dst=dst,
        )
