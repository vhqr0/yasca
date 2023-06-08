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


class Ether(Packet):
    src: MACAddress
    dst: MACAddress
    proto: Optional[_EtherProto]

    def __init__(
        self,
        src: Optional[_MACAddress] = None,
        dst: Optional[_MACAddress] = None,
        proto: Optional[_EtherProto] = None,
        **kwargs,
    ):
        super().__init__(**kwargs)
        if not isinstance(src, MACAddress):
            src = MACAddress(src)
        if not isinstance(dst, MACAddress):
            dst = MACAddress(dst)
        self.src = src
        self.dst = dst
        self.proto = proto

    def resolve_proto(self, ctx: PacketBuildCtx):
        proto: Optional[int] = None
        if isinstance(self.next_packet, EtherProtoHeader):
            proto = self.next_packet.proto
        self.proto = ctx.conflict_act.resolve(self.proto, proto,
                                              EtherProto.IPv6)

    def build(self, ctx: PacketBuildCtx) -> bytes:
        self.resolve_proto(ctx)
        assert isinstance(self.proto, int)

        payload = self.build_payload(ctx)
        header = bytes(self.dst) + \
            bytes(self.src) + \
            EtherProto.int2bytes(self.proto)
        return header + payload

    @classmethod
    def parse_from_buffer(cls, buffer: Buffer, ctx: PacketParseCtx) -> Self:
        dst = MACAddress.pop_from_buffer(buffer)
        src = MACAddress.pop_from_buffer(buffer)
        proto = EtherProto.pop_from_buffer(buffer)
        packet = cls(
            src=src,
            dst=dst,
            proto=proto,
        )
        packet.parse_payload_from_buffer(buffer, ctx)
        return packet

    def guess_payload_cls(
        self,
        ctx: PacketParseCtx,
    ) -> Optional[type['Packet']]:
        if self.proto is not None:
            return EtherProtoHeader.proto_dict.get(self.proto)
        return super().guess_payload_cls(ctx)

    @classmethod
    def get_fields(cls) -> list[str]:
        fields = super().get_fields()
        fields += ['src', 'dst', 'proto']
        return fields
