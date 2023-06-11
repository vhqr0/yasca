"""
RFCs:
- RFC4443: ICMPv6
"""
from typing import Any, Optional, Union

from typing_extensions import Self

from .buffer import Buffer
from .enums import U8Enum
from .ip import IPChecksumable, IPProto, IPProtoHeader
from .ipv6 import IPv6Error
from .packet import Packet, PacketBuildCtx, PacketParseCtx


class ICMPv6Type(U8Enum):
    DestinationUnreachable = 1
    PacketTooBig = 2
    TimeExceeded = 3
    ParameterProblem = 4
    EchoRequest = 128
    EchoReply = 129
    ND_RS = 133
    ND_RA = 134
    ND_NS = 135
    ND_NA = 136
    ND_RM = 137


class ICMPv6DestinationUnreachableCode(U8Enum):
    NoRouteToDestination = 0
    AdministrativelyProhibited = 1
    SourceAddressBeyondScope = 2
    AddressUnreachable = 3
    PortUnreachable = 4
    SourceAddressFailed = 5
    RejectRouteToDestination = 6


class ICMPv6TimeExceedCode(U8Enum):
    HopLimitExceeded = 0
    FragmentReassemblyTimeExceeded = 1


class ICMPv6ParameterProblemCode(U8Enum):
    ErroneousHeaderField = 0
    UnrecognizedNextHeader = 1
    UnrecognizedIPv6Option = 2


_ICMPv6Type = Union[ICMPv6Type, int]


class ICMPv6(IPProtoHeader, IPChecksumable):
    msg_dict: dict[int, type['ICMPv6']] = dict()

    type: _ICMPv6Type
    code: int

    proto = IPProto.ICMPv6

    def __init__(self, code: Optional[int] = 0, **kwargs):
        super().__init__(**kwargs)
        if code is None:
            code = 0
        self.code = code

    def __init_subclass__(cls, **kwargs):
        super().__init_subclass__(**kwargs)
        if hasattr(cls, 'type') and cls.type not in cls.msg_dict:
            cls.msg_dict[cls.type] = cls

    def build_with_payload(self, payload: bytes, ctx: PacketBuildCtx) -> bytes:
        msg = self.build_msg(ctx)
        pre_checksum = ICMPv6Type.int2bytes(self.type) + \
            self.code.to_bytes(1, 'big')
        post_checksum = msg + payload
        return self.ipproto_checksum_resolve_and_build(
            pre_checksum,
            post_checksum,
            self.proto,
            ctx,
        )

    def build_msg(self, ctx: PacketBuildCtx) -> bytes:
        raise NotImplementedError

    @classmethod
    def parse_header_from_buffer(
        cls,
        buffer: Buffer,
        ctx: PacketParseCtx,
    ) -> 'ICMPv6':
        type = ICMPv6Type.pop_from_buffer(buffer)
        code = buffer.pop_int(1)
        checksum = buffer.pop_int(2)
        kwargs = {'code': code, 'checksum': checksum}
        pcls = cls.msg_dict.get(type, ICMPv6Unknown)
        return pcls.parse_msg_from_buffer(type, buffer, kwargs, ctx)

    @classmethod
    def parse_msg_from_buffer(
        cls,
        type: _ICMPv6Type,
        buffer: Buffer,
        kwargs: dict[str, Any],
        ctx: PacketParseCtx,
    ) -> Self:
        raise NotImplementedError


class ICMPv6Unknown(ICMPv6):

    def __init__(
        self,
        type: Optional[_ICMPv6Type] = ICMPv6Type.EchoRequest,
        **kwargs,
    ):
        super().__init__(**kwargs)
        if type is None:
            type = ICMPv6Type.EchoRequest
        self.type = type

    def build_msg(self, ctx: PacketBuildCtx) -> bytes:
        return b''

    @classmethod
    def parse_msg_from_buffer(
        cls,
        type: _ICMPv6Type,
        buffer: Buffer,
        kwargs: dict[str, Any],
        ctx: PacketParseCtx,
    ) -> Self:
        kwargs['type'] = type
        return cls(**kwargs)


class ICMPv6Error(ICMPv6):

    def build_msg(self, ctx: PacketBuildCtx) -> bytes:
        return bytes(4)

    @classmethod
    def parse_msg_from_buffer(
        cls,
        type: _ICMPv6Type,
        buffer: Buffer,
        kwargs: dict[str, Any],
        ctx: PacketParseCtx,
    ) -> Self:
        buffer.pop(4)
        return cls(**kwargs)

    def guess_payload_cls(self, ctx: PacketParseCtx) -> Optional[type[Packet]]:
        return IPv6Error


class ICMPv6DestinationUnreachable(ICMPv6Error):
    type = ICMPv6Type.DestinationUnreachable


class ICMPv6PacketTooBig(ICMPv6Error):
    mtu: int

    type = ICMPv6Type.PacketTooBig

    def __init__(self, mtu: Optional[int] = 1280, **kwargs):
        super().__init__(**kwargs)
        if mtu is None:
            mtu = 1280
        self.mtu = mtu

    def build_msg(self, ctx: PacketBuildCtx) -> bytes:
        return self.mtu.to_bytes(4, 'big')

    @classmethod
    def parse_msg_from_buffer(
        cls,
        type: _ICMPv6Type,
        buffer: Buffer,
        kwargs: dict[str, Any],
        ctx: PacketParseCtx,
    ) -> Self:
        mtu = buffer.pop_int(4)
        kwargs['mtu'] = mtu
        return cls(**kwargs)


class ICMPv6TimeExceed(ICMPv6Error):
    type = ICMPv6Type.TimeExceeded


class ICMPv6ParameterProblem(ICMPv6Error):
    ptr: int

    type = ICMPv6Type.ParameterProblem

    def __init__(self, ptr: Optional[int] = 0, **kwargs):
        super().__init__(**kwargs)
        if ptr is None:
            ptr = 0
        self.ptr = ptr

    def build_msg(self, ctx: PacketBuildCtx) -> bytes:
        return self.ptr.to_bytes(4, 'big')

    @classmethod
    def parse_msg_from_buffer(
        cls,
        type: _ICMPv6Type,
        buffer: Buffer,
        kwargs: dict[str, Any],
        ctx: PacketParseCtx,
    ) -> Self:
        ptr = buffer.pop_int(4)
        kwargs['ptr'] = ptr
        return cls(**kwargs)


class ICMPv6Echo(ICMPv6):
    id: int
    seq: int

    def __init__(
        self,
        id: Optional[int] = 0,
        seq: Optional[int] = 0,
        **kwargs,
    ):
        super().__init__(**kwargs)
        if id is None:
            id = 0
        if seq is None:
            seq = 0
        self.id = id
        self.seq = seq

    def build_msg(self, ctx: PacketBuildCtx) -> bytes:
        return self.id.to_bytes(2, 'big') + self.seq.to_bytes(2, 'big')

    @classmethod
    def parse_msg_from_buffer(
        cls,
        type: _ICMPv6Type,
        buffer: Buffer,
        kwargs: dict[str, Any],
        ctx: PacketParseCtx,
    ) -> Self:
        id = buffer.pop_int(2)
        seq = buffer.pop_int(2)
        kwargs['id'] = id
        kwargs['seq'] = seq
        return cls(**kwargs)


class ICMPv6EchoRequest(ICMPv6Echo):
    type = ICMPv6Type.EchoRequest


class ICMPv6EchoReply(ICMPv6Echo):
    type = ICMPv6Type.EchoReply
