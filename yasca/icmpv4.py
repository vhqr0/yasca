"""
RFCs:
- RFC792: ICMPv4
"""
from typing import Any, Optional, Union

from typing_extensions import Self

from .addr import IPv4Address
from .buffer import Buffer
from .enums import U8Enum
from .ip import IPProto, IPProtoHeader, ip_checksum
from .ipv4 import IPv4Error
from .packet import FieldConflictAct, Packet, PacketBuildCtx, PacketParseCtx


class ICMPv4Type(U8Enum):
    DestinationUnreachable = 3
    TimeExceeded = 11
    ParameterProblem = 12
    SourceQuench = 4
    Redirect = 5
    EchoRequest = 8
    EchoReply = 0
    TimestampRequest = 13
    TimestampReply = 14
    InformationRequest = 15
    InformationReply = 16


class ICMPv4DestinationUnreachableCode(U8Enum):
    NetUnreachable = 0
    HostUnreachable = 1
    ProtocolUnreachable = 2
    PortUnreachable = 3
    FragmentationNeededAndDFSet = 4
    SourceRouteFailed = 5


class ICMPv4TimeExceededCode(U8Enum):
    TimeToLiveExceeded = 0
    FragmentReassemblyTimeExceeded = 1


class ICMPv4RedirectCode(U8Enum):
    Network = 0
    Host = 1
    TypeOfServiceAndNetwork = 2
    TypeOfServiceAndHost = 3


_IPv4Address = Union[IPv4Address, str, int, bytes]
_ICMPv4Type = Union[ICMPv4Type, int]


class ICMPv4(IPProtoHeader):
    msg_dict: dict[int, type['ICMPv4']] = dict()

    type: _ICMPv4Type
    code: int
    checksum: Optional[int]

    proto = IPProto.ICMPv4

    def __init__(
        self,
        code: Optional[int] = 0,
        checksum: Optional[int] = None,
        **kwargs,
    ):
        super().__init__(**kwargs)
        if code is None:
            code = 0
        self.code = code
        self.checksum = checksum

    def __init_subclass__(cls, **kwargs):
        super().__init_subclass__(**kwargs)
        if hasattr(cls, 'type') and cls.type not in cls.msg_dict:
            cls.msg_dict[cls.type] = cls

    def build(self, ctx: PacketBuildCtx) -> bytes:
        payload = self.build_payload(ctx)
        msg = self.build_msg(ctx)

        pre_checksum = ICMPv4Type.int2bytes(self.type) + \
            self.code.to_bytes(1, 'big')
        post_checksum = msg + payload

        if self.checksum is not None and \
           ctx.conflict_act is FieldConflictAct.Override:
            return pre_checksum + \
                self.checksum.to_bytes(2, 'big') + \
                post_checksum

        buf = pre_checksum + b'\x00\x00' + post_checksum
        checksum = ip_checksum(buf)
        self.checksum = ctx.conflict_act.resolve(self.checksum, checksum)
        assert isinstance(self.checksum, int)
        return pre_checksum + self.checksum.to_bytes(2, 'big') + post_checksum

    def build_msg(self, ctx: PacketBuildCtx) -> bytes:
        raise NotImplementedError

    @classmethod
    def parse_from_buffer(
        cls,
        buffer: Buffer,
        ctx: PacketParseCtx,
    ) -> 'ICMPv4':
        type = ICMPv4Type.pop_from_buffer(buffer)
        code = buffer.pop_int(1)
        checksum = buffer.pop_int(2)
        pcls = cls.msg_dict.get(type, ICMPv4Unknown)
        kwargs = {'code': code, 'checksum': checksum}
        packet = pcls.parse_msg_from_buffer(type, buffer, kwargs, ctx)
        packet.parse_payload_from_buffer(buffer, ctx)
        return packet

    @classmethod
    def parse_msg_from_buffer(
        cls,
        type: _ICMPv4Type,
        buffer: Buffer,
        kwargs: dict[str, Any],
        ctx: PacketParseCtx,
    ) -> Self:
        raise NotImplementedError


class ICMPv4Unknown(ICMPv4):

    def __init__(
        self,
        type: Optional[_ICMPv4Type] = ICMPv4Type.EchoRequest,
        **kwargs,
    ):
        super().__init__(**kwargs)
        if type is None:
            type = ICMPv4Type.EchoRequest
        self.type = type

    def build_msg(self, ctx: PacketBuildCtx) -> bytes:
        return b''


class ICMPv4Error(ICMPv4):

    def build_msg(self, ctx: PacketBuildCtx) -> bytes:
        return b'\x00\x00\x00\x00'

    @classmethod
    def parse_msg_from_buffer(
        cls,
        type: _ICMPv4Type,
        buffer: Buffer,
        kwargs: dict[str, Any],
        ctx: PacketParseCtx,
    ) -> Self:
        buffer.pop(4)
        return cls(**kwargs)

    def guess_payload_cls(self, ctx: PacketParseCtx) -> Optional[type[Packet]]:
        return IPv4Error


class ICMPv4DestinationUnreachable(ICMPv4Error):
    type = ICMPv4Type.DestinationUnreachable


class ICMPv4TimeExceed(ICMPv4Error):
    type = ICMPv4Type.TimeExceeded


class ICMPv4ParameterProblem(ICMPv4Error):
    ptr: int

    type = ICMPv4Type.ParameterProblem

    def __init__(self, ptr: Optional[int] = 0, **kwargs):
        super().__init__(**kwargs)
        if ptr is None:
            ptr = 0
        self.ptr = ptr

    def build_msg(self, ctx: PacketBuildCtx) -> bytes:
        return self.ptr.to_bytes(1, 'big') + bytes(3)

    @classmethod
    def parse_msg_from_buffer(
        cls,
        type: _ICMPv4Type,
        buffer: Buffer,
        kwargs: dict[str, Any],
        ctx: PacketParseCtx,
    ) -> Self:
        ptr = buffer.pop_int(1)
        buffer.pop(3)
        kwargs['ptr'] = ptr
        return cls(**kwargs)


class ICMPv4SourceQuench(ICMPv4Error):
    type = ICMPv4Type.SourceQuench


class ICMPv4Redirect(ICMPv4Error):
    gw: IPv4Address

    type = ICMPv4Type.Redirect

    def __init__(self, gw: Optional[_IPv4Address], **kwargs):
        super().__init__(**kwargs)
        if not isinstance(gw, IPv4Address):
            gw = IPv4Address(gw)
        self.gw = gw

    def build_msg(self, ctx: PacketBuildCtx) -> bytes:
        return bytes(self.gw)

    @classmethod
    def parse_msg_from_buffer(
        cls,
        type: _ICMPv4Type,
        buffer: Buffer,
        kwargs: dict[str, Any],
        ctx: PacketParseCtx,
    ) -> Self:
        gw = IPv4Address.pop_from_buffer(buffer)
        kwargs['gw'] = gw
        return cls(**kwargs)


class ICMPv4Echo(ICMPv4):
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
        type: _ICMPv4Type,
        buffer: Buffer,
        kwargs: dict[str, Any],
        ctx: PacketParseCtx,
    ) -> Self:
        id = buffer.pop_int(2)
        seq = buffer.pop_int(2)
        kwargs['id'] = id
        kwargs['seq'] = seq
        return cls(**kwargs)


class ICMPv4EchoRequest(ICMPv4Echo):
    type = ICMPv4Type.EchoRequest


class ICMPv4EchoReply(ICMPv4Echo):
    type = ICMPv4Type.EchoReply


class ICMPv4TimestampRequest(ICMPv4Echo):
    type = ICMPv4Type.TimestampRequest


class ICMPv4TimestampReply(ICMPv4Echo):
    type = ICMPv4Type.TimestampReply


class ICMPv4InformationRequest(ICMPv4Echo):
    type = ICMPv4Type.InformationRequest


class ICMPv4InformationReply(ICMPv4Echo):
    type = ICMPv4Type.InformationReply
