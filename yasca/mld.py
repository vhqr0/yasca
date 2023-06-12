"""
RFCs:
- RFC2710: MLD
- RFC3810: MLDv2
"""
from typing import Any, Optional, Union

from typing_extensions import Self

from .addr import IPv6Address
from .buffer import Buffer
from .enums import U8Enum
from .icmpv6 import ICMPv6, ICMPv6Type
from .packet import Packet, PacketBuildCtx, PacketParseCtx


class ICMPv6MLDv2RecordType(U8Enum):
    MODE_IS_INCLUDE = 1
    MODE_IS_EXCLUDE = 2
    CHANGE_TO_INCLUDE_MODE = 3
    CHANGE_TO_EXCLUDE_MODE = 4
    ALLOW_NEW_SOURCES = 5
    BLOCK_OLD_SOURCES = 6


_IPv6Address = Union[IPv6Address, str, int, bytes]
_ICMPv6Type = Union[ICMPv6Type, int]
_ICMPv6MLDv2RecordType = Union[ICMPv6MLDv2RecordType, int]


class ICMPv6MLD(ICMPv6):
    mr: int
    addr: IPv6Address

    def __init__(
        self,
        mr: Optional[int] = 0,
        addr: Optional[_IPv6Address] = None,
        **kwargs,
    ):
        super().__init__(**kwargs)
        if mr is None:
            mr = 0
        if not isinstance(addr, IPv6Address):
            addr = IPv6Address(addr)
        self.mr = mr
        self.addr = addr

    def build_msg(self, ctx: PacketBuildCtx) -> bytes:
        return self.mr.to_bytes(2, 'big') + \
            bytes(2) + \
            bytes(self.addr)

    @classmethod
    def parse_msg_from_buffer(
        cls,
        type: _ICMPv6Type,
        buffer: Buffer,
        kwargs: dict[str, Any],
        ctx: PacketParseCtx,
    ) -> Self:
        mr = buffer.pop_int(2)
        buffer.pop(2)
        addr = IPv6Address.pop_from_buffer(buffer)
        kwargs['mr'] = mr
        kwargs['addr'] = addr
        return cls(**kwargs)


class ICMPv6MLDQuery(ICMPv6MLD):
    type = ICMPv6Type.MLDQuery

    def guess_payload_cls(
        self,
        ctx: PacketParseCtx,
    ) -> Optional[type[Packet]]:  # type: ignore
        return ICMPv6MLDv2QueryExt


class ICMPv6MLDReport(ICMPv6MLD):
    type = ICMPv6Type.MLDReport


class ICMPv6MLDDone(ICMPv6MLD):
    type = ICMPv6Type.MLDDone


class ICMPv6MLDv2QueryExt(Packet):
    S: bool
    qrv: int
    qqi: int
    n: Optional[int]
    addrs: list[IPv6Address]

    def __init__(
        self,
        S: Optional[bool] = False,
        qrv: Optional[int] = 0,
        qqi: Optional[int] = 0,
        n: Optional[int] = None,
        addrs: Optional[Union[_IPv6Address, list[IPv6Address]]] = None,
        **kwargs,
    ):
        super().__init__(**kwargs)
        if S is None:
            S = False
        if qrv is None:
            qrv = 0
        if qqi is None:
            qqi = 0
        if not isinstance(addrs, (list, IPv6Address)):
            addrs = IPv6Address(addrs)
        if isinstance(addrs, IPv6Address):
            addrs = [addrs]
        self.S = S
        self.qrv = qrv
        self.qqi = qqi
        self.n = n
        self.addrs = addrs

    def build_with_payload(self, payload: bytes, ctx: PacketBuildCtx) -> bytes:
        n = len(self.addrs)
        self.n = ctx.conflict_act.resolve(self.n, n)
        assert isinstance(self.n, int)
        return ((int(self.S) << 3) + self.qrv & 7).to_bytes(1, 'big') + \
            self.qqi.to_bytes(1, 'big') + \
            self.n.to_bytes(2, 'big') + \
            b''.join(bytes(addr) for addr in self.addrs) + \
            payload

    @classmethod
    def parse_header_from_buffer(
        cls,
        buffer: Buffer,
        ctx: PacketParseCtx,
    ) -> Packet:
        i = buffer.pop_int(1)
        S = bool((i >> 3) & 1)
        qrv = i & 7
        qqi = buffer.pop_int(1)
        n = buffer.pop_int(2)
        addrs = list()
        for _ in range(n):
            addr = IPv6Address.pop_from_buffer(buffer)
            addrs.append(addr)
        return cls(
            S=S,
            qrv=qrv,
            qqi=qqi,
            n=n,
            addrs=addrs,
        )


class ICMPv6MLDv2Record(Packet):
    type: _ICMPv6MLDv2RecordType
    alen: Optional[int]
    n: Optional[int]
    addr: IPv6Address
    addrs: list[IPv6Address]
    aux: bytes

    def __init__(
        self,
        type: Optional[_ICMPv6MLDv2RecordType] = 0,
        alen: Optional[int] = None,
        n: Optional[int] = None,
        addr: Optional[_IPv6Address] = None,
        addrs: Optional[Union[_IPv6Address, list[IPv6Address]]] = None,
        aux: Optional[bytes] = b'',
        **kwargs,
    ):
        super().__init__(**kwargs)
        if type is None:
            type = 0
        if not isinstance(addr, IPv6Address):
            addr = IPv6Address(addr)
        if not isinstance(addrs, (list, IPv6Address)):
            addrs = IPv6Address(addrs)
        if isinstance(addrs, IPv6Address):
            addrs = [addrs]
        if aux is None:
            aux = b''
        self.type = type
        self.alen = alen
        self.n = n
        self.addr = addr
        self.addrs = addrs
        self.aux = aux

    def build(self, ctx: PacketBuildCtx) -> bytes:
        n = len(self.addrs)
        self.n = ctx.conflict_act.resolve(self.n, n)
        assert isinstance(self.n, int)

        div, mod = divmod(len(self.aux), 4)
        if mod != 0:
            div += 1
            self.aux += bytes(4 - mod)
        alen = div
        self.alen = ctx.conflict_act.resolve(self.alen, alen)
        assert isinstance(self.alen, int)

        return ICMPv6MLDv2RecordType.int2bytes(self.type) + \
            self.alen.to_bytes(1, 'big') + \
            self.n.to_bytes(2, 'big') + \
            bytes(self.addr) + \
            b''.join(bytes(addr) for addr in self.addrs) + \
            self.aux

    @classmethod
    def parse_from_buffer(cls, buffer: Buffer, ctx: PacketParseCtx) -> Packet:
        type = ICMPv6MLDv2RecordType.pop_from_buffer(buffer)
        alen = buffer.pop_int(1)
        n = buffer.pop_int(2)
        addr = IPv6Address.pop_from_buffer(buffer)
        addrs = list()
        for _ in range(n):
            addrs.append(IPv6Address.pop_from_buffer(buffer))
        aux = buffer.pop(alen * 4)
        return cls(
            type=type,
            alen=alen,
            n=n,
            addr=addr,
            addrs=addrs,
            aux=aux,
        )


class ICMPv6MLDv2Report(ICMPv6):
    n: Optional[int]
    records: list[ICMPv6MLDv2Record]

    type = ICMPv6Type.MLDv2Report

    def __init__(
        self,
        n: Optional[int] = None,
        records: Optional[Union[ICMPv6MLDv2Record,
                                list[ICMPv6MLDv2Record]]] = None,
        **kwargs,
    ):
        super().__init__(**kwargs)
        if records is None:
            records = list()
        if isinstance(records, ICMPv6MLDv2Record):
            records = [records]
        self.n = n
        self.records = records

    def build_msg(self, ctx: PacketBuildCtx) -> bytes:
        n = len(self.records)
        self.n = ctx.conflict_act.resolve(self.n, n)
        assert isinstance(self.n, int)
        return bytes(2) + \
            self.n.to_bytes(2, 'big') + \
            b''.join(record.build(ctx) for record in self.records)

    @classmethod
    def parse_msg_from_buffer(
        cls,
        type: _ICMPv6Type,
        buffer: Buffer,
        kwargs: dict[str, Any],
        ctx: PacketParseCtx,
    ) -> Self:
        buffer.pop(2)
        n = buffer.pop_int(2)
        records = list()
        for _ in range(n):
            record = ICMPv6MLDv2Record.parse_from_buffer(buffer, ctx)
            records.append(record)
        kwargs['n'] = n
        kwargs['records'] = records
        return cls(**kwargs)
