from collections.abc import Generator
from enum import Enum, auto
from typing import Any, Optional, Union

from typing_extensions import Self

from .addr import IPAddress
from .buffer import Buffer


class FieldConflictAct(Enum):
    Override = auto()  # keep field when conflict
    Ignore = auto()  # keep var when conflict
    Raise = auto()  # raise when conflict

    def resolve(self, field: Any, var: Any, default: Any = None) -> Any:
        if field == var:
            if field is None:
                field = default
            if field is None:
                raise RuntimeError
            return field
        if field is None:
            return var
        if var is None:
            return field
        if self is self.Override:
            return field
        if self is self.Ignore:
            return var
        raise RuntimeError


class PacketBuildCtx:
    conflict_act: FieldConflictAct
    ip_src: IPAddress
    ip_dst: IPAddress

    def __init__(
        self,
        strict: bool = False,
        conflict_act: Optional[FieldConflictAct] = None,
    ):
        if conflict_act is None:
            conflict_act = FieldConflictAct.Raise \
                if strict else FieldConflictAct.Ignore
        self.conflict_act = conflict_act


class PacketParseCtx:
    ensure_payload_type: bool
    ensure_payload_len: bool

    def __init__(
        self,
        strict: Optional[bool] = False,
        ensure_payload_type: Optional[bool] = None,
        ensure_payload_len: Optional[bool] = None,
    ):
        if strict is None:
            strict = False
        if ensure_payload_type is None:
            ensure_payload_type = strict
        if ensure_payload_len is None:
            ensure_payload_len = strict
        self.ensure_payload_type = ensure_payload_type
        self.ensure_payload_len = ensure_payload_len


class Packet:
    next_packet: Optional[Union['Packet', bytes]]

    def __init__(self, next_packet: Optional[Union['Packet', bytes]] = None):
        self.next_packet = next_packet

    @property
    def last_packet(self) -> 'Packet':
        p: Packet = self
        next_packet = p.next_packet
        while isinstance(next_packet, Packet):
            p = next_packet
            next_packet = p.next_packet
        return p

    def __truediv__(self, next_packet: Union['Packet', bytes]) -> Self:
        p = self.last_packet
        if p.next_packet is not None:
            raise RuntimeError
        p.next_packet = next_packet
        return self

    def __iter__(self) -> Generator[Union['Packet', bytes], None, None]:
        p: Optional[Union[Packet, bytes]] = self
        while p is not None:
            yield p
            if isinstance(p, Packet):
                p = p.next_packet
            else:
                p = None

    def get(self, key: type['Packet']) -> Optional['Packet']:
        for p in self:
            if isinstance(p, key):
                return p
        return None

    def __contains__(self, key: type['Packet']) -> bool:
        p = self.get(key)
        return p is not None

    def __getitem__(self, key: type['Packet']) -> 'Packet':
        p = self.get(key)
        if p is None:
            raise KeyError
        return p

    def __bytes__(self) -> bytes:
        ctx = PacketBuildCtx()
        self.init_build_ctx(ctx)
        return self.build(ctx)

    def init_build_ctx(self, ctx: PacketBuildCtx):
        if isinstance(self.next_packet, Packet):
            self.next_packet.init_build_ctx(ctx)

    def build(self, ctx: PacketBuildCtx) -> bytes:
        raise NotImplementedError

    def build_payload(self, ctx: PacketBuildCtx) -> bytes:
        next_packet = self.next_packet
        if next_packet is None:
            return b''
        if isinstance(next_packet, bytes):
            return next_packet
        return next_packet.build(ctx)

    @classmethod
    def parse(cls, buf: bytes) -> Self:
        ctx = PacketParseCtx()
        buffer = Buffer(buf)
        return cls.parse_from_buffer(buffer, ctx)

    @classmethod
    def parse_from_buffer(cls, buffer: Buffer, ctx: PacketParseCtx) -> Self:
        raise NotImplementedError

    def parse_payload_from_buffer(self, buffer: Buffer, ctx: PacketParseCtx):
        assert self.next_packet is None
        packet: Optional[Union['Packet', bytes]] = None
        pcls = self.guess_payload_cls(ctx)
        if pcls is not None:
            try:
                packet = pcls.parse_from_buffer(buffer.copy(), ctx)
            except Exception:
                if ctx.ensure_payload_type:
                    raise
        if packet is None and not buffer.empty():
            packet = buffer.pop_all()
        self.next_packet = packet

    def guess_payload_cls(
        self,
        ctx: PacketParseCtx,
    ) -> Optional[type['Packet']]:
        return None

    def __str__(self) -> str:
        return '/'.join(packet.__class__.__name__ for packet in self)

    def __repr__(self) -> str:
        fields = self.get_fields()
        r = '\n'.join('  {}={},'.format(f, repr(getattr(self, f)))
                      for f in fields)
        r = '{}(\n{}\n)'.format(self.__class__.__name__, r)
        if self.next_packet is None:
            return r
        return '{}/{}'.format(r, repr(self.next_packet))

    @classmethod
    def get_fields(cls) -> list[str]:
        return list()
