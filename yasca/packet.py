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


_Payload = Optional[Union['Packet', bytes, int]]


class Packet:
    payload: Optional['Packet']

    def __init__(self, payload: _Payload = None):
        if payload is not None:
            if not isinstance(payload, Packet):
                payload = Payload(payload)
        self.payload = payload

    def __iter__(self) -> Generator['Packet', None, None]:
        packet: Optional[Packet] = self
        while packet is not None:
            yield packet
            packet = packet.payload

    @property
    def last_payload(self) -> 'Packet':
        payload: Packet = self
        for packet in self:
            payload = packet
        return payload

    def __truediv__(self, payload: _Payload) -> Self:
        if payload is not None:
            if not isinstance(payload, Packet):
                payload = Payload(payload)
            self.last_payload.payload = payload
        return self

    def get(self, key: type['Packet']) -> Optional['Packet']:
        for packet in self:
            if isinstance(packet, key):
                return packet
        return None

    def __contains__(self, key: type['Packet']) -> bool:
        return self.get(key) is not None

    def __getitem__(self, key: type['Packet']) -> 'Packet':
        packet = self.get(key)
        if packet is None:
            raise KeyError
        return packet

    def __bytes__(self) -> bytes:
        ctx = PacketBuildCtx()
        return self.build(ctx)

    def build(self, ctx: PacketBuildCtx) -> bytes:
        payload = self.build_payload(ctx)
        return self.build_with_payload(payload, ctx)

    def build_payload(self, ctx: PacketBuildCtx) -> bytes:
        if self.payload is None:
            return b''
        return self.payload.build(ctx)

    def build_with_payload(self, payload: bytes, ctx: PacketBuildCtx) -> bytes:
        raise NotImplementedError

    @classmethod
    def parse(
        cls,
        buf: Union[Buffer, bytes],
        ctx: Optional[PacketParseCtx] = None,
    ) -> Optional[Union[Self, 'Payload']]:
        if ctx is None:
            ctx = PacketParseCtx()
        buffer = Buffer(buf)

        if buffer.empty():
            if ctx.ensure_payload_type:
                raise ValueError
            return None

        try:
            return cls.parse_from_buffer(buffer, ctx)
        except Exception:
            if ctx.ensure_payload_type:
                raise

        return Payload.parse_from_buffer(buffer, ctx)

    @classmethod
    def parse_from_buffer(cls, buffer: Buffer, ctx: PacketParseCtx) -> Self:
        packet = cls.parse_header_from_buffer(buffer, ctx)
        packet.parse_payload_from_buffer(buffer, ctx)
        return packet

    @classmethod
    def parse_header_from_buffer(
        cls,
        buffer: Buffer,
        ctx: PacketParseCtx,
    ) -> Self:
        raise NotImplementedError

    def parse_payload_from_buffer(self, buffer: Buffer, ctx: PacketParseCtx):
        assert self.payload is None

        if buffer.empty():
            return

        pcls = self.guess_payload_cls(ctx)
        if pcls is not None:
            try:
                self.payload = pcls.parse_from_buffer(buffer.copy(), ctx)
                return
            except Exception:
                if ctx.ensure_payload_type:
                    raise

        self.payload = Payload.parse_from_buffer(buffer, ctx)

    def guess_payload_cls(
        self,
        ctx: PacketParseCtx,
    ) -> Optional[type['Packet']]:
        return None

    def __str__(self) -> str:
        return '/'.join(packet.__class__.__name__ for packet in self)

    def __repr__(self) -> str:
        fields = self.get_fields()
        r = ','.join('{}={}'.format(f, repr(getattr(self, f))) for f in fields
                     if hasattr(self, f))
        r = '{}({})'.format(self.__class__.__name__, r)
        if self.payload is None:
            return r
        return '{}/{}'.format(r, repr(self.payload))

    def yapf(self):
        from yapf.yapflib.yapf_api import FormatCode
        code, _ = FormatCode(repr(self))
        print(code)

    @classmethod
    def get_fields(cls) -> list[str]:
        fields = list()
        for pcls in reversed(cls.__mro__):
            init = pcls.__dict__.get('__init__')
            if hasattr(init, '__annotations__'):
                for field in init.__annotations__:
                    if field != 'payload':
                        fields.append(field)
        return fields


class Payload(Packet):
    data: bytes

    def __init__(self, data: Optional[Union[bytes, int]] = b'', **kwargs):
        super().__init__(**kwargs)
        if data is None:
            data = b''
        if not isinstance(data, bytes):
            data = bytes(data)
        self.data = data

    def build(self, ctx: PacketBuildCtx) -> bytes:
        return self.data

    @classmethod
    def parse_from_buffer(cls, buffer: Buffer, ctx: PacketParseCtx) -> Self:
        data = buffer.pop_all()
        return cls(data=data)
