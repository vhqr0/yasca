"""
RFCs:
- RFC8200: IPv6
"""
from collections.abc import Iterator
from typing import Any, Optional, Union

from typing_extensions import Self

from .addr import IPv6Address
from .buffer import Buffer
from .enums import U8Enum
from .ether import EtherProto, EtherProtoHeader
from .ip import IPChainedHeader, IPProto, IPProtoHeader, IPVersion
from .packet import FieldConflictAct, Packet, PacketBuildCtx, PacketParseCtx


class IPv6OptType(U8Enum):
    Pad1 = 0
    PadN = 1


_IPv6Address = Union[IPv6Address, str, int, bytes]
_IPVersion = Union[IPVersion, int]
_IPProto = Union[IPProto, int]
_IPv6OptType = Union[IPv6OptType, int]


class IPv6(EtherProtoHeader, IPChainedHeader):
    ver: _IPVersion
    tc: int
    fl: int
    plen: Optional[int]
    hlim: int
    src: IPv6Address
    dst: IPv6Address

    proto = EtherProto.IPv6

    def __init__(
        self,
        ver: Optional[_IPVersion] = IPVersion.V6,
        tc: Optional[int] = 0,
        fl: Optional[int] = 0,
        plen: Optional[int] = None,
        hlim: Optional[int] = 64,
        src: Optional[_IPv6Address] = None,
        dst: Optional[_IPv6Address] = None,
        **kwargs,
    ):
        super().__init__(**kwargs)
        if ver is None:
            ver = IPVersion.V6
        if tc is None:
            tc = 0
        if fl is None:
            fl = 0
        if hlim is None:
            hlim = 64
        if not isinstance(src, IPv6Address):
            src = IPv6Address(src)
        if not isinstance(dst, IPv6Address):
            dst = IPv6Address(dst)
        self.ver = ver
        self.tc = tc
        self.fl = fl
        self.plen = plen
        self.hlim = hlim
        self.src = src
        self.dst = dst

    def init_build_ctx(self, ctx: PacketBuildCtx):
        ctx.ip_src = self.src
        ctx.ip_dst = self.dst
        super().init_build_ctx(ctx)

    def build(self, ctx: PacketBuildCtx) -> bytes:
        self.resolve_nh(ctx)
        assert isinstance(self.nh, int)

        payload = self.build_payload(ctx)
        plen = len(payload)
        self.plen = ctx.conflict_act.resolve(self.plen, plen)
        assert isinstance(self.plen, int)

        i = ((self.ver & 0xf) << 28) + \
            ((self.tc & 0xff) << 20) + \
            (self.fl & 0xfff)
        i <<= 32
        i += ((self.plen & 0xffff) << 16) + \
            ((self.nh & 0xff) << 8) + \
            (self.hlim & 0xff)
        header = i.to_bytes(8, 'big') + bytes(self.src) + bytes(self.dst)
        return header + payload

    @classmethod
    def parse_from_buffer(cls, buffer: Buffer, ctx: PacketParseCtx) -> Self:
        i = buffer.pop_int(4)
        ver = IPVersion.wrap((i >> 28) & 0xf)
        tc = (i >> 20) & 0xff
        fl = i & 0xfff
        plen = buffer.pop_int(2)
        nh = IPProto.pop_from_buffer(buffer)
        hlim = buffer.pop_int(1)
        src = IPv6Address.pop_from_buffer(buffer)
        dst = IPv6Address.pop_from_buffer(buffer)
        packet = cls(
            nh=nh,
            ver=ver,
            tc=tc,
            fl=fl,
            plen=plen,
            hlim=hlim,
            src=src,
            dst=dst,
        )
        if ctx.ensure_payload_len:
            if plen > len(buffer):
                raise RuntimeError
        buffer.narrow(plen)
        packet.parse_payload_from_buffer(buffer, ctx)
        return packet

    @classmethod
    def get_fields(cls) -> list[str]:
        fields = super().get_fields()
        fields += ['ver', 'tc', 'fl', 'plen', 'hlim', 'src', 'dst']
        return fields


class IPv6Error(IPv6):

    def init_build_ctx(self, ctx: PacketBuildCtx):
        # skip init ctx.ip_src/dst
        super(IPv6, self).init_build_ctx(ctx)

    @classmethod
    def parse_from_buffer(cls, buffer: Buffer, ctx: PacketParseCtx) -> Self:
        ctx.ensure_payload_type = False
        ctx.ensure_payload_len = False
        return super().parse_from_buffer(buffer, ctx)


class IPv6Ext(IPProtoHeader, IPChainedHeader):
    len: Optional[int]

    def __init__(self, len: Optional[int] = None, **kwargs):
        super().__init__(**kwargs)
        self.len = len

    def build(self, ctx: PacketBuildCtx) -> bytes:
        self.resolve_nh(ctx)
        assert isinstance(self.nh, int)

        payload = self.build_payload(ctx)
        ext = self.build_ext(ctx)
        div, mod = divmod(len(ext) + 2, 8)
        if mod != 0:
            raise RuntimeError
        elen = div - 1
        self.len = ctx.conflict_act.resolve(self.len, elen)
        assert isinstance(self.len, int)
        header = IPProto.int2bytes(self.nh) + \
            self.len.to_bytes(1, 'big') + \
            ext
        return header + payload

    def build_ext(self, ctx: PacketBuildCtx) -> bytes:
        raise NotImplementedError

    @classmethod
    def parse_from_buffer(cls, buffer: Buffer, ctx: PacketParseCtx) -> Self:
        nh = IPProto.pop_from_buffer(buffer)
        len = buffer.pop_int(1)
        ext = Buffer(buffer.pop((len + 1) * 8 - 2))
        kwargs = {'nh': nh, 'len': len}
        packet = cls.parse_ext_from_buffer(ext, kwargs, ctx)
        packet.parse_payload_from_buffer(buffer, ctx)
        return packet

    @classmethod
    def parse_ext_from_buffer(
        cls,
        buffer: Buffer,
        kwargs: dict[str, Any],
        ctx: PacketParseCtx,
    ) -> Self:
        raise NotImplementedError

    @classmethod
    def get_fields(cls) -> list[str]:
        fields = super().get_fields()
        fields.append('len')
        return fields


class IPv6ExtUnknown(IPv6Ext):
    data: bytes

    def __init__(
        self,
        proto: Optional[_IPProto] = IPProto.NoNext,
        data: Optional[bytes] = None,
        **kwargs,
    ):
        super().__init__(**kwargs)
        if proto is None:
            proto = IPProto.NoNext
        if data is None:
            data = bytes(6)
        self.proto = proto
        self.data = data

    def build_ext(self, ctx: PacketBuildCtx) -> bytes:
        return self.data

    @classmethod
    def get_fields(cls) -> list[str]:
        fields = super().get_fields()
        fields += ['proto', 'data']
        return fields


class IPv6Opt:
    opt_dict: dict[int, type['IPv6Opt']] = dict()

    type: _IPv6OptType
    len: Optional[int]

    def __init__(self, len: Optional[int] = None, **kwargs):
        super().__init__(**kwargs)
        self.len = len

    def __init_subclass__(cls, **kwargs):
        super().__init_subclass__(**kwargs)
        if hasattr(cls, 'type') and cls.type not in cls.opt_dict:
            cls.opt_dict[cls.type] = cls

    def build(self, ctx: PacketBuildCtx) -> bytes:
        opt = self.build_opt(ctx)
        olen = len(opt)
        self.len = ctx.conflict_act.resolve(self.len, olen)
        assert isinstance(self.len, int)
        return IPv6OptType.int2bytes(self.type) + \
            self.len.to_bytes(1, 'big') + \
            opt

    def build_opt(self, ctx: PacketBuildCtx) -> bytes:
        raise NotImplementedError

    @classmethod
    def parse_from_buffer(
        cls,
        buffer: Buffer,
        ctx: PacketParseCtx,
    ) -> 'IPv6Opt':
        type = IPv6OptType.pop_from_buffer(buffer)
        if type == IPv6OptType.Pad1:
            len = 0
        else:
            len = buffer.pop_int(1)
        obuffer = Buffer(buffer.pop(len))
        ocls = cls.opt_dict.get(type, IPv6OptUnknown)
        kwargs = {'len': len}
        opt = ocls.parse_opt_from_buffer(type, obuffer, kwargs, ctx)
        if not obuffer.empty():
            raise RuntimeError
        return opt

    @classmethod
    def parse_opt_from_buffer(
        cls,
        type: _IPv6OptType,
        buffer: Buffer,
        kwargs: dict[str, Any],
        ctx: PacketParseCtx,
    ) -> Self:
        raise NotImplementedError

    def __repr__(self) -> str:
        fields = self.get_fields()
        r = ','.join('{}={}'.format(f, repr(getattr(self, f))) for f in fields)
        return '{}({})'.format(self.__class__.__name__, r)

    @classmethod
    def get_fields(cls) -> list[str]:
        return ['len']


class IPv6OptUnknown(IPv6Opt):
    data: bytes

    def __init__(
        self,
        type: Optional[_IPv6OptType] = IPv6OptType.PadN,
        data: Optional[bytes] = b'',
        **kwargs,
    ):
        super().__init__(**kwargs)
        if type is None:
            type = IPv6OptType.PadN
        if data is None:
            data = b''
        self.type = type
        self.data = data

    def build_opt(self, ctx: PacketBuildCtx) -> bytes:
        return self.data

    @classmethod
    def parse_opt_from_buffer(
        cls,
        type: _IPv6OptType,
        buffer: Buffer,
        kwargs: dict[str, Any],
        ctx: PacketParseCtx,
    ) -> Self:
        data = buffer.pop_all()
        kwargs['type'] = type
        kwargs['data'] = data
        return cls(**kwargs)

    @classmethod
    def get_fields(cls) -> list[str]:
        fields = super().get_fields()
        fields += ['type', 'data']
        return fields


class IPv6OptPad1(IPv6Opt):
    type = IPv6OptType.Pad1

    def build(self, ctx: PacketBuildCtx) -> bytes:
        return IPv6OptType.int2bytes(self.type)

    @classmethod
    def parse_opt_from_buffer(
        cls,
        type: _IPv6OptType,
        buffer: Buffer,
        kwargs: dict[str, Any],
        ctx: PacketParseCtx,
    ) -> Self:
        return cls(**kwargs)


class IPv6OptPadN(IPv6Opt):
    n: int

    type = IPv6OptType.PadN

    def __init__(self, n: Optional[int] = 2, **kwargs):
        super().__init__(**kwargs)
        if n is None:
            n = 2
        if n < 2:
            raise RuntimeError
        self.n = n

    def build_opt(self, ctx: PacketBuildCtx) -> bytes:
        return bytes(self.n - 2)

    @classmethod
    def parse_opt_from_buffer(
        cls,
        type: _IPv6OptType,
        buffer: Buffer,
        kwargs: dict[str, Any],
        ctx: PacketParseCtx,
    ) -> Self:
        n = len(buffer.pop_all()) + 2
        kwargs['n'] = n
        return cls(**kwargs)

    @classmethod
    def get_fields(cls) -> list[str]:
        fields = super().get_fields()
        fields.append('n')
        return fields


class IPv6OptList:
    opts: list[IPv6Opt]

    def __init__(self, opts: Optional[Union[IPv6Opt, list[IPv6Opt]]] = None):
        if opts is None:
            opts = list()
        if isinstance(opts, IPv6Opt):
            opts = [opts]
        self.opts = opts

    def __iter__(self) -> Iterator[IPv6Opt]:
        return iter(self.opts)

    def __len__(self) -> int:
        return len(self.opts)

    def get(self, key: type[IPv6Opt]) -> Optional[IPv6Opt]:
        for opt in self:
            if isinstance(opt, key):
                return opt
        return None

    def __contains__(self, key: type[IPv6Opt]) -> bool:
        o = self.get(key)
        return o is not None

    def __getitem__(self, key: type[IPv6Opt]) -> IPv6Opt:
        o = self.get(key)
        if o is None:
            raise KeyError
        return o

    def append(self, opt: IPv6Opt):
        self.opts.append(opt)

    def build(self, ctx: PacketBuildCtx) -> bytes:
        buf = b''.join(opt.build(ctx) for opt in self)
        div, mod = divmod(len(buf) + 2, 8)
        act = ctx.conflict_act
        if act is FieldConflictAct.Override:
            return buf
        if act is FieldConflictAct.Ignore:
            pad: IPv6Opt
            n = 8 - mod
            if n == 1:
                pad = IPv6OptPad1()
            else:
                pad = IPv6OptPadN(n)
            self.append(pad)
            buf += pad.build(ctx)
            return buf
        raise RuntimeError

    @classmethod
    def parse_from_buffer(cls, buffer: Buffer, ctx: PacketParseCtx) -> Self:
        opts = list()
        while not buffer.empty():
            opts.append(IPv6Opt.parse_from_buffer(buffer, ctx))
        return cls(opts)

    def __repr__(self) -> str:
        r = ','.join(repr(opt) for opt in self)
        return '{}({})'.format(self.__class__.__name__, r)


class IPv6ExtOptList(IPv6Ext):
    opts: IPv6OptList

    def __init__(
        self,
        opts: Optional[Union[IPv6OptList, IPv6Opt, list[IPv6Opt]]] = None,
        **kwargs,
    ):
        super().__init__(**kwargs)
        if not isinstance(opts, IPv6OptList):
            opts = IPv6OptList(opts)
        self.opts = opts

    def build_ext(self, ctx: PacketBuildCtx) -> bytes:
        return self.opts.build(ctx)

    @classmethod
    def parse_ext_from_buffer(
        cls,
        buffer: Buffer,
        kwargs: dict[str, Any],
        ctx: PacketParseCtx,
    ) -> Self:
        opts = IPv6OptList.parse_from_buffer(buffer, ctx)
        kwargs['opts'] = opts
        return cls(**kwargs)

    @classmethod
    def get_fields(cls) -> list[str]:
        fields = super().get_fields()
        fields.append('opts')
        return fields


class IPv6ExtHopByHop(IPv6ExtOptList):
    proto = IPProto.HopByHopOption


class IPv6ExtDestination(IPv6ExtOptList):
    proto = IPProto.DestinationOption


class IPv6ExtFragment(IPv6Ext):
    offset: int
    M: bool
    id: int

    proto = IPProto.Fragment

    def __init__(
        self,
        offset: Optional[int] = 0,
        M: Optional[bool] = False,
        id: Optional[int] = 0,
        **kwargs,
    ):
        super().__init__(**kwargs)
        if offset is None:
            offset = 0
        if M is None:
            M = False
        if id is None:
            id = 0
        self.offset = offset
        self.M = M
        self.id = id

    def build(self, ctx: PacketBuildCtx) -> bytes:
        self.resolve_nh(ctx)
        assert isinstance(self.nh, int)

        payload = self.build_payload(ctx)
        ext = self.build_ext(ctx)
        header = IPProto.int2bytes(self.nh) + \
            b'\x00' + \
            ext
        return header + payload

    def build_ext(self, ctx: PacketBuildCtx) -> bytes:
        i = (self.offset << 3) + int(self.M)
        i <<= 32
        i += self.id & 0xffffffff
        return i.to_bytes(6, 'big')

    @classmethod
    def parse_from_buffer(cls, buffer: Buffer, ctx: PacketParseCtx) -> Self:
        nh = IPProto.pop_from_buffer(buffer)
        buffer.pop_int(1)  # reserved
        ext = Buffer(buffer.pop(6))
        kwargs = {'nh': nh}
        packet = cls.parse_ext_from_buffer(ext, kwargs, ctx)
        packet.parse_payload_from_buffer(buffer, ctx)
        return packet

    @classmethod
    def parse_ext_from_buffer(
        cls,
        buffer: Buffer,
        kwargs: dict[str, Any],
        ctx: PacketParseCtx,
    ) -> Self:
        i = buffer.pop_int(2)
        offset = i >> 3
        M = bool(i & 1)
        id = buffer.pop_int(4)
        kwargs['offset'] = offset
        kwargs['M'] = M
        kwargs['id'] = id
        return cls(**kwargs)

    def guess_payload_cls(self, ctx: PacketParseCtx) -> Optional[type[Packet]]:
        if self.offset != 0:
            return None
        return super().guess_payload_cls(ctx)

    @classmethod
    def get_fields(cls) -> list[str]:
        fields = super().get_fields()
        fields += ['offset', 'M', 'id']
        return fields
