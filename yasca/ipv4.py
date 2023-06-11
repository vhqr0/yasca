"""
RFCs:
- RFC791: IPv4
"""
from typing import Any, Optional, Union

from typing_extensions import Self

from .addr import IPv4Address
from .buffer import Buffer
from .enums import U8Enum
from .ether import EtherProto, EtherProtoHeader
from .ip import IPChainedHeader, IPChecksumable, IPProto, IPVersion
from .packet import Packet, PacketBuildCtx, PacketParseCtx, Payload


class IPv4OptType(U8Enum):
    EOL = 0
    NOP = 1
    SEC = 130
    LSRR = 131
    SSRR = 137
    RR = 7
    SID = 136
    TS = 68


_IPv4Address = Union[IPv4Address, str, int, bytes]
_IPVersion = Union[IPVersion, int]
_IPProto = Union[IPProto, int]
_IPv4OptType = Union[IPv4OptType, int]


class IPv4Opt(Packet):
    opt_dict: dict[int, type['IPv4Opt']] = dict()

    type: _IPv4OptType
    len: Optional[int]

    def __init__(self, len: Optional[int] = None, **kwargs):
        super().__init__(**kwargs)
        self.len = len

    def __init_subclass__(cls, **kwargs):
        super().__init_subclass__(**kwargs)
        if hasattr(cls, 'type') and cls.type not in cls.opt_dict:
            cls.opt_dict[cls.type] = cls

    def build_with_payload(self, payload: bytes, ctx: PacketBuildCtx) -> bytes:
        if isinstance(self, IPv4OptEOL) or \
           isinstance(self, IPv4OptNOP):
            return IPv4OptType.int2bytes(self.type)

        opt = self.build_opt(ctx)
        _len = len(opt) + 2
        self.len = ctx.conflict_act.resolve(self.len, _len)
        assert isinstance(self.len, int)

        return IPv4OptType.int2bytes(self.type) + \
            self.len.to_bytes(1, 'big') + \
            opt + \
            payload

    def build_opt(self, ctx: PacketBuildCtx) -> bytes:
        return b''

    @classmethod
    def parse_header_from_buffer(
        cls,
        buffer: Buffer,
        ctx: PacketParseCtx,
    ) -> Packet:
        type = IPv4OptType.pop_from_buffer(buffer)
        if type is IPv4OptType.EOL:
            buffer.pop_all()
            return IPv4OptEOL(len=1)
        if type is IPv4OptType.NOP:
            return IPv4OptNOP(len=1)

        len = buffer.pop_int(1)
        if len < 2:
            raise RuntimeError
        opt = buffer.pop(len - 2)
        kwargs = {'len': len}
        pcls = cls.opt_dict.get(type, IPv4OptUnknown)
        return pcls.parse_opt_from_buffer(type, Buffer(opt), kwargs, ctx)

    @classmethod
    def parse_opt_from_buffer(
        cls,
        type: _IPv4OptType,
        buffer: Buffer,
        kwargs: dict[str, Any],
        ctx: PacketParseCtx,
    ) -> Self:
        return cls(**kwargs)

    def guess_payload_cls(
        self,
        ctx: PacketParseCtx,
    ) -> Optional[type[Packet]]:  # type: ignore
        return IPv4Opt


class IPv4OptUnknown(IPv4Opt):
    data: bytes

    def __init__(
        self,
        type: Optional[_IPv4OptType] = 0,
        data: Optional[bytes] = b'',
        **kwargs,
    ):
        super().__init__(**kwargs)
        if type is None:
            type = 0
        if data is None:
            data = b''
        self.type = type
        self.data = data

    def build_opt(self, ctx: PacketBuildCtx) -> bytes:
        return self.data

    @classmethod
    def parse_opt_from_buffer(
        cls,
        type: _IPv4OptType,
        buffer: Buffer,
        kwargs: dict[str, Any],
        ctx: PacketParseCtx,
    ) -> Self:
        data = buffer.pop_all()
        kwargs['type'] = type
        kwargs['data'] = data
        return cls(**kwargs)


class IPv4OptEOL(IPv4Opt):
    type = IPv4OptType.EOL


class IPv4OptNOP(IPv4Opt):
    type = IPv4OptType.NOP


class IPv4OptSEC(IPv4Opt):
    data: bytes

    def __init__(self, data: Optional[bytes] = None, **kwargs):
        super().__init__(**kwargs)
        if data is None:
            data = bytes(11)
        if len(data) != 11:
            raise ValueError
        self.data = data

    def build_opt(self, ctx: PacketBuildCtx) -> bytes:
        return self.data

    @classmethod
    def parse_opt_from_buffer(
        cls,
        type: _IPv4OptType,
        buffer: Buffer,
        kwargs: dict[str, Any],
        ctx: PacketParseCtx,
    ) -> Self:
        data = buffer.pop_int(11)
        kwargs['data'] = data
        return cls(**kwargs)


class IPv4OptRR(IPv4Opt):
    ptr: int
    routes: list[IPv4Address]

    type = IPv4OptType.RR

    def __init__(
        self,
        ptr: Optional[int] = None,
        routes: Optional[Union[_IPv4Address, list[IPv4Address]]] = None,
        **kwargs,
    ):
        super().__init__(**kwargs)
        if ptr is None:
            ptr = 0
        if routes is None:
            routes = list()
        if not isinstance(routes, (list, IPv4Address)):
            routes = IPv4Address(routes)
        if isinstance(routes, IPv4Address):
            routes = [routes]
        self.ptr = ptr
        self.routes = routes

    def build_opt(self, ctx: PacketBuildCtx) -> bytes:
        return self.ptr.to_bytes(1, 'big') + \
            b''.join(bytes(route) for route in self.routes)

    @classmethod
    def parse_opt_from_buffer(
        cls,
        type: _IPv4OptType,
        buffer: Buffer,
        kwargs: dict[str, Any],
        ctx: PacketParseCtx,
    ) -> Self:
        ptr = buffer.pop_int(1)
        routes = list()
        while not buffer.empty():
            route = IPv4Address.pop_from_buffer(buffer)
            routes.append(route)
        kwargs['ptr'] = ptr
        kwargs['routes'] = routes
        return cls(**kwargs)


class IPv4OptLSRR(IPv4OptRR):
    type = IPv4OptType.LSRR


class IPv4OptSSRR(IPv4OptRR):
    type = IPv4OptType.SSRR


class IPv4OptSID(IPv4Opt):
    id: int

    type = IPv4OptType.SID

    def __init__(self, id: Optional[int] = 0, **kwargs):
        super().__init__(**kwargs)
        if id is None:
            id = 0
        self.id = id

    def build_opt(self, ctx: PacketBuildCtx) -> bytes:
        return self.id.to_bytes(2, 'big')

    @classmethod
    def parse_opt_from_buffer(
        cls,
        type: _IPv4OptType,
        buffer: Buffer,
        kwargs: dict[str, Any],
        ctx: PacketParseCtx,
    ) -> Self:
        id = buffer.pop_int(2)
        kwargs['id'] = id
        return cls(**kwargs)


class IPv4OptTS(IPv4Opt):
    ptr: int
    oflw: int
    flg: int
    addr: IPv4Address
    ts: list[int]

    type = IPv4OptType.TS

    def __init__(
        self,
        ptr: Optional[int] = 0,
        oflw: Optional[int] = 0,
        flg: Optional[int] = 0,
        addr: Optional[_IPv4Address] = None,
        ts: Optional[Union[int, list[int]]] = None,
        **kwargs,
    ):
        super().__init__(**kwargs)
        if ptr is None:
            ptr = 0
        if oflw is None:
            oflw = 0
        if flg is None:
            flg = 0
        if not isinstance(addr, IPv4Address):
            addr = IPv4Address(addr)
        if ts is None:
            ts = list()
        if isinstance(ts, int):
            ts = [ts]
        self.ptr = ptr
        self.oflw = oflw
        self.flg = flg
        self.addr = addr
        self.ts = ts

    def build_opt(self, ctx: PacketBuildCtx) -> bytes:
        return self.ptr.to_bytes(1, 'big') + \
            (((self.oflw & 0xf) << 4) + self.flg & 0xf).to_bytes(1, 'big') + \
            bytes(self.addr) + \
            b''.join(t.to_bytes(4, 'big') for t in self.ts)

    @classmethod
    def parse_opt_from_buffer(
        cls,
        type: _IPv4OptType,
        buffer: Buffer,
        kwargs: dict[str, Any],
        ctx: PacketParseCtx,
    ) -> Self:
        ptr = buffer.pop_int(1)
        i = buffer.pop_int(1)
        oflw = i >> 4
        flg = i & 0xf
        addr = IPv4Address.pop_from_buffer(buffer)
        ts = list()
        while not buffer.empty():
            t = buffer.pop_int(4)
            ts.append(t)
        kwargs['ptr'] = ptr
        kwargs['oflw'] = oflw
        kwargs['flg'] = flg
        kwargs['addr'] = addr
        kwargs['ts'] = ts
        return cls(**kwargs)


class IPv4(EtherProtoHeader, IPChainedHeader, IPChecksumable):
    ver: _IPVersion
    ihl: Optional[int]
    tos: int
    tlen: Optional[int]
    id: int
    DF: bool
    MF: bool
    offset: int
    ttl: int
    src: IPv4Address
    dst: IPv4Address
    opts: Optional[Packet]

    proto = EtherProto.IPv4

    def __init__(
        self,
        ver: Optional[_IPVersion] = IPVersion.V4,
        ihl: Optional[int] = None,
        tos: Optional[int] = 0,
        tlen: Optional[int] = None,
        id: Optional[int] = 0,
        DF: Optional[bool] = False,
        MF: Optional[bool] = False,
        offset: Optional[int] = 0,
        ttl: Optional[int] = 64,
        src: Optional[_IPv4Address] = None,
        dst: Optional[_IPv4Address] = None,
        opts: Optional[Union[Packet, bytes, int]] = None,
        **kwargs,
    ):
        super().__init__(**kwargs)
        if ver is None:
            ver = IPVersion.V4
        if tos is None:
            tos = 0
        if id is None:
            id = 0
        if DF is None:
            DF = False
        if MF is None:
            MF = False
        if offset is None:
            offset = 0
        if ttl is None:
            ttl = 64
        if not isinstance(src, IPv4Address):
            src = IPv4Address(src)
        if not isinstance(dst, IPv4Address):
            dst = IPv4Address(dst)
        if opts is not None:
            if not isinstance(opts, Packet):
                opts = Payload(opts)
        self.ver = ver
        self.ihl = ihl
        self.tos = tos
        self.tlen = tlen
        self.id = id
        self.DF = DF
        self.MF = MF
        self.offset = offset
        self.ttl = ttl
        self.src = src
        self.dst = dst
        self.opts = opts

    def build(self, ctx: PacketBuildCtx) -> bytes:
        origin_src, origin_dst = None, None

        if hasattr(ctx, 'ip_src'):
            origin_src = ctx.ip_src
        if hasattr(ctx, 'ip_dst'):
            origin_dst = ctx.ip_dst
        ctx.ip_src = self.src
        ctx.ip_dst = self.dst

        buf = super().build(ctx)

        if origin_src is not None:
            ctx.ip_src = origin_src
        if origin_dst is not None:
            ctx.ip_dst = origin_dst

        return buf

    def build_with_payload(self, payload: bytes, ctx: PacketBuildCtx) -> bytes:
        self.resolve_nh(ctx)
        assert isinstance(self.nh, int)

        if self.opts is None:
            opts = b''
        else:
            opts = self.opts.build(ctx)
        div, mod = divmod(len(opts), 4)
        if mod != 0:
            assert self.opts is not None
            div += 1
            if isinstance(self.opts.last_payload, IPv4OptEOL):
                opts += bytes(8 - mod)
            else:
                self.opts /= IPv4OptEOL(len=1)
                opts += b'\x01' + bytes(7 - mod)
        ihl = div + 5
        self.ihl = ctx.conflict_act.resolve(self.ihl, ihl)
        tlen = ihl * 4 + len(payload)
        self.tlen = ctx.conflict_act.resolve(self.tlen, tlen)
        assert isinstance(self.ihl, int) and isinstance(self.tlen, int)

        i = ((self.ver & 0xf) << 28) + \
            ((self.ihl & 0xf) << 24) + \
            ((self.tos & 0xff) << 16) + \
            (self.tlen & 0xffff)
        i <<= 32
        i += ((self.id & 0xffff) << 16) + \
            (int(self.DF) << 14) + \
            (int(self.MF) << 13) + \
            (self.offset & 0x1fff)
        pre_checksum = i.to_bytes(8, 'big')
        pre_checksum += self.ttl.to_bytes(2, 'big') + \
            IPProto.int2bytes(self.nh)
        post_checksum = bytes(self.src) + \
            bytes(self.dst) + \
            opts + \
            payload
        return self.ip_checksum_resolve_and_build(
            pre_checksum,
            post_checksum,
            ctx,
        )

    @classmethod
    def parse_header_from_buffer(
        cls,
        buffer: Buffer,
        ctx: PacketParseCtx,
    ) -> Packet:
        i = buffer.pop_int(1)
        ver = IPVersion.wrap((i >> 4) & 0xf)
        ihl = i & 0xf
        tos = buffer.pop_int(1)
        tlen = buffer.pop_int(2)
        id = buffer.pop_int(2)
        i = buffer.pop_int(2)
        DF = bool((i >> 14) & 0x1)
        MF = bool((i >> 13) & 0x1)
        offset = i & 0x1fff
        ttl = buffer.pop_int(1)
        nh = IPProto.pop_from_buffer(buffer)
        checksum = buffer.pop_int(2)
        src = IPv4Address.pop_from_buffer(buffer)
        dst = IPv4Address.pop_from_buffer(buffer)

        if ihl < 5:
            raise RuntimeError
        buf = buffer.pop((ihl - 5) * 4)
        opts = IPv4Opt.parse(buf, ctx)

        plen = tlen - (4 * ihl)
        if ctx.ensure_payload_len:
            if plen > len(buffer):
                raise RuntimeError
        buffer.narrow(plen)

        return cls(
            nh=nh,
            ver=ver,
            ihl=ihl,
            tos=tos,
            tlen=tlen,
            id=id,
            DF=DF,
            MF=MF,
            offset=offset,
            ttl=ttl,
            checksum=checksum,
            src=src,
            dst=dst,
            opts=opts,
        )


class IPv4Error(IPv4):

    @classmethod
    def parse_from_buffer(cls, buffer: Buffer, ctx: PacketParseCtx) -> Packet:
        ctx.ensure_payload_type = False
        ctx.ensure_payload_len = False
        return super().parse_from_buffer(buffer, ctx)
