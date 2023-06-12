"""
RFCs:
- RFC8200: IPv6
- RFC2675: IPv6 Opt Jumbo
- RFC2460, RFC5095: IPv6 Routing Type 0
"""
from typing import Any, Optional, Union

from typing_extensions import Self

from .addr import IPv6Address
from .buffer import Buffer
from .enums import U8Enum
from .ether import EtherProto, EtherProtoHeader
from .ip import IPChainedHeader, IPProto, IPProtoHeader, IPVersion
from .packet import (FieldConflictAct, Packet, PacketBuildCtx, PacketParseCtx,
                     Payload)


class IPv6OptType(U8Enum):
    Pad1 = 0x00
    PadN = 0x01
    Jumbo = 0xc2


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

        return i.to_bytes(8, 'big') + \
            bytes(self.src) + \
            bytes(self.dst) + \
            payload

    @classmethod
    def parse_header_from_buffer(
        cls,
        buffer: Buffer,
        ctx: PacketParseCtx,
    ) -> Packet:
        i = buffer.pop_int(4)
        ver = IPVersion.wrap((i >> 28) & 0xf)
        tc = (i >> 20) & 0xff
        fl = i & 0xfff
        plen = buffer.pop_int(2)
        nh = cls.parse_nh_from_buffer(buffer, ctx)
        hlim = buffer.pop_int(1)
        src = IPv6Address.pop_from_buffer(buffer)
        dst = IPv6Address.pop_from_buffer(buffer)

        if ctx.ensure_payload_len:
            if plen > len(buffer):
                raise RuntimeError
        buffer.narrow(plen)

        return cls(
            nh=nh,
            ver=ver,
            tc=tc,
            fl=fl,
            plen=plen,
            hlim=hlim,
            src=src,
            dst=dst,
        )


class IPv6Error(IPv6):

    @classmethod
    def parse_from_buffer(cls, buffer: Buffer, ctx: PacketParseCtx) -> Packet:
        ctx.ensure_payload_type = False
        ctx.ensure_payload_len = False
        return super().parse_from_buffer(buffer, ctx)


class IPv6Opt(Packet):
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

    def build_with_payload(self, payload: bytes, ctx: PacketBuildCtx) -> bytes:
        if isinstance(self, IPv6OptPad1):
            return IPv6OptType.int2bytes(self.type)

        opt = self.build_opt(ctx)
        _len = len(opt)
        self.len = ctx.conflict_act.resolve(self.len, _len)
        assert isinstance(self.len, int)

        return IPv6OptType.int2bytes(self.type) + \
            self.len.to_bytes(1, 'big') + \
            opt + \
            payload

    def build_opt(self, ctx: PacketBuildCtx) -> bytes:
        raise NotImplementedError

    @classmethod
    def parse_header_from_buffer(
        cls,
        buffer: Buffer,
        ctx: PacketParseCtx,
    ) -> Packet:
        type = IPv6OptType.pop_from_buffer(buffer)
        if type is IPv6OptType.Pad1:
            return IPv6OptPad1(len=0)

        len = buffer.pop_int(1)
        opt = buffer.pop(len)
        kwargs = {'len': len}
        pcls = cls.opt_dict.get(type, IPv6OptUnknown)
        return pcls.parse_opt_from_buffer(type, Buffer(opt), kwargs, ctx)

    @classmethod
    def parse_opt_from_buffer(
        cls,
        type: _IPv6OptType,
        buffer: Buffer,
        kwargs: dict[str, Any],
        ctx: PacketParseCtx,
    ) -> Self:
        raise NotImplementedError

    def guess_payload_cls(
        self,
        ctx: PacketParseCtx,
    ) -> Optional[type[Packet]]:  # type: ignore
        return IPv6Opt


class IPv6OptUnknown(IPv6Opt):
    data: bytes

    def __init__(
        self,
        type: Optional[_IPv6OptType] = 0,
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
        type: _IPv6OptType,
        buffer: Buffer,
        kwargs: dict[str, Any],
        ctx: PacketParseCtx,
    ) -> Self:
        data = buffer.pop_all()
        kwargs['type'] = type
        kwargs['data'] = data
        return cls(**kwargs)


class IPv6OptPad1(IPv6Opt):
    type = IPv6OptType.Pad1


class IPv6OptPadN(IPv6Opt):
    n: int

    type = IPv6OptType.PadN

    def __init__(self, n: Optional[int] = 2, **kwargs):
        super().__init__(**kwargs)
        if n is None:
            n = 2
        if n < 2:
            raise ValueError
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


class IPv6OptJumbo(IPv6Opt):
    plen: int

    type = IPv6OptType.Jumbo

    def __init__(self, plen: Optional[int] = 0, **kwargs):
        super().__init__(**kwargs)
        if plen is None:
            plen = 0
        self.plen = plen

    def build_opt(self, ctx: PacketBuildCtx) -> bytes:
        return self.plen.to_bytes(4, 'big')

    @classmethod
    def parse_opt_from_buffer(
        cls,
        type: _IPv6OptType,
        buffer: Buffer,
        kwargs: dict[str, Any],
        ctx: PacketParseCtx,
    ) -> Self:
        plen = buffer.pop_int(4)
        kwargs['plen'] = plen
        return cls(**kwargs)


class IPv6ExtHeader(IPProtoHeader, IPChainedHeader):
    len: Optional[int]

    def __init__(self, len: Optional[int] = None, **kwargs):
        super().__init__(**kwargs)
        self.len = len

    def build_with_payload(self, payload: bytes, ctx: PacketBuildCtx) -> bytes:
        self.resolve_nh(ctx)
        assert isinstance(self.nh, int)

        ext = self.build_ext(ctx)
        if isinstance(self, IPv6ExtFragment):
            _len = 0
        else:
            div, mod = divmod(len(ext) + 2, 8)
            if mod != 0:
                raise RuntimeError
            _len = div - 1
        self.len = ctx.conflict_act.resolve(self.len, _len)
        assert isinstance(self.len, int)

        return IPProto.int2bytes(self.nh) + \
            self.len.to_bytes(1, 'big') + \
            ext + \
            payload

    def build_ext(self, ctx: PacketBuildCtx) -> bytes:
        raise NotImplementedError

    @classmethod
    def parse_header_from_buffer(
        cls,
        buffer: Buffer,
        ctx: PacketParseCtx,
    ) -> Packet:
        nh = cls.parse_nh_from_buffer(buffer, ctx)
        len = buffer.pop_int(1)
        if nh is IPProto.Fragment:
            ext = buffer.pop(6)
        else:
            ext = buffer.pop((len + 1) * 8 - 2)
        kwargs = {'nh': nh, 'len': len}
        return cls.parse_ext_from_buffer(Buffer(ext), kwargs, ctx)

    @classmethod
    def parse_ext_from_buffer(
        cls,
        buffer: Buffer,
        kwargs: dict[str, Any],
        ctx: PacketParseCtx,
    ) -> Packet:
        raise NotImplementedError


# Notice: IPv6ExtHeader is not a dispatched parser, therefore
# IPv6ExtUnknown, unlike IPv6OptUnknown or ICMPv6Unknown, is a
# build-only class for custom ext type and other fields. If you want
# to parse an ext with custom type, you have better to def a new
# IPv6ExtHeader instead.
class IPv6ExtUnknown(IPv6ExtHeader):
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


class IPv6ExtRouting(IPv6ExtHeader):
    type: int
    segs: int
    addrs: list[IPv6Address]

    proto = IPProto.Routing

    def __init__(
        self,
        type: Optional[int] = 0,
        segs: Optional[int] = 0,
        addrs: Optional[Union[_IPv6Address, list[IPv6Address]]] = None,
        **kwargs,
    ):
        super().__init__(**kwargs)
        if type is None:
            type = 0
        if segs is None:
            segs = 0
        if not isinstance(addrs, (list, IPv6Address)):
            addrs = IPv6Address(addrs)
        if isinstance(addrs, IPv6Address):
            addrs = [addrs]
        self.type = type
        self.segs = segs
        self.addrs = addrs

    def build_ext(self, ctx: PacketBuildCtx) -> bytes:
        return self.type.to_bytes(1, 'big') + \
            self.segs.to_bytes(1, 'big') + \
            bytes(4) + \
            b''.join(bytes(addr) for addr in self.addrs)

    @classmethod
    def parse_ext_from_buffer(
        cls,
        buffer: Buffer,
        kwargs: dict[str, Any],
        ctx: PacketParseCtx,
    ) -> Packet:
        type = buffer.pop_int(1)
        segs = buffer.pop_int(1)
        buffer.pop(4)
        addrs = list()
        while not buffer.empty():
            addrs.append(IPv6Address.pop_from_buffer(buffer))
        kwargs['type'] = type
        kwargs['segs'] = segs
        kwargs['addrs'] = addrs
        return cls(**kwargs)


class IPv6ExtOptList(IPv6ExtHeader):
    opts: Optional[Union[IPv6Opt, Payload]]

    def __init__(
        self,
        opts: Optional[Union[IPv6Opt, Payload, bytes, int]] = None,
        **kwargs,
    ):
        super().__init__(**kwargs)
        if opts is not None:
            if not isinstance(opts, Packet):
                opts = Payload(opts)
        self.opts = opts

    def build_ext(self, ctx: PacketBuildCtx) -> bytes:
        if self.opts is None:
            ext = b''
        else:
            ext = self.opts.build(ctx)
        div, mod = divmod(len(ext) + 2, 8)
        act = ctx.conflict_act
        if act is FieldConflictAct.Override:
            return ext
        if act is FieldConflictAct.Ignore:
            pad: IPv6Opt
            n = 8 - mod
            if n == 1:
                pad = IPv6OptPad1()
            else:
                pad = IPv6OptPadN(n)
            if self.opts is None:
                self.opts = pad
            else:
                self.opts /= pad
            ext += pad.build(ctx)
            return ext
        raise RuntimeError

    @classmethod
    def parse_ext_from_buffer(
        cls,
        buffer: Buffer,
        kwargs: dict[str, Any],
        ctx: PacketParseCtx,
    ) -> Packet:
        opts = IPv6Opt.parse(buffer, ctx)
        kwargs['opts'] = opts
        return cls(**kwargs)


class IPv6ExtHopByHop(IPv6ExtOptList):
    proto = IPProto.HopByHopOption


class IPv6ExtDestination(IPv6ExtOptList):
    proto = IPProto.DestinationOption


class IPv6ExtFragment(IPv6ExtHeader):
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

    def build_ext(self, ctx: PacketBuildCtx) -> bytes:
        i = (self.offset << 3) + int(self.M)
        i <<= 32
        i += self.id & 0xffffffff
        return i.to_bytes(6, 'big')

    @classmethod
    def parse_ext_from_buffer(
        cls,
        buffer: Buffer,
        kwargs: dict[str, Any],
        ctx: PacketParseCtx,
    ) -> Packet:
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
