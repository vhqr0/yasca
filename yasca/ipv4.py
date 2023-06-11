"""
RFCs:
- RFC791: IPv4
"""
from typing import Optional, Union

from .addr import IPv4Address
from .buffer import Buffer
from .ether import EtherProto, EtherProtoHeader
from .ip import IPChainedHeader, IPChecksumable, IPProto, IPVersion
from .packet import FieldConflictAct, Packet, PacketBuildCtx, PacketParseCtx

_IPv4Address = Union[IPv4Address, str, int, bytes]
_IPVersion = Union[IPVersion, int]
_IPProto = Union[IPProto, int]


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
    opts: bytes

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
        opts: Optional[bytes] = b'',
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
        if opts is None:
            opts = b''
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

    def resolve_opts(self, ctx: PacketBuildCtx):
        div, mod = divmod(len(self.opts), 4)
        if mod == 0:
            return
        act = ctx.conflict_act
        if act is FieldConflictAct.Override:
            return
        if act is FieldConflictAct.Ignore:
            self.opts += bytes(8 - mod)
            return
        raise RuntimeError

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
        self.resolve_opts(ctx)
        assert isinstance(self.nh, int)

        div, mod = divmod(len(self.opts), 4)
        if mod != 0:
            raise RuntimeError
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
            self.opts + \
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
        opts = buffer.pop((ihl - 5) * 4)

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
