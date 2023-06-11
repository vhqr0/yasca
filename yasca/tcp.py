"""
RFCs:
- RFC9293: TCP
- RFC7323: TCP Opt WS, TS
- RFC2018, RFC2883: TCP Opt SACK
"""
from typing import Any, Optional, Union

from typing_extensions import Self

from .buffer import Buffer
from .enums import U8Enum
from .ip import IPChecksumable, IPProto, IPProtoHeader
from .packet import Packet, PacketBuildCtx, PacketParseCtx, Payload


class TCPOptType(U8Enum):
    EOL = 0
    NOP = 1
    MSS = 2
    WS = 3
    TS = 8
    SACKOK = 4
    SACK = 5


_TCPOptType = Union[TCPOptType, int]


class TCPOpt(Packet):
    opt_dict: dict[int, type['TCPOpt']] = dict()

    type: _TCPOptType
    len: Optional[int]

    def __init__(self, len: Optional[int] = None, **kwargs):
        super().__init__(**kwargs)
        self.len = len

    def __init_subclass__(cls, **kwargs):
        super().__init_subclass__(**kwargs)
        if hasattr(cls, 'type') and cls.type not in cls.opt_dict:
            cls.opt_dict[cls.type] = cls

    def build_with_payload(self, payload: bytes, ctx: PacketBuildCtx) -> bytes:
        if isinstance(self, TCPOptEOL) or \
           isinstance(self, TCPOptNOP):
            return TCPOptType.int2bytes(self.type)

        opt = self.build_opt(ctx)
        _len = len(opt) + 2
        self.len = ctx.conflict_act.resolve(self.len, _len)
        assert isinstance(self.len, int)

        return TCPOptType.int2bytes(self.type) + \
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
        type = TCPOptType.pop_from_buffer(buffer)
        if type is TCPOptType.EOL:
            buffer.pop_all()
            return TCPOptEOL(len=1)
        if type is TCPOptType.NOP:
            return TCPOptNOP(len=1)

        len = buffer.pop_int(1)
        if len < 2:
            raise RuntimeError
        opt = buffer.pop(len - 2)
        kwargs = {'len': len}
        pcls = cls.opt_dict.get(type, TCPOptUnknown)
        return pcls.parse_opt_from_buffer(type, Buffer(opt), kwargs, ctx)

    @classmethod
    def parse_opt_from_buffer(
        cls,
        type: _TCPOptType,
        buffer: Buffer,
        kwargs: dict[str, Any],
        ctx: PacketParseCtx,
    ) -> Self:
        return cls(**kwargs)

    def guess_payload_cls(
        self,
        ctx: PacketParseCtx,
    ) -> Optional[type[Packet]]:  # type: ignore
        return TCPOpt


class TCPOptUnknown(TCPOpt):
    data: bytes

    def __init__(
        self,
        type: Optional[_TCPOptType] = 0,
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
        type: _TCPOptType,
        buffer: Buffer,
        kwargs: dict[str, Any],
        ctx: PacketParseCtx,
    ) -> Self:
        data = buffer.pop_all()
        kwargs['type'] = type
        kwargs['data'] = data
        return cls(**kwargs)


class TCPOptEOL(TCPOpt):
    type = TCPOptType.EOL


class TCPOptNOP(TCPOpt):
    type = TCPOptType.NOP


class TCPOptMSS(TCPOpt):
    mss: int

    type = TCPOptType.MSS

    def __init__(self, mss: Optional[int] = 1220, **kwargs):
        super().__init__(**kwargs)
        if mss is None:
            mss = 1220
        self.mss = mss

    def build_opt(self, ctx: PacketBuildCtx) -> bytes:
        return self.mss.to_bytes(2, 'big')

    @classmethod
    def parse_opt_from_buffer(
        cls,
        type: _TCPOptType,
        buffer: Buffer,
        kwargs: dict[str, Any],
        ctx: PacketParseCtx,
    ) -> Self:
        mss = buffer.pop_int(2)
        kwargs['mss'] = mss
        return cls(**kwargs)


class TCPOptWS(TCPOpt):
    cnt: int

    type = TCPOptType.WS

    def __init__(
        self,
        cnt: Optional[int] = 0,
        **kwargs,
    ):
        super().__init__(**kwargs)
        if cnt is None:
            cnt = 0
        self.cnt = cnt

    def build_opt(self, ctx: PacketBuildCtx) -> bytes:
        return self.cnt.to_bytes(1, 'big')

    @classmethod
    def parse_opt_from_buffer(
        cls,
        type: _TCPOptType,
        buffer: Buffer,
        kwargs: dict[str, Any],
        ctx: PacketParseCtx,
    ) -> Self:
        cnt = buffer.pop_int(1)
        kwargs['cnt'] = cnt
        return cls(**kwargs)


class TCPOptTS(TCPOpt):
    val: int
    ecr: int

    type = TCPOptType.TS

    def __init__(
        self,
        val: Optional[int] = 0,
        ecr: Optional[int] = 0,
        **kwargs,
    ):
        super().__init__(**kwargs)
        if val is None:
            val = 0
        if ecr is None:
            ecr = 0
        self.val = val
        self.ecr = ecr

    def build_opt(self, ctx: PacketBuildCtx) -> bytes:
        return self.val.to_bytes(4, 'big') + self.ecr.to_bytes(4, 'big')

    @classmethod
    def parse_opt_from_buffer(
        cls,
        type: _TCPOptType,
        buffer: Buffer,
        kwargs: dict[str, Any],
        ctx: PacketParseCtx,
    ) -> Self:
        val = buffer.pop_int(4)
        ecr = buffer.pop_int(4)
        kwargs['val'] = val
        kwargs['ecr'] = ecr
        return cls(**kwargs)


class TCPOptSACKOK(TCPOpt):
    type = TCPOptType.SACKOK


class TCPOptSACK(TCPOpt):
    edges: list[int]

    type = TCPOptType.SACK

    def __init__(
        self,
        edges: Optional[Union[int, list[int]]] = None,
        **kwargs,
    ):
        super().__init__(**kwargs)
        if edges is None:
            edges = list()
        if isinstance(edges, int):
            edges = [edges]
        self.edges = edges

    def build_opt(self, ctx: PacketBuildCtx) -> bytes:
        return b''.join(edge.to_bytes(4, 'big') for edge in self.edges)

    @classmethod
    def parse_opt_from_buffer(
        cls,
        type: _TCPOptType,
        buffer: Buffer,
        kwargs: dict[str, Any],
        ctx: PacketParseCtx,
    ) -> Self:
        edges = list()
        while not buffer.empty():
            edge = buffer.pop_int(4)
            edges.append(edge)
        kwargs['edges'] = edges
        return cls(**kwargs)


class TCP(IPProtoHeader, IPChecksumable):
    src: int
    dst: int
    seqno: int
    ackno: int
    offset: Optional[int]
    CWR: bool
    ECE: bool
    URG: bool
    ACK: bool
    PSH: bool
    RST: bool
    SYN: bool
    FIN: bool
    window: int
    ptr: int
    opts: Optional[Packet]

    proto = IPProto.TCP

    def __init__(
        self,
        src: Optional[int] = 0,
        dst: Optional[int] = 0,
        seqno: Optional[int] = 0,
        ackno: Optional[int] = 0,
        offset: Optional[int] = None,
        CWR: Optional[bool] = False,
        ECE: Optional[bool] = False,
        URG: Optional[bool] = False,
        ACK: Optional[bool] = False,
        PSH: Optional[bool] = False,
        RST: Optional[bool] = False,
        SYN: Optional[bool] = False,
        FIN: Optional[bool] = False,
        window: Optional[int] = 65535,
        ptr: Optional[int] = 0,
        opts: Optional[Union[Packet, bytes, int]] = None,
        **kwargs,
    ):
        super().__init__(**kwargs)
        if src is None:
            src = 0
        if dst is None:
            dst = 0
        if seqno is None:
            seqno = 0
        if ackno is None:
            ackno = 0
        if CWR is None:
            CWR = False
        if ECE is None:
            ECE = False
        if URG is None:
            URG = False
        if ACK is None:
            ACK = False
        if PSH is None:
            PSH = False
        if RST is None:
            RST = False
        if SYN is None:
            SYN = False
        if FIN is None:
            FIN = False
        if window is None:
            window = 65535
        if ptr is None:
            ptr = 0
        if opts is not None:
            if not isinstance(opts, Packet):
                opts = Payload(opts)
        self.src = src
        self.dst = dst
        self.seqno = seqno
        self.ackno = ackno
        self.offset = offset
        self.CWR = CWR
        self.ECE = ECE
        self.URG = URG
        self.ACK = ACK
        self.PSH = PSH
        self.RST = RST
        self.SYN = SYN
        self.FIN = FIN
        self.window = window
        self.ptr = ptr
        self.opts = opts

    def build_with_payload(self, payload: bytes, ctx: PacketBuildCtx) -> bytes:
        if self.opts is None:
            opts = b''
        else:
            opts = self.opts.build(ctx)
        div, mod = divmod(len(opts), 4)
        if mod != 0:
            assert self.opts is not None
            div += 1
            if isinstance(self.opts.last_payload, TCPOptEOL):
                opts += bytes(8 - mod)
            else:
                self.opts /= TCPOptEOL(len=1)
                opts += b'\x01' + bytes(7 - mod)
        offset = div + 5
        self.offset = ctx.conflict_act.resolve(self.offset, offset)
        assert isinstance(self.offset, int)

        i = (self.offset << 12) + \
            (int(self.CWR) << 7) + \
            (int(self.ECE) << 6) + \
            (int(self.URG) << 5) + \
            (int(self.ACK) << 4) + \
            (int(self.PSH) << 3) + \
            (int(self.RST) << 2) + \
            (int(self.SYN) << 1) + \
            int(self.FIN)
        pre_checksum = self.src.to_bytes(2, 'big') + \
            self.dst.to_bytes(2, 'big') + \
            self.seqno.to_bytes(4, 'big') + \
            self.ackno.to_bytes(4, 'big') + \
            i.to_bytes(2, 'big') + \
            self.window.to_bytes(2, 'big')
        post_checksum = self.ptr.to_bytes(2, 'big') + \
            opts + \
            payload
        return self.ipproto_checksum_resolve_and_build(
            pre_checksum,
            post_checksum,
            self.proto,
            ctx,
        )

    @classmethod
    def parse_header_from_buffer(
        cls,
        buffer: Buffer,
        ctx: PacketParseCtx,
    ) -> Packet:
        src = buffer.pop_int(2)
        dst = buffer.pop_int(2)
        seqno = buffer.pop_int(4)
        ackno = buffer.pop_int(4)
        offset = buffer.pop_int(1) >> 4
        i = buffer.pop_int(1)
        CWR = bool((i >> 7) & 1)
        ECE = bool((i >> 6) & 1)
        URG = bool((i >> 5) & 1)
        ACK = bool((i >> 4) & 1)
        PSH = bool((i >> 3) & 1)
        RST = bool((i >> 2) & 1)
        SYN = bool((i >> 1) & 1)
        FIN = bool(i & 1)
        window = buffer.pop_int(2)
        checksum = buffer.pop_int(2)
        ptr = buffer.pop_int(2)

        if offset < 5:
            raise RuntimeError
        buf = buffer.pop((offset - 5) * 4)
        opts = TCPOpt.parse(buf, ctx)

        return cls(
            src=src,
            dst=dst,
            seqno=seqno,
            ackno=ackno,
            offset=offset,
            CWR=CWR,
            ECE=ECE,
            URG=URG,
            ACK=ACK,
            PSH=PSH,
            RST=RST,
            SYN=SYN,
            FIN=FIN,
            window=window,
            checksum=checksum,
            ptr=ptr,
            opts=opts,
        )
