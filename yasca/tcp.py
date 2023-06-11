"""
RFCs:
- RFC9293: TCP
"""
from typing import Optional

from typing_extensions import Self

from .buffer import Buffer
from .ip import IPProto, IPProtoHeader, ipproto_checksum
from .packet import FieldConflictAct, PacketBuildCtx, PacketParseCtx


class TCP(IPProtoHeader):
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
    checksum: Optional[int]
    ptr: int
    opts: bytes

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
        checksum: Optional[int] = None,
        ptr: Optional[int] = 0,
        opts: Optional[bytes] = b'',
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
        if opts is None:
            opts = b''
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
        self.checksum = checksum
        self.ptr = ptr
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
        self.resolve_opts(ctx)
        div, mod = divmod(len(self.opts), 4)
        if mod != 0:
            raise RuntimeError
        offset = div + 5
        self.offset = ctx.conflict_act.resolve(self.offset, offset)
        assert isinstance(self.offset, int)

        payload = self.build_payload(ctx)
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
            self.opts + \
            payload

        if self.checksum is not None and \
           ctx.conflict_act is FieldConflictAct.Override:
            return pre_checksum + \
                self.checksum.to_bytes(2, 'big') + \
                post_checksum

        buf = pre_checksum + b'\x00\x00' + post_checksum
        checksum = ipproto_checksum(buf, ctx.ip_src, ctx.ip_dst, self.proto)
        self.checksum = ctx.conflict_act.resolve(self.checksum, checksum)
        assert isinstance(self.checksum, int)
        return pre_checksum + self.checksum.to_bytes(2, 'big') + post_checksum

    @classmethod
    def parse_from_buffer(cls, buffer: Buffer, ctx: PacketParseCtx) -> Self:
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
        opts = buffer.pop((offset - 5) * 4)
        packet = cls(
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
        packet.parse_payload_from_buffer(buffer, ctx)
        return packet
