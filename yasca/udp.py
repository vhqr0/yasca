"""
RFCs:
- RFC768: UDP
"""
from typing import Optional

from typing_extensions import Self

from .buffer import Buffer
from .ip import IPProto, IPProtoHeader, ipproto_checksum
from .packet import FieldConflictAct, PacketBuildCtx, PacketParseCtx


class UDP(IPProtoHeader):
    src: int
    dst: int
    len: Optional[int]
    checksum: Optional[int]

    proto = IPProto.UDP

    def __init__(
        self,
        src: Optional[int] = 0,
        dst: Optional[int] = 0,
        len: Optional[int] = None,
        checksum: Optional[int] = None,
        **kwargs,
    ):
        super().__init__(**kwargs)
        if src is None:
            src = 0
        if dst is None:
            dst = 0
        self.src = src
        self.dst = dst
        self.len = len
        self.checksum = checksum

    def build(self, ctx: PacketBuildCtx) -> bytes:
        payload = self.build_payload(ctx)
        tlen = len(payload) + 8
        self.len = ctx.conflict_act.resolve(self.len, tlen)
        assert isinstance(self.len, int)

        pre_checksum = self.src.to_bytes(2, 'big') + \
            self.dst.to_bytes(2, 'big') + \
            self.len.to_bytes(2, 'big')
        post_checksum = payload

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
        tlen = buffer.pop_int(2)
        checksum = buffer.pop_int(2)
        packet = cls(
            src=src,
            dst=dst,
            len=tlen,
            checksum=checksum,
        )
        plen = tlen - 8
        if plen < 0:
            raise RuntimeError
        if ctx.ensure_payload_len:
            if plen > len(buffer):
                raise RuntimeError
        buffer.narrow(plen)
        packet.parse_payload_from_buffer(buffer, ctx)
        return packet
