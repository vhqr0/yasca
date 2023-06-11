"""
RFCs:
- RFC768: UDP
"""
from typing import Optional

from .buffer import Buffer
from .ip import IPChecksumable, IPProto, IPProtoHeader
from .packet import Packet, PacketBuildCtx, PacketParseCtx


class UDP(IPProtoHeader, IPChecksumable):
    src: int
    dst: int
    len: Optional[int]

    proto = IPProto.UDP

    def __init__(
        self,
        src: Optional[int] = 0,
        dst: Optional[int] = 0,
        len: Optional[int] = None,
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

    def build_with_payload(self, payload: bytes, ctx: PacketBuildCtx) -> bytes:
        tlen = len(payload) + 8
        self.len = ctx.conflict_act.resolve(self.len, tlen)
        assert isinstance(self.len, int)

        pre_checksum = self.src.to_bytes(2, 'big') + \
            self.dst.to_bytes(2, 'big') + \
            self.len.to_bytes(2, 'big')
        post_checksum = payload
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
        tlen = buffer.pop_int(2)
        checksum = buffer.pop_int(2)

        plen = tlen - 8
        if plen < 0:
            raise RuntimeError
        if ctx.ensure_payload_len:
            if plen > len(buffer):
                raise RuntimeError
        buffer.narrow(plen)

        return cls(
            src=src,
            dst=dst,
            len=tlen,
            checksum=checksum,
        )
