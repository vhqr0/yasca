"""
RFCs:
- RFC826: ARP
"""
from typing import Optional, Union

from typing_extensions import Self

from .addr import IPv4Address, MACAddress
from .buffer import Buffer
from .enums import U16Enum
from .ether import EtherProto, EtherProtoHeader, EtherType
from .packet import PacketBuildCtx, PacketParseCtx


class ARPOperation(U16Enum):
    Request = 1
    Reply = 2


_MACAddress = Union[MACAddress, str, int, bytes]
_IPv4Address = Union[IPv4Address, str, int, bytes]
_EtherType = Union[EtherType, int]
_EtherProto = Union[EtherProto, int]
_ARPOperation = Union[ARPOperation, int]


class ARP(EtherProtoHeader):
    hwtype: _EtherType
    prototype: _EtherProto
    hwlen: Optional[int]
    protolen: Optional[int]
    op: _ARPOperation
    hwsrc: Union[MACAddress, bytes]
    hwdst: Union[MACAddress, bytes]
    protosrc: Union[IPv4Address, bytes]
    protodst: Union[IPv4Address, bytes]

    proto = EtherProto.ARP

    def __init__(
        self,
        hwtype: Optional[_EtherType] = EtherType.Ether,
        prototype: Optional[_EtherProto] = EtherProto.IPv4,
        hwlen: Optional[int] = None,
        protolen: Optional[int] = None,
        op: Optional[_ARPOperation] = ARPOperation.Request,
        hwsrc: Optional[_MACAddress] = None,
        hwdst: Optional[_MACAddress] = None,
        protosrc: Optional[_IPv4Address] = None,
        protodst: Optional[_IPv4Address] = None,
        **kwargs,
    ):
        super().__init__(**kwargs)
        if hwtype is None:
            hwtype = EtherType.Ether
        if prototype is None:
            prototype = EtherProto.IPv4
        if hwlen is None and hwtype is EtherType.Ether:
            hwlen = MACAddress.len
        if protolen is None and prototype is EtherProto.IPv4:
            protolen = IPv4Address.len
        if op is None:
            op = ARPOperation.Request
        if hwtype is EtherType.Ether:
            if not isinstance(hwsrc, MACAddress):
                hwsrc = MACAddress(hwsrc)
            if not isinstance(hwdst, MACAddress):
                hwdst = MACAddress(hwdst)
        else:
            if not isinstance(hwsrc, bytes) or \
               not isinstance(hwdst, bytes):
                raise ValueError
        if prototype is EtherProto.IPv4:
            if not isinstance(protosrc, IPv4Address):
                protosrc = IPv4Address(protosrc)
            if not isinstance(protodst, IPv4Address):
                protodst = IPv4Address(protodst)
        else:
            if not isinstance(protosrc, bytes) or \
               not isinstance(protodst, bytes):
                raise ValueError
        self.hwtype = hwtype
        self.prototype = prototype
        self.hwlen = hwlen
        self.protolen = protolen
        self.op = op
        self.hwsrc = hwsrc
        self.hwdst = hwdst
        self.protosrc = protosrc
        self.protodst = protodst

    def build(self, ctx: PacketBuildCtx) -> bytes:
        payload = self.build_payload(ctx)

        hwlen = len(self.hwsrc)
        self.hwlen = ctx.conflict_act.resolve(self.hwlen, hwlen)
        protolen = len(self.protosrc)
        self.protolen = ctx.conflict_act.resolve(self.protolen, protolen)
        assert isinstance(self.hwlen, int) and isinstance(self.protolen, int)

        header = EtherType.int2bytes(self.hwtype) + \
            EtherProto.int2bytes(self.prototype) + \
            self.hwlen.to_bytes(1, 'big') + \
            self.protolen.to_bytes(1, 'big') + \
            ARPOperation.int2bytes(self.op) + \
            bytes(self.hwsrc) + \
            bytes(self.protosrc) + \
            bytes(self.hwdst) + \
            bytes(self.protodst)

        return header + payload

    @classmethod
    def parse_from_buffer(cls, buffer: Buffer, ctx: PacketParseCtx) -> Self:
        hwtype = EtherType.pop_from_buffer(buffer)
        prototype = EtherProto.pop_from_buffer(buffer)
        hwlen = buffer.pop_int(1)
        protolen = buffer.pop_int(1)
        op = ARPOperation.pop_from_buffer(buffer)
        hwsrc: Union[MACAddress, bytes]
        protosrc: Union[IPv4Address, bytes]
        hwdst: Union[MACAddress, bytes]
        protodst: Union[IPv4Address, bytes]
        if hwtype is EtherType.Ether and \
           hwlen == MACAddress.len:
            hwsrc = MACAddress.pop_from_buffer(buffer)
        else:
            hwsrc = buffer.pop(hwlen)
        if prototype is EtherProto.IPv4 and \
           protolen == IPv4Address.len:
            protosrc = IPv4Address.pop_from_buffer(buffer)
        else:
            protosrc = buffer.pop(protolen)
        if hwtype is EtherType.Ether and \
           hwlen == MACAddress.len:
            hwdst = MACAddress.pop_from_buffer(buffer)
        else:
            hwdst = buffer.pop(hwlen)
        if prototype is EtherProto.IPv4 and \
           protolen == IPv4Address.len:
            protodst = IPv4Address.pop_from_buffer(buffer)
        else:
            protodst = buffer.pop(protolen)
        return cls(
            hwtype=hwtype,
            prototype=prototype,
            hwlen=hwlen,
            protolen=protolen,
            op=op,
            hwsrc=hwsrc,
            hwdst=hwdst,
            protosrc=protosrc,
            protodst=protodst,
        )

    @classmethod
    def get_fields(cls) -> list[str]:
        fields = super().get_fields()
        fields += [
            'hwtype',
            'prototype',
            'hwlen',
            'protolen',
            'op',
            'hwsrc',
            'hwdst',
            'protosrc',
            'protodst',
        ]
        return fields
