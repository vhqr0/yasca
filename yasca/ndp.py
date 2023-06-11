"""
RFCs:
- RFC4861: NDP
"""
from typing import Any, Optional, Union

from typing_extensions import Self

from .addr import IPv6Address, MACAddress
from .buffer import Buffer
from .enums import U8Enum
from .icmpv6 import ICMPv6, ICMPv6Type
from .packet import Packet, PacketBuildCtx, PacketParseCtx


class ICMPv6NDOptType(U8Enum):
    SourceLinkLayerAddress = 1
    TargetLinkLayerAddress = 2
    PrefixInformation = 3
    RedirectedHeader = 4
    MTU = 5


_MACAddress = Union[MACAddress, str, int, bytes]
_IPv6Address = Union[IPv6Address, str, int, bytes]
_ICMPv6Type = Union[ICMPv6Type, int]
_ICMPv6NDOptType = Union[ICMPv6NDOptType, int]


class ICMPv6ND(ICMPv6):

    def build_msg(self, ctx: PacketBuildCtx) -> bytes:
        return bytes(4)

    @classmethod
    def parse_msg_from_buffer(
        cls,
        type: _ICMPv6Type,
        buffer: Buffer,
        kwargs: dict[str, Any],
        ctx: PacketParseCtx,
    ) -> Self:
        buffer.pop(4)
        return cls(**kwargs)

    def guess_payload_cls(self, ctx: PacketParseCtx) -> Optional[type[Packet]]:
        return ICMPv6NDOpt


class ICMPv6ND_RS(ICMPv6ND):
    type = ICMPv6Type.ND_RS


class ICMPv6ND_RA(ICMPv6ND):
    hlim: int
    M: bool
    O: bool
    lifetime: int
    reachable_time: int
    retrans_timer: int

    type = ICMPv6Type.ND_RA

    def __init__(
        self,
        hlim: Optional[int] = 255,
        M: Optional[bool] = True,
        O: Optional[bool] = True,  # noqa
        lifetime: Optional[int] = 7200,
        reachable_time: Optional[int] = 0,
        retrans_timer: Optional[int] = 0,
        **kwargs,
    ):
        super().__init__(**kwargs)
        if hlim is None:
            hlim = 255
        if M is None:
            M = True
        if O is None:
            O = True  # noqa
        if lifetime is None:
            lifetime = 7200
        if reachable_time is None:
            reachable_time = 0
        if retrans_timer is None:
            retrans_timer = 0

    def build_msg(self, ctx: PacketBuildCtx) -> bytes:
        return self.hlim.to_bytes(1, 'big') + \
            ((int(self.M) << 7) + (int(self.O) << 6)).to_bytes(1, 'big') + \
            self.lifetime.to_bytes(2, 'big') + \
            self.reachable_time.to_bytes(4, 'big') + \
            self.retrans_timer.to_bytes(4, 'big')

    @classmethod
    def parse_msg_from_buffer(
        cls,
        type: _ICMPv6Type,
        buffer: Buffer,
        kwargs: dict[str, Any],
        ctx: PacketParseCtx,
    ) -> Self:
        hlim = buffer.pop_int(1)
        i = buffer.pop_int(1)
        M = bool((i >> 7) & 1)
        O = bool((i >> 6) & 1)  # noqa
        lifetime = buffer.pop_int(2)
        reachable_time = buffer.pop_int(4)
        retrans_timer = buffer.pop_int(4)
        kwargs['hlim'] = hlim
        kwargs['M'] = M
        kwargs['O'] = O
        kwargs['lifetime'] = lifetime
        kwargs['reachable_time'] = reachable_time
        kwargs['retrans_timer'] = retrans_timer
        return cls(**kwargs)


class ICMPv6ND_NS(ICMPv6ND):
    target: IPv6Address

    type = ICMPv6Type.ND_NS

    def __init__(self, target: Optional[_IPv6Address] = None, **kwargs):
        super().__init__(**kwargs)
        if not isinstance(target, IPv6Address):
            target = IPv6Address(target)
        self.target = target

    def build_msg(self, ctx: PacketBuildCtx) -> bytes:
        return bytes(4) + bytes(self.target)

    @classmethod
    def parse_msg_from_buffer(
        cls,
        type: _ICMPv6Type,
        buffer: Buffer,
        kwargs: dict[str, Any],
        ctx: PacketParseCtx,
    ) -> Self:
        buffer.pop(4)
        target = IPv6Address.pop_from_buffer(buffer)
        kwargs['target'] = target
        return cls(**kwargs)


class ICMPv6ND_NA(ICMPv6ND):
    R: bool
    S: bool
    O: bool
    target: IPv6Address

    type = ICMPv6Type.ND_NA

    def __init__(
        self,
        R: Optional[bool] = True,
        S: Optional[bool] = True,
        O: Optional[bool] = True,  # noqa
        target: Optional[_IPv6Address] = None,
        **kwargs,
    ):
        super().__init__(**kwargs)
        if R is None:
            R = True
        if S is None:
            S = True
        if O is None:
            O = True  # noqa
        if not isinstance(target, IPv6Address):
            target = IPv6Address(target)
        self.R = R
        self.S = S
        self.O = O  # noqa
        self.target = target

    def build_msg(self, ctx: PacketBuildCtx) -> bytes:
        i = (int(self.R) << 7) + \
            (int(self.S) << 6) + \
            (int(self.O) << 5)
        return i.to_bytes(1, 'big') + \
            bytes(3) + \
            bytes(self.target)

    @classmethod
    def parse_msg_from_buffer(
        cls,
        type: _ICMPv6Type,
        buffer: Buffer,
        kwargs: dict[str, Any],
        ctx: PacketParseCtx,
    ) -> Self:
        i = buffer.pop_int(1)
        R = bool((i >> 7) & 1)
        S = bool((i >> 6) & 1)
        O = bool((i >> 5) & 1)  # noqa
        buffer.pop(3)
        target = IPv6Address.pop_from_buffer(buffer)
        kwargs['R'] = R
        kwargs['S'] = S
        kwargs['O'] = O
        kwargs['target'] = target
        return cls(**kwargs)


class ICMPv6ND_RM(ICMPv6ND):
    target: IPv6Address
    dest: IPv6Address

    type = ICMPv6Type.ND_RM

    def __init__(
        self,
        target: Optional[_IPv6Address] = None,
        dest: Optional[_IPv6Address] = None,
        **kwargs,
    ):
        super().__init__(**kwargs)
        if not isinstance(target, IPv6Address):
            target = IPv6Address(target)
        if not isinstance(dest, IPv6Address):
            dest = IPv6Address(dest)
        self.target = target
        self.dest = dest

    def build_msg(self, ctx: PacketBuildCtx) -> bytes:
        return bytes(4) + \
            bytes(self.target) + \
            bytes(self.dest)

    @classmethod
    def parse_msg_from_buffer(
        cls,
        type: _ICMPv6Type,
        buffer: Buffer,
        kwargs: dict[str, Any],
        ctx: PacketParseCtx,
    ) -> Self:
        buffer.pop(4)
        target = IPv6Address.pop_from_buffer(buffer)
        dest = IPv6Address.pop_from_buffer(buffer)
        kwargs['target'] = target
        kwargs['dest'] = dest
        return cls(**kwargs)


class ICMPv6NDOpt(Packet):
    opt_dict: dict[int, type['ICMPv6NDOpt']] = dict()

    type: _ICMPv6NDOptType
    len: Optional[int]

    def __init__(self, len: Optional[int] = None, **kwargs):
        super().__init__(**kwargs)
        self.len = len

    def __init_subclass__(cls, **kwargs):
        super().__init_subclass__(**kwargs)
        if hasattr(cls, 'type') and cls.type not in cls.opt_dict:
            cls.opt_dict[cls.type] = cls

    def build_with_payload(self, payload: bytes, ctx: PacketBuildCtx) -> bytes:
        opt = self.build_opt(ctx)
        div, mod = divmod(len(opt) + 2, 8)
        if mod != 0:
            div += 1
            opt += bytes(8 - mod)
        _len = div
        self.len = ctx.conflict_act.resolve(self.len, _len)
        assert isinstance(self.len, int)
        return ICMPv6NDOptType.int2bytes(self.type) + \
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
    ) -> 'ICMPv6NDOpt':
        type = ICMPv6NDOptType.pop_from_buffer(buffer)
        len = buffer.pop_int(1) * 8 - 2
        if len < 0:
            raise RuntimeError
        opt = buffer.pop(len)
        kwargs = {'len': len}
        pcls = cls.opt_dict.get(type, ICMPv6NDOptUnknown)
        return pcls.parse_opt_from_buffer(type, Buffer(opt), kwargs, ctx)

    @classmethod
    def parse_opt_from_buffer(
        cls,
        type: _ICMPv6NDOptType,
        buffer: Buffer,
        kwargs: dict[str, Any],
        ctx: PacketParseCtx,
    ) -> Self:
        raise NotImplementedError

    def guess_payload_cls(
        self,
        ctx: PacketParseCtx,
    ) -> Optional[type[Packet]]:  # type: ignore
        return ICMPv6NDOpt


class ICMPv6NDOptUnknown(ICMPv6NDOpt):
    data: bytes

    def __init__(
        self,
        type: Optional[_ICMPv6NDOptType] = 0,
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
        type: _ICMPv6NDOptType,
        buffer: Buffer,
        kwargs: dict[str, Any],
        ctx: PacketParseCtx,
    ) -> Self:
        data = buffer.pop_all()
        kwargs['type'] = type
        kwargs['data'] = data
        return cls(**kwargs)


class ICMPv6NDOptLinkLayerAddress(ICMPv6NDOpt):
    addr: MACAddress

    def __init__(self, addr: Optional[_MACAddress] = None, **kwargs):
        super().__init__(**kwargs)
        if not isinstance(addr, MACAddress):
            addr = MACAddress(addr)
        self.addr = addr

    def build_opt(self, ctx: PacketBuildCtx) -> bytes:
        return bytes(self.addr)

    @classmethod
    def parse_opt_from_buffer(
        cls,
        type: _ICMPv6NDOptType,
        buffer: Buffer,
        kwargs: dict[str, Any],
        ctx: PacketParseCtx,
    ) -> Self:
        addr = MACAddress.pop_from_buffer(buffer)
        kwargs['addr'] = addr
        return cls(**kwargs)


class ICMPv6NDOptSourceLinkLayerAddress(ICMPv6NDOptLinkLayerAddress):
    type = ICMPv6NDOptType.SourceLinkLayerAddress


class ICMPv6NDOptTargetLinkLayerAddress(ICMPv6NDOptLinkLayerAddress):
    type = ICMPv6NDOptType.TargetLinkLayerAddress


class ICMPv6NDOptPrefixInformation(ICMPv6NDOpt):
    plen: int
    L: bool
    A: bool
    valid_lifetime: int
    prefered_lifetime: int
    prefix: IPv6Address

    type = ICMPv6NDOptType.PrefixInformation

    def __init__(
        self,
        plen: Optional[int] = 64,
        L: Optional[bool] = True,
        A: Optional[bool] = True,
        valid_lifetime: Optional[int] = 7200,
        prefered_lifetime: Optional[int] = 3600,
        prefix: Optional[_IPv6Address] = None,
        **kwargs,
    ):
        super().__init__(**kwargs)
        if plen is None:
            plen = 64
        if L is None:
            L = True
        if A is None:
            A = True
        if valid_lifetime is None:
            valid_lifetime = 7200
        if prefered_lifetime is None:
            prefered_lifetime = 3600
        if not isinstance(prefix, IPv6Address):
            prefix = IPv6Address(prefix)
        self.plen = plen
        self.L = L
        self.A = A
        self.valid_lifetime = valid_lifetime
        self.prefered_lifetime = prefered_lifetime
        self.prefix = prefix

    def build_opt(self, ctx: PacketBuildCtx) -> bytes:
        return self.plen.to_bytes(1, 'big') + \
            ((int(self.L) << 7) + int(self.A) << 6).to_bytes(1, 'big') + \
            self.valid_lifetime.to_bytes(4, 'big') + \
            self.prefered_lifetime.to_bytes(4, 'big') + \
            bytes(4) + \
            bytes(self.prefix)

    @classmethod
    def parse_opt_from_buffer(
        cls,
        type: _ICMPv6NDOptType,
        buffer: Buffer,
        kwargs: dict[str, Any],
        ctx: PacketParseCtx,
    ) -> Self:
        plen = buffer.pop_int(1)
        i = buffer.pop_int(1)
        L = bool((i >> 7) & 1)
        A = bool((i >> 6) & 1)
        valid_lifetime = buffer.pop_int(4)
        prefered_lifetime = buffer.pop_int(4)
        buffer.pop(4)
        prefix = IPv6Address.pop_from_buffer(buffer)
        kwargs['plen'] = plen
        kwargs['L'] = L
        kwargs['A'] = A
        kwargs['valid_lifetime'] = valid_lifetime
        kwargs['prefered_lifetime'] = prefered_lifetime
        kwargs['prefix'] = prefix
        return cls(**kwargs)


class ICMPv6NDOptRedirectedHeader(ICMPv6NDOpt):
    data: bytes

    type = ICMPv6NDOptType.RedirectedHeader

    def __init__(self, data: Optional[bytes] = b'', **kwargs):
        super().__init__(**kwargs)
        if data is None:
            data = b''
        self.data = data

    def build_opt(self, ctx: PacketBuildCtx) -> bytes:
        return bytes(6) + self.data

    @classmethod
    def parse_opt_from_buffer(
        cls,
        type: _ICMPv6NDOptType,
        buffer: Buffer,
        kwargs: dict[str, Any],
        ctx: PacketParseCtx,
    ) -> Self:
        buffer.pop(6)
        data = buffer.pop_all()
        kwargs['data'] = data
        return cls(**kwargs)


class ICMPv6NDOptMTU(ICMPv6NDOpt):
    mtu: int

    type = ICMPv6NDOptType.MTU

    def __init__(self, mtu: Optional[int] = 1280, **kwargs):
        super().__init__(**kwargs)
        if mtu is None:
            mtu = 1280
        self.mtu = mtu

    def build_opt(self, ctx: PacketBuildCtx) -> bytes:
        return bytes(2) + self.mtu.to_bytes(4, 'big')

    @classmethod
    def parse_opt_from_buffer(
        cls,
        type: _ICMPv6NDOptType,
        buffer: Buffer,
        kwargs: dict[str, Any],
        ctx: PacketParseCtx,
    ) -> Self:
        buffer.pop(2)
        mtu = buffer.pop_int(4)
        kwargs['mtu'] = mtu
        return cls(**kwargs)
