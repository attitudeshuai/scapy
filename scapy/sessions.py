# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information

"""
Sessions: decode flow of packets when sniffing
"""

from collections import OrderedDict, defaultdict, deque
import socket
import struct
import threading
import time

from scapy.config import conf
from scapy.data import MTU
from scapy.error import log_runtime
from scapy.packet import Packet
from scapy.pton_ntop import inet_pton

# Typing imports
from typing import (
    Any,
    Callable,
    DefaultDict,
    Deque,
    Dict,
    Iterator,
    List,
    Optional,
    Tuple,
    Type,
    cast,
    TYPE_CHECKING,
)
from scapy.compat import Self
if TYPE_CHECKING:
    from scapy.supersocket import SuperSocket


# Policies used by the 'on_limit' session parameter: they describe what
# happens when a packet would open a new connection past 'max_connections'.
SESSION_LIMIT_REJECT = "reject"  # ignore packets from the new connection
SESSION_LIMIT_EVICT = "evict"  # evict the least recently used connection
SESSION_LIMIT_FAIL = "fail"  # fail the processing of the current packet

SESSION_LIMIT_POLICIES = frozenset(
    {
        SESSION_LIMIT_REJECT,
        SESSION_LIMIT_EVICT,
        SESSION_LIMIT_FAIL,
    }
)

# Reasons found in EvictedConnection records
SESSION_EVICT_IDLE = "idle_timeout"
SESSION_EVICT_OLDEST = "evicted_oldest"


class SessionLimitExceeded(Exception):
    """Raised when a session declared with ``on_limit=SESSION_LIMIT_FAIL``
    receives a packet that would open a new connection past
    ``max_connections``."""

    def __init__(self, table, key):
        # type: (str, Any) -> None
        self.table = table
        self.key = key
        super(SessionLimitExceeded, self).__init__(
            "New %s connection %r exceeded max_connections" % (table, key)
        )


class EvictedConnection(object):
    """Record of a reassembly connection removed by a session cleanup.

    :param table: table the connection was held in (``'ip'`` or ``'tcp'``)
    :param key: key used by that table (an IP fragment tuple, or the raw
        TCP ident returned by TCPSession._get_ident())
    :param reason: SESSION_EVICT_IDLE or SESSION_EVICT_OLDEST
    :param last_seen: timestamp of the last packet seen on the connection
    :param removed_at: timestamp at which it was removed
    :param buffered: number of buffered bytes accounted on it
    """

    __slots__ = [
        "table",
        "key",
        "reason",
        "last_seen",
        "removed_at",
        "buffered",
    ]

    def __init__(self, table, key, reason, last_seen, removed_at, buffered):
        # type: (str, Any, str, float, float, int) -> None
        self.table = table
        self.key = key
        self.reason = reason
        self.last_seen = last_seen
        self.removed_at = removed_at
        self.buffered = buffered

    def __repr__(self):
        # type: () -> str
        return (
            "<EvictedConnection %s %r reason=%s last_seen=%s buffered=%d>"
            % (
                self.table,
                self.key,
                self.reason,
                self.last_seen,
                self.buffered,
            )
        )


class _FlowTable(object):
    """LRU accounting of the connections of one reassembly dictionary.

    The session keeps owning the actual reassembly data. This object only
    tracks connection keys, their last seen timestamp and the number of
    buffered bytes. Every operation assumes the caller holds
    _SessionResourceManager.lock.
    """

    def __init__(self, name, remove, manager):
        # type: (str, Callable[[Any, Any], None], _SessionResourceManager) -> None
        self.name = name
        self._remove = remove
        self._manager = manager
        # key -> [last_seen, buffered_bytes, opaque session data]
        self.flows = OrderedDict()  # type: OrderedDict[Any, List[Any]]
        self._last_sweep = None  # type: Optional[float]

    def _sweep(self, now, force=False):
        # type: (float, bool) -> List[EvictedConnection]
        """Remove idle connections (least recently seen first)."""
        manager = self._manager
        timeout = manager.idle_timeout
        if timeout is None:
            return []
        if (
            not force
            and self._last_sweep is not None
            and now - self._last_sweep < timeout
        ):
            return []
        self._last_sweep = now
        removed = []  # type: List[EvictedConnection]
        while self.flows:
            key, state = next(iter(self.flows.items()))
            last_seen = float(state[0])
            if now - last_seen < timeout:
                break
            self.flows.popitem(last=False)
            self._remove(key, state[2])
            manager.stats["expired_connections"] += 1
            removed.append(
                manager.record(
                    self.name,
                    key,
                    SESSION_EVICT_IDLE,
                    last_seen,
                    now,
                    int(state[1]),
                )
            )
        return removed

    def admit(self, key, now, extra=None):
        # type: (Any, float, Any) -> bool
        """Account for a packet belonging to 'key'.

        Returns False when the new connection is rejected per the
        declared policy, and raises SessionLimitExceeded with the FAIL
        policy.
        """
        manager = self._manager
        self._sweep(now)
        state = self.flows.get(key)
        if state is not None:
            # Existing connection: refresh it and move it to the LRU end.
            state[0] = now
            self.flows.move_to_end(key)
            return True
        # New connection: apply the connection-count policy.
        if (
            manager.max_connections is not None
            and len(self.flows) >= manager.max_connections
        ):
            if manager.on_limit == SESSION_LIMIT_REJECT:
                manager.stats["rejected_connections"] += 1
                return False
            if manager.on_limit == SESSION_LIMIT_FAIL:
                manager.stats["failed_packets"] += 1
                raise SessionLimitExceeded(self.name, key)
            # SESSION_LIMIT_EVICT: drop the least recently used connection.
            old_key, old_state = self.flows.popitem(last=False)
            self._remove(old_key, old_state[2])
            manager.stats["evicted_connections"] += 1
            manager.record(
                self.name,
                old_key,
                SESSION_EVICT_OLDEST,
                float(old_state[0]),
                now,
                int(old_state[1]),
            )
        self.flows[key] = [now, 0, extra]
        return True

    def size(self, key):
        # type: (Any) -> int
        state = self.flows.get(key)
        return int(state[1]) if state is not None else 0

    def add_size(self, key, delta):
        # type: (Any, int) -> None
        state = self.flows.get(key)
        if state is not None:
            state[1] = int(state[1]) + delta

    def set_size(self, key, value):
        # type: (Any, int) -> None
        state = self.flows.get(key)
        if state is not None:
            state[1] = value

    def completed(self, key):
        # type: (Any) -> None
        """Forget a connection that finished reassembling normally."""
        state = self.flows.pop(key, None)
        if state is not None:
            self._remove(key, state[2])

    def prune(self, now):
        # type: (float) -> List[EvictedConnection]
        return self._sweep(now, force=True)


class _SessionResourceManager(object):
    """Resource limits declared on a session and shared synchronization.

    Created only when at least one of 'max_connections', 'max_buffer' or
    'idle_timeout' is set. Sessions without limits run their unmanaged
    fast path and never touch this object.
    """

    def __init__(
        self,
        max_connections,
        max_buffer,
        idle_timeout,
        on_limit,
        eviction_log_size,
    ):
        # type: (Optional[int], Optional[int], Optional[float], str, Optional[int]) -> None  # noqa: E501
        if max_connections is not None and (
            not isinstance(max_connections, int) or max_connections <= 0
        ):
            raise ValueError("max_connections must be a positive integer")
        if max_buffer is not None and (
            not isinstance(max_buffer, int) or max_buffer <= 0
        ):
            raise ValueError("max_buffer must be a positive integer")
        if idle_timeout is not None and idle_timeout <= 0:
            raise ValueError("idle_timeout must be strictly positive")
        if on_limit not in SESSION_LIMIT_POLICIES:
            raise ValueError(
                "on_limit must be one of %s"
                % sorted(SESSION_LIMIT_POLICIES)
            )
        if eviction_log_size is not None and (
            not isinstance(eviction_log_size, int)
            or eviction_log_size <= 0
        ):
            raise ValueError(
                "eviction_log_size must be a positive integer or None"
            )
        self.max_connections = max_connections
        self.max_buffer = max_buffer
        self.idle_timeout = idle_timeout
        self.on_limit = on_limit
        self.lock = threading.RLock()
        self.stats = {
            "rejected_connections": 0,
            "evicted_connections": 0,
            "expired_connections": 0,
            "failed_packets": 0,
            "buffer_dropped_packets": 0,
        }  # type: Dict[str, int]
        self.eviction_log = deque(
            maxlen=eviction_log_size
        )  # type: Deque[EvictedConnection]
        self.tables = []  # type: List[_FlowTable]

    def new_table(self, name, remove):
        # type: (str, Callable[[Any, Any], None]) -> _FlowTable
        table = _FlowTable(name, remove, self)
        self.tables.append(table)
        return table

    def record(
        self,
        table,
        key,
        reason,
        last_seen,
        removed_at,
        buffered,
    ):
        # type: (str, Any, str, float, float, int) -> EvictedConnection
        entry = EvictedConnection(
            table,
            key,
            reason,
            last_seen,
            removed_at,
            buffered,
        )
        self.eviction_log.append(entry)
        return entry


class DefaultSession(object):
    """Default session: no stream decoding"""

    def __init__(self, supersession: Optional[Self] = None):
        if supersession and not isinstance(supersession, DefaultSession):
            supersession = supersession()
        self.supersession = supersession

    def process(self, pkt: Packet) -> Optional[Packet]:
        """
        Called to pre-process the packet
        """
        # Optionally handle supersession
        if self.supersession:
            return self.supersession.process(pkt)
        return pkt

    def recv(self, sock: 'SuperSocket') -> Iterator[Packet]:
        """
        Will be called by sniff() to ask for a packet
        """
        pkt = sock.recv()
        if not pkt:
            return
        try:
            pkt = self.process(pkt)
        except Exception as ex:
            log_runtime.warning(
                "%s processing failed with '%s'. Skipping." % (
                    type(self),
                    ex,
                )
            )
            if conf.debug_dissector:
                raise
            if pkt is not None:
                yield pkt
            return
        if pkt:
            yield pkt


class IPSession(DefaultSession):
    """Defragment IP packets 'on-the-flow'.

    Usage:
    >>> sniff(session=IPSession)

    Resource limits can be declared to bound the memory held by the
    reassembly tables:

    :param max_connections: maximum number of live (incomplete) fragment
        groups.
    :param max_buffer: maximum number of buffered bytes per fragment
        group; a fragment that would exceed it is dropped and counted in
        ``quota_stats['buffer_dropped_packets']``.
    :param idle_timeout: age in seconds (using packet timestamps) after
        which a group untouched is reaped.
    :param on_limit: what to do when a packet opens a new group past
        max_connections: SESSION_LIMIT_REJECT (default, the packet is
        ignored and counted), SESSION_LIMIT_EVICT (the least recently
        used group is reaped first) or SESSION_LIMIT_FAIL (a
        SessionLimitExceeded is raised and the packet is counted).
    :param eviction_log_size: maximum number of EvictedConnection
        records kept in ``eviction_log`` (None for unlimited).

    Removed groups are recorded in ``eviction_log`` and counted in
    ``quota_stats``; idle groups can also be reaped from another thread
    with ``cleanup_idle()``. When none of the limits are set, the
    reassembly behaviour is identical to the unmanaged session.
    """

    def __init__(self, *args, **kwargs):
        # type: (*Any, **Any) -> None
        max_connections = kwargs.pop("max_connections", None)
        max_buffer = kwargs.pop("max_buffer", None)
        idle_timeout = kwargs.pop("idle_timeout", None)
        on_limit = kwargs.pop("on_limit", SESSION_LIMIT_REJECT)
        eviction_log_size = kwargs.pop("eviction_log_size", 1000)
        if on_limit not in SESSION_LIMIT_POLICIES:
            raise ValueError(
                "on_limit must be one of %s"
                % sorted(SESSION_LIMIT_POLICIES)
            )
        if eviction_log_size is not None and (
            not isinstance(eviction_log_size, int)
            or eviction_log_size <= 0
        ):
            raise ValueError(
                "eviction_log_size must be a positive integer or None"
            )
        DefaultSession.__init__(self, *args, **kwargs)
        self.fragments = defaultdict(list)  # type: DefaultDict[Tuple[Any, ...], List[Packet]]  # noqa: E501
        self.quota_stats = None  # type: Optional[Dict[str, int]]
        self.eviction_log = None  # type: Optional[Deque[EvictedConnection]]
        self._manager = None  # type: Optional[_SessionResourceManager]
        self._ip_table = None  # type: Optional[_FlowTable]
        if (
            max_connections is not None
            or max_buffer is not None
            or idle_timeout is not None
        ):
            manager = _SessionResourceManager(
                max_connections,
                max_buffer,
                idle_timeout,
                on_limit,
                eviction_log_size,
            )
            self._manager = manager
            self.quota_stats = manager.stats
            self.eviction_log = manager.eviction_log
            self._ip_table = manager.new_table(
                "ip", self._remove_ip_fragments
            )

    def _remove_ip_fragments(self, key, extra):
        # type: (Any, Any) -> None
        """Remove an IP fragment group after a quota cleanup."""
        self.fragments.pop(key, None)

    def cleanup_idle(self, now=None):
        # type: (Optional[float]) -> List[EvictedConnection]
        """Reap idle connections immediately.

        Automatic reaping happens while processing packets; this entry
        point lets another task (e.g. a periodic timer thread) reap idle
        connections even when no packet is received. 'now' defaults to
        the wall-clock time; pass a timestamp aligned with the packet
        clock to replay a capture deterministically.
        """
        manager = self._manager
        if manager is None:
            return []
        if now is None:
            now = time.monotonic()
        removed = []  # type: List[EvictedConnection]
        with manager.lock:
            for table in manager.tables:
                removed.extend(table.prune(now))
        return removed

    def process(self, packet: Packet) -> Optional[Packet]:
        from scapy.layers.inet import BadFragments, IP, _defrag_ip_pkt
        if not packet:
            return None
        if IP not in packet:
            return packet
        manager = self._manager
        if manager is None:
            try:
                return _defrag_ip_pkt(packet, self.fragments)[1]  # type: ignore  # noqa: E501
            except BadFragments:
                return None
        ip = packet[IP]
        if ip.frag == 0 and not ip.flags.MF:
            # Non-fragmented packet: nothing to account for.
            return packet
        uid = (ip.id, ip.src, ip.dst, ip.proto)
        now = float(packet.time)
        if ip.len is None or ip.ihl is None:
            fraglen = len(ip.payload)
        else:
            fraglen = ip.len - (ip.ihl << 2)
        table = self._ip_table
        assert table is not None
        with manager.lock:
            if not table.admit(uid, now):
                # Rejected per policy: do not buffer this fragment.
                return None
            if (
                manager.max_buffer is not None
                and table.size(uid) + fraglen > manager.max_buffer
            ):
                manager.stats["buffer_dropped_packets"] += 1
                return None
        result = None  # type: Optional[Packet]
        try:
            _, result = _defrag_ip_pkt(packet, self.fragments)
        except BadFragments:
            with manager.lock:
                table.completed(uid)
            return None
        with manager.lock:
            if uid in self.fragments:
                # Reassembly is still incomplete: account for new bytes.
                table.add_size(uid, fraglen)
            else:
                # The group just completed (or was discarded): free slot.
                table.completed(uid)
        return result


class StringBuffer(object):
    """StringBuffer is an object used to re-order data received during
    a TCP transmission.

    Each TCP fragment contains a sequence number, which marks
    (relatively to the first sequence number) the index of the data contained
    in the fragment.

    If a TCP fragment is missed, this class will fill the missing space with
    zeros.

    :param max_gap: the largest missing range that will be zero-filled, in bytes.
        A sequence number far from the data already buffered would otherwise
        allocate the whole distance. Defaults to MTU.
    """

    def __init__(self, max_gap: int = MTU) -> None:
        self.content = bytearray(b"")
        self.content_len = 0
        self.noff = 0  # negative offset
        self.incomplete = []  # type: List[Tuple[int, int]]
        self.max_gap = max_gap

    def append(
        self,
        data: bytes,
        seq: Optional[int] = None,
        max_size: Optional[int] = None,
    ) -> bool:
        """Append data at the given relative sequence number.

        :param max_size: hard cap on the total buffered size. Data that
            would grow the buffer past it is dropped and False is
            returned. Defaults to None (no cap, always returns True).
        """
        if not data:
            return True
        data_len = len(data)
        if seq is None:
            seq = self.content_len
        seq = seq - 1 - self.noff
        if seq < 0:
            # Data is located before the start of the current buffer
            # (e.g. the first fragment was missing)
            if max_size is not None and \
                    self.content_len + (-seq) > max_size:
                log_runtime.warning(
                    "Dropped data further than allowed per 'max_size'."
                )
                return False
            if -seq - data_len > self.max_gap:
                log_runtime.warning(
                    "Dropped data further than allowed per 'max_gap'."
                )
                return False
            self.content = bytearray(b"\x00" * (-seq)) + self.content
            self.content_len += (-seq)
            self.noff += seq
            seq = 0
        if seq + data_len > self.content_len:
            # Data is located after the end of the current buffer
            if max_size is not None and seq + data_len > max_size:
                log_runtime.warning(
                    "Dropped data further than allowed per 'max_size'."
                )
                return False
            if seq - self.content_len > self.max_gap:
                log_runtime.warning(
                    "Dropped data further than allowed per 'max_gap'."
                )
                return False
            self.content += b"\x00" * (seq - self.content_len + data_len)
            # As data was missing, mark it.
            # self.incomplete.append((self.content_len, seq))
            self.content_len = seq + data_len
            assert len(self.content) == self.content_len
        # XXX removes empty space marker.
        # for ifrag in self.incomplete:
        #     if [???]:
        #         self.incomplete.remove([???])
        memoryview(self.content)[seq:seq + data_len] = data
        return True

    def shiftleft(self, i: int) -> None:
        self.content = self.content[i:]
        self.content_len -= i

    def full(self):
        # type: () -> bool
        # Should only be true when all missing data was filled up,
        # (or there never was missing data)
        return bool(self)

    def clear(self):
        # type: () -> None
        self.__init__()  # type: ignore

    def __bool__(self):
        # type: () -> bool
        return bool(self.content_len)
    __nonzero__ = __bool__

    def __len__(self):
        # type: () -> int
        return self.content_len

    def __bytes__(self):
        # type: () -> bytes
        return bytes(self.content)

    def __str__(self):
        # type: () -> str
        return cast(str, self.__bytes__())


def streamcls(cls: Type[Packet]) -> Callable[
    [bytes, Dict[str, Any], Dict[str, Any]],
    Optional[Packet],
]:
    """
    Wraps a class for use when dissecting streams.
    """
    if hasattr(cls, "tcp_reassemble"):
        return cls.tcp_reassemble  # type: ignore
    else:
        # There is no tcp_reassemble. Just dissect the packet
        return lambda data, *_: data and cls(data)


def _reverse_tcp_ident(ident):
    # type: (bytes) -> bytes
    """Return the unidirectional TCPSession ident of the reverse flow."""
    halflen = 4 if len(ident) == 12 else 16
    dport, sport = struct.unpack(
        "!HH", ident[2 * halflen:2 * halflen + 4]
    )
    return (
        ident[halflen:2 * halflen]
        + ident[:halflen]
        + struct.pack("!HH", sport, dport)
    )


class TCPSession(IPSession):
    """A Session that reconstructs TCP streams.

    NOTE: this has the same effect as wrapping a real socket.socket into StreamSocket,
    but for all concurrent TCP streams (can be used on pcaps or sniffed sessions).

    NOTE: only protocols that implement a ``tcp_reassemble`` function will be processed
    by this session. Other protocols will not be reconstructed.

    DEV: implement a class-function `tcp_reassemble` in your Packet class::

        @classmethod
        def tcp_reassemble(cls, data, metadata, session):
            # data = the reassembled data from the same request/flow
            # metadata = empty dictionary, that can be used to store data
            #            during TCP reassembly
            # session = a dictionary proper to the bidirectional TCP session,
            #           that can be used to store anything
            [...]
            # If the packet is available, return it. Otherwise don't.
            # Whenever you return a packet, the buffer will be discarded.
            return pkt
            # Otherwise, maybe store stuff in metadata, and return None,
            # as you need additional data.
            return None

    For more details and a real example, see:
    https://scapy.readthedocs.io/en/latest/usage.html#how-to-use-tcpsession-to-defragment-tcp-packets

    :param app: Whether the socket is on application layer = has no TCP
                layer. This is identical to StreamSocket so only use this if your
                underlying source of data isn't a socket.socket.

    The ``max_connections``, ``max_buffer``, ``idle_timeout``,
    ``on_limit`` and ``eviction_log_size`` parameters bound the resources
    of the TCP stream tables (and, by inheritance, of the IP fragment
    table); see IPSession. A 'connection' is a unidirectional TCP flow;
    the bidirectional metadata dictionary is removed only once both of
    its directions are gone. Limits do not apply in 'app' mode, which
    holds a single application stream.
    """

    def __init__(self, app=False, *args, **kwargs):
        # type: (bool, *Any, **Any) -> None
        max_connections = kwargs.pop("max_connections", None)
        max_buffer = kwargs.pop("max_buffer", None)
        idle_timeout = kwargs.pop("idle_timeout", None)
        on_limit = kwargs.pop("on_limit", SESSION_LIMIT_REJECT)
        eviction_log_size = kwargs.pop("eviction_log_size", 1000)
        super(TCPSession, self).__init__(
            *args,
            max_connections=max_connections,
            max_buffer=max_buffer,
            idle_timeout=idle_timeout,
            on_limit=on_limit,
            eviction_log_size=eviction_log_size,
            **kwargs
        )
        self.app = app
        self._tcp_table = None  # type: Optional[_FlowTable]
        if app:
            self.data = StringBuffer()
            self.metadata = {}  # type: Dict[str, Any]
            self.session = {}  # type: Dict[str, Any]
        else:
            # The StringBuffer() is used to build a global
            # string from fragments and their seq nulber
            self.tcp_frags = defaultdict(
                lambda: (StringBuffer(), {})
            )  # type: DefaultDict[bytes, Tuple[StringBuffer, Dict[str, Any]]]
            self.tcp_sessions = defaultdict(
                dict
            )  # type: DefaultDict[bytes, Dict[str, Any]]
            if self._manager is not None:
                self._tcp_table = self._manager.new_table(
                    "tcp", self._remove_tcp_flow
                )
        # Setup stopping dissection condition
        from scapy.layers.inet import TCP
        self.stop_dissection_after = TCP

    def _remove_tcp_flow(self, ident, bidi_ident):
        # type: (bytes, Any) -> None
        """Remove a unidirectional flow and, once both directions of its
        bidirectional session are gone, the matching session dictionary."""
        self.tcp_frags.pop(ident, None)
        if (
            bidi_ident is not None
            and _reverse_tcp_ident(ident) not in self.tcp_frags
        ):
            self.tcp_sessions.pop(bidi_ident, None)

    def _get_ident(self, pkt, session=False):
        # type: (Packet, bool) -> bytes
        underlayer = pkt["TCP"].underlayer
        af = socket.AF_INET6 if "IPv6" in pkt else socket.AF_INET
        src = underlayer and inet_pton(af, underlayer.src) or b""
        dst = underlayer and inet_pton(af, underlayer.dst) or b""
        if session:
            # Bidirectional
            def xor(x, y):
                # type: (bytes, bytes) -> bytes
                return bytes(a ^ b for a, b in zip(x, y))
            return struct.pack("!4sH", xor(src, dst), pkt.dport ^ pkt.sport)
        else:
            # Uni-directional
            return src + dst + struct.pack("!HH", pkt.dport, pkt.sport)

    def _strip_padding(self, pkt: Packet) -> Optional[bytes]:
        """Strip the packet of any padding, and return the padding.
        """
        if isinstance(pkt, conf.padding_layer):
            return cast(bytes, pkt.load)
        pad = pkt.getlayer(conf.padding_layer)
        if pad is not None and pad.underlayer is not None:
            # strip padding
            del pad.underlayer.payload
            return cast(bytes, pad.load)
        return None

    def process(self,
                pkt: Packet,
                cls: Optional[Type[Packet]] = None) -> Optional[Packet]:
        """Process each packet: matches the TCP seq/ack numbers
        to follow the TCP streams, and orders the fragments.
        """
        packet = None  # type: Optional[Packet]
        if self.app:
            # Special mode: Application layer. Use on top of TCP
            self.data.append(bytes(pkt))
            if cls is None and not isinstance(pkt, bytes):
                cls = pkt.__class__
            if "tcp_reassemble" in self.metadata:
                tcp_reassemble = self.metadata["tcp_reassemble"]
            elif cls is not None:
                self.metadata["tcp_reassemble"] = tcp_reassemble = streamcls(cls)
            else:
                return None
            if self.data.full():
                min_len = self.metadata.get("tcp_min_len")
                if min_len is None or len(self.data) >= min_len:
                    self.metadata.pop("tcp_min_len", None)
                    packet = tcp_reassemble(
                        bytes(self.data),
                        self.metadata,
                        self.session,
                    )
            if packet:
                padding = self._strip_padding(packet)
                if padding:
                    # There is remaining data for the next payload.
                    self.data.shiftleft(len(self.data) - len(padding))
                    # Skip full-padding
                    if isinstance(packet, conf.padding_layer):
                        return None
                else:
                    # No padding (data) left. Clear
                    self.data.clear()
                self.metadata.clear()
                return packet
            return None

        _pkt = super(TCPSession, self).process(pkt)
        if _pkt is None:
            return None
        else:  # Python 3.8 := would be nice
            pkt = _pkt

        from scapy.layers.inet import IP, TCP
        if not pkt:
            return None
        if TCP not in pkt:
            return pkt
        pay = pkt[TCP].payload
        new_data = pay.original
        # Match packets by a unique TCP identifier
        ident = self._get_ident(pkt)
        table = self._tcp_table
        manager = self._manager
        if table is not None:
            assert manager is not None
            bidi_ident = self._get_ident(pkt, True)
            with manager.lock:
                # Admission control; also reaps idle connections.
                if not table.admit(ident, float(pkt.time), bidi_ident):
                    return None
                # Fetch the flow state under the lock so that a concurrent
                # cleanup cannot tear it down halfway.
                data, metadata = self.tcp_frags[ident]
                tcp_session = self.tcp_sessions[bidi_ident]
        else:
            data, metadata = self.tcp_frags[ident]
            tcp_session = self.tcp_sessions[self._get_ident(pkt, True)]
        # Handle TCP sequence numbers
        seq = pkt[TCP].seq
        if "seq" not in metadata:
            metadata["seq"] = seq
        if "next_seq" in metadata and seq < metadata["next_seq"]:
            # Retransmitted data (that we already returned)
            new_data = new_data[metadata["next_seq"] - seq:]
            if not new_data:
                return None
            seq = metadata["next_seq"]
        # Let's guess which class is going to be used
        if "pay_class" not in metadata:
            metadata["pay_class"] = pay_class = pkt[TCP].guess_payload_class(new_data)
            metadata["tcp_reassemble"] = tcp_reassemble = streamcls(pay_class)
        else:
            tcp_reassemble = metadata["tcp_reassemble"]

        if pay:
            # Get a relative sequence number for a storage purpose
            relative_seq = metadata.get("relative_seq", None)
            if relative_seq is None:
                relative_seq = metadata["relative_seq"] = seq - 1
            seq = seq - relative_seq
            # Add the data to the buffer
            noff = data.noff
            if (
                table is not None
                and manager is not None
                and manager.max_buffer is not None
            ):
                if not data.append(
                    new_data, seq, max_size=manager.max_buffer
                ):
                    manager.stats["buffer_dropped_packets"] += 1
                with manager.lock:
                    table.set_size(ident, len(data))
            else:
                data.append(new_data, seq)
            if data.noff != noff:
                # The negative offset has changed => data was prepended.
                # this means that our estimate min length may be wrong.
                metadata.pop("tcp_min_len", None)

        # Check TCP FIN or TCP RESET
        if pkt[TCP].flags.F or pkt[TCP].flags.R:
            metadata["tcp_end"] = True
        elif not pay:
            # If there's no payload and the stream isn't ending, ignore.
            return pkt

        # In case any app layer protocol requires it,
        # allow the parser to inspect TCP PSH flag
        if pkt[TCP].flags.P:
            metadata["tcp_psh"] = True
        # XXX TODO: check that no empty space is missing in the buffer.
        # XXX Currently, if a TCP fragment was missing, we won't notice it.
        if data.full():
            min_len = metadata.get("tcp_min_len")
            if min_len is None or len(data) >= min_len:
                # Reassemble using all previous packets
                metadata["original"] = pkt
                metadata["ident"] = ident
                metadata.pop("tcp_min_len", None)
                packet = tcp_reassemble(
                    bytes(data),
                    metadata,
                    tcp_session
                )
        # Stack the result on top of the previous frames
        if packet:
            if "seq" in metadata:
                pkt[TCP].seq = metadata["seq"]
            # Clear TCP reassembly metadata
            metadata.clear()
            # Check for padding
            padding = self._strip_padding(packet)
            while padding:
                # There is remaining data for the next payload.
                full_length = data.content_len - len(padding)
                metadata["relative_seq"] = relative_seq + full_length
                data.shiftleft(full_length)
                # There might be a sub-payload hidden in the padding
                sub_packet = tcp_reassemble(
                    bytes(data),
                    metadata,
                    tcp_session
                )
                if sub_packet:
                    packet.add_payload(sub_packet)
                    padding = self._strip_padding(sub_packet)
                else:
                    break
            else:
                # No padding (data) left. Clear
                data.clear()
                if table is not None:
                    assert manager is not None
                    with manager.lock:
                        table.completed(ident)
                else:
                    del self.tcp_frags[ident]
            if table is not None and manager is not None:
                # Reflect the bytes consumed through padding handling.
                with manager.lock:
                    table.set_size(ident, len(data))
            # Minimum next seq
            metadata["next_seq"] = pkt[TCP].seq + len(new_data)
            # Skip full-padding
            if isinstance(packet, conf.padding_layer):
                return None
            # Rebuild resulting packet
            if pay:
                pay.underlayer.remove_payload()
            if IP in pkt:
                pkt[IP].len = None
                pkt[IP].chksum = None
            pkt = pkt / packet
            pkt.wirelen = None
            return pkt
        return None

    def recv(self, sock: 'SuperSocket') -> Iterator[Packet]:
        """
        Will be called by sniff() to ask for a packet
        """
        pkt = sock.recv(stop_dissection_after=self.stop_dissection_after)
        _orig = pkt
        # Now handle TCP reassembly
        if self.app:
            while pkt is not None:
                try:
                    pkt = self.process(pkt)
                except Exception as ex:
                    log_runtime.warning(
                        "%s processing failed with '%s'. Aborting." % (
                            type(self),
                            ex,
                        )
                    )
                    if conf.debug_dissector:
                        raise
                    return None
                if pkt:
                    yield pkt
                    # keep calling process as there might be more
                    pkt = b""  # type: ignore
        else:
            try:
                pkt = self.process(pkt)  # type: ignore
            except Exception as ex:
                log_runtime.warning(
                    "%s processing failed with '%s'. Skipping." % (
                        type(self),
                        ex,
                    )
                )
                if conf.debug_dissector:
                    raise
                if _orig is not None:
                    yield _orig
                return None
            if pkt:
                yield pkt
        return None
