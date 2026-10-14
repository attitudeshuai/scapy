# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) Philippe Biondi <phil@secdev.org>

"""
Answering machines.
"""

########################
#  Answering machines  #
########################

import abc
import functools
import threading
import socket
import time
import warnings
import weakref

from scapy.arch import get_if_addr
from scapy.config import conf
from scapy.error import log_runtime
from scapy.sendrecv import sendp, sniff, AsyncSniffer
from scapy.packet import Packet
from scapy.plist import PacketList

from typing import (
    Any,
    Callable,
    Dict,
    Generic,
    List,
    Optional,
    Set,
    Tuple,
    Type,
    TypeVar,
    cast,
)

_T = TypeVar("_T", Packet, PacketList)

#: Group assigned to an answering machine when none is given
DEFAULT_AM_GROUP = "default"

#: Packet passed the BPF filter but is_request() rejected it
AM_DROP_FILTER_MISS = "filter_miss"
#: The packet was a request but no answer could be built for it
AM_DROP_BUILD_FAILURE = "build_failure"
#: The answer was built but could not be sent
AM_DROP_SEND_FAILURE = "send_failure"


def _normalize_bpf_filter(bpf_filter):
    # type: (Optional[str]) -> str
    return " ".join((bpf_filter or "").split())


def bpf_filters_overlap(filter1, filter2):
    # type: (Optional[str], Optional[str]) -> bool
    """Return whether two sniffing BPF filters certainly overlap.

    An empty/missing filter matches every packet and therefore overlaps
    any other filter. Filters that only differ in whitespace are treated
    as equal. Filters that semantically overlap but are written
    differently are not detected: only certain overlaps are reported.
    """
    norm1 = _normalize_bpf_filter(filter1)
    norm2 = _normalize_bpf_filter(filter2)
    if not norm1 or not norm2:
        return True
    return norm1 == norm2


class ReferenceAM(type):
    def __new__(cls,
                name,  # type: str
                bases,  # type: Tuple[type, ...]
                dct  # type: Dict[str, Any]
                ):
        # type: (...) -> Type['AnsweringMachine[_T]']
        obj = cast('Type[AnsweringMachine[_T]]',
                   super(ReferenceAM, cls).__new__(cls, name, bases, dct))
        try:
            import inspect
            obj.__signature__ = inspect.signature(  # type: ignore
                obj.parse_options
            )
        except (ImportError, AttributeError):
            pass
        if obj.function_name:
            func = lambda obj=obj, *args, **kargs: obj(*args, **kargs)()  # type: ignore  # noqa: E501
            # Inject signature
            func.__name__ = func.__qualname__ = obj.function_name
            func.__doc__ = obj.__doc__ or obj.parse_options.__doc__
            try:
                func.__signature__ = obj.__signature__  # type: ignore
            except (AttributeError):
                pass
            globals()[obj.function_name] = func
        return obj


class AnsweringMachine(Generic[_T], metaclass=ReferenceAM):
    function_name = ""
    filter = None  # type: Optional[str]
    sniff_options = {"store": 0}  # type: Dict[str, Any]
    sniff_options_list = ["store", "iface", "count", "promisc", "filter",
                          "type", "prn", "stop_filter", "opened_socket"]
    send_options = {"verbose": 0}  # type: Dict[str, Any]
    send_options_list = ["iface", "inter", "loop", "verbose", "socket"]
    send_function = staticmethod(sendp)

    def __init__(self, **kargs):
        # type: (Any) -> None
        self.mode = 0
        self.verbose = kargs.get("verbose", conf.verb >= 0)
        # Cataloging options (not sniff/send options: popped before parsing)
        am_name = kargs.pop("name", None)  # type: Optional[str]
        am_group = kargs.pop("group", DEFAULT_AM_GROUP)  # type: str
        if self.filter:
            kargs.setdefault("filter", self.filter)
        kargs.setdefault("prn", self.reply)
        self.optam1 = {}  # type: Dict[str, Any]
        self.optam2 = {}  # type: Dict[str, Any]
        self.optam0 = {}  # type: Dict[str, Any]
        doptsend, doptsniff = self.parse_all_options(1, kargs)
        self.defoptsend = self.send_options.copy()
        self.defoptsend.update(doptsend)
        self.defoptsniff = self.sniff_options.copy()
        self.defoptsniff.update(doptsniff)
        self.optsend = {}   # type: Dict[str, Any]
        self.optsniff = {}   # type: Dict[str, Any]
        # Activity counters (updated from the sniffing thread, read from
        # the catalog: every read or write goes through _am_lock)
        self._am_lock = threading.Lock()
        self._am_bind(am_name, am_group, None)

    def __getattr__(self, attr):
        # type: (str) -> Any
        for dct in [self.optam2, self.optam1]:
            if attr in dct:
                return dct[attr]
        raise AttributeError(attr)

    def __setattr__(self, attr, val):
        # type: (str, Any) -> None
        mode = self.__dict__.get("mode", 0)
        if mode == 0:
            self.__dict__[attr] = val
        else:
            [self.optam1, self.optam2][mode - 1][attr] = val

    def parse_options(self):
        # type: () -> None
        pass

    def parse_all_options(self, mode, kargs):
        # type: (int, Any) -> Tuple[Dict[str, Any], Dict[str, Any]]
        sniffopt = {}  # type: Dict[str, Any]
        sendopt = {}  # type: Dict[str, Any]
        for k in list(kargs):  # use list(): kargs is modified in the loop
            if k in self.sniff_options_list:
                sniffopt[k] = kargs[k]
            if k in self.send_options_list:
                sendopt[k] = kargs[k]
            if k in self.sniff_options_list + self.send_options_list:
                del kargs[k]
        if mode != 2 or kargs:
            if mode == 1:
                self.optam0 = kargs
            elif mode == 2 and kargs:
                k = self.optam0.copy()
                k.update(kargs)
                self.parse_options(**k)
                kargs = k
            omode = self.__dict__.get("mode", 0)
            self.__dict__["mode"] = mode
            self.parse_options(**kargs)
            self.__dict__["mode"] = omode
        return sendopt, sniffopt

    def is_request(self, req):
        # type: (Packet) -> int
        return 1

    @abc.abstractmethod
    def make_reply(self, req):
        # type: (Packet) -> _T
        pass

    def send_reply(self, reply, send_function=None):
        # type: (_T, Optional[Callable[..., None]]) -> None
        if send_function:
            send_function(reply)
        else:
            self.send_function(reply, **self.optsend)

    def print_reply(self, req, reply):
        # type: (Packet, _T) -> None
        if isinstance(reply, PacketList):
            print("%s ==> %s" % (req.summary(),
                                 [res.summary() for res in reply]))
        else:
            print("%s ==> %s" % (req.summary(), reply.summary()))

    def reply(self, pkt, send_function=None, address=None):
        # type: (Packet, Optional[Callable[..., None]], Optional[Any]) -> None
        self._am_note_received()
        if not self.is_request(pkt):
            self._am_note_drop(AM_DROP_FILTER_MISS)
            return
        try:
            if address:
                # Only on AnsweringMachineTCP
                reply = self.make_reply(pkt, address=address)  # type: ignore
            else:
                reply = self.make_reply(pkt)
        except Exception:
            self._am_note_drop(AM_DROP_BUILD_FAILURE)
            raise
        if not reply:
            self._am_note_drop(AM_DROP_BUILD_FAILURE)
            return
        try:
            if send_function:
                self.send_reply(reply, send_function=send_function)
            else:
                # Retro-compability. Remove this if eventually
                self.send_reply(reply)
        except Exception:
            self._am_note_drop(AM_DROP_SEND_FAILURE)
            raise
        self._am_note_sent()
        if self.verbose:
            self.print_reply(pkt, reply)

    #
    # Cataloging helpers
    #

    def _am_bind(self, name, group, started_at, running=False):
        # type: (Optional[str], str, Optional[float], bool) -> None
        with self._am_lock:
            self._am_name = name  # type: Optional[str]
            self._am_group = group  # type: str
            self._am_running = running  # type: bool
            self._am_started_at = started_at  # type: Optional[float]
            self._am_last_activity = None  # type: Optional[float]
            self._am_packets_received = 0  # type: int
            self._am_replies_sent = 0  # type: int
            self._am_dropped = {
                AM_DROP_FILTER_MISS: 0,
                AM_DROP_BUILD_FAILURE: 0,
                AM_DROP_SEND_FAILURE: 0,
            }  # type: Dict[str, int]

    def _am_note_received(self):
        # type: () -> None
        with self._am_lock:
            self._am_packets_received += 1
            self._am_last_activity = time.time()

    def _am_note_sent(self):
        # type: () -> None
        with self._am_lock:
            self._am_replies_sent += 1
            self._am_last_activity = time.time()

    def _am_note_drop(self, reason):
        # type: (str) -> None
        with self._am_lock:
            self._am_dropped[reason] += 1

    def _am_sniff_endpoint(self):
        # type: () -> Tuple[Any, Optional[str]]
        optsniff = self.optsniff or self.defoptsniff
        return optsniff.get("iface"), cast(
            Optional[str], optsniff.get("filter"))

    def am_is_running(self):
        # type: () -> bool
        """Whether the machine is currently registered as sniffing."""
        return self._am_running

    def am_status(self):
        # type: () -> Dict[str, Any]
        """Return a thread-safe snapshot of the machine's activity."""
        with self._am_lock:
            status = {
                "running": self._am_running,
                "started_at": self._am_started_at,
                "last_activity": self._am_last_activity,
                "packets_received": self._am_packets_received,
                "replies_sent": self._am_replies_sent,
                "dropped": dict(self._am_dropped),
                "name": self._am_name,
                "group": self._am_group,
            }  # type: Dict[str, Any]
        iface, bpf_filter = self._am_sniff_endpoint()
        status["machine"] = type(self).__name__
        status["iface"] = iface
        status["filter"] = bpf_filter
        status["registered_at"] = status["started_at"]
        status["overlaps"] = []
        return status

    def _am_register(self):
        # type: () -> None
        answering_machines.register(self)

    def _am_unregister(self):
        # type: () -> None
        answering_machines.unregister(self)

    def run(self, *args, **kargs):
        # type: (Any, Any) -> None
        warnings.warn(
            "run() method deprecated. The instance is now callable",
            DeprecationWarning
        )
        self(*args, **kargs)

    def bg(self, *args, **kwargs):
        # type: (Any, Any) -> AsyncSniffer
        kwargs.setdefault("bg", True)
        self(*args, **kwargs)
        return self.sniffer

    def __call__(self, *args, **kargs):
        # type: (Any, Any) -> None
        bg = kargs.pop("bg", False)
        optsend, optsniff = self.parse_all_options(2, kargs)
        self.optsend = self.defoptsend.copy()
        self.optsend.update(optsend)
        self.optsniff = self.defoptsniff.copy()
        self.optsniff.update(optsniff)

        if bg:
            self.sniff_bg()
        else:
            self._am_register()
            try:
                self.sniff()
            except KeyboardInterrupt:
                print("Interrupted by user")
            finally:
                self._am_unregister()

    def sniff(self):
        # type: () -> None
        sniff(**self.optsniff)

    def sniff_bg(self):
        # type: () -> None
        self.sniffer = _CatalogAsyncSniffer(self, **self.optsniff)
        self.sniffer.start()
        self._am_register()


class AnsweringMachineTCP(AnsweringMachine[Packet]):
    """
    An answering machine that use the classic socket.socket to
    answer multiple TCP clients
    """
    TYPE = socket.SOCK_STREAM

    def parse_options(self, port=80, cls=conf.raw_layer):
        # type: (int, Type[Packet]) -> None
        self.port = port
        self.cls = cls

    def close(self):
        # type: () -> None
        pass

    def sniff(self):
        # type: () -> None
        from scapy.supersocket import StreamSocket
        ssock = socket.socket(socket.AF_INET, self.TYPE)
        try:
            ssock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        except OSError:
            pass
        ssock.bind(
            (get_if_addr(self.optsniff.get("iface", conf.iface)), self.port))
        ssock.listen()
        sniffers = []
        try:
            while True:
                clientsocket, address = ssock.accept()
                print("%s connected" % repr(address))
                sock = StreamSocket(clientsocket, self.cls)
                optsniff = self.optsniff.copy()
                optsniff["prn"] = functools.partial(self.reply,
                                                    send_function=sock.send,
                                                    address=address)
                del optsniff["iface"]
                sniffer = AsyncSniffer(opened_socket=sock, **optsniff)
                sniffer.start()
                sniffers.append((sniffer, sock))
        finally:
            for (sniffer, sock) in sniffers:
                try:
                    sniffer.stop()
                except Exception:
                    pass
                sock.close()
            self.close()
            ssock.close()
            self._am_unregister()

    def sniff_bg(self):
        # type: () -> None
        self._am_register()
        try:
            self.sniffer = threading.Thread(  # type: ignore
                target=self.sniff)
            self.sniffer.start()
        except Exception:
            self._am_unregister()
            raise

    def make_reply(self, req, address=None):
        # type: (Packet, Optional[Any]) -> Packet
        return req


class AnsweringMachineUDP(AnsweringMachineTCP):
    """
    An answering machine that use the classic socket.socket to
    answer multiple UDP clients
    """
    TYPE = socket.SOCK_DGRAM


class _CatalogAsyncSniffer(AsyncSniffer):
    """AsyncSniffer that unregisters its machine from the catalog on stop."""

    def __init__(self, am, **kwargs):
        # type: (AnsweringMachine[Any], Any) -> None
        self._am = am  # type: AnsweringMachine[Any]
        super(_CatalogAsyncSniffer, self).__init__(**kwargs)

    def stop(self, join=True):
        # type: (bool) -> Optional[PacketList]
        try:
            return super(_CatalogAsyncSniffer, self).stop(join)
        finally:
            self._am._am_unregister()


class AnsweringMachineCatalog(object):
    """Thread-safe catalog of the running answering machines.

    Answering machines register when they start sniffing and unregister
    when they stop. Each entry exposes the interface and BPF filter the
    machine is bound to, packet/reply counters, last activity time and
    per-reason drop counters. When a machine registers in a group where
    another running machine uses an overlapping BPF filter on the same
    interface, the overlap is logged and recorded instead of being
    silently ignored.
    """

    def __init__(self):
        # type: () -> None
        self._lock = threading.RLock()
        self._entries = {}  # type: Dict[int, Dict[str, Any]]
        self._names = set()  # type: Set[str]
        self._class_count = {}  # type: Dict[str, int]
        self._overlap_notices = []  # type: List[Dict[str, Any]]

    def _alloc_name_locked(self, requested, cls_name):
        # type: (Optional[str], str) -> str
        if requested is None:
            index = self._class_count.get(cls_name, 0) + 1
            self._class_count[cls_name] = index
            requested = "%s#%d" % (cls_name, index)
        name = requested
        index = 2
        while name in self._names:
            name = "%s#%d" % (requested, index)
            index += 1
        return name

    def _prune_locked(self):
        # type: () -> None
        for mid in [
            mid for mid, entry in self._entries.items()
            if entry["ref"]() is None
        ]:
            self._names.discard(cast(str, self._entries[mid]["name"]))
            del self._entries[mid]

    def register(self, am):
        # type: (AnsweringMachine[Any]) -> str
        """Register a started answering machine; return its catalog name."""
        with self._lock:
            self._prune_locked()
            entry = self._entries.get(id(am))
            if entry is not None:
                return cast(str, entry["name"])
            name = self._alloc_name_locked(am._am_name, type(am).__name__)
            group = am._am_group or DEFAULT_AM_GROUP
            iface, bpf_filter = am._am_sniff_endpoint()
            started_at = time.time()
            am._am_bind(name, group, started_at, running=True)
            overlapping = []  # type: List[str]
            for other in self._entries.values():
                other_am = other["ref"]()
                if other_am is None or not other_am.am_is_running():
                    continue
                if other["group"] != group or other["iface"] != iface:
                    continue
                if bpf_filters_overlap(bpf_filter, other["filter"]):
                    overlapping.append(cast(str, other["name"]))
            for other_name in overlapping:
                self._overlap_notices.append({
                    "time": started_at,
                    "group": group,
                    "iface": str(iface) if iface is not None else None,
                    "filter": bpf_filter,
                    "machine": name,
                    "other": other_name,
                })
                log_runtime.warning(
                    "Answering machine %s of group %r listens on %s with "
                    "BPF filter %r, which overlaps machine %s; whichever "
                    "machine receives a matching packet first answers it.",
                    name, group,
                    iface if iface is not None else "the default interface",
                    bpf_filter or "", other_name,
                )
            self._entries[id(am)] = {
                "ref": weakref.ref(am),
                "name": name,
                "group": group,
                "iface": iface,
                "filter": bpf_filter,
                "registered_at": started_at,
            }
            self._names.add(name)
            return name

    def unregister(self, am):
        # type: (AnsweringMachine[Any]) -> None
        """Remove an answering machine from the catalog."""
        with self._lock:
            am._am_running = False
            entry = self._entries.pop(id(am), None)
            if entry is not None:
                self._names.discard(cast(str, entry["name"]))

    def names(self, group=None):
        # type: (Optional[str]) -> List[str]
        """Return the sorted catalog names, optionally restricted to a group."""
        with self._lock:
            self._prune_locked()
            return sorted(
                cast(str, entry["name"])
                for entry in self._entries.values()
                if group is None or entry["group"] == group
            )

    def get(self, name):
        # type: (str) -> Optional[AnsweringMachine[Any]]
        """Return the machine registered under a catalog name."""
        with self._lock:
            self._prune_locked()
            for entry in self._entries.values():
                if entry["name"] == name:
                    return cast(
                        Optional[AnsweringMachine[Any]], entry["ref"]())
            return None

    @staticmethod
    def _overlaps_with(entry, alive):
        # type: (Dict[str, Any], List[Tuple[Dict[str, Any], AnsweringMachine[Any]]]) -> List[str]  # noqa: E501
        result = []  # type: List[str]
        for other_entry, other_am in alive:
            if other_entry["name"] == entry["name"]:
                continue
            if not other_am.am_is_running():
                continue
            if other_entry["group"] != entry["group"]:
                continue
            if other_entry["iface"] != entry["iface"]:
                continue
            if bpf_filters_overlap(entry["filter"], other_entry["filter"]):
                result.append(cast(str, other_entry["name"]))
        return sorted(result)

    @staticmethod
    def _active_overlaps(alive):
        # type: (List[Tuple[Dict[str, Any], AnsweringMachine[Any]]]) -> List[Dict[str, Any]]  # noqa: E501
        result = []  # type: List[Dict[str, Any]]
        seen = set()  # type: Set[Tuple[str, str, str]]
        for index, (entry, am) in enumerate(alive):
            if not am.am_is_running():
                continue
            for other_entry, other_am in alive[index + 1:]:
                if not other_am.am_is_running():
                    continue
                if entry["group"] != other_entry["group"]:
                    continue
                if entry["iface"] != other_entry["iface"]:
                    continue
                if not bpf_filters_overlap(entry["filter"],
                                           other_entry["filter"]):
                    continue
                pair = sorted((cast(str, entry["name"]),
                               cast(str, other_entry["name"])))
                key = (cast(str, entry["group"]), pair[0], pair[1])
                if key in seen:
                    continue
                seen.add(key)
                result.append({
                    "group": entry["group"],
                    "iface": entry["iface"],
                    "filter": entry["filter"],
                    "machines": pair,
                })
        return result

    def report(self, group=None):
        # type: (Optional[str]) -> Dict[str, Any]
        """Return a point-in-time report of the (group's) machines.

        The report is built from short-lived counter snapshots: reading
        it never stops nor meaningfully blocks an ongoing answer.
        """
        with self._lock:
            self._prune_locked()
            entries = [
                (dict(entry), entry["ref"]())
                for entry in self._entries.values()
            ]
            notices = [
                dict(notice)
                for notice in self._overlap_notices
                if group is None or notice["group"] == group
            ]
        alive = []  # type: List[Tuple[Dict[str, Any], AnsweringMachine[Any]]]
        for entry, am in entries:
            if am is not None and (
                    group is None or entry["group"] == group):
                alive.append((entry, am))
        machines = []  # type: List[Dict[str, Any]]
        for entry, am in alive:
            status = am.am_status()
            status["name"] = entry["name"]
            status["group"] = entry["group"]
            status["machine"] = type(am).__name__
            status["iface"] = entry["iface"]
            status["filter"] = entry["filter"]
            status["registered_at"] = entry["registered_at"]
            status["overlaps"] = self._overlaps_with(entry, alive)
            machines.append(status)
        return {
            "group": group,
            "machines": machines,
            "overlaps": self._active_overlaps(alive),
            "notices": notices,
        }

    def format_report(self, group=None):
        # type: (Optional[str]) -> str
        """Return a human-readable version of report()."""
        report = self.report(group)
        lines = [
            "%-16s %-9s %-10s %-22s %-7s %5s %5s %5s %5s %5s %s" % (
                "NAME", "GROUP", "IFACE", "FILTER", "STATE",
                "RECV", "SENT", "MISS", "BUILD", "SEND", "LAST_ACTIVITY",
            )
        ]
        for machine in report["machines"]:
            drops = machine["dropped"]
            last_activity = machine["last_activity"]
            lines.append(
                "%-16s %-9s %-10s %-22s %-7s %5d %5d %5d %5d %5d %s" % (
                    cast(str, machine["name"])[:16],
                    cast(str, machine["group"])[:9],
                    (str(machine["iface"])
                     if machine["iface"] is not None else "*")[:10],
                    (machine["filter"] or "")[:22],
                    "running" if machine["running"] else "stopped",
                    machine["packets_received"],
                    machine["replies_sent"],
                    drops[AM_DROP_FILTER_MISS],
                    drops[AM_DROP_BUILD_FAILURE],
                    drops[AM_DROP_SEND_FAILURE],
                    time.strftime(
                        "%H:%M:%S", time.localtime(last_activity)
                    ) if last_activity is not None else "-",
                )
            )
        if report["overlaps"]:
            lines.append("")
            lines.append("Overlapping filters:")
            for overlap in report["overlaps"]:
                lines.append(
                    "  %s: %s on %s (%s)" % (
                        overlap["group"],
                        " <-> ".join(overlap["machines"]),
                        overlap["iface"]
                        if overlap["iface"] is not None
                        else "default interface",
                        overlap["filter"] or "all packets",
                    )
                )
        return "\n".join(lines)

    def clear(self):
        # type: () -> None
        """Empty the catalog (mainly used by tests)."""
        with self._lock:
            for entry in self._entries.values():
                am = entry["ref"]()
                if am is not None:
                    am._am_running = False
            self._entries.clear()
            self._names.clear()
            self._class_count.clear()
            self._overlap_notices.clear()


#: Global catalog every answering machine registers to on start
answering_machines = AnsweringMachineCatalog()
