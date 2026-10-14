# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) Philippe Biondi <phil@secdev.org>

import os
import queue
import subprocess
import time
from math import exp
from threading import Event, Lock, Thread

from scapy.automaton import (
    Message,
    ObjectPipe,
    select_objects,
)
from scapy.consts import WINDOWS
from scapy.config import conf
from scapy.error import Scapy_Exception, log_runtime, warning
from scapy.utils import get_temp_file, do_graph

from typing import (
    Any,
    Callable,
    Dict,
    Iterable,
    List,
    Optional,
    Set,
    Tuple,
    Union,
    Type,
    TypeVar,
    cast,
)

#: Upstream producer waits until room is available in the link queue
PIPE_OVERFLOW_WAIT = "wait"
#: Upstream message is dropped (and counted) when the link queue is full
PIPE_OVERFLOW_DROP = "drop"
#: A :class:`PipeLinkFull` is raised and the whole chain is marked errored
PIPE_OVERFLOW_ERROR = "error"

#: On engine stop, keep pumping until the link queue is empty (or deadline)
PIPE_STOP_DRAIN = "drain"
#: On engine stop, discard the link queue immediately
PIPE_STOP_DISCARD = "discard"


class PipeLinkFull(Scapy_Exception):
    """Raised on a pipe link whose overflow policy is ``"error"``

    The link stays in the ``"error"`` state and the whole connected chain
    is removed from the engine scheduling.
    """

    def __init__(self, link, piece=None):
        # type: (PipeLink, Optional[Pipe]) -> None
        self.link = link
        self.piece = piece
        Scapy_Exception.__init__(
            self,
            "pipe link %r queue is full (maxsize=%s)" % (
                link.name, link.queue_maxsize))


# Set of sources handled by the engine loop (the engine itself is used
# as its own command source). Forward references are resolved lazily.
_SourcesSet = Set[Union["Source", "PipeEngine"]]


class PipeEngine(ObjectPipe[str]):
    pipes = {}  # type: Dict[str, Type[Pipe]]

    @classmethod
    def list_pipes(cls):
        # type: () -> None
        for pn, pc in sorted(cls.pipes.items()):
            doc = pc.__doc__ or ""
            if doc:
                doc = doc.splitlines()[0]
            print("%20s: %s" % (pn, doc))

    @classmethod
    def list_pipes_detailed(cls):
        # type: () -> None
        for pn, pc in sorted(cls.pipes.items()):
            if pc.__doc__:
                print("###### %s\n %s" % (pn, pc.__doc__))
            else:
                print("###### %s" % pn)

    def __init__(self, *pipes):
        # type: (*Pipe) -> None
        ObjectPipe.__init__(self, "PipeEngine")
        self.active_pipes = set()  # type: Set[Pipe]
        self.active_sources = set()  # type: Set[Union[Source, PipeEngine]]
        self.active_drains = set()  # type: Set[Pipe]
        self.active_sinks = set()  # type: Set[Pipe]
        self._add_pipes(*pipes)
        self.thread_lock = Lock()
        self.command_lock = Lock()
        self.thread = None  # type: Optional[Thread]
        # Pipes belonging to a chain stopped by an "error" overflow link
        self._failed_pipes = set()  # type: Set[Pipe]

    def __getattr__(self, attr):
        # type: (str) -> Callable[..., Pipe]
        if attr.startswith("spawn_"):
            dname = attr[6:]
            if dname in self.pipes:
                def f(*args, **kargs):
                    # type: (*Any, **Any) -> Pipe
                    k = self.pipes[dname]
                    p = k(*args, **kargs)  # type: Pipe
                    self.add(p)
                    return p
                return f
        raise AttributeError(attr)

    def _read_cmd(self):
        # type: () -> str
        return self.recv()  # type: ignore

    def _write_cmd(self, _cmd):
        # type: (str) -> None
        self.send(_cmd)

    def add_one_pipe(self, pipe):
        # type: (Pipe) -> None
        self.active_pipes.add(pipe)
        if isinstance(pipe, Source):
            self.active_sources.add(pipe)
        if isinstance(pipe, Drain):
            self.active_drains.add(pipe)
        if isinstance(pipe, Sink):
            self.active_sinks.add(pipe)

    def get_pipe_list(self, pipe):
        # type: (Pipe) -> Set[Any]
        def flatten(p,  # type: Any
                    li,  # type: Set[Pipe]
                    ):
            # type: (...) -> None
            li.add(p)
            for q in p.sources | p.sinks | p.high_sources | p.high_sinks:
                if q not in li:
                    flatten(q, li)
        pl = set()  # type: Set[Pipe]
        flatten(pipe, pl)
        return pl

    def _add_pipes(self, *pipes):
        # type: (*Pipe) -> Set[Pipe]
        pl = set()
        for p in pipes:
            pl |= self.get_pipe_list(p)
        pl -= self.active_pipes
        for q in pl:
            self.add_one_pipe(q)
        return pl

    def _mark_component_failed(self, origin, sources, exhausted):
        # type: (Pipe, _SourcesSet, _SourcesSet) -> None
        # Stop scheduling every source of the chain connected to origin
        for p in self.get_pipe_list(origin):
            self._failed_pipes.add(p)
            if isinstance(p, Source):
                exhausted.add(p)
                sources.discard(p)

    def _reconcile_failed_links(self, sources, exhausted):
        # type: (_SourcesSet, _SourcesSet) -> None
        # A link may also fail from a producer thread outside of deliver();
        # catch those failures here and stop their chain as well.
        for p in self.active_pipes:
            if isinstance(p, BackPressureDrain) and p.link.state == "error":
                if p not in self._failed_pipes:
                    self._mark_component_failed(p, sources, exhausted)

    def _stop_with_buffers(self, buffers):
        # type: (List[BackPressureDrain]) -> None
        # Shutdown honoring the per-link drain/discard declarations:
        # 1. stop producers that cannot receive buffered messages anymore,
        # 2. shut the buffers down (they drain or discard their queues),
        # 3. stop the remaining pieces that the buffers may push to.
        buffer_set = set(buffers)  # type: Set[Pipe]
        downstream = set()  # type: Set[Pipe]
        stack = []  # type: List[Pipe]
        for b in buffers:
            b._upstream_buffers = self._upstream_buffers(b, buffer_set)
            stack.extend(b.sinks | b.high_sinks | b.trigger_sinks)
        while stack:
            p = stack.pop()
            if p in downstream:
                continue
            downstream.add(p)
            stack.extend(p.sinks | p.high_sinks | p.trigger_sinks)
        stopped = set()  # type: Set[Pipe]
        for p in list(self.active_pipes):
            if isinstance(p, Source) and p not in downstream:
                p.stop()
                stopped.add(p)
        for b in buffers:
            b.stop()
            stopped.add(b)
        for p in self.active_pipes - stopped:
            p.stop()

    @staticmethod
    def _upstream_buffers(buffer, buffer_set):
        # type: (BackPressureDrain, Set[Pipe]) -> Set[BackPressureDrain]
        upstream = set()  # type: Set[BackPressureDrain]
        stack = list(buffer.sources |
                     buffer.high_sources |
                     buffer.trigger_sources)  # type: List[Pipe]
        while stack:
            p = stack.pop()
            if p in upstream:
                continue
            if p in buffer_set:
                # A buffer is a queueing boundary: do not cross it.
                upstream.add(cast(BackPressureDrain, p))
            else:
                stack.extend(p.sources | p.high_sources | p.trigger_sources)
        return upstream

    def run(self):
        # type: () -> None
        log_runtime.debug("Pipe engine thread started.")
        try:
            for p in self.active_pipes:
                p.start()
            sources = self.active_sources
            sources.add(self)
            exhausted = set([])  # type: _SourcesSet
            RUN = True
            STOP_IF_EXHAUSTED = False
            while RUN and (not STOP_IF_EXHAUSTED or len(sources) > 1):
                self._reconcile_failed_links(sources, exhausted)
                fds = select_objects(sources, 0.5)
                for fd in fds:
                    if fd is self:
                        cmd = self._read_cmd()
                        if cmd == "X":
                            RUN = False
                            break
                        elif cmd == "B":
                            STOP_IF_EXHAUSTED = True
                        elif cmd == "A":
                            sources = {
                                src for src in self.active_sources - exhausted
                                if src not in self._failed_pipes
                            }
                            sources.add(self)
                        else:
                            warning("Unknown internal pipe engine command: %r."
                                    " Ignoring.", cmd)
                    elif fd in sources:
                        try:
                            fd.deliver()
                        except Exception as e:
                            if isinstance(e, PipeLinkFull):
                                self._mark_component_failed(
                                    fd, sources, exhausted)
                            log_runtime.exception("piping from %s failed: %s",
                                                  fd.name, e)
                        else:
                            if fd.exhausted():
                                exhausted.add(fd)
                                sources.remove(fd)
        except KeyboardInterrupt:
            pass
        finally:
            try:
                buffers = [
                    p for p in self.active_pipes
                    if isinstance(p, BackPressureDrain)
                ]
                if buffers:
                    self._stop_with_buffers(buffers)
                else:
                    for p in self.active_pipes:
                        p.stop()
            finally:
                self.thread_lock.release()
                log_runtime.debug("Pipe engine thread stopped.")

    def stats(self):
        # type: () -> Dict[str, Dict[str, Any]]
        """Return the metrics of every declared link of the engine.

        For each link name: ``state`` (``active``, ``error`` or
        ``stopped``), ``backlog`` (queued messages), ``dropped``,
        ``delivered``, ``rate`` (delivered messages per second, EMA) and
        ``queues``, the per-buffer breakdown. Counters are summed over the
        link buffers: with several buffers in a chain, ``delivered``
        counts messages per buffer hop; ``queues`` keeps each hop apart.
        """
        links = {}  # type: Dict[PipeLink, List[BackPressureDrain]]
        for p in self.active_pipes:
            if isinstance(p, BackPressureDrain):
                links.setdefault(p.link, []).append(p)
        results = {}  # type: Dict[str, Dict[str, Any]]
        for link, bufs in links.items():
            results[link.name] = {
                "state": link.state,
                "backlog": sum(b.q.qsize() for b in bufs),
                "dropped": sum(b.dropped for b in bufs),
                "delivered": sum(b.delivered for b in bufs),
                "rate": link.rate,
                "queues": [
                    {
                        "name": b.name,
                        "backlog": b.q.qsize(),
                        "dropped": b.dropped,
                        "delivered": b.delivered,
                    }
                    for b in bufs
                ],
            }
        return results

    def start(self):
        # type: () -> None
        if self.thread_lock.acquire(False):
            _t = Thread(target=self.run, name="scapy.pipetool.PipeEngine")
            _t.daemon = True
            _t.start()
            self.thread = _t
        else:
            log_runtime.debug("Pipe engine already running")

    def wait_and_stop(self):
        # type: () -> None
        self.stop(_cmd="B")

    def stop(self, _cmd="X"):
        # type: (str) -> None
        try:
            with self.command_lock:
                if self.thread is not None:
                    self._write_cmd(_cmd)
                    self.thread.join()
                    try:
                        self.thread_lock.release()
                    except Exception:
                        pass
                else:
                    log_runtime.debug("Pipe engine thread not running")
        except KeyboardInterrupt:
            print("Interrupted by user.")

    def add(self, *pipes):
        # type: (*Pipe) -> None
        _pipes = self._add_pipes(*pipes)
        with self.command_lock:
            if self.thread is not None:
                for p in _pipes:
                    p.start()
                self._write_cmd("A")

    def graph(self, **kargs):
        # type: (Any) -> None
        g = ['digraph "pipe" {', "\tnode [shape=rectangle];", ]
        for p in self.active_pipes:
            g.append('\t"%i" [label="%s"];' % (id(p), p.name))
        g.append("")
        g.append("\tedge [color=blue, arrowhead=vee];")
        for p in self.active_pipes:
            for s in p.sinks:
                g.append('\t"%i" -> "%i";' % (id(p), id(s)))
        g.append("")
        g.append("\tedge [color=purple, arrowhead=veevee];")
        for p in self.active_pipes:
            for hs in p.high_sinks:
                g.append('\t"%i" -> "%i";' % (id(p), id(hs)))
        g.append("")
        g.append("\tedge [color=red, arrowhead=diamond];")
        for p in self.active_pipes:
            for ts in p.trigger_sinks:
                g.append('\t"%i" -> "%i";' % (id(p), id(ts)))
        g.append('}')
        graph = "\n".join(g)
        do_graph(graph, **kargs)


class _PipeMeta(type):
    def __new__(cls,
                name,  # type: str
                bases,  # type: Tuple[type, ...]
                dct  # type: Dict[str, Any]
                ):
        # type: (...) -> Type[Pipe]
        c = cast('Type[Pipe]',
                 super(_PipeMeta, cls).__new__(cls, name, bases, dct))
        PipeEngine.pipes[name] = c
        return c


_S = TypeVar("_S", bound="Sink")
_TS = TypeVar("_TS", bound="TriggerSink")


class Pipe(metaclass=_PipeMeta):
    def __init__(self, name=None):
        # type: (Optional[str]) -> None
        self.sources = set()  # type: Set['Pipe']
        self.sinks = set()  # type: Set['Sink']
        self.high_sources = set()  # type: Set['Pipe']
        self.high_sinks = set()  # type: Set['Sink']
        self.trigger_sources = set()  # type: Set['Pipe']
        self.trigger_sinks = set()  # type: Set['TriggerSink']
        if name is None:
            name = "%s" % (self.__class__.__name__)
        self.name = name

    def _send(self, msg):
        # type: (Any) -> None
        for s in self.sinks:
            s.push(msg)

    def _high_send(self, msg):
        # type: (Any) -> None
        for s in self.high_sinks:
            s.high_push(msg)

    def _trigger(self, msg=None):
        # type: (Any) -> None
        for s in self.trigger_sinks:
            s.on_trigger(msg)

    def __gt__(self, other):
        # type: (_S) -> _S
        self.sinks.add(other)
        other.sources.add(self)
        return other

    def __rshift__(self, other):
        # type: (_S) -> _S
        self.high_sinks.add(other)
        other.high_sources.add(self)
        return other

    def __xor__(self, other):
        # type: (_TS) -> _TS
        self.trigger_sinks.add(other)
        other.trigger_sources.add(self)
        return other

    def __hash__(self):
        # type: () -> int
        return object.__hash__(self)

    def __eq__(self, other):
        # type: (Any) -> bool
        return object.__eq__(self, other)

    def __repr__(self):
        # type: () -> str
        ct = conf.color_theme
        s = "%s%s" % (ct.punct("<"), ct.layer_name(self.name))
        if self.sources or self.sinks:
            s += " %s" % ct.punct("[")
            if self.sources:
                s += "%s%s" % (ct.punct(",").join(ct.field_name(s.name) for s in self.sources),  # noqa: E501
                               ct.field_value(">"))
            s += ct.layer_name("#")
            if self.sinks:
                s += "%s%s" % (ct.field_value(">"),
                               ct.punct(",").join(ct.field_name(s.name) for s in self.sinks))  # noqa: E501
            s += ct.punct("]")

        if self.high_sources or self.high_sinks:
            s += " %s" % ct.punct("[")
            if self.high_sources:
                s += "%s%s" % (ct.punct(",").join(ct.field_name(s.name) for s in self.high_sources),  # noqa: E501
                               ct.field_value(">>"))
            s += ct.layer_name("#")
            if self.high_sinks:
                s += "%s%s" % (ct.field_value(">>"),
                               ct.punct(",").join(ct.field_name(s.name) for s in self.high_sinks))  # noqa: E501
            s += ct.punct("]")

        if self.trigger_sources or self.trigger_sinks:
            s += " %s" % ct.punct("[")
            if self.trigger_sources:
                s += "%s%s" % (ct.punct(",").join(ct.field_name(s.name) for s in self.trigger_sources),  # noqa: E501
                               ct.field_value("^"))
            s += ct.layer_name("#")
            if self.trigger_sinks:
                s += "%s%s" % (ct.field_value("^"),
                               ct.punct(",").join(ct.field_name(s.name) for s in self.trigger_sinks))  # noqa: E501
            s += ct.punct("]")

        s += ct.punct(">")
        return s

    def start(self):
        # type: () -> None
        pass

    def stop(self):
        # type: () -> None
        pass


class Source(Pipe, ObjectPipe[Any]):
    def __init__(self, name=None):
        # type: (Optional[str]) -> None
        ObjectPipe.__init__(self, name)
        Pipe.__init__(self, name=name)
        self.is_exhausted = False

    def _read_message(self):
        # type: () -> Message
        return Message()

    def deliver(self):
        # type: () -> None
        msg = self._read_message
        self._send(msg)

    def exhausted(self):
        # type: () -> bool
        return self.is_exhausted


class Drain(Pipe):
    """Repeat messages from low/high entries to (resp.) low/high exits

    .. code::

         +-------+
      >>-|-------|->>
         |       |
       >-|-------|->
         +-------+
    """

    def push(self, msg):
        # type: (Any) -> None
        self._send(msg)

    def high_push(self, msg):
        # type: (Any) -> None
        self._high_send(msg)


class Sink(Pipe):
    """
    Does nothing; interface to extend for custom sinks.

    All sinks have the following constructor parameters:

    :param name: a human-readable name for the element
    :type name: str
    """
    def push(self, msg):
        # type: (Any) -> None
        """
        Called by :py:class:`PipeEngine` when there is a new message for the
        low entry.

        :param msg: The message data
        :returns: None
        :rtype: None
        """
        pass

    def high_push(self, msg):
        # type: (Any) -> None
        """
        Called by :py:class:`PipeEngine` when there is a new message for the
        high entry.

        :param msg: The message data
        :returns: None
        :rtype: None
        """
        pass

    def __lt__(self, other):
        # type: (_S) -> _S
        other.sinks.add(self)
        self.sources.add(other)
        return other

    def __lshift__(self, other):
        # type: (_S) -> _S
        self.high_sources.add(other)
        other.high_sinks.add(self)
        return other

    def __floordiv__(self, other):
        # type: (_S) -> _S
        self >> other
        other >> self
        return other

    def __mod__(self, other):
        # type: (_S) -> _S
        self > other
        other > self
        return other


class TriggerSink(Sink):
    def on_trigger(self, msg):
        # type: (Any) -> None
        pass


class AutoSource(Source):
    def __init__(self, name=None):
        # type: (Optional[str]) -> None
        Source.__init__(self, name=name)

    def _gen_data(self, msg):
        # type: (str) -> None
        ObjectPipe.send(self, (msg, False, False))

    def _gen_high_data(self, msg):
        # type: (str) -> None
        ObjectPipe.send(self, (msg, True, False))

    def _exhaust(self):
        # type: () -> None
        ObjectPipe.send(self, (None, None, True))

    def deliver(self):
        # type: () -> None
        msg, high, exhaust = self.recv()  # type: ignore
        if exhaust:
            pass
        if high:
            self._high_send(msg)
        else:
            self._send(msg)


class ThreadGenSource(AutoSource):
    def __init__(self, name=None):
        # type: (Optional[str]) -> None
        AutoSource.__init__(self, name=name)
        self.RUN = False

    def generate(self):
        # type: () -> None
        pass

    def start(self):
        # type: () -> None
        self.RUN = True
        Thread(target=self.generate,
               name="scapy.pipetool.ThreadGenSource").start()

    def stop(self):
        # type: () -> None
        self.RUN = False


class ConsoleSink(Sink):
    """Print messages on low and high entries to ``stdout``

    .. code::

         +-------+
      >>-|--.    |->>
         | print |
       >-|--'    |->
         +-------+
    """

    def push(self, msg):
        # type: (str) -> None
        print(">" + repr(msg))

    def high_push(self, msg):
        # type: (str) -> None
        print(">>" + repr(msg))


class RawConsoleSink(Sink):
    """Print messages on low and high entries, using os.write

    .. code::

         +-------+
      >>-|--.    |->>
         | write |
       >-|--'    |->
         +-------+

    :param newlines: Include a new-line character after printing each packet.
                     Defaults to True.
    :type newlines: bool
    """

    def __init__(self, name=None, newlines=True):
        # type: (Optional[str], bool) -> None
        Sink.__init__(self, name=name)
        self.newlines = newlines
        self._write_pipe = 1

    def push(self, msg):
        # type: (str) -> None
        if self.newlines:
            msg += "\n"
        os.write(self._write_pipe, msg.encode("utf8"))

    def high_push(self, msg):
        # type: (str) -> None
        if self.newlines:
            msg += "\n"
        os.write(self._write_pipe, msg.encode("utf8"))


class CLIFeeder(AutoSource):
    """Send messages from python command line:

    .. code::

         +--------+
      >>-|        |->>
         | send() |
       >-|   `----|->
         +--------+
    """

    def send(self, msg):
        # type: (str) -> int
        self._gen_data(msg)
        return 1

    def close(self):
        # type: () -> None
        self.is_exhausted = True


class CLIHighFeeder(CLIFeeder):
    """Send messages from python command line to high output:

    .. code::

         +--------+
      >>-|   .----|->>
         | send() |
       >-|        |->
         +--------+
    """

    def send(self, msg):
        # type: (Any) -> int
        self._gen_high_data(msg)
        return 1


class PeriodicSource(ThreadGenSource):
    """Generate messages periodically on low exit:

    .. code::

         +-------+
      >>-|       |->>
         | msg,T |
       >-|  `----|->
         +-------+
    """

    def __init__(self, msg, period, period2=0, name=None):
        # type: (Union[Iterable[Any], Any], int, int, Optional[str]) -> None
        ThreadGenSource.__init__(self, name=name)
        if not isinstance(msg, (list, set, tuple)):
            self.msg = [msg]  # type: Iterable[Any]
        else:
            self.msg = msg
        self.period = period
        self.period2 = period2

    def generate(self):
        # type: () -> None
        while self.RUN:
            empty_gen = True
            for m in self.msg:
                empty_gen = False
                self._gen_data(m)
                time.sleep(self.period)
            if empty_gen:
                self.is_exhausted = True
                self._exhaust()
            time.sleep(self.period2)


class TermSink(Sink):
    """
    Prints messages on the low and high entries, on a separate terminal (xterm
    or cmd).

    .. code::

         +-------+
      >>-|--.    |->>
         | print |
       >-|--'    |->
         +-------+

    :param keepterm: Leave the terminal window open after :py:meth:`~Pipe.stop`
                     is called. Defaults to True.
    :type keepterm: bool
    :param newlines: Include a new-line character after printing each packet.
                     Defaults to True.
    :type newlines: bool
    :param openearly: Automatically starts the terminal when the constructor is
                      called, rather than waiting for :py:meth:`~Pipe.start`.
                      Defaults to True.
    :type openearly: bool
    """

    def __init__(self, name=None, keepterm=True, newlines=True,
                 openearly=True):
        # type: (Optional[str], bool, bool, bool) -> None
        Sink.__init__(self, name=name)
        self.keepterm = keepterm
        self.newlines = newlines
        self.openearly = openearly
        self.opened = False
        if self.openearly:
            self.start()

    if WINDOWS:
        def _start_windows(self):
            # type: () -> None
            if not self.opened:
                self.opened = True
                self.__f = get_temp_file()
                open(self.__f, "a").close()
                self.name = "Scapy" if self.name is None else self.name
                # Start a powershell in a new window and print the PID
                cmd = "$app = Start-Process PowerShell -ArgumentList '-command &{$host.ui.RawUI.WindowTitle=\\\"%s\\\";Get-Content \\\"%s\\\" -wait}' -passthru; echo $app.Id" % (self.name, self.__f.replace("\\", "\\\\"))  # noqa: E501
                proc = subprocess.Popen(
                    [
                        getattr(conf.prog, "powershell"),
                        cmd
                    ],
                    stdout=subprocess.PIPE
                )
                output, _ = proc.communicate()
                # This is the process PID
                self.pid = int(output)
                print("PID: %d" % self.pid)

        def _stop_windows(self):
            # type: () -> None
            if not self.keepterm:
                self.opened = False
                # Recipe to kill process with PID
                # http://code.activestate.com/recipes/347462-terminating-a-subprocess-on-windows/
                import ctypes
                PROCESS_TERMINATE = 1
                handle = ctypes.windll.kernel32.OpenProcess(PROCESS_TERMINATE, False, self.pid)  # noqa: E501
                ctypes.windll.kernel32.TerminateProcess(handle, -1)
                ctypes.windll.kernel32.CloseHandle(handle)
    else:
        def _start_unix(self):
            # type: () -> None
            if not self.opened:
                self.opened = True
                rdesc, self.wdesc = os.pipe()
                os.set_inheritable(rdesc, True)
                cmd = ["xterm"]
                if self.name is not None:
                    cmd.extend(["-title", self.name])
                if self.keepterm:
                    cmd.append("-hold")
                cmd.extend(["-e", "cat <&%d" % rdesc])
                self.proc = subprocess.Popen(cmd, close_fds=False)
                os.close(rdesc)

        def _stop_unix(self):
            # type: () -> None
            if not self.keepterm:
                self.opened = False
                self.proc.kill()
                self.proc.wait()

    def start(self):
        # type: () -> None
        if WINDOWS:
            return self._start_windows()
        else:
            return self._start_unix()

    def stop(self):
        # type: () -> None
        if WINDOWS:
            return self._stop_windows()
        else:
            return self._stop_unix()

    def _print(self, s):
        # type: (str) -> None
        if self.newlines:
            s += "\n"
        if WINDOWS:
            wdesc = open(self.__f, "a")
            wdesc.write(s)
            wdesc.close()
        else:
            os.write(self.wdesc, s.encode())

    def push(self, msg):
        # type: (str) -> None
        self._print(str(msg))

    def high_push(self, msg):
        # type: (str) -> None
        self._print(str(msg))


class QueueSink(Sink):
    """
    Collects messages on the low and high entries into a :py:class:`Queue`.
    Messages are dequeued with :py:meth:`recv`.
    Both high and low entries share the same :py:class:`Queue`.

    .. code::

         +-------+
      >>-|--.    |->>
         | queue |
       >-|--'    |->
         +-------+
    """

    def __init__(self, name=None):
        # type: (Optional[str]) -> None
        Sink.__init__(self, name=name)
        self.q: queue.Queue[Any] = queue.Queue()

    def push(self, msg):
        # type: (Any) -> None
        self.q.put(msg)

    def high_push(self, msg):
        # type: (Any) -> None
        self.q.put(msg)

    def recv(self, block=True, timeout=None):
        # type: (bool, Optional[int]) -> Optional[Any]
        """
        Reads the next message from the queue.

        If no message is available in the queue, returns None.

        :param block: Blocks execution until a packet is available in the
                      queue. Defaults to True.
        :type block: bool
        :param timeout: Controls how long to wait if ``block=True``. If None
                        (the default), this method will wait forever. If a
                        non-negative number, this is a number of seconds to
                        wait before giving up (and returning None).
        :type timeout: None, int or float
        """
        try:
            return self.q.get(block=block, timeout=timeout)
        except queue.Empty:
            return None


class TransformDrain(Drain):
    """Apply a function to messages on low and high entry:

    .. code::

         +-------+
      >>-|--[f]--|->>
         |       |
       >-|--[f]--|->
         +-------+
    """

    def __init__(self, f, name=None):
        # type: (Callable[[Any], None], Optional[str]) -> None
        Drain.__init__(self, name=name)
        self.f = f

    def push(self, msg):
        # type: (Any) -> None
        self._send(self.f(msg))

    def high_push(self, msg):
        # type: (Any) -> None
        self._high_send(self.f(msg))


class UpDrain(Drain):
    """Repeat messages from low entry to high exit:

    .. code::

         +-------+
      >>-|    ,--|->>
         |   /   |
       >-|--'    |->
         +-------+
    """

    def push(self, msg):
        # type: (Any) -> None
        self._high_send(msg)

    def high_push(self, msg):
        # type: (Any) -> None
        pass


class DownDrain(Drain):
    r"""Repeat messages from high entry to low exit:

    .. code::

         +-------+
      >>-|--.    |->>
         |   \   |
       >-|    `--|->
         +-------+
    """

    def push(self, msg):
        # type: (Any) -> None
        pass

    def high_push(self, msg):
        # type: (Any) -> None
        self._send(msg)


class PipeLink(object):
    """Backpressure and quota declaration for a pipe chain.

    A link is inserted into a chain by adding buffers between pipe
    elements:

    .. code:: python

        link = PipeLink(queue_maxsize=100, quota=50, period=1.0,
                        on_overflow=PIPE_OVERFLOW_DROP,
                        on_stop=PIPE_STOP_DRAIN, drain_timeout=5)
        s > link.buffer() > c

    :param name: human-readable name used in :py:meth:`PipeEngine.stats`
    :param queue_maxsize: maximum number of queued messages per buffer;
                          ``None`` leaves the queue unbounded
    :param quota: maximum number of messages delivered per ``period``
                  seconds; ``None`` disables the quota
    :param period: quota period in seconds (default 1)
    :param on_overflow: ``PIPE_OVERFLOW_WAIT`` (wait for room, default),
                        ``PIPE_OVERFLOW_DROP`` (drop and count) or
                        ``PIPE_OVERFLOW_ERROR`` (raise
                        :class:`PipeLinkFull` and fail the whole chain)
    :param on_stop: ``PIPE_STOP_DRAIN`` (drain on stop, default) or
                    ``PIPE_STOP_DISCARD`` (discard on stop)
    :param drain_timeout: drain deadline in seconds; ``None`` waits until
                          the queue is empty
    :param on_error: optional callback ``f(link, exception)`` called once
                     when the link enters the ``error`` state

    Each link owns an independent quota bucket and set of counters: two
    concurrent links never share tokens. Chains without a buffer keep
    their previous behavior unchanged.
    """

    _counter = 0

    def __init__(
        self,
        name=None,  # type: Optional[str]
        queue_maxsize=None,  # type: Optional[int]
        quota=None,  # type: Optional[float]
        period=1.0,  # type: float
        on_overflow=PIPE_OVERFLOW_WAIT,  # type: str
        on_stop=PIPE_STOP_DRAIN,  # type: str
        drain_timeout=None,  # type: Optional[float]
        on_error=None,  # type: Optional[Callable[..., None]]
    ):
        # type: (...) -> None
        if (queue_maxsize is not None and
                (isinstance(queue_maxsize, bool) or
                 not isinstance(queue_maxsize, int) or
                 queue_maxsize <= 0)):
            raise ValueError("queue_maxsize must be a positive integer "
                             "or None")
        if quota is not None and quota <= 0:
            raise ValueError("quota must be positive or None")
        if period <= 0:
            raise ValueError("period must be positive")
        if on_overflow not in (PIPE_OVERFLOW_WAIT, PIPE_OVERFLOW_DROP,
                               PIPE_OVERFLOW_ERROR):
            raise ValueError("on_overflow must be one of %r, %r or %r" % (
                PIPE_OVERFLOW_WAIT, PIPE_OVERFLOW_DROP,
                PIPE_OVERFLOW_ERROR))
        if on_stop not in (PIPE_STOP_DRAIN, PIPE_STOP_DISCARD):
            raise ValueError("on_stop must be one of %r or %r" % (
                PIPE_STOP_DRAIN, PIPE_STOP_DISCARD))
        if drain_timeout is not None and drain_timeout < 0:
            raise ValueError("drain_timeout must be non-negative or None")
        if name is None:
            PipeLink._counter += 1
            name = "link-%d" % PipeLink._counter
        self.name = name
        self.queue_maxsize = queue_maxsize
        self.quota = quota
        self.period = period
        self.on_overflow = on_overflow
        self.on_stop = on_stop
        self.drain_timeout = drain_timeout
        self.on_error = on_error
        self.state = "active"  # type: str
        self.error = None  # type: Optional[Exception]
        self._buffers = set()  # type: Set[BackPressureDrain]
        self._buffer_counter = 0
        self._lock = Lock()
        # Token bucket: the quota is the refill rate per period
        self._tokens = (float(quota) if quota is not None
                        else None)  # type: Optional[float]
        self._token_time = time.monotonic()
        # EMA of the delivery rate (time constant of one second)
        self.rate = 0.0  # type: float
        self._rate_time = 0.0

    def buffer(self, name=None):
        # type: (Optional[str]) -> BackPressureDrain
        """Create a bounded buffer bound to this link."""
        if name is None:
            self._buffer_counter += 1
            name = "%s[%d]" % (self.name, self._buffer_counter)
        return BackPressureDrain(self, name=name)

    def _register(self, buf):
        # type: (BackPressureDrain) -> None
        self._buffers.add(buf)

    @property
    def backlog(self):
        # type: () -> int
        return sum(b.q.qsize() for b in self._buffers)

    @property
    def received(self):
        # type: () -> int
        return sum(b.received for b in self._buffers)

    @property
    def delivered(self):
        # type: () -> int
        return sum(b.delivered for b in self._buffers)

    @property
    def dropped(self):
        # type: () -> int
        return sum(b.dropped for b in self._buffers)

    def _acquire(self, running=None):
        # type: (Optional[Callable[[], bool]]) -> bool
        """Consume one quota token; return False if stopping while waiting."""
        if self.quota is None:
            return True
        while True:
            with self._lock:
                now = time.monotonic()
                assert self._tokens is not None
                self._tokens = min(
                    float(self.quota),
                    self._tokens +
                    (now - self._token_time) * self.quota / self.period)
                self._token_time = now
                if self._tokens >= 1.0:
                    self._tokens -= 1.0
                    return True
                delay = ((1.0 - self._tokens) *
                         self.period / self.quota)  # type: float
            if running is not None and not running():
                return False
            time.sleep(min(0.1, max(0.0, delay)))

    def _record_delivery(self):
        # type: () -> None
        now = time.monotonic()
        with self._lock:
            if self._rate_time:
                dt = now - self._rate_time
                if dt > 0:
                    self.rate += (1.0 - exp(-dt)) * (1.0 / dt - self.rate)
            self._rate_time = now

    def _fail(self, exception):
        # type: (Exception) -> Exception
        with self._lock:
            if self.state == "error":
                assert self.error is not None
                return self.error
            self.state = "error"
            self.error = exception
            on_error = self.on_error
        if on_error is not None:
            on_error(self, exception)
        return exception

    def _mark_stopped(self):
        # type: () -> None
        with self._lock:
            if self.state != "error":
                self.state = "stopped"


class BackPressureDrain(Drain):
    """Bounded queue between pipe elements, paced by a :class:`PipeLink`.

    Messages received on the low and high entries are enqueued in FIFO
    order (the low/high interleaving is preserved) and delivered on the
    matching exits by a dedicated pump thread, at the link quota rate.
    This keeps the engine loop free of queue and quota waits, so two
    concurrent links never block each other. Usually created through
    :meth:`PipeLink.buffer`.
    """

    def __init__(self, link, name=None):
        # type: (PipeLink, Optional[str]) -> None
        Drain.__init__(self, name=name)
        self.link = link
        # queue.Queue treats a maxsize of 0 as unbounded, like None
        self.q = queue.Queue(
            maxsize=link.queue_maxsize or 0
        )  # type: queue.Queue[Tuple[bool, Any]]
        self.received = 0
        self.delivered = 0
        self.dropped = 0
        self.RUN = False
        self._draining = False
        self._drain_deadline = None  # type: Optional[float]
        self._stopping = False
        self._finished = Event()
        self._finished.set()
        self._thread = None  # type: Optional[Thread]
        self._upstream_buffers = set()  # type: Set[BackPressureDrain]
        self.link._register(self)

    def start(self):
        # type: () -> None
        if self._thread is None and not self._stopping:
            self.RUN = True
            self._finished.clear()
            thread = Thread(
                target=self._pump,
                name="scapy.pipetool.BackPressureDrain")
            thread.daemon = True
            thread.start()
            self._thread = thread

    def push(self, msg):
        # type: (Any) -> None
        self._ingest(False, msg)

    def high_push(self, msg):
        # type: (Any) -> None
        self._ingest(True, msg)

    def _ingest(self, high, msg):
        # type: (bool, Any) -> None
        if self.link.state == "error":
            raise PipeLinkFull(self.link, self)
        item = (high, msg)
        if self.link.on_overflow == PIPE_OVERFLOW_ERROR:
            try:
                self.q.put_nowait(item)
            except queue.Full:
                self.link._fail(PipeLinkFull(self.link, self))
                raise
        elif self.link.on_overflow == PIPE_OVERFLOW_DROP:
            try:
                self.q.put_nowait(item)
            except queue.Full:
                self.dropped += 1
                return
        else:
            while True:
                try:
                    self.q.put(item, timeout=0.1)
                    break
                except queue.Full:
                    if not self.RUN or self._stopping:
                        self.dropped += 1
                        return
        self.received += 1

    def _running(self):
        # type: () -> bool
        if not self.RUN:
            return False
        if (self._draining and self._drain_deadline is not None and
                time.monotonic() >= self._drain_deadline):
            return False
        return True

    def _upstreams_empty(self):
        # type: () -> bool
        return all(buf.q.empty() for buf in self._upstream_buffers)

    def _pump(self):
        # type: () -> None
        try:
            while self.RUN:
                timeout = 0.1  # type: float
                if self._draining and self._drain_deadline is not None:
                    remaining = self._drain_deadline - time.monotonic()
                    if remaining <= 0:
                        break
                    timeout = min(timeout, remaining)
                try:
                    item = self.q.get(timeout=timeout)
                except queue.Empty:
                    # Stay alive while an upstream buffer may still feed us
                    if self._draining and self._upstreams_empty():
                        break
                    continue
                if not self.link._acquire(running=self._running):
                    self.dropped += 1
                    break
                high, payload = item
                try:
                    if high:
                        self._high_send(payload)
                    else:
                        self._send(payload)
                except Exception as e:
                    log_runtime.exception("piping from %s failed: %s",
                                          self.name, e)
                self.delivered += 1
                self.link._record_delivery()
        finally:
            # Discard whatever the queue still holds (drain deadline,
            # immediate stop or failed chain shutdown)
            while True:
                try:
                    self.q.get_nowait()
                except queue.Empty:
                    break
                else:
                    self.dropped += 1
            self._finished.set()

    def stop(self):
        # type: () -> None
        if self._thread is None:
            return
        if self._stopping:
            self._finished.wait()
            return
        self._stopping = True
        if self.link.on_stop == PIPE_STOP_DISCARD:
            self.RUN = False
            self._finished.wait()
        else:
            self._draining = True
            if self.link.drain_timeout is not None:
                self._drain_deadline = (time.monotonic() +
                                        self.link.drain_timeout)
            if not self._finished.wait(self.link.drain_timeout):
                # Drain deadline expired: the pump discards and exits.
                self.RUN = False
                self._finished.wait()
        self.link._mark_stopped()
