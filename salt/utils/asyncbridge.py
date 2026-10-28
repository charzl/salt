"""
Call async code from sync code through one event loop per process.

``salt.utils.asynchronous.SyncWrapper`` creates a new event loop for every
wrapped object.  This module keeps a single loop running in a background
thread instead.  Sync callers hand a coroutine to that loop and wait for the
result, so wrapped objects do not own a loop that has to be closed or can leak.

Rules:

* A sync call made from the bridge thread itself would block the loop it is
  waiting on, so it raises ``RuntimeError`` instead of deadlocking.
* The bridge thread does not survive ``os.fork()``.  A child process builds its
  own bridge on first use, and a wrapper created in the parent raises if the
  child tries to use it.
"""

import asyncio
import inspect
import logging
import os
import threading

import tornado.ioloop

log = logging.getLogger(__name__)

_bridge = None
_bridge_lock = threading.Lock()


class LoopBridge:
    """
    An asyncio event loop running in a daemon thread.
    """

    def __init__(self):
        self.pid = os.getpid()
        self._loop = None
        self._ready = threading.Event()
        self._thread = threading.Thread(
            target=self._run, name="salt-loop-bridge", daemon=True
        )
        self._thread.start()
        self._ready.wait()

    def _run(self):
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        self._loop = loop
        self._ready.set()
        try:
            loop.run_forever()
        finally:
            try:
                for task in asyncio.all_tasks(loop):
                    task.cancel()
                loop.run_until_complete(loop.shutdown_asyncgens())
            finally:
                loop.close()

    def in_loop_thread(self):
        return threading.get_ident() == self._thread.ident

    def run(self, coro, timeout=None):
        """
        Run ``coro`` on the bridge loop and return its result.
        """
        if os.getpid() != self.pid:
            coro.close()
            raise RuntimeError(
                "This object was created before fork and cannot be used in the"
                " child process; create a new one."
            )
        if self.in_loop_thread():
            coro.close()
            raise RuntimeError(
                "Sync call made from the loop bridge thread. Await the async"
                " API instead."
            )
        future = asyncio.run_coroutine_threadsafe(coro, self._loop)
        try:
            return future.result(timeout)
        except BaseException:
            # Timeout, KeyboardInterrupt, or the coroutine's own error.
            if not future.done():
                future.cancel()
            raise


def get_bridge():
    """
    Return this process's bridge, starting it on first use.
    """
    global _bridge
    with _bridge_lock:
        if _bridge is None or _bridge.pid != os.getpid():
            _bridge = LoopBridge()
        return _bridge


def _reset_after_fork():
    global _bridge, _bridge_lock
    _bridge = None
    _bridge_lock = threading.Lock()


if hasattr(os, "register_at_fork"):
    os.register_at_fork(after_in_child=_reset_after_fork)


class BridgedWrapper:
    """
    Drop-in for ``SyncWrapper``: build an async object on the shared loop and
    call its async methods as blocking calls.

    ``async_methods`` lists the methods to run on the loop (the wrapped class
    may also provide an ``async_methods`` attribute).  Everything else is passed
    through.  ``close_methods`` run on the loop when the wrapper is closed.
    """

    def __init__(
        self,
        cls,
        args=None,
        kwargs=None,
        async_methods=None,
        close_methods=None,
        loop_kwarg=None,
    ):
        args = tuple(args or ())
        kwargs = dict(kwargs or {})
        bridge = get_bridge()

        async def create():
            if loop_kwarg:
                kwargs[loop_kwarg] = tornado.ioloop.IOLoop.current()
            return cls(*args, **kwargs)

        self._bridge = bridge
        self.cls = cls
        self.obj = bridge.run(create())
        self._async_methods = set(async_methods or ()) | set(
            getattr(self.obj, "async_methods", [])
        )
        self._close_methods = set(close_methods or ()) | set(
            getattr(self.obj, "close_methods", [])
        )

    def __repr__(self):
        return f"<BridgedWrapper(cls={self.__dict__.get('cls')})>"

    def _call(self, name, *args, **kwargs):
        obj = self.obj

        async def run():
            result = getattr(obj, name)(*args, **kwargs)
            if inspect.isawaitable(result):
                result = await result
            return result

        return self._bridge.run(run())

    def __getattr__(self, key):
        # Only reached when normal lookup fails.  Look in __dict__ so a
        # half-built instance cannot recurse.
        state = self.__dict__
        obj = state.get("obj")
        if obj is None:
            raise AttributeError(key)
        if key in state["_async_methods"]:
            return lambda *args, **kwargs: self._call(key, *args, **kwargs)
        return getattr(obj, key)

    def close(self):
        state = self.__dict__
        if state.get("obj") is None:
            return
        try:
            for name in state["_close_methods"]:
                try:
                    self._call(name)
                except Exception:  # pylint: disable=broad-except
                    log.exception("Error running %s on %r", name, self.obj)
        finally:
            self.obj = None

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, tb):
        self.close()
