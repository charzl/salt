import asyncio
import os
import sys
import threading
import warnings

import pytest

import salt.utils.asyncbridge as asyncbridge

pytestmark = [pytest.mark.core_test]


class Counter:
    async_methods = ["add", "fail", "slow"]
    close_methods = ["close"]

    def __init__(self, start=0):
        self.value = start
        self.created_in = threading.get_ident()
        self.closed_in = None

    async def add(self, n):
        await asyncio.sleep(0)
        self.value += n
        return self.value

    async def fail(self):
        raise ValueError("boom")

    async def slow(self):
        await asyncio.sleep(30)

    def close(self):
        self.closed_in = threading.get_ident()


def test_run_returns_result():
    async def coro():
        return 42

    assert asyncbridge.get_bridge().run(coro()) == 42


def test_run_propagates_exception():
    async def coro():
        raise ValueError("boom")

    with pytest.raises(ValueError, match="boom"):
        asyncbridge.get_bridge().run(coro())


def test_run_timeout_cancels_the_task():
    bridge = asyncbridge.get_bridge()
    cancelled = threading.Event()

    async def coro():
        try:
            await asyncio.sleep(30)
        except asyncio.CancelledError:
            cancelled.set()
            raise

    with pytest.raises(TimeoutError):
        bridge.run(coro(), timeout=0.1)
    assert cancelled.wait(5)


def test_same_loop_is_used_for_every_call():
    bridge = asyncbridge.get_bridge()

    async def loop_id():
        return id(asyncio.get_running_loop())

    assert bridge.run(loop_id()) == bridge.run(loop_id())


def test_call_from_bridge_thread_raises_instead_of_deadlocking():
    bridge = asyncbridge.get_bridge()

    async def inner():
        return 1

    async def outer():
        # A sync call made from inside the loop. SyncWrapper hung here.
        return bridge.run(inner())

    with warnings.catch_warnings():
        warnings.simplefilter("error")  # no "coroutine was never awaited"
        with pytest.raises(RuntimeError, match="bridge thread"):
            bridge.run(outer())


def test_concurrent_callers_share_one_loop():
    wrapper = asyncbridge.BridgedWrapper(Counter)
    results = []

    def work():
        for _ in range(50):
            results.append(wrapper.add(1))

    threads = [threading.Thread(target=work) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    wrapper.close()
    assert len(results) == 400
    assert sorted(results) == list(range(1, 401))


def test_wrapper_builds_object_on_bridge_thread():
    wrapper = asyncbridge.BridgedWrapper(Counter, args=(5,))
    try:
        assert wrapper.created_in == asyncbridge.get_bridge()._thread.ident
        assert wrapper.created_in != threading.get_ident()
        assert wrapper.value == 5  # plain attribute passes through
        assert wrapper.add(2) == 7
    finally:
        wrapper.close()


def test_wrapper_propagates_exceptions():
    with asyncbridge.BridgedWrapper(Counter) as wrapper:
        with pytest.raises(ValueError, match="boom"):
            wrapper.fail()


def test_wrapper_close_runs_on_bridge_thread_and_is_idempotent():
    wrapper = asyncbridge.BridgedWrapper(Counter)
    obj = wrapper.obj
    wrapper.close()
    wrapper.close()
    assert obj.closed_in == asyncbridge.get_bridge()._thread.ident
    with pytest.raises(AttributeError):
        wrapper.add  # pylint: disable=pointless-statement


def test_wrapper_passes_loop_kwarg():
    class NeedsLoop:
        def __init__(self, io_loop=None):
            self.io_loop = io_loop

    wrapper = asyncbridge.BridgedWrapper(NeedsLoop, loop_kwarg="io_loop")
    try:
        bridge_loop = asyncbridge.get_bridge()._loop
        assert wrapper.io_loop.asyncio_loop is bridge_loop
    finally:
        wrapper.close()


def test_many_wrappers_do_not_add_threads_or_loops():
    asyncbridge.get_bridge()
    before = threading.active_count()
    wrappers = [asyncbridge.BridgedWrapper(Counter) for _ in range(50)]
    try:
        assert threading.active_count() == before
    finally:
        for wrapper in wrappers:
            wrapper.close()


@pytest.mark.skipif(not hasattr(os, "fork"), reason="needs os.fork")
@pytest.mark.skipif(
    sys.platform == "darwin", reason="fork after threads is unreliable on macOS"
)
def test_fork_gets_a_new_bridge_and_old_wrappers_fail_fast():
    parent_bridge = asyncbridge.get_bridge()
    wrapper = asyncbridge.BridgedWrapper(Counter)
    read_fd, write_fd = os.pipe()
    pid = os.fork()
    if pid == 0:  # child
        status = b"ok"
        try:
            try:
                wrapper.add(1)
                status = b"old wrapper still worked"
            except RuntimeError:
                pass
            child_bridge = asyncbridge.get_bridge()
            if child_bridge is parent_bridge:
                status = b"bridge was inherited"
            elif asyncbridge.BridgedWrapper(Counter).add(3) != 3:
                status = b"new wrapper broken"
        except BaseException as exc:  # pylint: disable=broad-except
            status = repr(exc).encode()
        os.write(write_fd, status)
        os._exit(0)
    os.close(write_fd)
    os.waitpid(pid, 0)
    assert os.read(read_fd, 1000) == b"ok"
    os.close(read_fd)
    assert wrapper.add(1) == 1  # parent unaffected
    wrapper.close()
