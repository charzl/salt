"""
Contract for ``RequestClient.close_async()``: once it has been started, the
REQ socket must end up closed whether the coroutine finishes, is cancelled at
its ``await``, or is abandoned because its loop went away.

The last case is the one that froze minions: the socket is detached from the
client before the ``await`` and was only closed after it, so an abandoned
coroutine left an open socket that nothing could reach.
"""

import asyncio

import pytest

import salt.transport.zeromq


@pytest.fixture
def opts(minion_opts):
    minion_opts["master_uri"] = "tcp://192.0.2.1:4506"  # unroutable
    return minion_opts


def _start_close_async_and_abandon(opts):
    """
    Start ``close_async()``, let it reach its ``await`` and close the loop
    without ever letting it resume.  Returns the socket and the context.
    """
    loop = asyncio.new_event_loop()

    async def main():
        client = salt.transport.zeromq.RequestClient(opts, io_loop=loop)
        await client.connect()
        sock, ctx = client.socket, client.context
        task = loop.create_task(client.close_async())
        await asyncio.sleep(0)
        return sock, ctx, task

    sock, ctx, task = loop.run_until_complete(main())
    loop.close()
    return sock, ctx, task


def test_close_async_abandoned_at_its_await_leaves_no_open_socket(opts):
    sock, ctx, task = _start_close_async_and_abandon(opts)
    try:
        assert sock.closed
    finally:
        # Do not leave the context to the finalizer if the assertion fails.
        task._log_destroy_pending = False
        sock.close(linger=0)
        ctx.destroy(linger=0)


@pytest.mark.parametrize("steps", [1, 2, 3])
async def test_close_async_cancelled_leaves_no_open_socket(opts, steps):
    client = salt.transport.zeromq.RequestClient(opts, io_loop=None)
    await client.connect()
    sock, ctx = client.socket, client.context
    task = asyncio.get_running_loop().create_task(client.close_async())
    for _ in range(steps):
        await asyncio.sleep(0)
    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass
    try:
        assert sock.closed
    finally:
        sock.close(linger=0)
        ctx.destroy(linger=0)


async def test_close_async_completes_with_socket_and_context_closed(opts):
    client = salt.transport.zeromq.RequestClient(opts, io_loop=None)
    await client.connect()
    sock, ctx = client.socket, client.context
    await client.close_async()
    assert sock.closed
    assert ctx.closed
