"""
Unit tests for the socket tracking that keeps ``_finalize_zmq_context`` from
blocking in ``zmq_ctx_term()``.
"""

import zmq

import salt.transport.zeromq
from tests.support.mock import MagicMock


def test_close_zmq_sockets_closes_open_sockets():
    first = MagicMock(closed=False)
    second = MagicMock(closed=False)
    salt.transport.zeromq._close_zmq_sockets([first, second])
    first.close.assert_called_once_with(linger=0)
    second.close.assert_called_once_with(linger=0)


def test_close_zmq_sockets_skips_closed_sockets():
    sock = MagicMock(closed=True)
    salt.transport.zeromq._close_zmq_sockets([sock])
    sock.close.assert_not_called()


def test_close_zmq_sockets_accepts_none_and_empty():
    salt.transport.zeromq._close_zmq_sockets(None)
    salt.transport.zeromq._close_zmq_sockets([])


def test_close_zmq_sockets_falls_back_to_the_base_close(monkeypatch):
    """
    A zmq.asyncio socket also talks to its event loop on close(), and the
    loop may already be closed.  The underlying socket must still be closed,
    and one failing socket must not stop the others from being closed.
    """
    broken = MagicMock(closed=False)
    broken.close.side_effect = RuntimeError("Event loop is closed")
    healthy = MagicMock(closed=False)
    base_close = MagicMock()
    monkeypatch.setattr(zmq.Socket, "close", base_close)

    salt.transport.zeromq._close_zmq_sockets([broken, healthy])

    base_close.assert_called_once_with(broken, linger=0)
    healthy.close.assert_called_once_with(linger=0)


def test_finalize_closes_sockets_before_destroying_the_context():
    calls = []
    context = MagicMock(closed=False)
    context.destroy.side_effect = lambda **kwargs: calls.append("destroy")
    sock = MagicMock(closed=False)
    sock.close.side_effect = lambda **kwargs: calls.append("close")

    salt.transport.zeromq._finalize_zmq_context(context, [sock])

    assert calls == ["close", "destroy"]


def test_finalize_without_sockets_still_destroys_the_context():
    context = MagicMock(closed=False)
    salt.transport.zeromq._finalize_zmq_context(context)
    context.destroy.assert_called_once_with(linger=1000)


async def test_request_client_tracks_its_open_socket(minion_opts, io_loop):
    minion_opts["master_uri"] = "tcp://127.0.0.1:4506"
    client = salt.transport.zeromq.RequestClient(minion_opts, io_loop)
    try:
        assert client._zmq_sockets == []
        await client.connect()
        assert client._zmq_sockets == [client.socket]
    finally:
        await client.close_async()


async def test_request_client_drops_closed_sockets_on_reconnect(minion_opts, io_loop):
    """
    The list the finalizer holds must not grow with every reconnect.
    """
    minion_opts["master_uri"] = "tcp://127.0.0.1:4506"
    client = salt.transport.zeromq.RequestClient(minion_opts, io_loop)
    try:
        await client.connect()
        first = client.socket
        client._init_socket()
        assert first.closed
        assert client._zmq_sockets == [client.socket]
    finally:
        await client.close_async()
