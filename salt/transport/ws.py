import asyncio
import contextlib
import logging
import multiprocessing
import os
import signal
import socket

import aiohttp
import aiohttp.web

import salt.exceptions
import salt.payload
import salt.transport.base
import salt.transport.frame
import salt.utils.asynchronous
import salt.utils.resource_warnings
from salt.exceptions import SaltClientError, SaltReqTimeoutError
from salt.transport.tcp import (
    USE_LOAD_BALANCER,
    ClosingError,
    LoadBalancerServer,
    _get_bind_addr,
    _get_socket,
    _set_tcp_keepalive,
)
from salt.utils.asynchronous import cancel_tasks, resolve_result

log = logging.getLogger(__name__)


class PublishClient(salt.transport.base.PublishClient):
    """WebSocket subscription client whose I/O belongs to the caller's loop."""

    ttype = "ws"
    async_methods = ["connect", "recv", "send", "close_async"]
    close_methods = ["close_async"]

    def __init__(
        self, opts, io_loop, **kwargs
    ):  # pylint: disable=super-init-not-called
        self.opts = opts
        self.io_loop = (
            asyncio.get_event_loop()
            if io_loop is None
            else salt.utils.asynchronous.aioloop(io_loop)
        )
        self.asyncio_loop = self.io_loop
        self.host = kwargs.get("host")
        self.port = kwargs.get("port")
        self.path = kwargs.get("path")
        self.ssl = kwargs.get("ssl")
        if not (
            (self.host and self.port and not self.path)
            or (self.path and self.host is None and self.port is None)
        ):
            raise ValueError("Provide a host and port, or a Unix socket path")
        self.backoff = opts.get("tcp_reconnect_backoff", 1)
        self.source_ip = opts.get("source_ip")
        self.source_port = opts.get("source_publish_port")
        self.connected = False
        self._closing = False
        self._closed = False
        self._ws = self._session = None
        self.connect_callback = self.disconnect_callback = None
        self.on_recv_task = self.close_task = None
        self._connect_lock = asyncio.Lock()
        self._recv_lock = asyncio.Lock()
        self._close_lock = asyncio.Lock()
        self._io_tasks = {}
        self._recv_tasks = set()
        self._creator_pid = os.getpid()

    @contextlib.contextmanager
    def _track_io(self):
        task = asyncio.current_task()
        self._io_tasks[task] = self._io_tasks.get(task, 0) + 1
        try:
            yield
        finally:
            remaining = self._io_tasks[task] - 1
            if remaining:
                self._io_tasks[task] = remaining
            else:
                del self._io_tasks[task]

    async def _close_connection(self):
        ws, session = self._ws, self._session
        self._ws = self._session = None
        self.connected = False
        try:
            # Abort the HTTP connection before the WebSocket handshake on shutdown.
            if session is not None:
                await session.close()
        finally:
            if ws is not None:
                await ws.close()

    async def getstream(self, timeout=None):
        deadline = None if timeout is None else self.io_loop.time() + timeout
        while not self._closing:
            session = None
            try:
                ctx = (
                    True
                    if self.ssl is None
                    else salt.transport.base.ssl_context(self.ssl, server_side=False)
                )
                if self.path:
                    connector = aiohttp.UnixConnector(path=self.path)
                    url = "http://ipc.saltproject.io/ws"
                else:
                    local_addr = (
                        (self.source_ip or "0.0.0.0", self.source_port or 0)
                        if self.source_ip or self.source_port
                        else None
                    )
                    connector = aiohttp.TCPConnector(local_addr=local_addr)
                    scheme = "https" if self.ssl is not None else "http"
                    url = f"{scheme}://{self.host}:{self.port}/ws"
                session = aiohttp.ClientSession(connector=connector)
                remaining = (
                    5 if deadline is None else max(0, deadline - self.io_loop.time())
                )
                ws = await asyncio.wait_for(session.ws_connect(url, ssl=ctx), remaining)
                return ws, session
            except asyncio.CancelledError:
                if session is not None:
                    await session.close()
                raise
            except (aiohttp.ClientError, OSError, asyncio.TimeoutError):
                if session is not None:
                    await session.close()
                if self._closing or (
                    deadline is not None and self.io_loop.time() >= deadline
                ):
                    raise
                delay = (
                    self.backoff
                    if deadline is None
                    else min(self.backoff, max(0, deadline - self.io_loop.time()))
                )
                await asyncio.sleep(delay)
        raise salt.exceptions.SaltClientError("Publish client is closed")

    async def connect(
        self, port=None, connect_callback=None, disconnect_callback=None, timeout=None
    ):
        if port is not None:
            self.port = port
        if connect_callback is not None:
            self.connect_callback = connect_callback
        if disconnect_callback is not None:
            self.disconnect_callback = disconnect_callback
        with self._track_io():
            async with self._connect_lock:
                if self._closing:
                    raise salt.exceptions.SaltClientError("Publish client is closed")
                if self._ws is not None and not self._ws.closed:
                    return
                await self._close_connection()
                self._ws, self._session = await self.getstream(timeout)
                self.connected = True
            if self.connect_callback is not None:
                await resolve_result(self.connect_callback(True))

    async def send(self, msg):
        with self._track_io():
            await self.connect()
            await self._ws.send_bytes(msg)

    async def _recv(self):
        while not self._closing:
            await self.connect()
            ws = self._ws
            response = await ws.receive()
            if response.type == aiohttp.WSMsgType.BINARY:
                return salt.payload.loads(response.data, raw=True)
            if response.type in (
                aiohttp.WSMsgType.CLOSE,
                aiohttp.WSMsgType.CLOSED,
                aiohttp.WSMsgType.CLOSING,
                aiohttp.WSMsgType.ERROR,
            ) or (response.type == aiohttp.WSMsgType.TEXT and response.data == "close"):
                await self._close_connection()
                if self.disconnect_callback is not None and not self._closing:
                    await resolve_result(self.disconnect_callback())
        return None

    async def recv(self, timeout=None):
        with self._track_io():
            async with self._recv_lock:
                try:
                    return await asyncio.wait_for(
                        self._recv(), 0.0001 if timeout == 0 else timeout
                    )
                except asyncio.TimeoutError:
                    return None

    async def on_recv_handler(self, callback):
        while not self._closing:
            message = await self.recv()
            if message is not None:
                await resolve_result(callback(message))

    def on_recv(self, callback):
        if self.on_recv_task is not None:
            self.on_recv_task.cancel()
        if callback is None or self._closing:
            self.on_recv_task = None
        else:
            task = self.io_loop.create_task(self.on_recv_handler(callback))
            self.on_recv_task = task
            self._recv_tasks.add(task)
            task.add_done_callback(self._recv_tasks.discard)

    async def close_async(self):
        current = asyncio.current_task()
        if self.close_task is not None and self.close_task is not current:
            await asyncio.shield(self.close_task)
            return
        async with self._close_lock:
            if self._closed:
                return
            self._closing = True
            await cancel_tasks(*self._io_tasks, *self._recv_tasks)
            await self._close_connection()
            self.on_recv_task = None
            self._closed = True

    def close(self):
        if not self._closing:
            self._closing = True
            if not self._io_tasks and not self._recv_tasks and self._session is None:
                self._closed = True
            else:
                self.close_task = self.io_loop.create_task(self.close_async())

    def _decode_messages(self, messages):
        return messages if isinstance(messages, dict) else salt.payload.loads(messages)

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        await self.close_async()

    def __del__(self):  # pylint: disable=no-dunder-del
        if getattr(self, "_creator_pid", None) == os.getpid() and not getattr(
            self, "_closing", True
        ):
            salt.utils.resource_warnings.warn_until_close(
                f"unclosed publish client {self!r}", source=self, log=log
            )


class PublishServer(salt.transport.base.DaemonizedPublishServer):
    """ """

    # TODO: opts!
    # Based on default used in tornado.netutil.bind_sockets()
    backlog = 128
    async_methods = ["connect", "publish", "close_async"]
    close_methods = ["close_async"]

    def __init__(
        self,
        opts,
        pub_host=None,
        pub_port=None,
        pub_path=None,
        pull_host=None,
        pull_port=None,
        pull_path=None,
        pull_path_perms=0o600,
        pub_path_perms=0o600,
        started=None,
        _shutdown=None,
        ssl=None,
    ):
        self.opts = opts
        self.pub_host = pub_host
        self.pub_port = pub_port
        self.pub_path = pub_path
        self.pull_host = pull_host
        self.pull_port = pull_port
        self.pull_path = pull_path
        self.pull_path_perms = pull_path_perms
        self.pub_path_perms = pub_path_perms
        self.ssl = ssl
        self.clients = set()
        self._run = None
        if _shutdown is None:
            self._shutdown = multiprocessing.Event()  # Cross-process shutdown signal
        else:
            self._shutdown = _shutdown
        self.pub_writer = None
        self.pub_reader = None
        self._connect_lock = asyncio.Lock()
        self._publish_lock = asyncio.Lock()
        self._close_lock = asyncio.Lock()
        self._connect_tasks = set()
        self._publish_tasks = set()
        self._ipc_connections = {}
        self._publisher_task = None
        self._publisher_done = asyncio.Event()
        self._monitor_task = None
        self._loop = None
        self._closing = self._closed = False
        self.close_task = None
        self.runner = None
        self.site = None
        self.puller = None
        if started is None:
            self.started = multiprocessing.Event()
        else:
            self.started = started

    @classmethod
    def support_ssl(cls):
        # Required from DaemonizedPublishServer
        return True

    def topic_support(self):
        # Required from DaemonizedPublishServer
        return not self.opts.get("order_masters", False)

    def __setstate__(self, state):
        self.__init__(**state)

    def __getstate__(self):
        return {
            "opts": self.opts,
            "pub_host": self.pub_host,
            "pub_port": self.pub_port,
            "pub_path": self.pub_path,
            "pull_host": self.pull_host,
            "pull_port": self.pull_port,
            "pull_path": self.pull_path,
            "pull_path_perms": self.pull_path_perms,
            "pub_path_perms": self.pub_path_perms,
            "ssl": self.ssl,
            "started": self.started,
            "_shutdown": self._shutdown,
        }

    def publish_daemon(
        self,
        publish_payload,
        presence_callback=None,
        remove_presence_callback=None,
        secrets=None,
        started=None,
    ):
        if started is not None:
            self.started = started
        asyncio.run(
            self._run_daemon(
                publish_payload, presence_callback, remove_presence_callback
            )
        )

    async def _run_daemon(
        self, publish_payload, presence_callback, remove_presence_callback
    ):
        loop = asyncio.get_running_loop()
        try:
            loop.add_signal_handler(signal.SIGTERM, self.close)
        except NotImplementedError:
            pass
        try:
            await self.publisher(
                publish_payload, presence_callback, remove_presence_callback
            )
        finally:
            try:
                loop.remove_signal_handler(signal.SIGTERM)
            except NotImplementedError:
                pass

    async def _watch_shutdown(self):
        while not self._shutdown.is_set():
            # Bound the blocking process-event wait so cancellation cannot leave
            # asyncio.run() waiting forever for an executor thread to exit.
            if await asyncio.to_thread(self._shutdown.wait, 0.1):
                break
        self._run.set()

    async def publisher(
        self,
        publish_payload,
        presence_callback=None,
        remove_presence_callback=None,
        io_loop=None,
    ):
        if self._shutdown.is_set():
            return
        self._loop = asyncio.get_running_loop()
        if (
            io_loop is not None
            and salt.utils.asynchronous.aioloop(io_loop) is not self._loop
        ):
            raise RuntimeError("Publisher must run on its owning loop")
        self._publisher_task = asyncio.current_task()
        self._run = asyncio.Event()
        self._pub_payload = publish_payload
        try:
            ctx = (
                None
                if self.ssl is None
                else salt.transport.base.ssl_context(self.ssl, server_side=True)
            )
            server = aiohttp.web.Server(self.handle_request)
            self.runner = aiohttp.web.ServerRunner(server, shutdown_timeout=1)
            await self.runner.setup()
            if self.pub_path:
                with salt.utils.files.set_umask(0o177):
                    self.site = aiohttp.web.UnixSite(
                        self.runner, self.pub_path, ssl_context=ctx
                    )
                    await self.site.start()
                    os.chmod(self.pub_path, self.pub_path_perms)
            else:
                sock = _get_socket(self.opts)
                try:
                    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                    sock.setblocking(False)
                    sock.bind((self.pub_host, self.pub_port))
                    sock.listen(self.backlog)
                    self.site = aiohttp.web.SockSite(self.runner, sock, ssl_context=ctx)
                    await self.site.start()
                    self.pub_port = sock.getsockname()[1]
                except BaseException:
                    sock.close()
                    raise
            if self.pull_path:
                with salt.utils.files.set_umask(0o177):
                    self.puller = await asyncio.start_unix_server(
                        self._accept_ipc, self.pull_path
                    )
                    os.chmod(self.pull_path, self.pull_path_perms)
            else:
                self.puller = await asyncio.start_server(
                    self._accept_ipc, self.pull_host, self.pull_port
                )
                self.pull_port = self.puller.sockets[0].getsockname()[1]
            self._monitor_task = self._loop.create_task(self._watch_shutdown())
            self.started.set()
            await self._run.wait()
        finally:
            self._closing = True
            self._shutdown.set()
            try:
                await self._close_resources()
            finally:
                self._publisher_done.set()

    def _accept_ipc(self, reader, writer):
        if self._closing:
            writer.close()
            return
        task = asyncio.create_task(self.pull_handler(reader, writer))
        self._ipc_connections[task] = writer
        task.add_done_callback(self._ipc_done)

    def _ipc_done(self, task):
        writer = self._ipc_connections.pop(task, None)
        if writer is not None:
            writer.close()
        if not task.cancelled() and task.exception() is not None:
            log.error("Publisher IPC connection failed: %s", task.exception())

    async def pull_handler(self, reader, writer):
        unpacker = salt.utils.msgpack.Unpacker(raw=True)
        try:
            while not self._closing:
                data = await reader.read(65536)
                if not data:
                    return
                unpacker.feed(data)
                for message in unpacker:
                    await resolve_result(self._pub_payload(message))
        finally:
            writer.close()
            await writer.wait_closed()

    def pre_fork(self, process_manager, *args, **kwargs):
        """
        Do anything necessary pre-fork. Since this is on the master side this will
        primarily be used to create IPC channels and create our daemon process to
        do the actual publishing
        """
        process_manager.add_process(
            self.publish_daemon,
            args=[self.publish_payload],
            name=self.__class__.__name__,
        )

    async def handle_request(self, request):
        try:
            cert = request.get_extra_info("peercert")
        except AttributeError:
            pass
        else:
            if cert:
                name = salt.transport.base.common_name(cert)
                log.debug("Request client cert %r", name)
        ws = aiohttp.web.WebSocketResponse()
        await ws.prepare(request)
        self.clients.add(ws)
        try:
            # Keep connection alive until client disconnects
            async for msg in ws:
                if msg.type == aiohttp.WSMsgType.ERROR:
                    log.error("ws connection closed with exception %s", ws.exception())
                    break
        finally:
            self.clients.discard(ws)
        return ws

    async def _disconnect_pusher(self):
        writer, self.pub_writer = self.pub_writer, None
        self.pub_reader = None
        if writer is not None:
            writer.close()
            try:
                await writer.wait_closed()
            except ConnectionError:
                pass

    async def connect(self, timeout=None):  # pylint: disable=invalid-overridden-method
        task = asyncio.current_task()
        self._connect_tasks.add(task)
        self._loop = asyncio.get_running_loop()
        try:
            async with self._connect_lock:
                if self._closing:
                    raise salt.exceptions.SaltClientError("Publish server is closed")
                if self.pub_writer is not None and not self.pub_writer.is_closing():
                    return
                await self._disconnect_pusher()
                connection = (
                    asyncio.open_unix_connection(self.pull_path)
                    if self.pull_path
                    else asyncio.open_connection(self.pull_host, self.pull_port)
                )
                self.pub_reader, self.pub_writer = await asyncio.wait_for(
                    connection, timeout
                )
        finally:
            self._connect_tasks.discard(task)

    async def publish(
        self, payload, **kwargs
    ):  # pylint: disable=invalid-overridden-method
        task = asyncio.current_task()
        self._publish_tasks.add(task)
        try:
            async with self._publish_lock:
                await self.connect()
                self.pub_writer.write(salt.payload.dumps(payload, use_bin_type=True))
                await self.pub_writer.drain()
        finally:
            self._publish_tasks.discard(task)

    async def publish_payload(self, payload, topic_list=None, raw_payload=None):
        # ``raw_payload`` is accepted for interface parity with the
        # TCP PublishServer, which uses it to skip a redundant
        # msgpack round-trip on the EP fan-out hot path.  The ws
        # transport frames with ``salt.payload.dumps`` below, so the
        # unframed passthrough shortcut doesn't apply here.
        payload = salt.payload.dumps(payload, use_bin_type=True)
        for ws in list(self.clients):
            try:
                await ws.send_bytes(payload)
            except ConnectionResetError:
                self.clients.discard(ws)

    async def _close_resources(self):
        async with self._close_lock:
            if self._closed:
                return
            if self.puller is not None:
                self.puller.close()
                await self.puller.wait_closed()
                self.puller = None
            connections = tuple(self._ipc_connections.items())
            await cancel_tasks(
                self._monitor_task,
                *self._connect_tasks,
                *self._publish_tasks,
                *(task for task, _ in connections),
            )
            for _, writer in connections:
                writer.close()
                await writer.wait_closed()
            await self._disconnect_pusher()
            if self.runner is not None:
                await self.runner.cleanup()
                self.runner = self.site = None
            self.clients.clear()
            self._closed = True

    async def close_async(self):
        self.close()
        if (
            self.close_task is not None
            and self.close_task is not asyncio.current_task()
        ):
            await asyncio.shield(self.close_task)
        elif (
            self._publisher_task is not None
            and self._publisher_task is not asyncio.current_task()
        ):
            await self._publisher_done.wait()
        else:
            await self._close_resources()

    def close(self):
        if self._closing:
            return
        self._closing = True
        self._shutdown.set()
        if self._run is not None:
            self._run.set()
        if self._publisher_task is None:
            if self._loop is not None:
                self.close_task = self._loop.create_task(self._close_resources())
            else:
                self._closed = True

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        await self.close_async()


class RequestServer(salt.transport.base.DaemonizedRequestServer):
    def __init__(self, opts):  # pylint: disable=W0231
        self.opts = opts
        self.site = None
        self.ssl = self.opts.get("ssl", None)
        self._run = None
        self._socket = None

    def pre_fork(self, process_manager, *args, **kwargs):
        """
        Pre-fork we need to create the zmq router device
        """
        if USE_LOAD_BALANCER:
            self.socket_queue = multiprocessing.Queue()
            process_manager.add_process(
                LoadBalancerServer,
                args=(self.opts, self.socket_queue),
                name="LoadBalancerServer",
            )
        elif not salt.utils.platform.is_windows():
            if self.opts.get("ipc_mode") == "ipc" and self.opts.get("workers_ipc_name"):
                self._socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                self._socket.setblocking(0)
                ipc_path = os.path.join(
                    self.opts["sock_dir"], self.opts["workers_ipc_name"]
                )
                if os.path.exists(ipc_path):
                    os.unlink(ipc_path)
                self._socket.bind(ipc_path)
                os.chmod(ipc_path, 0o600)
            else:
                self._socket = _get_socket(self.opts)
                self._socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                _set_tcp_keepalive(self._socket, self.opts)
                self._socket.setblocking(0)
                self._socket.bind(_get_bind_addr(self.opts, "ret_port"))

    def post_fork(self, message_handler, io_loop, **kwargs):
        """
        After forking we need to create all of the local sockets to listen to the
        router

        message_handler: function to call with your payloads
        """
        self.message_handler = message_handler
        self._run = asyncio.Event()
        self._started = asyncio.Event()

        # Convert to asyncio loop
        io_loop = salt.utils.asynchronous.aioloop(io_loop)

        async def server():
            server = aiohttp.web.Server(self.handle_message)
            runner = aiohttp.web.ServerRunner(server)
            await runner.setup()
            ctx = None
            if self.ssl is not None:
                ctx = salt.transport.base.ssl_context(self.ssl, server_side=True)
            self.site = aiohttp.web.SockSite(runner, self._socket, ssl_context=ctx)
            log.info("Worker binding to socket %s", self._socket)
            await self.site.start()
            self._started.set()
            # pause here for very long time by serving HTTP requests and
            # waiting for keyboard interruption
            # Wait for shutdown signal instead of polling
            await self._run.wait()
            await self.site.stop()
            self._socket.close()

        io_loop.create_task(server())

    async def handle_message(self, request):
        try:
            cert = request.get_extra_info("peercert")
        except AttributeError:
            pass
        else:
            if cert:
                name = salt.transport.base.common_name(cert)
                log.debug("Request client cert %r", name)
        ws = aiohttp.web.WebSocketResponse()
        await ws.prepare(request)
        async for msg in ws:
            if msg.type == aiohttp.WSMsgType.TEXT:
                if msg.data == "close":
                    await ws.close()
            if msg.type == aiohttp.WSMsgType.BINARY:
                payload = salt.payload.loads(msg.data)
                reply = await self.message_handler(payload)
                await ws.send_bytes(salt.payload.dumps(reply))
            elif msg.type == aiohttp.WSMsgType.ERROR:
                log.error("ws connection closed with exception %s", ws.exception())
        return ws

    def close(self):
        if self._run is not None:
            self._run.set()  # Signal shutdown
        if self._socket is not None:
            self._socket.shutdown(socket.SHUT_RDWR)
            self._socket.close()
            self._socket = None

    async def forward_message(self, payload):
        """
        Forward a message into this transport's worker queue.

        Not implemented for WebSocket transport. Worker pool routing is only
        supported for ZeroMQ transport.
        """
        log.warning(
            "Worker pool message forwarding is not supported for WebSocket transport. "
            "Use ZeroMQ transport for worker pool routing."
        )
        return None


class RequestClient(salt.transport.base.RequestClient):

    ttype = "ws"

    def __init__(self, opts, io_loop):  # pylint: disable=W0231
        self.opts = opts
        self.ws = None
        self.session = None
        self.io_loop = salt.utils.asynchronous.aioloop(io_loop)
        self._closing = False
        self._closed = False
        self.close_task = None
        self._send_task = None
        self._send_lock = asyncio.Lock()
        self._connect_lock = asyncio.Lock()
        self._close_lock = asyncio.Lock()
        self.ssl = self.opts.get("ssl", None)
        self._creator_pid = os.getpid()

    async def connect(self):  # pylint: disable=invalid-overridden-method
        async with self._connect_lock:
            if self._closing:
                raise ClosingError("Request client is closed")
            if self.ws is not None and not self.ws.closed:
                return self.ws
            await self._close_connection()
            ctx = None
            if self.ssl is not None:
                ctx = salt.transport.base.ssl_context(self.ssl, server_side=False)
            master_uri = self.opts.get("master_uri", "")
            if master_uri.startswith("ipc://"):
                connector = aiohttp.UnixConnector(path=master_uri[6:])
                self.session = aiohttp.ClientSession(connector=connector)
                url = "http://localhost/ws"
            else:
                self.session = aiohttp.ClientSession()
                url = self.get_master_uri(self.opts)
            try:
                self.ws = await self.session.ws_connect(
                    url, ssl=ctx if ctx is not None else True
                )
                if self._closing:
                    raise ClosingError("Request client is closed")
                return self.ws
            except BaseException:
                await self._close_connection(abort=True)
                raise

    async def send(self, load, timeout=60):
        try:
            return await asyncio.wait_for(self._send(load), timeout)
        except asyncio.TimeoutError as exc:
            raise SaltReqTimeoutError("WebSocket request timed out") from exc

    async def _send(self, load):
        async with self._send_lock:
            if self._closing:
                raise ClosingError("Request client is closed")
            self._send_task = asyncio.current_task()
            try:
                ws = await self.connect()
                await ws.send_bytes(salt.payload.dumps(load))
                response = await ws.receive()
                if response.type != aiohttp.WSMsgType.BINARY:
                    raise SaltClientError(
                        "WebSocket closed or returned a non-binary reply"
                    )
                return salt.payload.loads(response.data)
            except BaseException:
                # A cancelled or failed exchange cannot leave a late reply for
                # the next caller. Discard the connection before releasing the lock.
                await self._close_connection(abort=True)
                raise
            finally:
                self._send_task = None

    async def _close_connection(self, abort=False):
        ws, session = self.ws, self.session
        self.ws = self.session = None
        try:
            # Failed requests cannot wait for a peer's WebSocket close handshake.
            if abort and session is not None:
                await session.close()
            if ws is not None:
                await ws.close()
        finally:
            if session is not None and not session.closed:
                await session.close()

    async def close_async(self):
        current = asyncio.current_task()
        if self.close_task is not None and self.close_task is not current:
            await asyncio.shield(self.close_task)
            return
        async with self._close_lock:
            if self._closed:
                return
            self._closing = True
            task = self._send_task
            if task is not None and task is not current:
                task.cancel()
                await asyncio.gather(task, return_exceptions=True)
            await self._close_connection()
            self._closed = True

    def close(self):
        """Request shutdown from a synchronous transport callback."""
        if self._closing:
            return
        self._closing = True
        self.close_task = self.io_loop.create_task(self.close_async())

    def get_master_uri(self, opts):
        if "master_uri" in opts:
            if self.opts.get("ssl", None):
                return opts["master_uri"].replace("tcp:", "https:", 1)
            return opts["master_uri"].replace("tcp:", "http:", 1)
        if self.opts.get("ssl", None):
            return f"https://{opts['master_ip']}:{opts['master_port']}/ws"
        return f"http://{opts['master_ip']}:{opts['master_port']}/ws"

    # pylint: disable=W1701
    def __del__(self):
        if getattr(self, "_creator_pid", None) is not None and (
            os.getpid() != self._creator_pid
        ):
            # Forked child: the parent still owns the underlying FDs; do NOT
            # close them here (that would break the parent's transport) and
            # do NOT emit a leak warning (this object is not our responsibility).
            return
        if not getattr(self, "_closing", True):
            salt.utils.resource_warnings.warn_until_close(
                f"unclosed publish client {self!r}", source=self, log=log
            )

    # pylint: enable=W1701
