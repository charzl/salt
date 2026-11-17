"""
A ``RequestClient`` whose ``close_async()`` never finishes must not freeze the
process when it is garbage collected.

``close_async()`` detaches the REQ socket from the client and only closes it
after an ``await``.  If the loop is closed while the coroutine is suspended
(for example the private loop of a ``SyncWrapper``), the socket is reachable
only from that coroutine's locals.  pyzmq no longer tracks it by then, so the
``weakref.finalize`` callback had nothing to close and ``zmq_ctx_term()``
blocked forever on the open socket.
"""

import os
import subprocess
import sys
import textwrap

import pytest

import salt

pytestmark = [
    pytest.mark.skip_on_windows(reason="Uses faulthandler exit in a subprocess"),
]

SCRIPT = textwrap.dedent(
    """
    import asyncio
    import faulthandler
    import gc

    import salt.transport.zeromq as z

    # An unroutable address: the connect never completes.
    opts = {"master_uri": "tcp://192.0.2.1:4506", "master_ip": "192.0.2.1"}

    loop = asyncio.new_event_loop()


    async def main():
        client = z.RequestClient(opts, io_loop=loop)
        await client.connect()
        task = loop.create_task(client.close_async())
        await asyncio.sleep(0)
        return task


    task = loop.run_until_complete(main())
    # Stop with close_async() still suspended in its drain.
    loop.close()
    del task

    faulthandler.dump_traceback_later(20, exit=True)
    gc.collect()
    faulthandler.cancel_dump_traceback_later()
    print("gc.collect() returned")
    """
)


def test_gc_of_request_client_with_suspended_close_async_does_not_wedge():
    env = os.environ.copy()
    salt_root = os.path.dirname(os.path.dirname(os.path.abspath(salt.__file__)))
    env["PYTHONPATH"] = os.pathsep.join(
        [salt_root] + ([env["PYTHONPATH"]] if env.get("PYTHONPATH") else [])
    )
    proc = subprocess.run(
        [sys.executable, "-c", SCRIPT],
        env=env,
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    assert "gc.collect() returned" in proc.stdout, (
        "gc.collect() wedged in zmq_ctx_term()\n"
        f"returncode={proc.returncode}\nstderr:\n{proc.stderr}"
    )
