"""
The filter redacts the message after it has been formatted, so a value is found
whatever way it got into the text: as an argument that is an object, in the
traceback of an exception, or in the ``colormsg`` of a Salt record.
"""

import collections
import io
import logging
import sys

import pytest

import salt._logging.filters.pillar as pillar_filter
import salt.utils.immutabletypes
from salt._logging.filters.pillar import install_on_handler
from salt._logging.handlers import StreamHandler

SECRET = "hunter2-secret"
MASKED = pillar_filter.REDACT_PLACEHOLDER


@pytest.fixture(autouse=True)
def registered_secret():
    pillar_filter.clear()
    pillar_filter.register({"password": SECRET})
    try:
        yield
    finally:
        pillar_filter.clear()


def _logger(name, fmt="%(message)s", handler_count=1):
    opts = salt.utils.immutabletypes.freeze({"pillar_mask_output": True, "pillar": {}})
    logger = logging.getLogger(name)
    logger.setLevel(logging.DEBUG)
    logger.propagate = False
    logger.handlers = []
    streams = []
    for _ in range(handler_count):
        stream = io.StringIO()
        handler = StreamHandler(stream)
        handler.setFormatter(logging.Formatter(fmt))
        install_on_handler(handler, opts)
        logger.addHandler(handler)
        streams.append(stream)
    return logger, streams


class _Custom:
    def __str__(self):
        return f"Custom(password={SECRET})"


def test_object_argument():
    logger, (stream,) = _logger("salt.tests.formatted.object")
    logger.error("connect failed: %s", _Custom())
    assert stream.getvalue().strip() == f"connect failed: Custom(password={MASKED})"


def test_exception_argument():
    logger, (stream,) = _logger("salt.tests.formatted.exception")
    logger.error("failed: %s", RuntimeError(f"bad {SECRET}"))
    assert stream.getvalue().strip() == f"failed: bad {MASKED}"


def test_values_inside_a_set_and_an_ordered_dict():
    logger, (stream,) = _logger("salt.tests.formatted.containers")
    logger.debug("%s %s", {SECRET}, collections.OrderedDict(a=SECRET))
    output = stream.getvalue()
    assert SECRET not in output
    assert MASKED in output


def test_traceback_of_log_exception():
    logger, (stream,) = _logger("salt.tests.formatted.traceback")
    try:
        raise RuntimeError(f"login failed with {SECRET}")
    except RuntimeError:
        logger.exception("boom")
    output = stream.getvalue()
    assert f"RuntimeError: login failed with {MASKED}" in output
    assert SECRET not in output


def test_traceback_that_a_handler_formatted_earlier():
    logger, (stream,) = _logger("salt.tests.formatted.earlier")
    try:
        raise RuntimeError(f"bad {SECRET}")
    except RuntimeError:
        record = logging.LogRecord(
            logger.name, logging.ERROR, __file__, 1, "boom", (), sys.exc_info()
        )
    # As if a handler that does not redact had formatted the traceback first.
    record.exc_text = f"Traceback (most recent call last):\nRuntimeError: bad {SECRET}"
    logger.handle(record)
    assert SECRET not in stream.getvalue()


def test_colormsg_format():
    logger, (stream,) = _logger("salt.tests.formatted.color", fmt="%(colormsg)s")
    logger.debug("pw %s", SECRET)
    assert SECRET not in stream.getvalue()
    assert MASKED in stream.getvalue()


def test_traceback_added_for_exc_info_on_loglevel():
    """Salt adds a traceback for the handlers that are enabled for its level."""
    logger, (stream,) = _logger("salt.tests.formatted.onloglevel")
    try:
        raise RuntimeError(f"bad {SECRET}")
    except RuntimeError:
        logger.error("failed", exc_info_on_loglevel=logging.DEBUG)
    output = stream.getvalue()
    assert "Traceback" in output
    assert f"RuntimeError: bad {MASKED}" in output
    assert SECRET not in output


def test_stack_info():
    logger, (stream,) = _logger("salt.tests.formatted.stack")

    def leaky():
        local = SECRET  # noqa: F841
        logger.debug("here %s", SECRET, stack_info=True)

    leaky()
    assert SECRET not in stream.getvalue()


def test_every_handler_gets_the_redacted_message():
    logger, streams = _logger("salt.tests.formatted.handlers", handler_count=3)
    logger.error("failed: %s", _Custom())
    assert [s.getvalue().strip() for s in streams] == [
        f"failed: Custom(password={MASKED})"
    ] * 3


def test_a_malformed_log_call_is_left_alone():
    """``getMessage()`` fails, which the logging module reports as usual."""
    flt = pillar_filter.PillarRedactingFilter({"pillar_mask_output": True})
    record = logging.LogRecord(
        "x", logging.INFO, __file__, 1, "needs %s and %s", ("one",), None
    )
    assert flt.filter(record) is True
    assert record.msg == "needs %s and %s"
    assert record.args == ("one",)


def test_message_that_is_not_a_string():
    logger, (stream,) = _logger("salt.tests.formatted.notstr")
    logger.error(RuntimeError(f"bad {SECRET}"))
    assert stream.getvalue().strip() == f"bad {MASKED}"
