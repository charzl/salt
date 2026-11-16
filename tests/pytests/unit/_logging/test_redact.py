"""
Tests for salt._logging.redact and its use by the Salt log handlers.
"""

import io
import logging

import pytest

import salt._logging.redact as redact
from salt._logging.handlers import StreamHandler

PILLAR = {
    "db": {"user": "admin", "password": "hunter2-secret"},
    "keys": ["first-secret-key", {"nested": "second-secret-key"}],
    "token": b"bytes-secret-token",
    "pin": 1234,
    "flag": True,
    "short": "yes",
    "empty": "",
    "none": None,
}


@pytest.fixture(autouse=True)
def clean_registry():
    redact.clear()
    try:
        yield
    finally:
        redact.clear()


@pytest.fixture
def log_output():
    stream = io.StringIO()
    handler = StreamHandler(stream)
    handler.setFormatter(logging.Formatter("%(levelname)s %(message)s"))
    logger = logging.getLogger("salt.tests.redact")
    logger.setLevel(logging.DEBUG)
    logger.propagate = False
    logger.addHandler(handler)
    try:
        yield logger, stream
    finally:
        logger.removeHandler(handler)


def test_nothing_is_redacted_before_a_pillar_is_registered():
    assert redact.redact("password hunter2-secret") == "password hunter2-secret"


def test_registered_values_are_redacted_at_any_depth():
    redact.register(PILLAR)
    for value in (
        "hunter2-secret",
        "first-secret-key",
        "second-secret-key",
        "bytes-secret-token",
    ):
        assert redact.redact(f"x {value} y") == f"x {redact.REDACT_PLACEHOLDER} y"


@pytest.mark.parametrize("text", ["yes", "1234", "True", "None", "admin_user"])
def test_short_and_non_string_values_are_not_redacted(text):
    redact.register({"short": "yes", "pin": 1234, "flag": True, "none": None})
    assert redact.redact(text) == text


def test_longer_value_is_redacted_whole_when_it_contains_another():
    redact.register({"a": "secret", "b": "secret-and-more"})
    assert redact.redact("secret-and-more") == redact.REDACT_PLACEHOLDER


def test_values_are_kept_after_a_later_registration():
    redact.register({"a": "first-secret"})
    redact.register({"b": "second-secret"})
    assert redact.redact("first-secret second-secret") == "********** **********"


def test_registering_a_cyclic_pillar_does_not_recurse_forever():
    pillar = {"password": "hunter2-secret"}
    pillar["self"] = pillar
    redact.register(pillar)
    assert redact.redact("hunter2-secret") == redact.REDACT_PLACEHOLDER


def test_log_message_args_are_redacted(log_output):
    logger, stream = log_output
    redact.register(PILLAR)
    logger.debug("pillar: %s", PILLAR)
    logger.debug("running mysql -p%s", "hunter2-secret")
    output = stream.getvalue()
    assert "hunter2-secret" not in output
    assert "second-secret-key" not in output
    assert "bytes-secret-token" not in output
    assert "mysql -p**********" in output
    # Values that are not registered stay readable.
    assert "1234" in output


def test_exception_traceback_is_redacted(log_output):
    logger, stream = log_output
    redact.register(PILLAR)
    try:
        raise RuntimeError("login failed with hunter2-secret")
    except RuntimeError:
        logger.exception("boom")
    output = stream.getvalue()
    assert "boom" in output
    assert "RuntimeError: login failed with **********" in output
    assert "hunter2-secret" not in output


def test_log_output_is_untouched_when_nothing_is_registered(log_output):
    logger, stream = log_output
    logger.debug("password %s", "hunter2-secret")
    assert "hunter2-secret" in stream.getvalue()
