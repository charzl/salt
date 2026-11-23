"""
Tests for salt._logging.redact and its use by the Salt log handlers.
"""

import datetime
import io
import logging
import re
import sys
import types

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


HEADER_FORMAT = "%(asctime)s,%(msecs)03d [%(name)-14s][%(levelname)-8s] %(message)s"


@pytest.fixture
def header_output():
    """
    A logger whose lines have the time, the logger name and the level in front
    of the message, as the Salt log file does.
    """
    stream = io.StringIO()
    handler = StreamHandler(stream)
    handler.setFormatter(logging.Formatter(HEADER_FORMAT, "%Y-%m-%d %H:%M:%S"))
    logger = logging.getLogger("salt.minion")
    logger.setLevel(logging.DEBUG)
    logger.propagate = False
    logger.addHandler(handler)
    try:
        yield logger, stream
    finally:
        logger.removeHandler(handler)


def test_only_the_message_is_redacted_not_the_header(header_output):
    logger, stream = header_output
    today = datetime.date.today().isoformat()
    # Values that also appear in the time and in the logger name.
    redact.register({"date": today, "pkg": "salt", "pw": "hunter2-secret"})
    logger.info("login with %s as salt", "hunter2-secret")
    line = stream.getvalue().strip()
    header, _, message = line.partition("] ")
    assert line.startswith(today)
    assert "salt.minion" in line
    assert "[INFO" in line
    assert message.endswith("login with ********** as **********")


def test_traceback_is_redacted_and_the_header_is_not(header_output):
    logger, stream = header_output
    redact.register({"pkg": "salt", "pw": "hunter2-secret"})
    try:
        raise RuntimeError("bad hunter2-secret")
    except RuntimeError:
        logger.exception("boom")
    output = stream.getvalue()
    assert "[salt.minion " in output
    assert "RuntimeError: bad **********" in output
    assert "hunter2-secret" not in output


def test_record_is_restored_after_it_was_formatted():
    redact.register(PILLAR)
    handler = StreamHandler(io.StringIO())
    record = logging.LogRecord(
        "x", logging.INFO, __file__, 1, "pw %s", ("hunter2-secret",), None
    )
    handler.format(record)
    assert record.msg == "pw %s"
    assert record.args == ("hunter2-secret",)
    # The next handler starts from the original record and redacts it too.
    other = StreamHandler(io.StringIO())
    other.setFormatter(logging.Formatter("%(message)s"))
    assert other.format(record) == "pw **********"


def test_colormsg_format_is_redacted():
    stream = io.StringIO()
    handler = StreamHandler(stream)
    handler.setFormatter(logging.Formatter("%(colormsg)s"))
    logger = logging.getLogger("salt.tests.redact.color")
    logger.setLevel(logging.DEBUG)
    logger.propagate = False
    logger.addHandler(handler)
    redact.register(PILLAR)
    logger.debug("pw %s", "hunter2-secret")
    assert "hunter2-secret" not in stream.getvalue()
    assert "**********" in stream.getvalue()


class _BrokenPattern:
    def sub(self, *args, **kwargs):
        raise RuntimeError("it failed on hunter2-secret")


def test_failing_redaction_withholds_the_message_but_keeps_the_line(
    header_output, monkeypatch, capsys
):
    logger, stream = header_output
    redact.register(PILLAR)
    monkeypatch.setattr(redact, "_pattern", _BrokenPattern())
    logger.info("login with %s", "hunter2-secret")
    line = stream.getvalue().strip()
    assert "[INFO" in line
    assert redact.WITHHELD in line
    assert "hunter2-secret" not in line
    # Reported once, and without the text of the error.
    err = capsys.readouterr().err
    assert "RuntimeError" in err
    assert "hunter2-secret" not in err
    logger.info("again %s", "hunter2-secret")
    assert capsys.readouterr().err == ""
    assert stream.getvalue().count(redact.WITHHELD) == 2


def test_failing_redaction_withholds_the_traceback(header_output, monkeypatch):
    logger, stream = header_output
    redact.register(PILLAR)
    monkeypatch.setattr(redact, "_pattern", _BrokenPattern())
    try:
        raise RuntimeError("bad hunter2-secret")
    except RuntimeError:
        logger.exception("boom")
    output = stream.getvalue()
    assert redact.WITHHELD in output
    assert "hunter2-secret" not in output


def test_malformed_log_call_is_left_to_the_logging_module():
    redact.register(PILLAR)
    record = logging.LogRecord(
        "x", logging.INFO, __file__, 1, "needs %s and %s", ("one",), None
    )
    assert redact.redact_record(record) is None
    assert record.msg == "needs %s and %s"
    assert record.args == ("one",)


def test_redact_of_text_does_not_raise(monkeypatch):
    redact.register(PILLAR)
    monkeypatch.setattr(redact, "_pattern", _BrokenPattern())
    assert redact.redact("pw hunter2-secret") == redact.WITHHELD


def test_register_does_not_raise_when_the_pattern_cannot_be_built(monkeypatch, caplog):
    redact.register({"a": "first-secret"})

    def broken_compile(*args, **kwargs):
        raise RuntimeError("it failed on second-secret")

    fake_re = types.SimpleNamespace(compile=broken_compile, escape=re.escape)
    monkeypatch.setattr(redact, "re", fake_re)
    with caplog.at_level(logging.WARNING, logger=redact.log.name):
        redact.register({"b": "second-secret"})
    assert "RuntimeError" in caplog.text
    assert "second-secret" not in caplog.text
    # What was registered before still works, and the failed value was not kept.
    assert redact.redact("first-secret second-secret") == "********** second-secret"
    # A later registration works again.
    monkeypatch.undo()
    redact.register({"b": "second-secret"})
    assert redact.redact("first-secret second-secret") == "********** **********"


def test_register_does_not_raise_when_the_pillar_cannot_be_walked(monkeypatch, caplog):
    def broken_walk(*args, **kwargs):
        raise RecursionError("too deep")

    monkeypatch.setattr(redact, "_iter_values", broken_walk)
    with caplog.at_level(logging.WARNING, logger=redact.log.name):
        redact.register({"a": "first-secret"})
    assert "RecursionError" in caplog.text


@pytest.mark.parametrize(
    "value",
    [
        "    ",
        "\n\n\n\n",
        " \t \t ",
        "----",
        "....",
        "====",
        "-=-=",
        "- - - -",
        "////",
        "\\\\\\\\",
        "_____",
    ],
)
def test_indents_and_separators_are_not_registered(value):
    redact.register({"x": value})
    text = f"a{value}b"
    assert redact.redact(text) == text


@pytest.mark.parametrize("value", ["!@#$", "aaaa", "0000", "a-b-c-d"])
def test_other_short_values_are_still_registered(value):
    redact.register({"x": value})
    assert redact.redact(f"x {value} y") == f"x {redact.REDACT_PLACEHOLDER} y"


def test_trailing_newline_of_a_yaml_block_does_not_hide_the_value():
    import salt.utils.yaml

    pillar = salt.utils.yaml.safe_load("password: |\n  hunter2-secret\n")
    assert pillar["password"] == "hunter2-secret\n"
    redact.register(pillar)
    assert redact.redact("pw is hunter2-secret") == "pw is **********"
    # The newline in the text is kept.
    assert redact.redact("pw hunter2-secret\nnext") == "pw **********\nnext"


def test_value_with_only_a_short_part_left_after_stripping_is_not_registered():
    redact.register({"x": "ab\n\n"})
    assert redact.redact("ab\n\n") == "ab\n\n"


class _CountingPattern:
    def __init__(self, real):
        self.real = real
        self.calls = 0

    def sub(self, repl, text):
        self.calls += 1
        return self.real.sub(repl, text)


def _plain_handler():
    handler = StreamHandler(io.StringIO())
    handler.setFormatter(logging.Formatter("%(message)s"))
    return handler


def _record(msg="pw %s", args=("hunter2-secret",), exc_info=None):
    return logging.LogRecord("x", logging.INFO, __file__, 1, msg, args, exc_info)


def test_a_record_is_scanned_once_however_many_handlers_get_it(monkeypatch):
    redact.register(PILLAR)
    counting = _CountingPattern(redact._pattern)
    monkeypatch.setattr(redact, "_pattern", counting)

    handlers = [_plain_handler() for _ in range(3)]
    record = _record()
    assert [h.format(record) for h in handlers] == ["pw **********"] * 3
    calls_for_three_handlers = counting.calls

    counting.calls = 0
    _plain_handler().format(_record())
    assert calls_for_three_handlers == counting.calls


def test_new_registration_makes_the_kept_result_invalid():
    redact.register({"a": "first-secret"})
    first, second = _plain_handler(), _plain_handler()
    record = _record("x %s %s", ("first-secret", "second-secret"))
    assert first.format(record) == "x ********** second-secret"
    redact.register({"b": "second-secret"})
    assert second.format(record) == "x ********** **********"


def test_traceback_that_was_formatted_earlier_is_redacted_too():
    redact.register(PILLAR)
    try:
        raise RuntimeError("bad hunter2-secret")
    except RuntimeError:
        exc_info = sys.exc_info()
    record = _record("boom", (), exc_info)
    # As if a handler that does not redact had formatted the traceback first.
    record.exc_text = (
        "Traceback (most recent call last):\nRuntimeError: bad hunter2-secret"
    )
    output = _plain_handler().format(record)
    assert "RuntimeError: bad **********" in output
    assert "hunter2-secret" not in output


def test_what_is_kept_on_the_record_is_plain_data():
    redact.register(PILLAR)
    record = _record()
    _plain_handler().format(record)
    kept = getattr(record, "_pillar_redaction")
    assert all(isinstance(item, (int, str, type(None))) for item in kept)


def test_colormsg_is_redacted_without_scanning_it_again(monkeypatch):
    redact.register(PILLAR)
    counting = _CountingPattern(redact._pattern)
    monkeypatch.setattr(redact, "_pattern", counting)
    stream = io.StringIO()
    handler = StreamHandler(stream)
    handler.setFormatter(logging.Formatter("%(colormsg)s"))
    logger = logging.getLogger("salt.tests.redact.color.once")
    logger.setLevel(logging.DEBUG)
    logger.propagate = False
    logger.addHandler(handler)
    logger.debug("pw %s", "hunter2-secret")
    assert "hunter2-secret" not in stream.getvalue()
    assert "**********" in stream.getvalue()
    # Only the message was scanned.
    assert counting.calls == 1


def test_colormsg_that_does_not_contain_the_message_is_scanned_itself():
    redact.register(PILLAR)
    record = _record()
    record.colormsg = "other text with hunter2-secret"
    handler = StreamHandler(io.StringIO())
    handler.setFormatter(logging.Formatter("%(colormsg)s"))
    assert handler.format(record) == "other text with **********"
