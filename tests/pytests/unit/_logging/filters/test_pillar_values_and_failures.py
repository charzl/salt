"""
What the filter registers, and what it does when it fails.
"""

import logging

import pytest

import salt._logging.filters.pillar as pillar_filter
import salt.utils.yaml
from salt._logging.filters.pillar import (
    REDACT_PLACEHOLDER,
    WITHHELD,
    PillarRedactingFilter,
)

SECRET = "hunter2-secret"


@pytest.fixture(autouse=True)
def clean_registry():
    pillar_filter.clear()
    try:
        yield
    finally:
        pillar_filter.clear()


def _filter(pillar):
    return PillarRedactingFilter({"pillar_mask_output": True, "pillar": pillar})


def _record(msg, args=()):
    return logging.LogRecord("x", logging.INFO, __file__, 1, msg, args, None)


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
    record = _record(f"a{value}b")
    _filter({"x": value}).filter(record)
    assert record.msg == f"a{value}b"


@pytest.mark.parametrize("value", ["!@#$", "aaaa", "0000", "a-b-c-d"])
def test_other_short_values_are_still_registered(value):
    record = _record(f"x {value} y")
    _filter({"x": value}).filter(record)
    assert record.msg == f"x {REDACT_PLACEHOLDER} y"


def test_trailing_newline_of_a_yaml_block_does_not_hide_the_value():
    pillar = salt.utils.yaml.safe_load(f"password: |\n  {SECRET}\n")
    assert pillar["password"] == f"{SECRET}\n"
    flt = _filter(pillar)
    record = _record(f"pw is {SECRET}")
    flt.filter(record)
    assert record.msg == f"pw is {REDACT_PLACEHOLDER}"
    # The newline in the text is kept.
    record = _record(f"pw {SECRET}\nnext")
    flt.filter(record)
    assert record.msg == f"pw {REDACT_PLACEHOLDER}\nnext"


def test_value_with_only_a_short_part_left_after_stripping_is_not_registered():
    record = _record("ab\n\n")
    _filter({"x": "ab\n\n"}).filter(record)
    assert record.msg == "ab\n\n"


def test_registered_values_get_the_same_treatment():
    pillar_filter.register({"a": "    ", "b": f"{SECRET}\n"})
    flt = PillarRedactingFilter({"pillar_mask_output": True})
    record = _record(f"    {SECRET}")
    flt.filter(record)
    assert record.msg == f"    {REDACT_PLACEHOLDER}"


def test_a_failure_in_the_filter_withholds_the_message(monkeypatch, capsys):
    flt = _filter({"k": SECRET})

    def boom(*args, **kwargs):
        raise RuntimeError(f"synthetic failure on {SECRET}")

    monkeypatch.setattr(flt, "_scrub", boom)
    record = _record("password is %s", (SECRET,))
    assert flt.filter(record) is True
    assert record.msg == WITHHELD
    assert record.args == ()
    assert SECRET not in record.getMessage()
    # Reported once, and without the text of the error.
    err = capsys.readouterr().err
    assert "RuntimeError" in err
    assert SECRET not in err
    flt.filter(_record("password is %s", (SECRET,)))
    assert capsys.readouterr().err == ""


def test_a_failure_while_building_the_regex_withholds_the_message(monkeypatch):
    flt = _filter({"k": SECRET})
    monkeypatch.setattr(flt, "_compile", lambda: 1 / 0)
    flt._snapshot_id = None  # make the filter rebuild
    record = _record(f"password is {SECRET}")
    assert flt.filter(record) is True
    assert record.msg == WITHHELD


def _salt_record(msg="pw %s", args=(SECRET,)):
    from salt._logging.impl import SaltColorLogRecord

    return SaltColorLogRecord("x", logging.INFO, __file__, 1, msg, args, None)


def test_colormsg_of_a_salt_record_is_redacted():
    record = _salt_record()
    assert SECRET in record.colormsg
    _filter({"k": SECRET}).filter(record)
    assert SECRET not in record.colormsg
    assert REDACT_PLACEHOLDER in record.colormsg
    # The color codes around the message are kept.
    assert record.colormsg.startswith("\x1b[")


def test_a_console_format_with_colormsg_is_redacted():
    import io

    from salt._logging.handlers import StreamHandler

    stream = io.StringIO()
    handler = StreamHandler(stream)
    handler.setFormatter(logging.Formatter("%(colorlevel)s %(colormsg)s"))
    handler.addFilter(_filter({"k": SECRET}))
    handler.handle(_salt_record())
    assert SECRET not in stream.getvalue()
    assert REDACT_PLACEHOLDER in stream.getvalue()


def test_a_record_without_colormsg_is_fine():
    record = _record("pw %s", (SECRET,))
    assert not hasattr(record, "colormsg")
    _filter({"k": SECRET}).filter(record)
    assert record.getMessage() == f"pw {REDACT_PLACEHOLDER}"


def test_a_failure_withholds_the_colormsg_too(monkeypatch):
    flt = _filter({"k": SECRET})
    record = _salt_record()

    calls = []
    original = flt._scrub

    def fail_on_colormsg(obj):
        calls.append(obj)
        if isinstance(obj, str) and "\x1b[" in obj:
            raise RuntimeError("synthetic failure")
        return original(obj)

    monkeypatch.setattr(flt, "_scrub", fail_on_colormsg)
    assert flt.filter(record) is True
    assert record.msg == WITHHELD
    assert record.colormsg == WITHHELD
