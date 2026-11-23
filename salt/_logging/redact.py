"""
Redact known pillar values from log output.

Pillar functions return real values and the data is never wrapped. When
``pillar_mask_output`` is enabled, the pillar a process receives is registered
here, and the message and the traceback of every record a Salt log handler
writes are checked against those values before they are emitted. The time, the
logger name and the level are left alone.

The check is made on the formatted message, so it does not matter how a value
got into it: nested data, a command line, a diff or a traceback are all handled
the same way.

Redaction must never take a log line away, and registering must never break
the code that compiles the pillar. If either fails, the failure is reported once
and the work goes on.

This module only uses the standard library, so the logging code can import it
without a cycle.
"""

import logging
import re
import sys
import threading

log = logging.getLogger(__name__)

REDACT_PLACEHOLDER = "**********"

# Written in place of a message that could not be checked, so that a value is
# never written because the check failed.
WITHHELD = "[log message withheld: pillar redaction failed]"

# Shorter values (``1``, ``yes``, ...) would redact ordinary text.
MIN_VALUE_LENGTH = 4

# A value made only of these characters is an indent or a separator, not a
# secret, and redacting it would hit every line that has one.
SEPARATOR_CHARS = frozenset(" \t\r\n\f\v-_=.*#~+|/\\")

_MISSING = object()

_lock = threading.Lock()
_values = set()
_pattern = None
_redact_failure_reported = False


def _report_redact_failure(exc):
    """
    Say once, on stderr, that a record could not be redacted. This must not use
    logging: it runs inside a log handler.
    """
    global _redact_failure_reported  # pylint: disable=global-statement
    if _redact_failure_reported:
        return
    _redact_failure_reported = True
    try:
        # Only the type of the error: its text could contain a value.
        sys.stderr.write(
            f"salt: pillar redaction of a log record failed ({type(exc).__name__}); "
            "such messages are withheld\n"
        )
    except Exception:  # pylint: disable=broad-except
        pass


def _iter_values(data, _seen=None):
    """
    Yield the string and bytes leaves of nested pillar data.
    """
    if isinstance(data, bytes):
        data = data.decode("utf-8", "ignore")
    if isinstance(data, str):
        yield data
        return
    if not isinstance(data, (dict, list, tuple, set, frozenset)):
        return
    if _seen is None:
        _seen = set()
    if id(data) in _seen:
        return
    _seen.add(id(data))
    try:
        items = data.values() if isinstance(data, dict) else data
        for item in items:
            yield from _iter_values(item, _seen)
    finally:
        _seen.discard(id(data))


def _registrable(value):
    """
    Return the part of ``value`` that is registered, or ``None`` if the value
    is not worth redacting.

    Leading and trailing whitespace is dropped: a YAML ``|`` block ends with a
    newline that the log text does not have, and leaving it in would keep the
    value from matching.
    """
    value = value.strip()
    if len(value) < MIN_VALUE_LENGTH or set(value) <= SEPARATOR_CHARS:
        return None
    return value


def register(pillar):
    """
    Add the string values found in ``pillar`` to the values that are redacted.

    Values are only added, never dropped, so a value that was removed by a
    pillar refresh stays redacted for the life of the process.

    This does not raise. If the values cannot be registered, a warning is
    logged and the values registered so far stay in place.
    """
    global _pattern  # pylint: disable=global-statement
    try:
        found = {
            value
            for value in map(_registrable, _iter_values(pillar))
            if value is not None
        }
        with _lock:
            new = found - _values
            if not new:
                return
            # Longest first, so a value that contains another one is redacted
            # whole. The set is only updated once the pattern has been built.
            pattern = re.compile(
                "|".join(
                    re.escape(v) for v in sorted(_values | new, key=len, reverse=True)
                )
            )
            _values.update(new)
            _pattern = pattern
    except Exception as exc:  # pylint: disable=broad-except
        # Only the type of the error: its text could contain a value.
        log.warning(
            "Could not register the pillar values for log redaction (%s). "
            "Log output may contain them.",
            type(exc).__name__,
        )


def clear():
    """
    Forget all registered values.
    """
    global _pattern, _redact_failure_reported  # pylint: disable=global-statement
    with _lock:
        _values.clear()
        _pattern = None
        _redact_failure_reported = False


def redact(text):
    """
    Return ``text`` with every registered value replaced by the placeholder.

    This does not raise. If the text cannot be checked, the fixed ``WITHHELD``
    message is returned instead.
    """
    pattern = _pattern
    if pattern is None or not text:
        return text
    try:
        return pattern.sub(REDACT_PLACEHOLDER, text)
    except Exception as exc:  # pylint: disable=broad-except
        _report_redact_failure(exc)
        return WITHHELD


def redact_record(record):
    """
    Redact the message and the traceback of a log record, in place.

    The time, the logger name and the level are not touched, because they are
    added by the formatter from other attributes of the record.

    Returns what ``restore_record`` needs, or ``None`` when the record was left
    as it was. The record is meant to be restored after it has been formatted,
    so the next handler starts from the original.
    """
    pattern = _pattern
    if pattern is None:
        return None
    try:
        message = record.getMessage()
    except Exception:  # pylint: disable=broad-except
        # A malformed log call: leave it to the logging module to report it.
        return None
    saved = (
        record.msg,
        record.args,
        getattr(record, "colormsg", _MISSING),
        record.stack_info,
    )
    try:
        record.msg = pattern.sub(REDACT_PLACEHOLDER, message)
        record.args = ()
        if saved[2] is not _MISSING:
            record.colormsg = pattern.sub(REDACT_PLACEHOLDER, saved[2])
        if record.stack_info:
            record.stack_info = pattern.sub(REDACT_PLACEHOLDER, record.stack_info)
        if record.exc_info and not record.exc_text:
            # Formatting the traceback here makes the formatter reuse it.
            record.exc_text = pattern.sub(
                REDACT_PLACEHOLDER, logging.Formatter().formatException(record.exc_info)
            )
    except Exception as exc:  # pylint: disable=broad-except
        _report_redact_failure(exc)
        # Keep the line, but do not write anything that was not checked.
        record.msg, record.args = WITHHELD, ()
        if saved[2] is not _MISSING:
            record.colormsg = WITHHELD
        if record.stack_info:
            record.stack_info = WITHHELD
        if record.exc_info:
            record.exc_text = WITHHELD
    return saved


def restore_record(record, saved):
    """
    Put back what ``redact_record`` replaced. A traceback that was formatted
    stays on the record, already redacted.
    """
    if saved is None:
        return
    record.msg, record.args, colormsg, record.stack_info = saved
    if colormsg is not _MISSING:
        record.colormsg = colormsg
