"""
Redact known pillar values from log output.

Pillar functions return real values and the data is never wrapped. When
``pillar_mask_output`` is enabled, the pillar a process receives is registered
here, and every string a Salt log handler writes is checked against those
values before it is emitted.

Only the formatted text is touched, so it does not matter how a value got into
the message: nested data, a command line, a diff or a traceback are all handled
the same way.

This module only uses the standard library, so the logging code can import it
without a cycle.
"""

import re
import threading

REDACT_PLACEHOLDER = "**********"

# Shorter values (``1``, ``yes``, ...) would redact ordinary text.
MIN_VALUE_LENGTH = 4

_lock = threading.Lock()
_values = set()
_pattern = None


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


def register(pillar):
    """
    Add the string values found in ``pillar`` to the values that are redacted.

    Values are only added, never dropped, so a value that was removed by a
    pillar refresh stays redacted for the life of the process.
    """
    global _pattern  # pylint: disable=global-statement
    found = {v for v in _iter_values(pillar) if len(v) >= MIN_VALUE_LENGTH}
    with _lock:
        new = found - _values
        if not new:
            return
        _values.update(new)
        # Longest first, so a value that contains another one is redacted whole.
        _pattern = re.compile(
            "|".join(re.escape(v) for v in sorted(_values, key=len, reverse=True))
        )


def clear():
    """
    Forget all registered values.
    """
    global _pattern  # pylint: disable=global-statement
    with _lock:
        _values.clear()
        _pattern = None


def redact(text):
    """
    Return ``text`` with every registered value replaced by the placeholder.
    """
    pattern = _pattern
    if pattern is None or not text:
        return text
    return pattern.sub(REDACT_PLACEHOLDER, text)
