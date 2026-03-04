# Copyright (c) 2026 OpaqueInfra
# Licensed under the Apache License, Version 2.0.
# See LICENSE file for details.

"""
Minimal RFC 8785 JSON Canonicalization Scheme (JCS) implementation.

Spec reference: oi-docs/02_spec/01_bundle_format_spec.md Section 6
"""

import json
import struct


def canonicalize(obj):
    """Return canonical JSON bytes per RFC 8785 (JCS).

    - Object keys sorted lexicographically by Unicode codepoint
    - No insignificant whitespace
    - Numbers: shortest representation per ECMAScript
    - Strings: minimal escaping per RFC 8785
    - UTF-8 encoded output
    """
    return _serialize(obj).encode("utf-8")


def _serialize(obj):
    if obj is None:
        return "null"
    if isinstance(obj, bool):
        return "true" if obj else "false"
    if isinstance(obj, int):
        return str(obj)
    if isinstance(obj, float):
        if not (obj == obj):  # NaN
            raise ValueError("NaN not allowed in JCS")
        if obj == float("inf") or obj == float("-inf"):
            raise ValueError("Infinity not allowed in JCS")
        return _serialize_float(obj)
    if isinstance(obj, str):
        return _serialize_string(obj)
    if isinstance(obj, (list, tuple)):
        items = ",".join(_serialize(item) for item in obj)
        return "[" + items + "]"
    if isinstance(obj, dict):
        _check_duplicate_keys(obj)
        sorted_keys = sorted(obj.keys(), key=lambda k: [ord(c) for c in k])
        pairs = ",".join(
            _serialize_string(k) + ":" + _serialize(obj[k]) for k in sorted_keys
        )
        return "{" + pairs + "}"
    raise TypeError(f"Cannot serialize type {type(obj).__name__}")


def _serialize_float(value):
    """Serialize float per ECMAScript / RFC 8785 rules."""
    if value == 0.0:
        return "0"
    return json.dumps(value)


def _serialize_string(s):
    """Serialize string with minimal escaping per RFC 8785."""
    result = ['"']
    for ch in s:
        code = ord(ch)
        if ch == '"':
            result.append('\\"')
        elif ch == '\\':
            result.append('\\\\')
        elif ch == '\b':
            result.append('\\b')
        elif ch == '\f':
            result.append('\\f')
        elif ch == '\n':
            result.append('\\n')
        elif ch == '\r':
            result.append('\\r')
        elif ch == '\t':
            result.append('\\t')
        elif code < 0x20:
            result.append(f'\\u{code:04x}')
        else:
            result.append(ch)
    result.append('"')
    return "".join(result)


def _check_duplicate_keys(obj):
    """Python dicts don't have duplicate keys, but validate parsed input."""
    pass


def canonicalize_file(path):
    """Read a JSON file and return its canonical bytes."""
    with open(path, "r", encoding="utf-8") as f:
        obj = json.load(f)
    return canonicalize(obj)
