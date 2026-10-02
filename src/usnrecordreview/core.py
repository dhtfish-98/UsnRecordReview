import argparse
import hashlib
import json
import os
import stat
import struct

MAX_BYTES = 16 * 1024 * 1024
MAX_RECORDS = 100000


class Invalid(ValueError):
    pass


class Unsupported(ValueError):
    pass


def require(ok, code):
    if not ok:
        raise Invalid(code)


def unpack(fmt, data, offset=0):
    require(
        offset >= 0 and offset + struct.calcsize(fmt) <= len(data), "truncated_field"
    )
    return struct.unpack_from(fmt, data, offset)


def text(data, encoding="utf-8"):
    try:
        return data.decode(encoding)
    except UnicodeError:
        raise Invalid("invalid_text_encoding") from None


def inspect(data):
    if not isinstance(data, bytes):
        raise TypeError("input must be bytes")
    digest = hashlib.sha256(data).hexdigest()
    try:
        require(len(data) <= MAX_BYTES, "input_limit")
        result = analyze(data)
        result.setdefault("status", "PASS")
        result.setdefault("complete", result["status"] == "PASS")
        result.setdefault("findings", [])
    except Unsupported as exc:
        result = {"status": "OPEN", "complete": False, "findings": [str(exc)]}
    except Invalid as exc:
        result = {"status": "FAIL", "complete": False, "findings": [str(exc)]}
    result.update(
        {
            "input_sha256": digest,
            "input_bytes": len(data),
            "claim": "Recorded format checks only; no authenticity, runtime or CVP approval conclusion.",
        }
    )
    return result


def read_local(path):
    nofollow = getattr(os, "O_NOFOLLOW", None)
    nonblock = getattr(os, "O_NONBLOCK", None)
    if not isinstance(nofollow, int) or not nofollow or not isinstance(nonblock, int) or not nonblock:
        raise Unsupported("safe_local_read_flags_unavailable")
    fd = os.open(path, os.O_RDONLY | nofollow | nonblock)
    try:
        info = os.fstat(fd)
        require(stat.S_ISREG(info.st_mode), "regular_file_required")
        require(info.st_size <= MAX_BYTES, "input_limit")
        with os.fdopen(fd, "rb", closefd=False) as stream:
            data = stream.read(MAX_BYTES + 1)
        require(len(data) <= MAX_BYTES, "input_limit")
        after = os.fstat(fd)
        require(
            (info.st_size, info.st_mtime_ns, info.st_ino)
            == (after.st_size, after.st_mtime_ns, after.st_ino),
            "input_changed_during_read",
        )
        return data
    finally:
        os.close(fd)


def main():
    parser = argparse.ArgumentParser(
        description="Read an explicitly supplied local evidence file and print a private-safe JSON report."
    )
    parser.add_argument("input")
    args = parser.parse_args()
    try:
        report = inspect(read_local(args.input))
    except Unsupported as exc:
        report = {"status": "OPEN", "complete": False, "findings": [str(exc)]}
    except (OSError, Invalid):
        report = {
            "status": "FAIL",
            "complete": False,
            "findings": ["input_read_failed"],
        }
    print(json.dumps(report, sort_keys=True, ensure_ascii=True))
    return {"PASS": 0, "FAIL": 1, "OPEN": 2}[report["status"]]


def analyze(data):
    require(len(data) > 0, "empty_journal")
    records, offset, last_usn = [], 0, None
    extent_entries = 0
    while offset < len(data):
        require(len(records) < MAX_RECORDS, "record_limit")
        if data[offset : offset + 4] == b"\0" * 4:
            end = min(len(data), (offset // 4096 + 1) * 4096)
            require(not any(data[offset:end]), "nonzero_journal_padding")
            offset = end
            continue
        length, major, minor = unpack("<IHH", data, offset)
        require(
            length >= 8 and length % 8 == 0 and offset + length <= len(data),
            "record_length",
        )
        if major not in (2, 3, 4) or minor != 0:
            raise Unsupported("unsupported_usn_record_version")
        raw = data[offset : offset + length]
        if major in (2, 3):
            fixed = 60 if major == 2 else 76
            require(length >= fixed, "record_header_length")
            usn_offset = 24 if major == 2 else 40
            usn, timestamp, reason, source = unpack("<qQII", raw, usn_offset)
            name_len, name_offset = unpack("<HH", raw, fixed - 4)
            require(
                name_len % 2 == 0
                and name_offset >= fixed
                and name_offset % 2 == 0
                and name_offset + name_len <= length,
                "filename_bounds",
            )
            name = text(raw[name_offset : name_offset + name_len], "utf-16-le")
            require(
                "\0" not in name and not any(ord(c) < 32 for c in name),
                "invalid_filename",
            )
            require(not any(raw[name_offset + name_len :]), "nonzero_record_padding")
            record = {
                "offset": offset,
                "version": major,
                "usn": usn,
                "timestamp_filetime": timestamp,
                "reason_mask": reason,
                "source_mask": source,
                "filename_characters": len(name),
            }
        else:
            require(length >= 64, "v4_header_length")
            usn, reason, source, remaining, count, extent_size = unpack(
                "<qIIIHH", raw, 40
            )
            require(
                count > 0 and extent_size >= 16 and 64 + count * extent_size <= length,
                "extent_bounds",
            )
            if extent_size != 16:
                raise Unsupported("unsupported_extent_size")
            extent_entries += count
            require(extent_entries <= MAX_RECORDS, "aggregate_extent_limit")
            extents = []
            for i in range(count):
                pos, size = unpack("<qq", raw, 64 + i * extent_size)
                require(pos >= 0 and size > 0 and pos + size < 2**63, "invalid_extent")
                extents.append({"offset": pos, "length": size})
            require(not any(raw[64 + count * extent_size :]), "nonzero_record_padding")
            record = {
                "offset": offset,
                "version": 4,
                "usn": usn,
                "reason_mask": reason,
                "source_mask": source,
                "remaining_extents": remaining,
                "extents": extents,
            }
        require(usn >= 0, "negative_usn")
        require(last_usn is None or usn >= last_usn, "decreasing_usn_sequence")
        last_usn = usn
        records.append(record)
        offset += length
    require(records, "journal_contains_no_records")
    partial = any(r.get("remaining_extents", 0) for r in records)
    return {
        "records": records,
        "record_count": len(records),
        "status": "OPEN" if partial else "PASS",
        "complete": not partial,
        "findings": ["v4_continuation_not_present"] if partial else [],
        "scope": "Extracted USN record stream; no MFT path reconstruction or event attribution.",
    }
