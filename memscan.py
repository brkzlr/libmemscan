# ctypes wrapper for libmemscan that exports `lm_*` C ABI functions.

# Copyright (C) 2026 brkzlr <brksys@icloud.com>
#
# This file is part of Libmemscan.
#
# Libmemscan is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

import ctypes
import math
import os
from dataclasses import dataclass
from enum import IntEnum
from typing import Generator, Optional

def decode(raw_bytes: bytes, errors: str = "strict") -> str:
    return raw_bytes.decode(errors=errors)


def encode(unicode_string: str, errors: str = "strict") -> bytes:
    return unicode_string.encode(errors=errors)


class LibmemscanError(RuntimeError):
    def __init__(self, status: int, name: str, operation: str):
        self.status = Status(status)
        self.operation = operation
        super().__init__(f"{operation} failed with {name} ({status})")


class Status(IntEnum):
    OK = 0
    INVALID_ARGUMENT = 1
    OUT_OF_MEMORY = 2
    ALREADY_ATTACHED = 3
    NOT_ATTACHED = 4
    NO_REGIONS = 5
    NO_MATCHES = 6
    NO_UNDO = 7
    UNDO_IO_FAILED = 8
    UNDO_CORRUPT = 9
    SNAPSHOT_REQUIRES_RESET = 10
    MATCH_INDEX_OUT_OF_RANGE = 11
    BUFFER_TOO_SMALL = 12
    INVALID_USER_VALUE_COUNT = 13
    INVALID_ALIGNMENT = 14
    INVALID_WRITE_VALUE = 15
    INVALID_WRITE_LENGTH = 16
    UNSUPPORTED_SCAN_COMBINATION = 17
    UNSUPPORTED_READ_DATA_TYPE = 18
    UNSUPPORTED_WRITE_DATA_TYPE = 19
    ATTACH_FAILED = 20
    READ_FAILED = 21
    WRITE_FAILED = 22
    REGION_ENUM_FAILED = 23
    PARSE_FAILED = 24
    CONVERSION_FAILED = 25
    INTERNAL_ERROR = 26
    INVALID_POINTER_MAP_DATA = 27
    INVALID_POINTER_MAP_FORMAT = 28
    INVALID_POINTER_SCAN_OPTIONS = 29
    UNSUPPORTED_POINTER_MAP_VERSION = 30
    POINTER_MODULE_INDEX_OUT_OF_RANGE = 31
    POINTER_MAP_CREATE_FAILED = 32
    POINTER_MAP_READ_FAILED = 33
    POINTER_MAP_WRITE_FAILED = 34


class ScanLevel(IntEnum):
    ALL = 0
    ALL_RW = 1
    HEAP_STACK_EXE = 2
    HEAP_STACK_EXE_BSS = 3


class DataType(IntEnum):
    ANYNUMBER = 0
    ANYINTEGER = 1
    ANYFLOAT = 2
    INTEGER8 = 3
    INTEGER16 = 4
    INTEGER32 = 5
    INTEGER64 = 6
    FLOAT32 = 7
    FLOAT64 = 8
    BYTEARRAY = 9
    STRING = 10


class RegionKind(IntEnum):
    MISC = 0
    CODE = 1
    EXE = 2
    HEAP = 3
    STACK = 4


class MatchType(IntEnum):
    MATCHANY = 0
    MATCHEQUALTO = 1
    MATCHNOTEQUALTO = 2
    MATCHGREATERTHAN = 3
    MATCHLESSTHAN = 4
    MATCHRANGE = 5
    MATCHUPDATE = 6
    MATCHNOTCHANGED = 7
    MATCHCHANGED = 8
    MATCHINCREASED = 9
    MATCHDECREASED = 10
    MATCHINCREASEDBY = 11
    MATCHDECREASEDBY = 12


class PointerEndianness(IntEnum):
    NATIVE = 0
    LITTLE = 1
    BIG = 2


FLAG_U8 = 1 << 0
FLAG_S8 = 1 << 1
FLAG_U16 = 1 << 2
FLAG_S16 = 1 << 3
FLAG_U32 = 1 << 4
FLAG_S32 = 1 << 5
FLAG_U64 = 1 << 6
FLAG_S64 = 1 << 7
FLAG_F32 = 1 << 8
FLAG_F64 = 1 << 9

WILDCARD_FIXED = 0xFF
WILDCARD_ANY = 0x00
_MAX_SIZE_T = (1 << (ctypes.sizeof(ctypes.c_size_t) * 8)) - 1
_MAX_U64 = (1 << 64) - 1


class ValueData(ctypes.Union):
    _fields_ = [
        ("int8_value", ctypes.c_int8),
        ("uint8_value", ctypes.c_uint8),
        ("int16_value", ctypes.c_int16),
        ("uint16_value", ctypes.c_uint16),
        ("int32_value", ctypes.c_int32),
        ("uint32_value", ctypes.c_uint32),
        ("int64_value", ctypes.c_int64),
        ("uint64_value", ctypes.c_uint64),
        ("float32_value", ctypes.c_float),
        ("float64_value", ctypes.c_double),
        ("bytes", ctypes.c_uint8 * 8),
        ("chars", ctypes.c_uint8 * 8),
    ]


class Value(ctypes.Structure):
    _fields_ = [
        ("data", ValueData),
        ("flags", ctypes.c_uint16),
    ]


class MatchRecord(ctypes.Structure):
    _fields_ = [
        ("index", ctypes.c_size_t),
        ("address", ctypes.c_size_t),
        ("stored_value", Value),
        ("raw_match_info_bits", ctypes.c_uint16),
    ]


class RegionRecord(ctypes.Structure):
    _fields_ = [
        ("index", ctypes.c_size_t),
        ("id", ctypes.c_uint32),
        ("start", ctypes.c_size_t),
        ("size", ctypes.c_size_t),
        ("kind", ctypes.c_int),
        ("flags_bits", ctypes.c_uint8),
        ("load_addr", ctypes.c_size_t),
    ]


class AbiUserValue(ctypes.Structure):
    _fields_ = [
        ("int8_value", ctypes.c_int8),
        ("uint8_value", ctypes.c_uint8),
        ("int16_value", ctypes.c_int16),
        ("uint16_value", ctypes.c_uint16),
        ("int32_value", ctypes.c_int32),
        ("uint32_value", ctypes.c_uint32),
        ("int64_value", ctypes.c_int64),
        ("uint64_value", ctypes.c_uint64),
        ("float32_value", ctypes.c_float),
        ("float64_value", ctypes.c_double),
        ("data", ctypes.POINTER(ctypes.c_uint8)),
        ("wildcards", ctypes.POINTER(ctypes.c_uint8)),
        ("data_len", ctypes.c_size_t),
        ("flags_bits", ctypes.c_uint16),
    ]


class AbiPointerScanOptions(ctypes.Structure):
    _fields_ = [
        ("pointer_width", ctypes.c_uint8),
        ("max_depth", ctypes.c_uint8),
        ("module_base_only", ctypes.c_bool),
        ("has_max_results", ctypes.c_bool),
        ("endianness", ctypes.c_int),
        ("max_positive_offset", ctypes.c_size_t),
        ("max_negative_offset", ctypes.c_size_t),
        ("max_results", ctypes.c_uint64),
    ]


@dataclass(frozen=True)
class BytePattern:
    data: bytes
    wildcards: Optional[bytes] = None

    @classmethod
    def from_string(cls, text: str) -> "BytePattern":
        tokens = text.split()
        if not tokens:
            raise ValueError("byte pattern string must not be empty")

        data = bytearray(len(tokens))
        wildcards = bytearray(len(tokens))

        for index, token in enumerate(tokens):
            if len(token) != 2:
                raise ValueError(f"invalid byte token: {token!r}")

            if token == "??":
                data[index] = 0
                wildcards[index] = WILDCARD_ANY
            else:
                try:
                    data[index] = int(token, 16)
                except ValueError as exc:
                    raise ValueError(f"invalid byte token: {token!r}") from exc
                wildcards[index] = WILDCARD_FIXED

        return cls(data=bytes(data), wildcards=bytes(wildcards))


@dataclass
class MatchView:
    index: int
    address: int
    data_type: DataType
    match_info: "MatchFlagsView"
    stored_value: object

    def is_string_match(self) -> bool:
        return self.data_type == DataType.STRING

    def is_bytearray_match(self) -> bool:
        return self.data_type == DataType.BYTEARRAY

    def is_variable_length_match(self) -> bool:
        return self.data_type in (DataType.STRING, DataType.BYTEARRAY)

    def is_numeric_match(self) -> bool:
        return not self.is_variable_length_match()


@dataclass(frozen=True)
class MatchFlagsView:
    raw_bits: int

    def _has(self, flag: int) -> bool:
        return bool(self.raw_bits & flag)

    def has_uint8(self) -> bool:
        return self._has(FLAG_U8)

    def has_int8(self) -> bool:
        return self._has(FLAG_S8)

    def has_uint16(self) -> bool:
        return self._has(FLAG_U16)

    def has_int16(self) -> bool:
        return self._has(FLAG_S16)

    def has_uint32(self) -> bool:
        return self._has(FLAG_U32)

    def has_int32(self) -> bool:
        return self._has(FLAG_S32)

    def has_uint64(self) -> bool:
        return self._has(FLAG_U64)

    def has_int64(self) -> bool:
        return self._has(FLAG_S64)

    def has_float32(self) -> bool:
        return self._has(FLAG_F32)

    def has_float64(self) -> bool:
        return self._has(FLAG_F64)

    def integer_signedness(self) -> Optional[bool]:
        has_signed = any(
            (
                self.has_int8(),
                self.has_int16(),
                self.has_int32(),
                self.has_int64(),
            )
        )
        has_unsigned = any(
            (
                self.has_uint8(),
                self.has_uint16(),
                self.has_uint32(),
                self.has_uint64(),
            )
        )

        if has_signed and not has_unsigned:
            return True
        if has_unsigned and not has_signed:
            return False
        return None

    def is_signed_integer_only(self) -> bool:
        return self.integer_signedness() is True

    def is_unsigned_integer_only(self) -> bool:
        return self.integer_signedness() is False


@dataclass(frozen=True)
class RegionFlagsView:
    read: bool
    write: bool
    exec: bool
    shared: bool
    private: bool

    def to_text(self) -> str:
        return "".join(
            (
                "r" if self.read else "-",
                "w" if self.write else "-",
                "x" if self.exec else "-",
                "s" if self.shared else "p" if self.private else "-",
            )
        )


@dataclass
class RegionView:
    index: int
    id: int
    start: int
    size: int
    kind: RegionKind
    load_addr: int
    flags: RegionFlagsView
    filename: bytes

    def kind_text(self) -> str:
        return {
            RegionKind.MISC: "misc",
            RegionKind.CODE: "code",
            RegionKind.EXE: "exe",
            RegionKind.HEAP: "heap",
            RegionKind.STACK: "stack",
        }[self.kind]

    def filename_text(self, errors: str = "replace") -> str:
        return decode(self.filename, errors=errors) if self.filename else ""

    def permissions_text(self) -> str:
        return self.flags.to_text()

    def as_text_fields(self, errors: str = "replace") -> tuple[str, str, str, str, str, str, str]:
        return (
            str(self.id),
            f"0x{self.start:x}",
            str(self.size),
            self.kind_text(),
            f"0x{self.load_addr:x}",
            self.permissions_text(),
            self.filename_text(errors=errors) or "unassociated",
        )


@dataclass
class PointerScanOptions:
    pointer_width: int = ctypes.sizeof(ctypes.c_size_t)
    endianness: PointerEndianness = PointerEndianness.NATIVE
    max_depth: int = 5
    module_base_only: bool = True
    max_positive_offset: int = 2048
    max_negative_offset: int = 0
    max_results: Optional[int] = None


class Libmemscan:
    def __init__(self, libpath: str = "libmemscan.so"):
        self._lib = ctypes.CDLL(libpath)
        self._bind()
        self._scanner = self._lib.lm_scanner_create()
        if not self._scanner:
            raise RuntimeError("lm_scanner_create returned NULL")

        self._data_type = DataType.INTEGER32

    def _bind(self) -> None:
        self._lib.lm_status_name.restype = ctypes.c_char_p
        self._lib.lm_status_name.argtypes = [ctypes.c_int]

        self._lib.lm_scanner_create.restype = ctypes.c_void_p
        self._lib.lm_scanner_create.argtypes = []

        self._lib.lm_scanner_destroy.restype = None
        self._lib.lm_scanner_destroy.argtypes = [ctypes.c_void_p]

        signatures = {
            "lm_attach": [ctypes.c_void_p, ctypes.c_uint],
            "lm_detach": [ctypes.c_void_p],
            "lm_reset": [ctypes.c_void_p],
            "lm_set_scan_level": [ctypes.c_void_p, ctypes.c_int],
            "lm_set_data_type": [ctypes.c_void_p, ctypes.c_int],
            "lm_set_reverse_endianness": [ctypes.c_void_p, ctypes.c_bool],
            "lm_set_alignment": [ctypes.c_void_p, ctypes.c_uint16],
            "lm_set_stop_flag": [ctypes.c_void_p, ctypes.c_bool],
            "lm_snapshot": [ctypes.c_void_p],
            "lm_update": [ctypes.c_void_p],
            "lm_undo_scan": [ctypes.c_void_p],
            "lm_scan": [ctypes.c_void_p, ctypes.c_int, ctypes.POINTER(AbiUserValue), ctypes.POINTER(AbiUserValue)],
            "lm_pointer_scan": [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_char_p, ctypes.POINTER(AbiPointerScanOptions), ctypes.POINTER(ctypes.c_uint64)],
            "lm_pointer_map_compare": [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.POINTER(ctypes.c_uint64)],
            "lm_pointer_map_dump_text": [ctypes.c_char_p, ctypes.c_char_p],
            "lm_remove_region_by_id": [ctypes.c_void_p, ctypes.c_size_t, ctypes.POINTER(ctypes.c_bool)],
            "lm_remove_match_by_index": [ctypes.c_void_p, ctypes.c_size_t, ctypes.POINTER(ctypes.c_bool)],
            "lm_remove_match_by_address": [ctypes.c_void_p, ctypes.c_size_t, ctypes.POINTER(ctypes.c_bool)],
            "lm_get_region": [ctypes.c_void_p, ctypes.c_size_t, ctypes.POINTER(RegionRecord), ctypes.POINTER(ctypes.c_uint8), ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)],
            "lm_find_match_index_by_address": [ctypes.c_void_p, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)],
            "lm_get_match": [ctypes.c_void_p, ctypes.c_size_t, ctypes.POINTER(MatchRecord)],
            "lm_get_stored_match_bytes": [ctypes.c_void_p, ctypes.c_size_t, ctypes.POINTER(ctypes.c_uint8), ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)],
            "lm_read_bytes_exact": [ctypes.c_void_p, ctypes.c_size_t, ctypes.POINTER(ctypes.c_uint8), ctypes.c_size_t],
            "lm_read_match_bytes": [ctypes.c_void_p, ctypes.c_size_t, ctypes.POINTER(ctypes.c_uint8), ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)],
            "lm_write_bytes": [ctypes.c_void_p, ctypes.c_size_t, ctypes.POINTER(ctypes.c_uint8), ctypes.c_size_t],
            "lm_write_value": [ctypes.c_void_p, ctypes.c_size_t, ctypes.POINTER(AbiUserValue)],
            "lm_write_match": [ctypes.c_void_p, ctypes.c_size_t, ctypes.POINTER(AbiUserValue)],
        }

        for name, argtypes in signatures.items():
            fn = getattr(self._lib, name)
            fn.restype = ctypes.c_int
            fn.argtypes = argtypes

        self._lib.lm_match_count.restype = ctypes.c_size_t
        self._lib.lm_match_count.argtypes = [ctypes.c_void_p]

        self._lib.lm_region_count.restype = ctypes.c_size_t
        self._lib.lm_region_count.argtypes = [ctypes.c_void_p]

        self._lib.lm_scan_progress.restype = ctypes.c_double
        self._lib.lm_scan_progress.argtypes = [ctypes.c_void_p]

    def _status_name(self, status: int) -> str:
        return decode(self._lib.lm_status_name(status))

    def _check(self, status: int, operation: str) -> None:
        if status != Status.OK:
            raise LibmemscanError(status, self._status_name(status), operation)

    def close(self) -> None:
        if self._scanner:
            self._lib.lm_scanner_destroy(self._scanner)
            self._scanner = None

    def __del__(self) -> None:
        try:
            self.close()
        except Exception:
            pass

    def attach(self, pid: int) -> None:
        self._check(self._lib.lm_attach(self._scanner, pid), "attach")

    def detach(self) -> None:
        self._check(self._lib.lm_detach(self._scanner), "detach")

    def reset(self) -> None:
        self._check(self._lib.lm_reset(self._scanner), "reset")

    def set_scan_level(self, level: ScanLevel) -> None:
        self._check(self._lib.lm_set_scan_level(self._scanner, int(level)), "set_scan_level")

    def set_data_type(self, data_type: DataType) -> None:
        self._check(self._lib.lm_set_data_type(self._scanner, int(data_type)), "set_data_type")
        self._data_type = DataType(data_type)

    def set_reverse_endianness(self, enabled: bool) -> None:
        self._check(self._lib.lm_set_reverse_endianness(self._scanner, enabled), "set_reverse_endianness")

    def set_alignment(self, alignment: int) -> None:
        self._check(self._lib.lm_set_alignment(self._scanner, alignment), "set_alignment")

    def set_stop_flag(self, stop: bool) -> None:
        self._check(self._lib.lm_set_stop_flag(self._scanner, stop), "set_stop_flag")

    def snapshot(self) -> None:
        self._check(self._lib.lm_snapshot(self._scanner), "snapshot")

    def update(self) -> None:
        self._check(self._lib.lm_update(self._scanner), "update")

    def undo_scan(self) -> None:
        self._check(self._lib.lm_undo_scan(self._scanner), "undo_scan")

    def _make_numeric_user_value(self, value: object) -> AbiUserValue:
        if isinstance(value, bool):
            value = int(value)

        raw = AbiUserValue()
        flags = 0

        if isinstance(value, int):
            if value < -(1 << 63) or value > (1 << 64) - 1:
                raise OverflowError("integer value is outside supported 64-bit range")

            if 0 <= value <= 0xFF:
                raw.uint8_value = value
                flags |= FLAG_U8
            if -(1 << 7) <= value <= (1 << 7) - 1:
                raw.int8_value = value
                flags |= FLAG_S8
            if 0 <= value <= 0xFFFF:
                raw.uint16_value = value
                flags |= FLAG_U16
            if -(1 << 15) <= value <= (1 << 15) - 1:
                raw.int16_value = value
                flags |= FLAG_S16
            if 0 <= value <= 0xFFFFFFFF:
                raw.uint32_value = value
                flags |= FLAG_U32
            if -(1 << 31) <= value <= (1 << 31) - 1:
                raw.int32_value = value
                flags |= FLAG_S32
            if 0 <= value <= (1 << 64) - 1:
                raw.uint64_value = value
                flags |= FLAG_U64
            if -(1 << 63) <= value <= (1 << 63) - 1:
                raw.int64_value = value
                flags |= FLAG_S64

            float_value = float(value)
            raw.float32_value = ctypes.c_float(float_value).value
            raw.float64_value = float_value
            flags |= FLAG_F32 | FLAG_F64
        elif isinstance(value, float):
            if not math.isfinite(value):
                raise ValueError("float value must be finite")

            raw.float32_value = ctypes.c_float(value).value
            raw.float64_value = value
            flags |= FLAG_F32 | FLAG_F64

            truncated = int(value)
            if 0 <= value <= 0xFF:
                raw.uint8_value = truncated
                flags |= FLAG_U8
            if -(1 << 7) <= value <= (1 << 7) - 1:
                raw.int8_value = truncated
                flags |= FLAG_S8
            if 0 <= value <= 0xFFFF:
                raw.uint16_value = truncated
                flags |= FLAG_U16
            if -(1 << 15) <= value <= (1 << 15) - 1:
                raw.int16_value = truncated
                flags |= FLAG_S16
            if 0 <= value <= 0xFFFFFFFF:
                raw.uint32_value = truncated
                flags |= FLAG_U32
            if -(1 << 31) <= value <= (1 << 31) - 1:
                raw.int32_value = truncated
                flags |= FLAG_S32
            if 0 <= value <= float((1 << 64) - 1):
                raw.uint64_value = truncated
                flags |= FLAG_U64
            if -(1 << 63) <= value <= (1 << 63) - 1:
                raw.int64_value = truncated
                flags |= FLAG_S64
        else:
            raise TypeError("numeric scans and writes expect an int or float value")

        raw.flags_bits = flags
        return raw

    def _make_string_user_value(self, value: object) -> tuple[AbiUserValue, list[object]]:
        if isinstance(value, str):
            data = encode(value)
        elif isinstance(value, (bytes, bytearray, memoryview)):
            data = bytes(value)
        else:
            raise TypeError("string scans and writes expect str or bytes-like input")

        raw = AbiUserValue()
        raw.data_len = len(data)
        keepalive: list[object] = []

        if data:
            buffer = (ctypes.c_uint8 * len(data)).from_buffer_copy(data)
            raw.data = ctypes.cast(buffer, ctypes.POINTER(ctypes.c_uint8))
            keepalive.append(buffer)

        return raw, keepalive

    def _make_bytearray_user_value(self, value: object, *, for_write: bool) -> tuple[AbiUserValue, list[object]]:
        if isinstance(value, BytePattern):
            data = bytes(value.data)
            wildcard_bytes = None if value.wildcards is None else bytes(value.wildcards)
        elif isinstance(value, (bytes, bytearray, memoryview)):
            data = bytes(value)
            wildcard_bytes = None
        else:
            raise TypeError("bytearray scans and writes expect bytes-like input or BytePattern")

        if for_write and wildcard_bytes is not None:
            if any(item != WILDCARD_FIXED for item in wildcard_bytes):
                raise ValueError("bytearray writes do not accept wildcard bytes")
            wildcard_bytes = None

        if not for_write and wildcard_bytes is None:
            wildcard_bytes = bytes([WILDCARD_FIXED]) * len(data)

        if wildcard_bytes is not None and len(wildcard_bytes) != len(data):
            raise ValueError("bytearray data and wildcard lengths must match")

        if wildcard_bytes is not None:
            for item in wildcard_bytes:
                if item not in (WILDCARD_FIXED, WILDCARD_ANY):
                    raise ValueError("wildcards must use 0xFF for fixed bytes or 0x00 for wildcards")

        raw = AbiUserValue()
        raw.data_len = len(data)
        keepalive: list[object] = []

        if data:
            data_buffer = (ctypes.c_uint8 * len(data)).from_buffer_copy(data)
            raw.data = ctypes.cast(data_buffer, ctypes.POINTER(ctypes.c_uint8))
            keepalive.append(data_buffer)

        if wildcard_bytes:
            wildcard_buffer = (ctypes.c_uint8 * len(wildcard_bytes)).from_buffer_copy(wildcard_bytes)
            raw.wildcards = ctypes.cast(wildcard_buffer, ctypes.POINTER(ctypes.c_uint8))
            keepalive.append(wildcard_buffer)

        return raw, keepalive

    def _make_user_value(self, value: object, *, for_write: bool) -> tuple[AbiUserValue, list[object]]:
        if self._data_type == DataType.BYTEARRAY:
            return self._make_bytearray_user_value(value, for_write=for_write)
        if self._data_type == DataType.STRING:
            return self._make_string_user_value(value)
        return self._make_numeric_user_value(value), []

    def scan(self, match_type: MatchType, value1: Optional[object] = None, value2: Optional[object] = None) -> None:
        raw1 = None
        raw2 = None
        keepalive: list[object] = []

        if value1 is not None:
            raw1, extra = self._make_user_value(value1, for_write=False)
            keepalive.extend(extra)

        if value2 is not None:
            raw2, extra = self._make_user_value(value2, for_write=False)
            keepalive.extend(extra)

        self._check(
            self._lib.lm_scan(
                self._scanner,
                int(match_type),
                ctypes.byref(raw1) if raw1 is not None else None,
                ctypes.byref(raw2) if raw2 is not None else None,
            ),
            f"scan({MatchType(match_type).name})",
        )

    def _path_bytes(self, path: object) -> bytes:
        raw_path = os.fspath(path)
        if not raw_path:
            raise ValueError("path must not be empty")

        absolute_path = os.path.abspath(raw_path)
        path_bytes = absolute_path if isinstance(absolute_path, bytes) else os.fsencode(absolute_path)
        if b"\0" in path_bytes:
            raise ValueError("path must not contain NUL bytes")
        return path_bytes

    def _make_pointer_scan_options(self, options: PointerScanOptions) -> AbiPointerScanOptions:
        if not isinstance(options, PointerScanOptions):
            raise TypeError("options must be a PointerScanOptions instance")
        if type(options.pointer_width) is not int or options.pointer_width not in (4, 8):
            raise ValueError("pointer_width must be 4 or 8")
        if type(options.max_depth) is not int or not 1 <= options.max_depth <= 0xFF:
            raise ValueError("max_depth must be between 1 and 255")
        if (
            type(options.max_positive_offset) is not int
            or type(options.max_negative_offset) is not int
            or options.max_positive_offset < 0
            or options.max_negative_offset < 0
        ):
            raise ValueError("pointer offsets must be non-negative integers")
        if options.max_positive_offset > _MAX_SIZE_T or options.max_negative_offset > _MAX_SIZE_T:
            raise ValueError("pointer offsets must fit in size_t")
        if options.max_results is not None and (
            type(options.max_results) is not int
            or not 0 <= options.max_results <= _MAX_U64
        ):
            raise ValueError("max_results must fit in u64")
        if type(options.module_base_only) is not bool:
            raise ValueError("module_base_only must be a bool")

        if type(options.endianness) is bool:
            raise ValueError("endianness must be a PointerEndianness value")
        try:
            endianness = PointerEndianness(options.endianness)
        except (TypeError, ValueError) as exc:
            raise ValueError("endianness must be a PointerEndianness value") from exc
        raw = AbiPointerScanOptions()
        raw.pointer_width = options.pointer_width
        raw.max_depth = options.max_depth
        raw.module_base_only = options.module_base_only
        raw.has_max_results = options.max_results is not None
        raw.endianness = int(endianness)
        raw.max_positive_offset = options.max_positive_offset
        raw.max_negative_offset = options.max_negative_offset
        raw.max_results = 0 if options.max_results is None else options.max_results
        return raw

    def pointer_scan(self, target_address: int, output_map_path: object, options: Optional[PointerScanOptions] = None) -> int:
        if type(target_address) is not int or not 0 <= target_address <= _MAX_SIZE_T:
            raise ValueError("target_address must fit in size_t")

        raw_options = self._make_pointer_scan_options(options if options is not None else PointerScanOptions())
        path = self._path_bytes(output_map_path)
        paths_found = ctypes.c_uint64()
        self._check(
            self._lib.lm_pointer_scan(
                self._scanner,
                target_address,
                path,
                ctypes.byref(raw_options),
                ctypes.byref(paths_found),
            ),
            "pointer_scan",
        )
        return int(paths_found.value)

    def compare_pointer_maps(self, previous_map_path: object, current_map_path: object, output_map_path: object) -> int:
        previous_path = self._path_bytes(previous_map_path)
        current_path = self._path_bytes(current_map_path)
        output_path = self._path_bytes(output_map_path)
        paths_found = ctypes.c_uint64()
        self._check(
            self._lib.lm_pointer_map_compare(
                previous_path,
                current_path,
                output_path,
                ctypes.byref(paths_found),
            ),
            "compare_pointer_maps",
        )
        return int(paths_found.value)

    def dump_pointer_map_text(self, map_path: object, output_text_path: object) -> None:
        self._check(
            self._lib.lm_pointer_map_dump_text(
                self._path_bytes(map_path),
                self._path_bytes(output_text_path),
            ),
            "dump_pointer_map_text",
        )

    def get_match_count(self) -> int:
        return int(self._lib.lm_match_count(self._scanner))

    def get_region_count(self) -> int:
        return int(self._lib.lm_region_count(self._scanner))

    def get_scan_progress(self) -> float:
        return float(self._lib.lm_scan_progress(self._scanner))

    def remove_region_by_id(self, region_id: int) -> bool:
        removed = ctypes.c_bool()
        self._check(
            self._lib.lm_remove_region_by_id(self._scanner, region_id, ctypes.byref(removed)),
            "remove_region_by_id",
        )
        return bool(removed.value)

    def remove_match_by_index(self, match_index: int) -> bool:
        removed = ctypes.c_bool()
        self._check(
            self._lib.lm_remove_match_by_index(self._scanner, match_index, ctypes.byref(removed)),
            "remove_match_by_index",
        )
        return bool(removed.value)

    def remove_match_by_address(self, address: int) -> bool:
        removed = ctypes.c_bool()
        self._check(
            self._lib.lm_remove_match_by_address(self._scanner, address, ctypes.byref(removed)),
            "remove_match_by_address",
        )
        return bool(removed.value)

    def get_region(self, region_index: int) -> RegionView:
        record = RegionRecord()
        filename_len = ctypes.c_size_t()
        status = self._lib.lm_get_region(self._scanner, region_index, ctypes.byref(record), None, 0, ctypes.byref(filename_len))

        if status not in (Status.OK, Status.BUFFER_TOO_SMALL):
            self._check(status, "get_region")

        filename = b""
        if filename_len.value:
            filename_buf = (ctypes.c_uint8 * filename_len.value)()
            self._check(
                self._lib.lm_get_region(
                    self._scanner,
                    region_index,
                    ctypes.byref(record),
                    filename_buf,
                    filename_len.value,
                    ctypes.byref(filename_len),
                ),
                "get_region",
            )
            filename = bytes(filename_buf[: filename_len.value])

        flags = int(record.flags_bits)
        return RegionView(
            index=int(record.index),
            id=int(record.id),
            start=int(record.start),
            size=int(record.size),
            kind=RegionKind(record.kind),
            load_addr=int(record.load_addr),
            flags=RegionFlagsView(
                read=bool(flags & (1 << 0)),
                write=bool(flags & (1 << 1)),
                exec=bool(flags & (1 << 2)),
                shared=bool(flags & (1 << 3)),
                private=bool(flags & (1 << 4)),
            ),
            filename=filename,
        )

    def regions(self) -> Generator[RegionView, None, None]:
        count = self.get_region_count()
        for index in range(count):
            yield self.get_region(index)

    def find_match_index_by_address(self, address: int) -> Optional[int]:
        index = ctypes.c_size_t()
        status = self._lib.lm_find_match_index_by_address(self._scanner, address, ctypes.byref(index))
        if status == Status.NO_MATCHES:
            return None
        self._check(status, "find_match_index_by_address")
        return int(index.value)

    def get_match(self, match_index: int) -> MatchRecord:
        record = MatchRecord()
        self._check(self._lib.lm_get_match(self._scanner, match_index, ctypes.byref(record)), "get_match")
        return record

    def _make_match_info(self, raw_match_info_bits: int) -> MatchFlagsView:
        return MatchFlagsView(raw_match_info_bits)

    def _match_length(self, record: MatchRecord) -> int:
        # TODO: This currently derives numeric byte width from the wrapper's active
        # DataType, not the stored match's original type. This can be an issue if you
        # don't reset() after changing.
        if self._data_type in (DataType.BYTEARRAY, DataType.STRING):
            return int(record.raw_match_info_bits)
        if self._data_type in (DataType.INTEGER8,):
            return 1
        if self._data_type in (DataType.INTEGER16,):
            return 2
        if self._data_type in (DataType.INTEGER32, DataType.FLOAT32):
            return 4
        return 8

    def get_stored_match_bytes(self, match_index: int) -> bytes:
        record = self.get_match(match_index)
        buf_len = self._match_length(record)
        buf = (ctypes.c_uint8 * max(buf_len, 1))()
        out_len = ctypes.c_size_t()
        self._check(
            self._lib.lm_get_stored_match_bytes(self._scanner, match_index, buf, buf_len, ctypes.byref(out_len)),
            "get_stored_match_bytes",
        )
        return bytes(buf[: out_len.value])

    def get_stored_match_value(self, match_index: int) -> object:
        record = self.get_match(match_index)

        if self._data_type in (DataType.BYTEARRAY, DataType.STRING):
            return self.get_stored_match_bytes(match_index)

        return record.stored_value

    def read_bytes_exact(self, address: int, length: int) -> bytes:
        buf = (ctypes.c_uint8 * length)()
        self._check(
            self._lib.lm_read_bytes_exact(self._scanner, address, buf, length),
            "read_bytes_exact",
        )
        return bytes(buf)

    def read_match_bytes(self, match_index: int) -> bytes:
        record = self.get_match(match_index)
        buf_len = self._match_length(record)
        buf = (ctypes.c_uint8 * max(buf_len, 1))()
        out_len = ctypes.c_size_t()
        self._check(
            self._lib.lm_read_match_bytes(self._scanner, match_index, buf, buf_len, ctypes.byref(out_len)),
            "read_match_bytes",
        )
        return bytes(buf[: out_len.value])

    def write_bytes(self, address: int, data: bytes) -> None:
        if not data:
            raise ValueError("data must not be empty")
        buf = (ctypes.c_uint8 * len(data)).from_buffer_copy(data)
        self._check(
            self._lib.lm_write_bytes(self._scanner, address, buf, len(data)),
            "write_bytes",
        )

    def write_value(self, address: int, value: object) -> None:
        raw_value, _ = self._make_user_value(value, for_write=True)
        self._check(
            self._lib.lm_write_value(self._scanner, address, ctypes.byref(raw_value)),
            "write_value",
        )

    def write_match(self, match_index: int, value: object) -> None:
        raw_value, _ = self._make_user_value(value, for_write=True)
        self._check(
            self._lib.lm_write_match(self._scanner, match_index, ctypes.byref(raw_value)),
            "write_match",
        )

    def matches(self) -> Generator[MatchView, None, None]:
        count = self.get_match_count()
        for index in range(count):
            record = self.get_match(index)
            yield MatchView(
                index=record.index,
                address=record.address,
                data_type=self._data_type,
                match_info=self._make_match_info(record.raw_match_info_bits),
                stored_value=self.get_stored_match_value(index),
            )
