//! Public import root for the libmemscan package.
//! External non-Zig projects should use this C ABI instead of Scanner.

// Copyright (C) 2026 brkzlr <brksys@icloud.com>
//
// This file is part of Libmemscan.
//
// Libmemscan is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

const std = @import("std");

pub const process = @import("process.zig");
pub const value = @import("value.zig");
pub const targetmem = @import("targetmem.zig");
pub const scanroutines = @import("scanroutines.zig");
pub const scanner = @import("scanner.zig");
pub const pointerscan = @import("pointerscan.zig");

pub const MatchFlags = value.MatchFlags;
pub const Value = value.Value;
pub const Wildcard = value.Wildcard;
pub const Region = scanner.Region;
pub const ScanLevel = scanner.ScanLevel;
pub const ScanDataType = scanner.ScanDataType;
pub const ScanMatchType = scanner.ScanMatchType;
pub const UserValue = scanner.UserValue;
pub const Scanner = scanner.Scanner;
pub const ScannerError = scanner.ScannerError;
pub const ScanOptions = scanner.ScanOptions;
pub const ModuleBase = pointerscan.ModuleBase;
pub const PointerEntry = pointerscan.PointerEntry;
pub const PointerScanOptions = pointerscan.PointerScanOptions;
pub const PointerReverseIndex = pointerscan.PointerReverseIndex;
pub const PointerBase = pointerscan.PointerBase;
pub const PointerPath = pointerscan.PointerPath;
pub const OwnedPointerPath = pointerscan.OwnedPointerPath;
pub const PointerMapWriter = pointerscan.PointerMapWriter;
pub const PointerMapReader = pointerscan.PointerMapReader;
pub const PointerScanError = pointerscan.PointerScanError;

const c_allocator = std.heap.c_allocator;

const AbiScanner = struct {
    scanner: Scanner,
};

pub const LmScanner = opaque {};

pub const LmStatus = enum(c_int) {
    OK = 0,
    INVALID_ARGUMENT = 1,
    OUT_OF_MEMORY = 2,
    ALREADY_ATTACHED = 3,
    NOT_ATTACHED = 4,
    NO_REGIONS = 5,
    NO_MATCHES = 6,
    NO_UNDO = 7,
    UNDO_IO_FAILED = 8,
    UNDO_CORRUPT = 9,
    SNAPSHOT_REQUIRES_RESET = 10,
    MATCH_INDEX_OUT_OF_RANGE = 11,
    BUFFER_TOO_SMALL = 12,
    INVALID_USER_VALUE_COUNT = 13,
    INVALID_ALIGNMENT = 14,
    INVALID_WRITE_VALUE = 15,
    INVALID_WRITE_LENGTH = 16,
    UNSUPPORTED_SCAN_COMBINATION = 17,
    UNSUPPORTED_READ_DATA_TYPE = 18,
    UNSUPPORTED_WRITE_DATA_TYPE = 19,
    ATTACH_FAILED = 20,
    READ_FAILED = 21,
    WRITE_FAILED = 22,
    REGION_ENUM_FAILED = 23,
    PARSE_FAILED = 24,
    CONVERSION_FAILED = 25,
    INTERNAL_ERROR = 26,
    INVALID_POINTER_MAP_DATA = 27,
    INVALID_POINTER_MAP_FORMAT = 28,
    INVALID_POINTER_SCAN_OPTIONS = 29,
    UNSUPPORTED_POINTER_MAP_VERSION = 30,
    POINTER_MODULE_INDEX_OUT_OF_RANGE = 31,
    POINTER_MAP_CREATE_FAILED = 32,
    POINTER_MAP_READ_FAILED = 33,
    POINTER_MAP_WRITE_FAILED = 34,
    OPTION_REQUIRES_RESET = 35,
};

pub const LmDataType = enum(c_int) {
    ANYNUMBER = 0,
    ANYINTEGER = 1,
    ANYFLOAT = 2,
    INTEGER8 = 3,
    INTEGER16 = 4,
    INTEGER32 = 5,
    INTEGER64 = 6,
    FLOAT32 = 7,
    FLOAT64 = 8,
    BYTEARRAY = 9,
    STRING = 10,
};

pub const LmMatchType = enum(c_int) {
    MATCHANY = 0,
    MATCHEQUALTO = 1,
    MATCHNOTEQUALTO = 2,
    MATCHGREATERTHAN = 3,
    MATCHLESSTHAN = 4,
    MATCHRANGE = 5,
    MATCHUPDATE = 6,
    MATCHNOTCHANGED = 7,
    MATCHCHANGED = 8,
    MATCHINCREASED = 9,
    MATCHDECREASED = 10,
    MATCHINCREASEDBY = 11,
    MATCHDECREASEDBY = 12,
};

pub const LmScanLevel = enum(c_int) {
    ALL = 0,
    ALL_RW = 1,
    HEAP_STACK_EXE = 2,
    HEAP_STACK_EXE_BSS = 3,
};

pub const LmPointerEndianness = enum(c_int) {
    NATIVE = 0,
    LITTLE = 1,
    BIG = 2,
};

pub const LmMatchRecord = extern struct {
    index: usize,
    address: usize,
    stored_value: Value,
    raw_match_info_bits: u16,
};

pub const LmRegionRecord = extern struct {
    index: usize,
    id: u32,
    start: usize,
    size: usize,
    kind: c_int,
    flags_bits: u8,
    load_addr: usize,
};

pub const LmPointerScanOptions = extern struct {
    pointer_width: u8,
    max_depth: u8,
    module_base_only: bool,
    has_max_results: bool,
    endianness: c_int,
    max_positive_offset: usize,
    max_negative_offset: usize,
    max_results: u64,
};

pub const LmUserValue = extern struct {
    int8_value: i8 = 0,
    uint8_value: u8 = 0,
    int16_value: i16 = 0,
    uint16_value: u16 = 0,
    int32_value: i32 = 0,
    uint32_value: u32 = 0,
    int64_value: i64 = 0,
    uint64_value: u64 = 0,
    float32_value: f32 = 0,
    float64_value: f64 = 0,
    data: ?[*]const u8 = null,
    wildcards: ?[*]const u8 = null,
    data_len: usize = 0,
    flags_bits: u16 = 0,
};

fn toHandle(raw: ?*LmScanner) ?*AbiScanner {
    const ptr = raw orelse return null;
    return @ptrCast(@alignCast(ptr));
}

fn absolutePathFromAbi(raw: ?[*:0]const u8) ?[]const u8 {
    const ptr = raw orelse return null;
    const path = std.mem.span(ptr);
    if (path.len == 0 or !std.Io.Dir.path.isAbsolute(path)) return null;
    return path;
}

fn statusFrom(err: anyerror) LmStatus {
    return switch (err) {
        error.InvalidArgument => .INVALID_ARGUMENT,
        error.AlreadyAttached => .ALREADY_ATTACHED,
        error.NotAttached => .NOT_ATTACHED,
        error.NoRegions => .NO_REGIONS,
        error.NoMatches => .NO_MATCHES,
        error.NoUndo => .NO_UNDO,
        error.UndoIoFailed => .UNDO_IO_FAILED,
        error.UndoCorrupt => .UNDO_CORRUPT,
        error.SnapshotRequiresReset => .SNAPSHOT_REQUIRES_RESET,
        error.OptionRequiresReset => .OPTION_REQUIRES_RESET,
        error.MatchIndexOutOfRange => .MATCH_INDEX_OUT_OF_RANGE,
        error.BufferTooSmall => .BUFFER_TOO_SMALL,
        error.InvalidUserValueCount => .INVALID_USER_VALUE_COUNT,
        error.InvalidAlignment => .INVALID_ALIGNMENT,
        error.InvalidWriteValue => .INVALID_WRITE_VALUE,
        error.InvalidWriteLength => .INVALID_WRITE_LENGTH,
        error.UnsupportedScanCombination => .UNSUPPORTED_SCAN_COMBINATION,
        error.UnsupportedReadDataType => .UNSUPPORTED_READ_DATA_TYPE,
        error.UnsupportedWriteDataType => .UNSUPPORTED_WRITE_DATA_TYPE,
        error.AttachFailed => .ATTACH_FAILED,
        error.ReadFailed => .READ_FAILED,
        error.WriteFailed => .WRITE_FAILED,
        error.RegionEnumFailed => .REGION_ENUM_FAILED,
        error.OutOfMemory => .OUT_OF_MEMORY,
        error.InvalidMapData => .INVALID_POINTER_MAP_DATA,
        error.InvalidMapFormat => .INVALID_POINTER_MAP_FORMAT,
        error.InvalidOptions => .INVALID_POINTER_SCAN_OPTIONS,
        error.UnsupportedMapVersion => .UNSUPPORTED_POINTER_MAP_VERSION,
        error.ModuleIndexOutOfRange => .POINTER_MODULE_INDEX_OUT_OF_RANGE,
        error.MapCreateFailed => .POINTER_MAP_CREATE_FAILED,
        error.MapReadFailed => .POINTER_MAP_READ_FAILED,
        error.MapWriteFailed => .POINTER_MAP_WRITE_FAILED,
        error.InvalidCharacter,
        error.Overflow,
        error.Empty,
        error.InvalidToken,
        error.MissingOperand,
        error.InvalidRange,
        error.DuplicateSeparator,
        error.InvalidFormat,
        error.UnsupportedType,
        => .PARSE_FAILED,
        error.LossyConversion => .CONVERSION_FAILED,
        else => .INTERNAL_ERROR,
    };
}

fn userValueFromAbi(raw: LmUserValue, data_type: ScanDataType, for_write: bool) !UserValue {
    var user = UserValue{
        .int8_value = raw.int8_value,
        .uint8_value = raw.uint8_value,
        .int16_value = raw.int16_value,
        .uint16_value = raw.uint16_value,
        .int32_value = raw.int32_value,
        .uint32_value = raw.uint32_value,
        .int64_value = raw.int64_value,
        .uint64_value = raw.uint64_value,
        .float32_value = raw.float32_value,
        .float64_value = raw.float64_value,
        .flags = @bitCast(raw.flags_bits),
    };

    switch (data_type) {
        .BYTEARRAY => {
            const data_ptr = raw.data orelse return error.InvalidArgument;
            user.bytearray_value = data_ptr[0..raw.data_len];
            if (!for_write) {
                const wildcards_ptr = raw.wildcards orelse return error.InvalidArgument;
                const raw_wildcards = wildcards_ptr[0..raw.data_len];
                for (raw_wildcards) |item| {
                    switch (item) {
                        @intFromEnum(Wildcard.FIXED), @intFromEnum(Wildcard.WILDCARD) => {},
                        else => return error.InvalidArgument,
                    }
                }
                const typed_wildcards: [*]const Wildcard = @ptrCast(wildcards_ptr);
                user.wildcard_value = typed_wildcards[0..raw.data_len];
            }
        },
        .STRING => {
            const data_ptr = raw.data orelse return error.InvalidArgument;
            user.string_value = data_ptr[0..raw.data_len];
        },
        else => {},
    }

    return user;
}

pub export fn lm_status_name(status_code: c_int) [*:0]const u8 {
    return switch (status_code) {
        @intFromEnum(LmStatus.OK) => "OK",
        @intFromEnum(LmStatus.INVALID_ARGUMENT) => "INVALID_ARGUMENT",
        @intFromEnum(LmStatus.OUT_OF_MEMORY) => "OUT_OF_MEMORY",
        @intFromEnum(LmStatus.ALREADY_ATTACHED) => "ALREADY_ATTACHED",
        @intFromEnum(LmStatus.NOT_ATTACHED) => "NOT_ATTACHED",
        @intFromEnum(LmStatus.NO_REGIONS) => "NO_REGIONS",
        @intFromEnum(LmStatus.NO_MATCHES) => "NO_MATCHES",
        @intFromEnum(LmStatus.NO_UNDO) => "NO_UNDO",
        @intFromEnum(LmStatus.UNDO_IO_FAILED) => "UNDO_IO_FAILED",
        @intFromEnum(LmStatus.UNDO_CORRUPT) => "UNDO_CORRUPT",
        @intFromEnum(LmStatus.SNAPSHOT_REQUIRES_RESET) => "SNAPSHOT_REQUIRES_RESET",
        @intFromEnum(LmStatus.MATCH_INDEX_OUT_OF_RANGE) => "MATCH_INDEX_OUT_OF_RANGE",
        @intFromEnum(LmStatus.BUFFER_TOO_SMALL) => "BUFFER_TOO_SMALL",
        @intFromEnum(LmStatus.INVALID_USER_VALUE_COUNT) => "INVALID_USER_VALUE_COUNT",
        @intFromEnum(LmStatus.INVALID_ALIGNMENT) => "INVALID_ALIGNMENT",
        @intFromEnum(LmStatus.INVALID_WRITE_VALUE) => "INVALID_WRITE_VALUE",
        @intFromEnum(LmStatus.INVALID_WRITE_LENGTH) => "INVALID_WRITE_LENGTH",
        @intFromEnum(LmStatus.UNSUPPORTED_SCAN_COMBINATION) => "UNSUPPORTED_SCAN_COMBINATION",
        @intFromEnum(LmStatus.UNSUPPORTED_READ_DATA_TYPE) => "UNSUPPORTED_READ_DATA_TYPE",
        @intFromEnum(LmStatus.UNSUPPORTED_WRITE_DATA_TYPE) => "UNSUPPORTED_WRITE_DATA_TYPE",
        @intFromEnum(LmStatus.ATTACH_FAILED) => "ATTACH_FAILED",
        @intFromEnum(LmStatus.READ_FAILED) => "READ_FAILED",
        @intFromEnum(LmStatus.WRITE_FAILED) => "WRITE_FAILED",
        @intFromEnum(LmStatus.REGION_ENUM_FAILED) => "REGION_ENUM_FAILED",
        @intFromEnum(LmStatus.PARSE_FAILED) => "PARSE_FAILED",
        @intFromEnum(LmStatus.CONVERSION_FAILED) => "CONVERSION_FAILED",
        @intFromEnum(LmStatus.INTERNAL_ERROR) => "INTERNAL_ERROR",
        @intFromEnum(LmStatus.INVALID_POINTER_MAP_DATA) => "INVALID_POINTER_MAP_DATA",
        @intFromEnum(LmStatus.INVALID_POINTER_MAP_FORMAT) => "INVALID_POINTER_MAP_FORMAT",
        @intFromEnum(LmStatus.INVALID_POINTER_SCAN_OPTIONS) => "INVALID_POINTER_SCAN_OPTIONS",
        @intFromEnum(LmStatus.UNSUPPORTED_POINTER_MAP_VERSION) => "UNSUPPORTED_POINTER_MAP_VERSION",
        @intFromEnum(LmStatus.POINTER_MODULE_INDEX_OUT_OF_RANGE) => "POINTER_MODULE_INDEX_OUT_OF_RANGE",
        @intFromEnum(LmStatus.POINTER_MAP_CREATE_FAILED) => "POINTER_MAP_CREATE_FAILED",
        @intFromEnum(LmStatus.POINTER_MAP_READ_FAILED) => "POINTER_MAP_READ_FAILED",
        @intFromEnum(LmStatus.POINTER_MAP_WRITE_FAILED) => "POINTER_MAP_WRITE_FAILED",
        @intFromEnum(LmStatus.OPTION_REQUIRES_RESET) => "OPTION_REQUIRES_RESET",
        else => "INVALID_STATUS",
    };
}

pub export fn lm_scanner_create() ?*LmScanner {
    const handle = c_allocator.create(AbiScanner) catch return null;
    handle.* = .{
        .scanner = Scanner.init(c_allocator, std.Io.Threaded.global_single_threaded.io()),
    };
    return @ptrCast(handle);
}

pub export fn lm_scanner_destroy(raw: ?*LmScanner) void {
    const handle = toHandle(raw) orelse return;
    handle.scanner.deinit();
    c_allocator.destroy(handle);
}

pub export fn lm_attach(raw: ?*LmScanner, pid: c_uint) c_int {
    const handle = toHandle(raw) orelse return @intFromEnum(LmStatus.INVALID_ARGUMENT);
    const pid_value = std.math.cast(std.posix.pid_t, pid) orelse return @intFromEnum(LmStatus.INVALID_ARGUMENT);
    handle.scanner.attach(pid_value) catch |err| return @intFromEnum(statusFrom(err));
    return @intFromEnum(LmStatus.OK);
}

pub export fn lm_detach(raw: ?*LmScanner) c_int {
    const handle = toHandle(raw) orelse return @intFromEnum(LmStatus.INVALID_ARGUMENT);
    handle.scanner.detach();
    return @intFromEnum(LmStatus.OK);
}

pub export fn lm_reset(raw: ?*LmScanner) c_int {
    const handle = toHandle(raw) orelse return @intFromEnum(LmStatus.INVALID_ARGUMENT);
    handle.scanner.reset() catch |err| return @intFromEnum(statusFrom(err));
    return @intFromEnum(LmStatus.OK);
}

pub export fn lm_set_scan_level(raw: ?*LmScanner, level: c_int) c_int {
    const handle = toHandle(raw) orelse return @intFromEnum(LmStatus.INVALID_ARGUMENT);
    const level_enum: ScanLevel = switch (level) {
        @intFromEnum(LmScanLevel.ALL) => .ALL,
        @intFromEnum(LmScanLevel.ALL_RW) => .ALL_RW,
        @intFromEnum(LmScanLevel.HEAP_STACK_EXE) => .HEAP_STACK_EXE,
        @intFromEnum(LmScanLevel.HEAP_STACK_EXE_BSS) => .HEAP_STACK_EXE_BSS,
        else => return @intFromEnum(LmStatus.INVALID_ARGUMENT),
    };
    handle.scanner.setScanLevel(level_enum) catch |err| return @intFromEnum(statusFrom(err));
    return @intFromEnum(LmStatus.OK);
}

pub export fn lm_set_data_type(raw: ?*LmScanner, data_type: c_int) c_int {
    const handle = toHandle(raw) orelse return @intFromEnum(LmStatus.INVALID_ARGUMENT);
    const type_enum: ScanDataType = switch (data_type) {
        @intFromEnum(LmDataType.ANYNUMBER) => .ANYNUMBER,
        @intFromEnum(LmDataType.ANYINTEGER) => .ANYINTEGER,
        @intFromEnum(LmDataType.ANYFLOAT) => .ANYFLOAT,
        @intFromEnum(LmDataType.INTEGER8) => .INTEGER8,
        @intFromEnum(LmDataType.INTEGER16) => .INTEGER16,
        @intFromEnum(LmDataType.INTEGER32) => .INTEGER32,
        @intFromEnum(LmDataType.INTEGER64) => .INTEGER64,
        @intFromEnum(LmDataType.FLOAT32) => .FLOAT32,
        @intFromEnum(LmDataType.FLOAT64) => .FLOAT64,
        @intFromEnum(LmDataType.BYTEARRAY) => .BYTEARRAY,
        @intFromEnum(LmDataType.STRING) => .STRING,
        else => return @intFromEnum(LmStatus.INVALID_ARGUMENT),
    };
    handle.scanner.setDataType(type_enum) catch |err| return @intFromEnum(statusFrom(err));
    return @intFromEnum(LmStatus.OK);
}

pub export fn lm_set_reverse_endianness(raw: ?*LmScanner, enabled: bool) c_int {
    const handle = toHandle(raw) orelse return @intFromEnum(LmStatus.INVALID_ARGUMENT);
    handle.scanner.setReverseEndianness(enabled) catch |err| return @intFromEnum(statusFrom(err));
    return @intFromEnum(LmStatus.OK);
}

pub export fn lm_set_alignment(raw: ?*LmScanner, alignment: u16) c_int {
    const handle = toHandle(raw) orelse return @intFromEnum(LmStatus.INVALID_ARGUMENT);
    handle.scanner.setAlignment(alignment) catch |err| return @intFromEnum(statusFrom(err));
    return @intFromEnum(LmStatus.OK);
}

pub export fn lm_set_stop_flag(raw: ?*LmScanner, stop: bool) c_int {
    const handle = toHandle(raw) orelse return @intFromEnum(LmStatus.INVALID_ARGUMENT);
    handle.scanner.setStopFlag(stop);
    return @intFromEnum(LmStatus.OK);
}

pub export fn lm_match_count(raw: ?*LmScanner) usize {
    const handle = toHandle(raw) orelse return 0;
    return handle.scanner.matchCount();
}

pub export fn lm_region_count(raw: ?*LmScanner) usize {
    const handle = toHandle(raw) orelse return 0;
    return handle.scanner.regionCount();
}

pub export fn lm_scan_progress(raw: ?*LmScanner) f64 {
    const handle = toHandle(raw) orelse return 0;
    return handle.scanner.scan_progress;
}

pub export fn lm_snapshot(raw: ?*LmScanner) c_int {
    const handle = toHandle(raw) orelse return @intFromEnum(LmStatus.INVALID_ARGUMENT);
    handle.scanner.snapshot() catch |err| return @intFromEnum(statusFrom(err));
    return @intFromEnum(LmStatus.OK);
}

pub export fn lm_update(raw: ?*LmScanner) c_int {
    const handle = toHandle(raw) orelse return @intFromEnum(LmStatus.INVALID_ARGUMENT);
    handle.scanner.update() catch |err| return @intFromEnum(statusFrom(err));
    return @intFromEnum(LmStatus.OK);
}

pub export fn lm_undo_scan(raw: ?*LmScanner) c_int {
    const handle = toHandle(raw) orelse return @intFromEnum(LmStatus.INVALID_ARGUMENT);
    handle.scanner.undoLastScan() catch |err| return @intFromEnum(statusFrom(err));
    return @intFromEnum(LmStatus.OK);
}

pub export fn lm_scan(raw: ?*LmScanner, match_type: c_int, value1: ?*const LmUserValue, value2: ?*const LmUserValue) c_int {
    const handle = toHandle(raw) orelse return @intFromEnum(LmStatus.INVALID_ARGUMENT);
    const match_enum: ScanMatchType = switch (match_type) {
        @intFromEnum(LmMatchType.MATCHANY) => .MATCHANY,
        @intFromEnum(LmMatchType.MATCHEQUALTO) => .MATCHEQUALTO,
        @intFromEnum(LmMatchType.MATCHNOTEQUALTO) => .MATCHNOTEQUALTO,
        @intFromEnum(LmMatchType.MATCHGREATERTHAN) => .MATCHGREATERTHAN,
        @intFromEnum(LmMatchType.MATCHLESSTHAN) => .MATCHLESSTHAN,
        @intFromEnum(LmMatchType.MATCHRANGE) => .MATCHRANGE,
        @intFromEnum(LmMatchType.MATCHUPDATE) => .MATCHUPDATE,
        @intFromEnum(LmMatchType.MATCHNOTCHANGED) => .MATCHNOTCHANGED,
        @intFromEnum(LmMatchType.MATCHCHANGED) => .MATCHCHANGED,
        @intFromEnum(LmMatchType.MATCHINCREASED) => .MATCHINCREASED,
        @intFromEnum(LmMatchType.MATCHDECREASED) => .MATCHDECREASED,
        @intFromEnum(LmMatchType.MATCHINCREASEDBY) => .MATCHINCREASEDBY,
        @intFromEnum(LmMatchType.MATCHDECREASEDBY) => .MATCHDECREASEDBY,
        else => return @intFromEnum(LmStatus.INVALID_ARGUMENT),
    };
    if (value1 == null and value2 != null) return @intFromEnum(LmStatus.INVALID_ARGUMENT);

    var user_values: [2]UserValue = undefined;
    var user_value_len: usize = 0;

    if (value1) |first| {
        user_values[0] = userValueFromAbi(first.*, handle.scanner.options.scan_data_type, false) catch |err| {
            return @intFromEnum(statusFrom(err));
        };
        user_value_len = 1;
    }

    if (value2) |second| {
        user_values[user_value_len] = userValueFromAbi(second.*, handle.scanner.options.scan_data_type, false) catch |err| {
            return @intFromEnum(statusFrom(err));
        };
        user_value_len += 1;
    }

    handle.scanner.scan(match_enum, user_values[0..user_value_len]) catch |err| return @intFromEnum(statusFrom(err));
    return @intFromEnum(LmStatus.OK);
}

pub export fn lm_pointer_scan(raw: ?*LmScanner, target_address: usize, output_map_path: ?[*:0]const u8, options: ?*const LmPointerScanOptions, out_paths_found: ?*u64) c_int {
    const handle = toHandle(raw) orelse return @intFromEnum(LmStatus.INVALID_ARGUMENT);
    const path = absolutePathFromAbi(output_map_path) orelse return @intFromEnum(LmStatus.INVALID_ARGUMENT);

    const scan_options: PointerScanOptions = if (options) |abi| .{
        .pointer_width = abi.pointer_width,
        .endianness = switch (abi.endianness) {
            @intFromEnum(LmPointerEndianness.NATIVE) => .native,
            @intFromEnum(LmPointerEndianness.LITTLE) => .little,
            @intFromEnum(LmPointerEndianness.BIG) => .big,
            else => return @intFromEnum(LmStatus.INVALID_POINTER_SCAN_OPTIONS),
        },
        .max_depth = abi.max_depth,
        .max_positive_offset = abi.max_positive_offset,
        .max_negative_offset = abi.max_negative_offset,
        .max_results = if (abi.has_max_results) abi.max_results else null,
        .module_base_only = abi.module_base_only,
    } else .{};
    const paths_found = handle.scanner.scanPointers(target_address, path, scan_options) catch |err| return @intFromEnum(statusFrom(err));

    if (out_paths_found) |out| out.* = paths_found;
    return @intFromEnum(LmStatus.OK);
}

pub export fn lm_pointer_map_compare(previous_map_path: ?[*:0]const u8, current_map_path: ?[*:0]const u8, output_map_path: ?[*:0]const u8, out_paths_found: ?*u64) c_int {
    const previous_path = absolutePathFromAbi(previous_map_path) orelse return @intFromEnum(LmStatus.INVALID_ARGUMENT);
    const current_path = absolutePathFromAbi(current_map_path) orelse return @intFromEnum(LmStatus.INVALID_ARGUMENT);
    const output_path = absolutePathFromAbi(output_map_path) orelse return @intFromEnum(LmStatus.INVALID_ARGUMENT);
    if (std.mem.eql(u8, output_path, previous_path) or std.mem.eql(u8, output_path, current_path)) return @intFromEnum(LmStatus.INVALID_ARGUMENT);

    const io = std.Io.Threaded.global_single_threaded.io();
    const previous_file = std.Io.Dir.openFileAbsolute(io, previous_path, .{}) catch return @intFromEnum(LmStatus.POINTER_MAP_READ_FAILED);
    var previous_file_owned = true;
    errdefer if (previous_file_owned) previous_file.close(io);

    const current_file = std.Io.Dir.openFileAbsolute(io, current_path, .{}) catch return @intFromEnum(LmStatus.POINTER_MAP_READ_FAILED);
    var current_file_owned = true;
    errdefer if (current_file_owned) current_file.close(io);

    const output_file = std.Io.Dir.createFileAbsolute(io, output_path, .{ .read = true, .truncate = true }) catch return @intFromEnum(LmStatus.POINTER_MAP_CREATE_FAILED);
    var output_file_owned = true;
    errdefer if (output_file_owned) output_file.close(io);

    previous_file_owned = false;
    current_file_owned = false;
    output_file_owned = false;
    const paths_found = pointerscan.comparePointerMaps(c_allocator, io, previous_file, current_file, output_file) catch |err| return @intFromEnum(statusFrom(err));

    if (out_paths_found) |out| out.* = paths_found;
    return @intFromEnum(LmStatus.OK);
}

// TODO: Should replace this temporary dump API with a streaming pointer map reader
// so we avoid making another text file but dump the output into a window without huge allocations.
pub export fn lm_pointer_map_dump_text(map_path: ?[*:0]const u8, output_text_path: ?[*:0]const u8) c_int {
    const input_path = absolutePathFromAbi(map_path) orelse return @intFromEnum(LmStatus.INVALID_ARGUMENT);
    const output_path = absolutePathFromAbi(output_text_path) orelse return @intFromEnum(LmStatus.INVALID_ARGUMENT);
    if (std.mem.eql(u8, output_path, input_path)) return @intFromEnum(LmStatus.INVALID_ARGUMENT);

    const io = std.Io.Threaded.global_single_threaded.io();
    const input_file = std.Io.Dir.openFileAbsolute(io, input_path, .{}) catch return @intFromEnum(LmStatus.POINTER_MAP_READ_FAILED);
    var reader = pointerscan.PointerMapReader.init(c_allocator, io, input_file) catch |err| return @intFromEnum(statusFrom(err));
    defer reader.deinit();

    const output_file = std.Io.Dir.createFileAbsolute(io, output_path, .{ .truncate = true }) catch return @intFromEnum(LmStatus.WRITE_FAILED);
    defer output_file.close(io);

    var buffer: [16 * 1024]u8 = undefined;
    var output_writer = output_file.writer(io, &buffer);
    reader.dumpText(&output_writer.interface) catch |err| return @intFromEnum(statusFrom(err));
    output_writer.flush() catch return @intFromEnum(LmStatus.WRITE_FAILED);
    return @intFromEnum(LmStatus.OK);
}

pub export fn lm_remove_region_by_id(raw: ?*LmScanner, region_id: usize, removed: ?*bool) c_int {
    const handle = toHandle(raw) orelse return @intFromEnum(LmStatus.INVALID_ARGUMENT);
    const value_bool = handle.scanner.removeRegionById(region_id) catch |err| return @intFromEnum(statusFrom(err));
    if (removed) |out| out.* = value_bool;
    return @intFromEnum(LmStatus.OK);
}

pub export fn lm_remove_match_by_index(raw: ?*LmScanner, match_index: usize, removed: ?*bool) c_int {
    const handle = toHandle(raw) orelse return @intFromEnum(LmStatus.INVALID_ARGUMENT);
    const value_bool = handle.scanner.removeMatchByIndex(match_index) catch |err| return @intFromEnum(statusFrom(err));
    if (removed) |out| out.* = value_bool;
    return @intFromEnum(LmStatus.OK);
}

pub export fn lm_remove_match_by_address(raw: ?*LmScanner, address: usize, removed: ?*bool) c_int {
    const handle = toHandle(raw) orelse return @intFromEnum(LmStatus.INVALID_ARGUMENT);
    const value_bool = handle.scanner.removeMatchByAddress(address) catch |err| return @intFromEnum(statusFrom(err));
    if (removed) |out| out.* = value_bool;
    return @intFromEnum(LmStatus.OK);
}

pub export fn lm_get_region(
    raw: ?*LmScanner,
    region_index: usize,
    out_record: ?*LmRegionRecord,
    filename_buf: ?[*]u8,
    filename_buf_len: usize,
    out_filename_len: ?*usize,
) c_int {
    const handle = toHandle(raw) orelse return @intFromEnum(LmStatus.INVALID_ARGUMENT);
    const out = out_record orelse return @intFromEnum(LmStatus.INVALID_ARGUMENT);
    const record = handle.scanner.regionAt(region_index) catch |err| return @intFromEnum(statusFrom(err));
    const region = record.region;

    out.* = .{
        .index = record.index,
        .id = region.id,
        .start = region.start,
        .size = region.size,
        .kind = @intFromEnum(region.kind),
        .flags_bits = @bitCast(region.flags),
        .load_addr = region.load_addr,
    };

    if (out_filename_len) |len_out| len_out.* = region.filename.len;
    if (region.filename.len == 0) return @intFromEnum(LmStatus.OK);

    const buf_ptr = filename_buf orelse return @intFromEnum(LmStatus.BUFFER_TOO_SMALL);
    if (filename_buf_len < region.filename.len) return @intFromEnum(LmStatus.BUFFER_TOO_SMALL);
    @memcpy(buf_ptr[0..region.filename.len], region.filename);
    return @intFromEnum(LmStatus.OK);
}

pub export fn lm_find_match_index_by_address(raw: ?*LmScanner, address: usize, out_index: ?*usize) c_int {
    const handle = toHandle(raw) orelse return @intFromEnum(LmStatus.INVALID_ARGUMENT);
    if (out_index == null) return @intFromEnum(LmStatus.INVALID_ARGUMENT);
    if (handle.scanner.findMatchIndexByAddress(address)) |index| {
        out_index.?.* = index;
        return @intFromEnum(LmStatus.OK);
    }
    return @intFromEnum(LmStatus.NO_MATCHES);
}

pub export fn lm_get_match(raw: ?*LmScanner, match_index: usize, out_record: ?*LmMatchRecord) c_int {
    const handle = toHandle(raw) orelse return @intFromEnum(LmStatus.INVALID_ARGUMENT);
    const out = out_record orelse return @intFromEnum(LmStatus.INVALID_ARGUMENT);
    const record = handle.scanner.matchAt(match_index) catch |err| return @intFromEnum(statusFrom(err));
    out.* = .{
        .index = record.index,
        .address = record.address,
        .stored_value = record.stored_value,
        .raw_match_info_bits = record.raw_match_info_bits,
    };
    return @intFromEnum(LmStatus.OK);
}

pub export fn lm_get_stored_match_bytes(raw: ?*LmScanner, match_index: usize, buf: ?[*]u8, buf_len: usize, out_len: ?*usize) c_int {
    const handle = toHandle(raw) orelse return @intFromEnum(LmStatus.INVALID_ARGUMENT);
    const buf_ptr = buf orelse return @intFromEnum(LmStatus.INVALID_ARGUMENT);
    const bytes = handle.scanner.storedMatchBytes(match_index, buf_ptr[0..buf_len]) catch |err| return @intFromEnum(statusFrom(err));
    if (out_len) |out| out.* = bytes.len;
    return @intFromEnum(LmStatus.OK);
}

pub export fn lm_read_bytes_exact(raw: ?*LmScanner, address: usize, buf: ?[*]u8, buf_len: usize) c_int {
    const handle = toHandle(raw) orelse return @intFromEnum(LmStatus.INVALID_ARGUMENT);
    const buf_ptr = buf orelse return @intFromEnum(LmStatus.INVALID_ARGUMENT);
    handle.scanner.readBytesExact(address, buf_ptr[0..buf_len]) catch |err| return @intFromEnum(statusFrom(err));
    return @intFromEnum(LmStatus.OK);
}

pub export fn lm_read_match_bytes(raw: ?*LmScanner, match_index: usize, buf: ?[*]u8, buf_len: usize, out_len: ?*usize) c_int {
    const handle = toHandle(raw) orelse return @intFromEnum(LmStatus.INVALID_ARGUMENT);
    const buf_ptr = buf orelse return @intFromEnum(LmStatus.INVALID_ARGUMENT);
    const bytes = handle.scanner.readMatchBytes(match_index, buf_ptr[0..buf_len]) catch |err| return @intFromEnum(statusFrom(err));
    if (out_len) |out| out.* = bytes.len;
    return @intFromEnum(LmStatus.OK);
}

pub export fn lm_write_bytes(raw: ?*LmScanner, address: usize, data: ?[*]const u8, data_len: usize) c_int {
    const handle = toHandle(raw) orelse return @intFromEnum(LmStatus.INVALID_ARGUMENT);
    const data_ptr = data orelse return @intFromEnum(LmStatus.INVALID_ARGUMENT);
    handle.scanner.writeBytes(address, data_ptr[0..data_len]) catch |err| return @intFromEnum(statusFrom(err));
    return @intFromEnum(LmStatus.OK);
}

pub export fn lm_write_value(raw: ?*LmScanner, address: usize, value_obj: ?*const LmUserValue) c_int {
    const handle = toHandle(raw) orelse return @intFromEnum(LmStatus.INVALID_ARGUMENT);
    const raw_value = value_obj orelse return @intFromEnum(LmStatus.INVALID_ARGUMENT);
    const user_value = userValueFromAbi(raw_value.*, handle.scanner.options.scan_data_type, true) catch |err| {
        return @intFromEnum(statusFrom(err));
    };
    handle.scanner.writeValue(address, user_value) catch |err| return @intFromEnum(statusFrom(err));
    return @intFromEnum(LmStatus.OK);
}

pub export fn lm_write_match(raw: ?*LmScanner, match_index: usize, value_obj: ?*const LmUserValue) c_int {
    const handle = toHandle(raw) orelse return @intFromEnum(LmStatus.INVALID_ARGUMENT);
    const raw_value = value_obj orelse return @intFromEnum(LmStatus.INVALID_ARGUMENT);
    const user_value = userValueFromAbi(raw_value.*, handle.scanner.options.scan_data_type, true) catch |err| {
        return @intFromEnum(statusFrom(err));
    };
    handle.scanner.writeMatch(match_index, user_value) catch |err| return @intFromEnum(statusFrom(err));
    return @intFromEnum(LmStatus.OK);
}
