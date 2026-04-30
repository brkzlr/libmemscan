//! High-level scanner/session state

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
const process = @import("process.zig");
const scanroutines = @import("scanroutines.zig");
const targetmem = @import("targetmem.zig");
const value_mod = @import("value.zig");

pub const ProcessHandle = process.ProcessHandle;
pub const ProcessError = process.ProcessError;
pub const Region = process.Region;
pub const ScanLevel = process.ScanLevel;
pub const ScanDataType = scanroutines.ScanDataType;
pub const ScanMatchType = scanroutines.ScanMatchType;
pub const ScanRoutine = scanroutines.ScanRoutine;
pub const ScanResult = scanroutines.ScanResult;
pub const SaveInfo = scanroutines.SaveInfo;
pub const MatchesArray = targetmem.MatchesArray;
pub const MatchIterator = targetmem.MatchIterator;
pub const MatchLocation = targetmem.MatchLocation;
pub const StorageError = targetmem.StorageError;
pub const UserValue = value_mod.UserValue;
pub const Value = value_mod.Value;
pub const MatchFlags = value_mod.MatchFlags;

const Allocator = std.mem.Allocator;

pub const ScannerError = error{
    InvalidArgument,
    AlreadyAttached,
    NotAttached,
    NoRegions,
    NoMatches,
    NoUndo,
    UndoIoFailed,
    UndoCorrupt,
    SnapshotRequiresReset,
    MatchIndexOutOfRange,
    BufferTooSmall,
    InvalidUserValueCount,
    InvalidAlignment,
    InvalidWriteValue,
    InvalidWriteLength,
    UnsupportedScanCombination,
    UnsupportedReadDataType,
    UnsupportedWriteDataType,
} || ProcessError || StorageError;

pub const ScanOptions = struct {
    alignment: u16 = 1,
    scan_data_type: ScanDataType = .ANYINTEGER,
    scan_level: ScanLevel = .HEAP_STACK_EXE_BSS,
    reverse_endianness: bool = false,
};

pub const PreparedScan = struct {
    routine: ScanRoutine,
    match_type: ScanMatchType,
    data_type: ScanDataType,

    pub fn maxMatchLength(self: PreparedScan, user_values: []const UserValue) usize {
        return switch (self.data_type) {
            .INTEGER8 => 1,
            .INTEGER16 => 2,
            .INTEGER32 => 4,
            .INTEGER64 => 8,
            .FLOAT32 => 4,
            .FLOAT64 => 8,
            .ANYINTEGER, .ANYFLOAT, .ANYNUMBER => 8,
            .BYTEARRAY => switch (self.match_type) {
                .MATCHANY => std.math.maxInt(u16),
                else => if (user_values.len == 0) 0 else if (user_values[0].bytearray_value) |bytes| bytes.len else 0,
            },
            .STRING => switch (self.match_type) {
                .MATCHANY => std.math.maxInt(u16),
                else => if (user_values.len == 0) 0 else if (user_values[0].string_value) |text| text.len else 0,
            },
        };
    }
};

pub const MatchRecord = struct {
    index: usize,
    address: usize,
    stored_value: Value,
    raw_match_info_bits: u16,
};

pub const RegionRecord = struct {
    index: usize,
    region: Region,
};

pub const NumericMatchSnapshot = struct {
    match: MatchRecord,
    current_value: Value,
};

const UndoMetadata = struct {
    num_matches: usize,
    options: ScanOptions,
};

const UndoFileHeader = extern struct {
    num_matches: u64,
    used_len: u64,
    max_needed_bytes: u64,
    tail_swath_offset: u64,
    match_count: u64,
    alignment: u16,
    scan_data_type: u16,
    scan_level: u16,
    reverse_endianness: u8,
    _padding: [5]u8 = [_]u8{0} ** 5,

    fn init(scanner: *const Scanner, matches: *const MatchesArray) UndoFileHeader {
        return .{
            .num_matches = @intCast(scanner.num_matches),
            .used_len = @intCast(matches.used_len),
            .max_needed_bytes = @intCast(matches.max_needed_bytes),
            .tail_swath_offset = @intCast(matches.tail_swath_offset),
            .match_count = @intCast(matches.match_count),
            .alignment = scanner.options.alignment,
            .scan_data_type = @intFromEnum(scanner.options.scan_data_type),
            .scan_level = @intFromEnum(scanner.options.scan_level),
            .reverse_endianness = @intFromBool(scanner.options.reverse_endianness),
        };
    }

    fn validate(self: UndoFileHeader) ScannerError!void {
        if (self.used_len < @sizeOf(targetmem.SwathHeader)) return ScannerError.UndoCorrupt;
        if (self.tail_swath_offset >= self.used_len) return ScannerError.UndoCorrupt;
    }

    fn undoMetadata(self: UndoFileHeader) UndoMetadata {
        return .{
            .num_matches = @intCast(self.num_matches),
            .options = .{
                .alignment = self.alignment,
                .scan_data_type = @enumFromInt(self.scan_data_type),
                .scan_level = @enumFromInt(self.scan_level),
                .reverse_endianness = self.reverse_endianness != 0,
            },
        };
    }
};

pub const Scanner = struct {
    allocator: Allocator,
    io: std.Io,
    process_handle: ?ProcessHandle = null,
    target_pid: ?std.posix.pid_t = null,
    regions: []Region = &.{},
    matches: ?MatchesArray = null,
    undo_file: ?std.Io.File = null,
    undo_available: bool = false,
    num_matches: usize = 0,
    scan_progress: f64 = 0,
    stop_flag: bool = false,
    fresh_session: bool = true,
    options: ScanOptions = .{},

    pub fn init(allocator: Allocator, io: std.Io) Scanner {
        return .{
            .allocator = allocator,
            .io = io,
        };
    }

    pub fn deinit(self: *Scanner) void {
        self.resetMatches();
        self.clearUndoHistory();
        self.clearRegions();

        self.closeUndoFile();

        if (self.process_handle) |*handle| {
            handle.deinit();
            self.process_handle = null;
        }

        self.target_pid = null;
        self.scan_progress = 0;
        self.stop_flag = false;
    }

    pub fn attach(self: *Scanner, pid: std.posix.pid_t) ScannerError!void {
        if (self.process_handle != null) return ScannerError.AlreadyAttached;

        var handle = try ProcessHandle.attach(self.io, pid);
        errdefer handle.deinit();

        self.process_handle = handle;
        self.target_pid = pid;
        self.fresh_session = true;
        try self.reloadRegions();
    }

    pub fn detach(self: *Scanner) void {
        self.resetMatches();
        self.clearUndoHistory();
        self.clearRegions();

        if (self.process_handle) |*handle| {
            handle.deinit();
        }
        self.process_handle = null;
        self.target_pid = null;
        self.scan_progress = 0;
        self.stop_flag = false;
        self.fresh_session = true;
    }

    pub fn reloadRegions(self: *Scanner) ScannerError!void {
        self.clearRegions();

        if (self.process_handle) |*handle| {
            self.regions = try handle.readRegions(self.allocator, self.options.scan_level);
            return;
        }

        return ScannerError.NotAttached;
    }

    pub fn setScanLevel(self: *Scanner, level: ScanLevel) ScannerError!void {
        self.options.scan_level = level;
        if (self.process_handle != null) {
            try self.reloadRegions();
        }
    }

    pub fn setDataType(self: *Scanner, data_type: ScanDataType) void {
        self.options.scan_data_type = data_type;
    }

    pub fn setReverseEndianness(self: *Scanner, enabled: bool) void {
        self.options.reverse_endianness = enabled;
    }

    pub fn setStopFlag(self: *Scanner, stop: bool) void {
        self.stop_flag = stop;
    }

    pub fn reset(self: *Scanner) ScannerError!void {
        self.resetMatches();
        self.clearUndoHistory();
        self.scan_progress = 0;
        self.stop_flag = false;
        self.fresh_session = true;

        if (self.process_handle != null) {
            try self.reloadRegions();
        }
    }

    pub fn regionCount(self: *const Scanner) usize {
        return self.regions.len;
    }

    pub fn regionAt(self: *const Scanner, region_index: usize) ScannerError!RegionRecord {
        if (self.regions.len == 0) return ScannerError.NoRegions;
        if (region_index >= self.regions.len) return ScannerError.InvalidArgument;
        return .{
            .index = region_index,
            .region = self.regions[region_index],
        };
    }

    pub fn matchCount(self: *const Scanner) usize {
        return self.num_matches;
    }

    pub fn hasMatches(self: *const Scanner) bool {
        return self.matches != null and self.num_matches != 0;
    }

    pub fn matchAt(self: *const Scanner, match_index: usize) ScannerError!MatchRecord {
        const matches = self.matches orelse return ScannerError.NoMatches;
        const location = matches.nthMatch(match_index) orelse return ScannerError.MatchIndexOutOfRange;
        return .{
            .index = match_index,
            .address = location.remoteAddress(&matches),
            .stored_value = location.value(&matches),
            .raw_match_info_bits = location.rawMatchInfoBits(&matches),
        };
    }

    pub fn findMatchIndexByAddress(self: *const Scanner, address: usize) ?usize {
        const matches = self.matches orelse return null;
        return matches.findMatchIndexByAddress(address);
    }

    pub fn removeMatchByIndex(self: *Scanner, match_index: usize) ScannerError!bool {
        if (self.matches == null) return false;
        const matches = &self.matches.?;
        const location = matches.nthMatch(match_index) orelse return ScannerError.MatchIndexOutOfRange;
        matches.removeMatch(location);
        self.num_matches = matches.matchCount();
        return true;
    }

    pub fn removeMatchByAddress(self: *Scanner, address: usize) ScannerError!bool {
        const match_index = self.findMatchIndexByAddress(address) orelse return false;
        return self.removeMatchByIndex(match_index);
    }

    pub fn removeRegionById(self: *Scanner, region_id: usize) ScannerError!bool {
        return (try self.removeRegionsByIdSet(&.{region_id})) != 0;
    }

    pub fn removeRegionsByIdSet(self: *Scanner, region_ids: []const usize) ScannerError!usize {
        if (region_ids.len == 0 or self.regions.len == 0) return 0;

        var removed_count: usize = 0;
        for (self.regions) |region| {
            if (regionIdIncluded(region.id, region_ids)) {
                removed_count += 1;
            }
        }
        if (removed_count == 0) return 0;

        const kept_len = self.regions.len - removed_count;
        var kept_regions: []Region = &.{};
        if (kept_len != 0) {
            kept_regions = self.allocator.alloc(Region, kept_len) catch return ScannerError.OutOfMemory;
            errdefer self.allocator.free(kept_regions);
        }

        if (self.matches) |*matches| {
            for (self.regions) |region| {
                if (!regionIdIncluded(region.id, region_ids)) continue;
                try matches.deleteInAddressRange(region.start, region.start + region.size);
            }
            self.num_matches = matches.matchCount();
        }

        var write_index: usize = 0;
        for (self.regions) |region| {
            if (regionIdIncluded(region.id, region_ids)) {
                var owned = region;
                owned.deinit(self.allocator);
            } else {
                kept_regions[write_index] = region;
                write_index += 1;
            }
        }

        if (self.regions.len > 0) {
            self.allocator.free(self.regions);
        }
        self.regions = kept_regions;
        self.clearUndoHistory();
        return removed_count;
    }

    pub fn ensureMatchStorage(self: *Scanner, max_needed_bytes: usize) ScannerError!*MatchesArray {
        if (self.matches == null) {
            self.matches = try MatchesArray.init(self.allocator, max_needed_bytes);
            self.num_matches = 0;
        }

        return &self.matches.?;
    }

    pub fn prepareScan(
        self: *const Scanner,
        match_type: ScanMatchType,
        user_values: []const UserValue,
    ) ScannerError!PreparedScan {
        if (self.process_handle == null) return ScannerError.NotAttached;
        if (self.regions.len == 0) return ScannerError.NoRegions;

        const routine = scanroutines.chooseRoutine(
            self.options.scan_data_type,
            match_type,
            user_values,
            self.options.reverse_endianness,
        ) orelse return ScannerError.UnsupportedScanCombination;

        return .{
            .routine = routine,
            .match_type = match_type,
            .data_type = self.options.scan_data_type,
        };
    }

    pub fn scan(self: *Scanner, match_type: ScanMatchType, user_values: []const UserValue) ScannerError!void {
        if (self.matches == null or self.num_matches == 0) {
            self.clearUndoHistory();
            try self.initialScan(match_type, user_values);
            self.fresh_session = false;
        } else {
            try self.saveCurrentMatchesForUndo();
            try self.rescanMatches(match_type, user_values);
        }
    }

    pub fn snapshot(self: *Scanner) ScannerError!void {
        if (!self.fresh_session) return ScannerError.SnapshotRequiresReset;
        self.clearUndoHistory();
        try self.initialScan(.MATCHANY, &.{});
        self.fresh_session = false;
    }

    pub fn update(self: *Scanner) ScannerError!void {
        try self.scan(.MATCHUPDATE, &.{});
    }

    pub fn readBytes(self: *Scanner, address: usize, buf: []u8) ScannerError!usize {
        if (self.process_handle) |*handle| {
            return handle.read(address, buf);
        }
        return ScannerError.NotAttached;
    }

    pub fn readBytesExact(self: *Scanner, address: usize, buf: []u8) ScannerError!void {
        var offset: usize = 0;
        while (offset < buf.len) {
            const nread = try self.readBytes(address + offset, buf[offset..]);
            if (nread == 0) return ScannerError.ReadFailed;
            offset += nread;
        }
    }

    pub fn readOwnedBytes(self: *Scanner, allocator: Allocator, address: usize, len: usize) ScannerError![]u8 {
        const bytes = allocator.alloc(u8, len) catch return ScannerError.OutOfMemory;
        errdefer allocator.free(bytes);
        try self.readBytesExact(address, bytes);
        return bytes;
    }

    pub fn readMatchBytes(self: *Scanner, match_index: usize, buf: []u8) ScannerError![]const u8 {
        const record = try self.matchAt(match_index);
        const length = try matchReadLength(self.options.scan_data_type, record.raw_match_info_bits);
        if (buf.len < length) return ScannerError.BufferTooSmall;

        try self.readBytesExact(record.address, buf[0..length]);
        return buf[0..length];
    }

    pub fn readNumericMatchValue(self: *Scanner, match_index: usize) ScannerError!Value {
        const record = try self.matchAt(match_index);
        const flags = try matchReadFlags(self.options.scan_data_type, record.raw_match_info_bits);
        return self.readValueWithFlags(record.address, flags);
    }

    pub fn currentNumericMatchValue(self: *Scanner, match_index: usize) ScannerError!NumericMatchSnapshot {
        const record = try self.matchAt(match_index);
        return .{
            .match = record,
            .current_value = try self.readNumericMatchValue(match_index),
        };
    }

    pub fn readOwnedMatchBytes(self: *Scanner, allocator: Allocator, match_index: usize) ScannerError![]u8 {
        const record = try self.matchAt(match_index);
        const length = try matchReadLength(self.options.scan_data_type, record.raw_match_info_bits);
        return self.readOwnedBytes(allocator, record.address, length);
    }

    pub fn storedMatchBytes(self: *const Scanner, match_index: usize, buf: []u8) ScannerError![]const u8 {
        const matches = self.matches orelse return ScannerError.NoMatches;
        const location = matches.nthMatch(match_index) orelse return ScannerError.MatchIndexOutOfRange;
        const length = storedLengthForExistingMatch(self.options.scan_data_type, location.rawMatchInfoBits(&matches));
        if (length == 0) return ScannerError.UnsupportedReadDataType;
        if (buf.len < length) return ScannerError.BufferTooSmall;

        return matches.dataToBytes(location.swath_offset, location.index, length, buf);
    }

    pub fn undoLastScan(self: *Scanner) ScannerError!void {
        if (!self.undo_available) return ScannerError.NoUndo;
        const metadata = try self.loadUndoMatches();
        self.num_matches = metadata.num_matches;
        self.options = metadata.options;
        self.scan_progress = 1.0;
        self.undo_available = false;
    }

    pub fn clearUndoHistory(self: *Scanner) void {
        if (self.undo_file) |file| {
            file.setLength(self.io, 0) catch {};
        }
        self.undo_available = false;
    }

    pub fn writeBytes(self: *Scanner, address: usize, data: []const u8) ScannerError!void {
        if (data.len == 0) return ScannerError.InvalidWriteValue;
        if (self.process_handle) |*handle| {
            try handle.write(address, data);
            return;
        }
        return ScannerError.NotAttached;
    }

    pub fn writeValue(self: *Scanner, address: usize, user_value: UserValue) ScannerError!void {
        var scratch: [8]u8 = undefined;
        const data = try serializeWriteValue(
            self.options.scan_data_type,
            self.options.reverse_endianness,
            user_value,
            null,
            &scratch,
        );
        try self.writeBytes(address, data);
    }

    pub fn writeMatch(self: *Scanner, match_index: usize, user_value: UserValue) ScannerError!void {
        const matches = self.matches orelse return ScannerError.NoMatches;
        const location = matches.nthMatch(match_index) orelse return ScannerError.MatchIndexOutOfRange;

        const expected_length: ?usize = switch (self.options.scan_data_type) {
            .BYTEARRAY, .STRING => storedLengthForExistingMatch(
                self.options.scan_data_type,
                location.rawMatchInfoBits(&matches),
            ),
            else => null,
        };

        var scratch: [8]u8 = undefined;
        const data = try serializeWriteValue(
            self.options.scan_data_type,
            self.options.reverse_endianness,
            user_value,
            expected_length,
            &scratch,
        );
        try self.writeBytes(location.remoteAddress(&matches), data);
    }

    pub fn initialScan(self: *Scanner, match_type: ScanMatchType, user_values: []const UserValue) ScannerError!void {
        if (self.options.alignment == 0) return ScannerError.InvalidAlignment;

        const prepared = try self.prepareScan(match_type, user_values);
        const handle = &self.process_handle.?;

        self.resetMatches();
        const matches = try self.ensureMatchStorage(calculateMaxMatchStorage(self.regions));
        errdefer {
            matches.deinit();
            self.matches = null;
            self.num_matches = 0;
        }

        const overlap = prepared.maxMatchLength(user_values);
        const chunk_payload_size: usize = 1 << 20;
        const alloc_size = chunk_payload_size + @max(overlap, 1);
        const buffer = self.allocator.alloc(u8, alloc_size) catch return ScannerError.OutOfMemory;
        defer self.allocator.free(buffer);

        self.num_matches = 0;
        self.scan_progress = 0;
        self.stop_flag = false;

        const total_bytes = totalRegionBytes(self.regions);
        var processed_bytes: usize = 0;
        var required_extra_bytes: usize = 0;

        for (self.regions) |region| {
            var region_offset: usize = 0;

            while (region_offset < region.size) {
                if (self.stop_flag) break;

                const remaining = region.size - region_offset;
                const read_size = @min(remaining, chunk_payload_size + overlap);
                const bytes_read = handle.read(region.start + region_offset, buffer[0..read_size]) catch 0;
                if (bytes_read == 0) break;
                const scan_chunk = initialScanChunkDecision(region_offset, region.size, bytes_read, read_size, overlap);

                try scanChunkIntoMatches(
                    matches,
                    prepared,
                    user_values,
                    region.start + region_offset,
                    buffer[0..bytes_read],
                    scan_chunk.scan_limit,
                    self.options.alignment,
                    &required_extra_bytes,
                    &self.num_matches,
                );

                region_offset += scanLimitAdvance(scan_chunk.scan_limit);
                processed_bytes += scan_chunk.scan_limit;
                self.scan_progress = if (total_bytes == 0) 1.0 else @min(1.0, @as(f64, @floatFromInt(processed_bytes)) / @as(f64, @floatFromInt(total_bytes)));

                if (scan_chunk.scan_limit == 0) break;
                if (scan_chunk.stop_region) break;
            }

            required_extra_bytes = 0;
            if (self.stop_flag) break;
        }

        try matches.finalize();
        self.scan_progress = 1.0;
    }

    pub fn rescanMatches(self: *Scanner, match_type: ScanMatchType, user_values: []const UserValue) ScannerError!void {
        if (self.options.alignment == 0) return ScannerError.InvalidAlignment;
        const prepared = try self.prepareScan(match_type, user_values);
        const handle = &self.process_handle.?;
        const existing_matches = self.matches orelse return ScannerError.NoMatches;

        var byte_count: usize = 0;
        var count_iter = existing_matches.storedByteIterator();
        while (count_iter.next() != null) {
            byte_count += 1;
        }

        var new_matches = try MatchesArray.init(self.allocator, existing_matches.usedBytes());
        errdefer new_matches.deinit();

        self.num_matches = 0;
        self.scan_progress = 0;
        self.stop_flag = false;

        var iterator = existing_matches.storedByteIterator();
        var processed: usize = 0;
        var required_extra_bytes: usize = 0;
        var cache = MemoryCache{};

        while (iterator.next()) |stored| {
            if (self.stop_flag) break;

            if (stored.isMatch()) {
                const old_length = storedLengthForExistingMatch(prepared.data_type, stored.raw_match_info_bits);
                if (old_length > 0) {
                    const memory = cache.peek(handle, stored.address, @intCast(old_length)) catch {
                        required_extra_bytes = 0;
                        processed += 1;
                        self.scan_progress = if (byte_count == 0) 1.0 else @min(1.0, @as(f64, @floatFromInt(processed)) / @as(f64, @floatFromInt(byte_count)));
                        continue;
                    };
                    const old_value = existing_matches.dataToValue(stored.swath_offset, stored.index);
                    const result = prepared.routine(memory, &old_value, user_values);

                    if (result.matched_len > 0) {
                        try appendScanResult(&new_matches, stored.address, memory[0], result.save, &self.num_matches);
                        required_extra_bytes = result.matched_len - 1;
                    } else if (required_extra_bytes > 0) {
                        try new_matches.append(stored.address, memory[0], @bitCast(@as(u16, 0)));
                        required_extra_bytes -= 1;
                    }
                }
            } else if (required_extra_bytes > 0) {
                const memory = cache.peek(handle, stored.address, 1) catch {
                    required_extra_bytes = 0;
                    processed += 1;
                    self.scan_progress = if (byte_count == 0) 1.0 else @min(1.0, @as(f64, @floatFromInt(processed)) / @as(f64, @floatFromInt(byte_count)));
                    continue;
                };
                try new_matches.append(stored.address, memory[0], @bitCast(@as(u16, 0)));
                required_extra_bytes -= 1;
            }

            processed += 1;
            self.scan_progress = if (byte_count == 0) 1.0 else @min(1.0, @as(f64, @floatFromInt(processed)) / @as(f64, @floatFromInt(byte_count)));
        }

        try new_matches.finalize();
        const new_match_count = self.num_matches;
        self.resetMatches();
        self.matches = new_matches;
        self.num_matches = new_match_count;
        self.scan_progress = 1.0;
    }

    fn resetMatches(self: *Scanner) void {
        if (self.matches) |*matches| {
            matches.deinit();
            self.matches = null;
        }
        self.num_matches = 0;
    }

    fn clearRegions(self: *Scanner) void {
        for (self.regions) |*region| {
            region.deinit(self.allocator);
        }
        if (self.regions.len > 0) {
            self.allocator.free(self.regions);
        }
        self.regions = &.{};
    }

    fn readValueWithFlags(self: *Scanner, address: usize, flags: MatchFlags) ScannerError!Value {
        const length = flagsToNumericLength(flags);
        if (length == 0) return ScannerError.UnsupportedReadDataType;

        var value = Value{
            .data = .{ .uint64_value = 0 },
            .flags = flags,
        };
        try self.readBytesExact(address, value.data.bytes[0..length]);
        return value;
    }

    fn ensureUndoFile(self: *Scanner) ScannerError!*std.Io.File {
        if (self.undo_file == null) {
            self.undo_file = std.Io.Dir.createFileAbsolute(self.io, "/tmp/libmemscan-undo.bin", .{
                .read = true,
                .truncate = true,
            }) catch return ScannerError.UndoIoFailed;
        }

        return &self.undo_file.?;
    }

    fn closeUndoFile(self: *Scanner) void {
        if (self.undo_file) |file| {
            file.close(self.io);
            std.Io.Dir.deleteFileAbsolute(self.io, "/tmp/libmemscan-undo.bin") catch {};
            self.undo_file = null;
        }
    }

    fn saveCurrentMatchesForUndo(self: *Scanner) ScannerError!void {
        const matches = self.matches orelse return ScannerError.NoMatches;
        const file = try self.ensureUndoFile();
        const header = UndoFileHeader.init(self, &matches);

        file.setLength(self.io, 0) catch return ScannerError.UndoIoFailed;
        file.writePositionalAll(self.io, std.mem.asBytes(&header), 0) catch return ScannerError.UndoIoFailed;
        file.writePositionalAll(self.io, matches.storage[0..matches.used_len], @sizeOf(UndoFileHeader)) catch return ScannerError.UndoIoFailed;
        self.undo_available = true;
    }

    fn loadUndoMatches(self: *Scanner) ScannerError!UndoMetadata {
        const file = self.undo_file orelse return ScannerError.NoUndo;

        var header: UndoFileHeader = undefined;
        const header_bytes = file.readPositionalAll(self.io, std.mem.asBytes(&header), 0) catch return ScannerError.UndoIoFailed;
        if (header_bytes != @sizeOf(UndoFileHeader)) return ScannerError.UndoCorrupt;
        try header.validate();

        const used_len: usize = @intCast(header.used_len);

        if (self.matches) |*matches| {
            if (matches.storage.len >= used_len) {
                const storage = matches.storage[0..used_len];
                const storage_bytes = file.readPositionalAll(self.io, storage, @sizeOf(UndoFileHeader)) catch return ScannerError.UndoIoFailed;
                if (storage_bytes != storage.len) return ScannerError.UndoCorrupt;

                matches.used_len = used_len;
                matches.max_needed_bytes = @intCast(header.max_needed_bytes);
                matches.tail_swath_offset = @intCast(header.tail_swath_offset);
                matches.match_count = @intCast(header.match_count);
                return header.undoMetadata();
            }
        }

        self.resetMatches();
        const storage = self.allocator.alignedAlloc(u8, std.mem.Alignment.of(targetmem.SwathHeader), used_len) catch return ScannerError.OutOfMemory;
        errdefer self.allocator.free(storage);

        const storage_bytes = file.readPositionalAll(self.io, storage, @sizeOf(UndoFileHeader)) catch return ScannerError.UndoIoFailed;
        if (storage_bytes != storage.len) return ScannerError.UndoCorrupt;

        self.matches = .{
            .allocator = self.allocator,
            .storage = storage,
            .used_len = used_len,
            .max_needed_bytes = @intCast(header.max_needed_bytes),
            .tail_swath_offset = @intCast(header.tail_swath_offset),
            .match_count = @intCast(header.match_count),
        };

        return header.undoMetadata();
    }
};

const MemoryCache = struct {
    const read_chunk_size: usize = 2048;
    const max_size: usize = (1 << 16) + read_chunk_size;

    cache: [max_size]u8 = [_]u8{0} ** max_size,
    size: usize = 0,
    base: ?usize = null,

    fn peek(self: *MemoryCache, handle: *ProcessHandle, addr: usize, length: u16) ScannerError![]const u8 {
        const request_end = addr + length;

        if (self.base) |base| {
            const cache_end = base + self.size;
            if (addr >= base and request_end <= cache_end) {
                return self.cache[(addr - base)..self.size];
            }

            if (addr >= base and addr < cache_end) {
                var missing_bytes = request_end - cache_end;
                missing_bytes = read_chunk_size * (1 + (missing_bytes - 1) / read_chunk_size);

                if (self.size + missing_bytes > max_size) {
                    var shift_size = addr - base;
                    shift_size = read_chunk_size * (shift_size / read_chunk_size);

                    std.mem.copyForwards(u8, self.cache[0 .. self.size - shift_size], self.cache[shift_size..self.size]);
                    self.size -= shift_size;
                    self.base = base + shift_size;
                }
            } else {
                self.size = 0;
                self.base = addr;
            }
        } else {
            self.base = addr;
        }

        while (self.base.? + self.size < request_end) {
            const target_address = self.base.? + self.size;
            const read_len = @min(read_chunk_size, max_size - self.size);
            const nread = handle.read(target_address, self.cache[self.size .. self.size + read_len]) catch return ScannerError.ReadFailed;
            if (nread == 0) return ScannerError.ReadFailed;
            self.size += nread;
            if (nread < read_len) break;
        }

        const base = self.base orelse return ScannerError.ReadFailed;
        if (addr >= base + self.size) return ScannerError.ReadFailed;
        return self.cache[(addr - base)..self.size];
    }
};

fn scanChunkIntoMatches(
    matches: *MatchesArray,
    prepared: PreparedScan,
    user_values: []const UserValue,
    base_address: usize,
    chunk: []const u8,
    scan_limit: usize,
    alignment: u16,
    required_extra_bytes: *usize,
    num_matches: *usize,
) ScannerError!void {
    var offset: usize = 0;
    while (offset < scan_limit) : (offset += 1) {
        const absolute_address = base_address + offset;
        const should_check = alignment == 1 or absolute_address % alignment == 0;
        const result = if (should_check)
            prepared.routine(chunk[offset..], null, user_values)
        else
            ScanResult.noMatch();

        if (result.matched_len > 0) {
            try appendScanResult(matches, absolute_address, chunk[offset], result.save, num_matches);
            required_extra_bytes.* = result.matched_len - 1;
        } else if (required_extra_bytes.* > 0) {
            try matches.append(absolute_address, chunk[offset], @bitCast(@as(u16, 0)));
            required_extra_bytes.* -= 1;
        }
    }
}

fn appendScanResult(
    matches: *MatchesArray,
    address: usize,
    old_byte: u8,
    save: SaveInfo,
    num_matches: *usize,
) ScannerError!void {
    const raw_bits = save.raw();
    if (raw_bits == 0) return;

    try matches.append(address, old_byte, @bitCast(raw_bits));
    num_matches.* += 1;
}

fn storedLengthForExistingMatch(data_type: ScanDataType, raw_bits: u16) usize {
    return switch (data_type) {
        .BYTEARRAY, .STRING => raw_bits,
        else => flagsToNumericLength(@bitCast(raw_bits)),
    };
}

fn canonicalReadFlags(data_type: ScanDataType) ScannerError!MatchFlags {
    return switch (data_type) {
        .INTEGER8 => MatchFlags.i8b,
        .INTEGER16 => MatchFlags.i16b,
        .INTEGER32 => MatchFlags.i32b,
        .INTEGER64 => MatchFlags.i64b,
        .FLOAT32 => .{ .f32b = true },
        .FLOAT64 => .{ .f64b = true },
        else => ScannerError.UnsupportedReadDataType,
    };
}

fn matchReadLength(data_type: ScanDataType, raw_bits: u16) ScannerError!usize {
    return switch (data_type) {
        .BYTEARRAY, .STRING => if (raw_bits == 0) ScannerError.UnsupportedReadDataType else raw_bits,
        else => blk: {
            const length = flagsToNumericLength(@bitCast(raw_bits));
            if (length == 0) return ScannerError.UnsupportedReadDataType;
            break :blk length;
        },
    };
}

fn matchReadFlags(data_type: ScanDataType, raw_bits: u16) ScannerError!MatchFlags {
    return switch (data_type) {
        .BYTEARRAY, .STRING => ScannerError.UnsupportedReadDataType,
        .ANYINTEGER, .ANYFLOAT, .ANYNUMBER => blk: {
            const flags: MatchFlags = @bitCast(raw_bits);
            if (!flags.hasAny()) return ScannerError.UnsupportedReadDataType;
            break :blk flags;
        },
        else => canonicalReadFlags(data_type),
    };
}

fn serializeWriteValue(
    data_type: ScanDataType,
    reverse_endianness: bool,
    user_value: UserValue,
    expected_length: ?usize,
    scratch: *[8]u8,
) ScannerError![]const u8 {
    const endian: std.builtin.Endian = if (reverse_endianness) .big else .little;

    return switch (data_type) {
        .INTEGER8 => blk: {
            scratch[0] = try encodeInteger8(user_value);
            break :blk scratch[0..1];
        },
        .INTEGER16 => blk: {
            std.mem.writeInt(u16, scratch[0..2], try encodeInteger16(user_value), endian);
            break :blk scratch[0..2];
        },
        .INTEGER32 => blk: {
            std.mem.writeInt(u32, scratch[0..4], try encodeInteger32(user_value), endian);
            break :blk scratch[0..4];
        },
        .INTEGER64 => blk: {
            std.mem.writeInt(u64, scratch[0..8], try encodeInteger64(user_value), endian);
            break :blk scratch[0..8];
        },
        .FLOAT32 => blk: {
            if (!user_value.flags.f32b) return ScannerError.InvalidWriteValue;
            std.mem.writeInt(u32, scratch[0..4], @bitCast(user_value.float32_value), endian);
            break :blk scratch[0..4];
        },
        .FLOAT64 => blk: {
            if (!user_value.flags.f64b) return ScannerError.InvalidWriteValue;
            std.mem.writeInt(u64, scratch[0..8], @bitCast(user_value.float64_value), endian);
            break :blk scratch[0..8];
        },
        .BYTEARRAY => {
            const bytes = user_value.bytearray_value orelse return ScannerError.InvalidWriteValue;
            if (expected_length) |len| {
                if (bytes.len != len) return ScannerError.InvalidWriteLength;
            }
            return bytes;
        },
        .STRING => {
            const text = user_value.string_value orelse return ScannerError.InvalidWriteValue;
            if (expected_length) |len| {
                if (text.len != len) return ScannerError.InvalidWriteLength;
            }
            return text;
        },
        .ANYINTEGER, .ANYFLOAT, .ANYNUMBER => return ScannerError.UnsupportedWriteDataType,
    };
}

fn encodeInteger8(user_value: UserValue) ScannerError!u8 {
    if (user_value.flags.u8b) return user_value.uint8_value;
    if (user_value.flags.s8b) return @bitCast(user_value.int8_value);
    return ScannerError.InvalidWriteValue;
}

fn encodeInteger16(user_value: UserValue) ScannerError!u16 {
    if (user_value.flags.u16b) return user_value.uint16_value;
    if (user_value.flags.s16b) return @bitCast(user_value.int16_value);
    return ScannerError.InvalidWriteValue;
}

fn encodeInteger32(user_value: UserValue) ScannerError!u32 {
    if (user_value.flags.u32b) return user_value.uint32_value;
    if (user_value.flags.s32b) return @bitCast(user_value.int32_value);
    return ScannerError.InvalidWriteValue;
}

fn encodeInteger64(user_value: UserValue) ScannerError!u64 {
    if (user_value.flags.u64b) return user_value.uint64_value;
    if (user_value.flags.s64b) return @bitCast(user_value.int64_value);
    return ScannerError.InvalidWriteValue;
}

fn flagsToNumericLength(flags: value_mod.MatchFlags) usize {
    if (flags.u64b or flags.s64b or flags.f64b) return 8;
    if (flags.u32b or flags.s32b or flags.f32b) return 4;
    if (flags.u16b or flags.s16b) return 2;
    if (flags.u8b or flags.s8b) return 1;
    return 0;
}

const InitialScanChunkDecision = struct {
    scan_limit: usize,
    stop_region: bool,
};

fn initialScanChunkDecision(
    region_offset: usize,
    region_size: usize,
    bytes_read: usize,
    read_size: usize,
    overlap: usize,
) InitialScanChunkDecision {
    const short_read = bytes_read < read_size;
    const scan_limit = if (short_read or region_offset + bytes_read >= region_size or bytes_read <= overlap)
        bytes_read
    else
        bytes_read - overlap;

    return .{
        .scan_limit = scan_limit,
        .stop_region = short_read,
    };
}

fn totalRegionBytes(regions: []const Region) usize {
    var total: usize = 0;
    for (regions) |region| {
        total += region.size;
    }
    return total;
}

fn calculateMaxMatchStorage(regions: []const Region) usize {
    var total: usize = @sizeOf(targetmem.SwathHeader);
    for (regions) |region| {
        total += @sizeOf(targetmem.SwathHeader);
        total += region.size * @sizeOf(targetmem.OldValueAndMatchInfo);
    }
    total += @sizeOf(targetmem.SwathHeader);
    return total;
}

fn scanLimitAdvance(scan_limit: usize) usize {
    return if (scan_limit == 0) 0 else scan_limit;
}

fn regionIdIncluded(region_id: u32, region_ids: []const usize) bool {
    for (region_ids) |candidate| {
        if (candidate > std.math.maxInt(u32)) continue;
        if (region_id == @as(u32, @intCast(candidate))) return true;
    }
    return false;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "Init: starts detached with defaults" {
    var scanner = Scanner.init(std.testing.allocator, std.testing.io);
    defer scanner.deinit();

    try std.testing.expect(scanner.process_handle == null);
    try std.testing.expect(scanner.target_pid == null);
    try std.testing.expectEqual(@as(usize, 0), scanner.regionCount());
    try std.testing.expectEqual(@as(usize, 0), scanner.matchCount());
    try std.testing.expect(!scanner.hasMatches());
    try std.testing.expect(!scanner.undo_available);
    try std.testing.expect(scanner.fresh_session);
    try std.testing.expect(!scanner.stop_flag);
    try std.testing.expectEqual(@as(f64, 0), scanner.scan_progress);
    try std.testing.expectEqual(@as(u16, 1), scanner.options.alignment);
    try std.testing.expectEqual(ScanDataType.ANYINTEGER, scanner.options.scan_data_type);
    try std.testing.expectEqual(ScanLevel.HEAP_STACK_EXE_BSS, scanner.options.scan_level);
    try std.testing.expect(!scanner.options.reverse_endianness);
}

test "prepareScan: requires attachment" {
    var scanner = Scanner.init(std.testing.allocator, std.testing.io);
    defer scanner.deinit();

    const user = try UserValue.parseNumber("5");
    try std.testing.expectError(ScannerError.NotAttached, scanner.prepareScan(.MATCHEQUALTO, &.{user}));
}

test "ensureMatchStorage: allocates lazily" {
    var scanner = Scanner.init(std.testing.allocator, std.testing.io);
    defer scanner.deinit();

    const matches = try scanner.ensureMatchStorage(256);
    try std.testing.expectEqual(@as(usize, 0), matches.matchCount());
    try std.testing.expect(scanner.matches != null);
    try std.testing.expect(matches.storage.len >= @sizeOf(targetmem.SwathHeader));
    try std.testing.expect(matches.storage.len <= 256);
    try std.testing.expectEqual(@as(usize, 256), matches.max_needed_bytes);

    const storage_ptr = scanner.matches.?.storage.ptr;
    const storage_len = scanner.matches.?.storage.len;
    const reused = try scanner.ensureMatchStorage(512);
    try std.testing.expectEqual(storage_ptr, reused.storage.ptr);
    try std.testing.expectEqual(storage_len, reused.storage.len);
    try std.testing.expectEqual(@as(usize, 256), reused.max_needed_bytes);
}

test "setters update scanner options" {
    var scanner = Scanner.init(std.testing.allocator, std.testing.io);
    defer scanner.deinit();

    scanner.setDataType(.FLOAT64);
    try scanner.setScanLevel(.ALL_RW);
    scanner.setReverseEndianness(true);
    scanner.setStopFlag(true);

    try std.testing.expectEqual(ScanDataType.FLOAT64, scanner.options.scan_data_type);
    try std.testing.expectEqual(ScanLevel.ALL_RW, scanner.options.scan_level);
    try std.testing.expect(scanner.options.reverse_endianness);
    try std.testing.expect(scanner.stop_flag);
}

test "match helpers expose stored match ergonomically" {
    var scanner = Scanner.init(std.testing.allocator, std.testing.io);
    defer scanner.deinit();

    var matches = try MatchesArray.init(std.testing.allocator, 256);
    try matches.append(0x4000, 0x78, .{ .u32b = true, .s32b = true });
    try matches.append(0x4001, 0x56, .{});
    try matches.append(0x4002, 0x34, .{});
    try matches.append(0x4003, 0x12, .{});
    try matches.finalize();

    scanner.matches = matches;
    scanner.num_matches = matches.matchCount();

    const first = try scanner.matchAt(0);
    try std.testing.expectEqual(@as(usize, 0), first.index);
    try std.testing.expectEqual(@as(usize, 0x4000), first.address);
    try std.testing.expectEqual(@as(u16, (MatchFlags{ .u32b = true, .s32b = true }).bits()), first.raw_match_info_bits);
    try std.testing.expectEqual(@as(u16, (MatchFlags{ .u32b = true, .s32b = true }).bits()), first.stored_value.flags.bits());
    try std.testing.expectEqual(@as(u32, 0x12345678), first.stored_value.data.uint32_value);
    try std.testing.expectEqual(@as(usize, 0), scanner.findMatchIndexByAddress(0x4000).?);
    try std.testing.expectEqual(@as(?usize, null), scanner.findMatchIndexByAddress(0x4001));
    try std.testing.expectEqual(@as(usize, 1), scanner.matchCount());
    try std.testing.expect(scanner.hasMatches());
    try std.testing.expectError(ScannerError.MatchIndexOutOfRange, scanner.matchAt(1));
}

test "storedMatchBytes: returns raw stored bytes" {
    var scanner = Scanner.init(std.testing.allocator, std.testing.io);
    defer scanner.deinit();

    var numeric_matches = try MatchesArray.init(std.testing.allocator, 256);
    try numeric_matches.append(0x5000, 0x2a, .{ .u8b = true, .s8b = true });
    try numeric_matches.finalize();

    scanner.matches = numeric_matches;
    scanner.num_matches = numeric_matches.matchCount();
    scanner.options.scan_data_type = .INTEGER8;

    var numeric_buf: [1]u8 = undefined;
    try std.testing.expectEqualSlices(u8, &[_]u8{0x2a}, try scanner.storedMatchBytes(0, &numeric_buf));
    try std.testing.expectError(ScannerError.MatchIndexOutOfRange, scanner.storedMatchBytes(1, &numeric_buf));

    scanner.resetMatches();
    scanner.scan_progress = 0;

    var byte_matches = try MatchesArray.init(std.testing.allocator, 256);
    try byte_matches.append(0x6000, 0xaa, @bitCast(@as(u16, 3)));
    try byte_matches.append(0x6001, 0xbb, .{});
    try byte_matches.append(0x6002, 0xcc, .{});
    try byte_matches.finalize();

    scanner.matches = byte_matches;
    scanner.num_matches = byte_matches.matchCount();
    scanner.options.scan_data_type = .BYTEARRAY;

    var byte_buf: [3]u8 = undefined;
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0xaa, 0xbb, 0xcc }, try scanner.storedMatchBytes(0, &byte_buf));
}

test "clearUndoHistory: clears temp-file backed undo state" {
    var scanner = Scanner.init(std.testing.allocator, std.testing.io);
    defer scanner.deinit();

    var matches = try MatchesArray.init(std.testing.allocator, 256);
    try matches.append(0x7000, 0x2a, .{ .u8b = true, .s8b = true });
    try matches.finalize();

    scanner.matches = matches;
    scanner.num_matches = matches.matchCount();
    scanner.options.scan_data_type = .INTEGER8;
    try scanner.saveCurrentMatchesForUndo();

    try std.testing.expect(scanner.undo_available);
    const undo_file = scanner.undo_file.?;
    try std.testing.expect((try undo_file.length(scanner.io)) > 0);

    scanner.clearUndoHistory();
    try std.testing.expect(!scanner.undo_available);
    try std.testing.expectEqual(@as(u64, 0), try undo_file.length(scanner.io));
    var byte: [1]u8 = undefined;
    try std.testing.expectEqual(@as(usize, 0), try undo_file.readPositionalAll(scanner.io, &byte, 0));
}

test "undoLastScan: restores previous match list and options" {
    var scanner = Scanner.init(std.testing.allocator, std.testing.io);
    defer scanner.deinit();

    var old_matches = try MatchesArray.init(std.testing.allocator, 256);
    try old_matches.append(0x7100, 0x11, .{ .u8b = true, .s8b = true });
    try old_matches.finalize();

    var current_matches = try MatchesArray.init(std.testing.allocator, 256);
    try current_matches.append(0x7200, 0x22, .{ .u8b = true, .s8b = true });
    try current_matches.finalize();

    scanner.matches = old_matches;
    scanner.num_matches = old_matches.matchCount();
    scanner.options = .{
        .alignment = 4,
        .scan_data_type = .INTEGER8,
        .scan_level = .ALL_RW,
        .reverse_endianness = true,
    };
    try scanner.saveCurrentMatchesForUndo();

    scanner.resetMatches();
    scanner.matches = current_matches;
    scanner.num_matches = current_matches.matchCount();
    scanner.options = .{
        .alignment = 1,
        .scan_data_type = .FLOAT64,
        .scan_level = .ALL,
        .reverse_endianness = false,
    };

    try scanner.undoLastScan();

    try std.testing.expect(!scanner.undo_available);
    try std.testing.expectEqual(@as(usize, 1), scanner.matchCount());
    try std.testing.expectEqual(@as(u16, 4), scanner.options.alignment);
    try std.testing.expectEqual(ScanDataType.INTEGER8, scanner.options.scan_data_type);
    try std.testing.expectEqual(ScanLevel.ALL_RW, scanner.options.scan_level);
    try std.testing.expect(scanner.options.reverse_endianness);
    try std.testing.expectEqual(@as(f64, 1), scanner.scan_progress);

    const restored = try scanner.matchAt(0);
    try std.testing.expectEqual(@as(usize, 0x7100), restored.address);
    try std.testing.expectEqual(@as(u8, 0x11), restored.stored_value.data.uint8_value);
}

test "snapshot: requires a fresh reset state" {
    var scanner = Scanner.init(std.testing.allocator, std.testing.io);
    defer scanner.deinit();

    scanner.fresh_session = false;
    try std.testing.expectError(ScannerError.SnapshotRequiresReset, scanner.snapshot());

    var matches = try MatchesArray.init(std.testing.allocator, 256);
    try matches.append(0x7300, 0x44, .{ .u8b = true, .s8b = true });
    try matches.finalize();

    scanner.matches = matches;
    scanner.num_matches = matches.matchCount();
    scanner.options.scan_data_type = .INTEGER8;
    try scanner.saveCurrentMatchesForUndo();

    try scanner.reset();
    try std.testing.expect(scanner.fresh_session);
    try std.testing.expect(!scanner.undo_available);
    try std.testing.expect(!scanner.hasMatches());
    try std.testing.expectEqual(@as(usize, 0), scanner.matchCount());
    try std.testing.expectEqual(@as(f64, 0), scanner.scan_progress);
    try std.testing.expect(!scanner.stop_flag);
}

test "removeRegionById: prunes affected matches and shrinks region list" {
    var scanner = Scanner.init(std.testing.allocator, std.testing.io);
    defer scanner.deinit();

    scanner.regions = try std.testing.allocator.alloc(Region, 2);
    scanner.regions[0] = .{
        .start = 0x1000,
        .size = 0x10,
        .kind = .HEAP,
        .flags = .{ .read = true, .write = true, .exec = false, .shared = false, .private = true },
        .load_addr = 0,
        .id = 1,
        .filename = try std.testing.allocator.dupe(u8, "[heap]"),
    };
    scanner.regions[1] = .{
        .start = 0x2000,
        .size = 0x10,
        .kind = .HEAP,
        .flags = .{ .read = true, .write = true, .exec = false, .shared = false, .private = true },
        .load_addr = 0,
        .id = 2,
        .filename = try std.testing.allocator.dupe(u8, "[heap]"),
    };

    var matches = try MatchesArray.init(std.testing.allocator, 256);
    try matches.append(0x1000, 0xaa, .{ .u8b = true, .s8b = true });
    try matches.append(0x1008, 0xbb, .{ .u8b = true, .s8b = true });
    try matches.append(0x2000, 0xcc, .{ .u8b = true, .s8b = true });
    try matches.finalize();

    scanner.matches = matches;
    scanner.num_matches = matches.matchCount();

    const removed = try scanner.removeRegionById(1);
    try std.testing.expect(removed);
    try std.testing.expectEqual(@as(usize, 1), scanner.regionCount());
    try std.testing.expectEqual(@as(usize, 1), scanner.matchCount());
    try std.testing.expectEqual(@as(u32, 2), scanner.regions[0].id);
    try std.testing.expectEqual(@as(usize, 0x2000), (try scanner.matchAt(0)).address);
    try std.testing.expectEqual(@as(?usize, null), scanner.findMatchIndexByAddress(0x1000));
    try std.testing.expectEqual(@as(?usize, null), scanner.findMatchIndexByAddress(0x1008));
}

fn expectStoredByteRangeCleared(matches: *const MatchesArray, start_address: usize, len: usize) !void {
    var offset: usize = 0;
    while (offset < len) : (offset += 1) {
        const address = start_address + offset;
        var iter = matches.storedByteIterator();
        while (iter.next()) |stored| {
            if (stored.address != address) continue;
            try std.testing.expectEqual(@as(u8, 0), stored.old_value);
            try std.testing.expectEqual(@as(u16, 0), stored.raw_match_info_bits);
            break;
        } else {
            return error.TestUnexpectedResult;
        }
    }
}

test "removeMatchByIndex: removes full stored match record" {
    var scanner = Scanner.init(std.testing.allocator, std.testing.io);
    defer scanner.deinit();
    scanner.options.scan_data_type = .INTEGER32;

    var matches = try MatchesArray.init(std.testing.allocator, 256);
    try matches.append(0x1000, 0x78, .{ .u32b = true, .s32b = true });
    try matches.append(0x1001, 0x56, .{});
    try matches.append(0x1002, 0x34, .{});
    try matches.append(0x1003, 0x12, .{});
    try matches.append(0x2000, 0xaa, .{ .u8b = true, .s8b = true });
    try matches.finalize();

    scanner.matches = matches;
    scanner.num_matches = matches.matchCount();

    const removed = try scanner.removeMatchByIndex(0);
    try std.testing.expect(removed);
    try std.testing.expectEqual(@as(usize, 1), scanner.matchCount());
    try std.testing.expectEqual(@as(?usize, null), scanner.findMatchIndexByAddress(0x1000));
    try std.testing.expectEqual(@as(?usize, 0), scanner.findMatchIndexByAddress(0x2000));
    try std.testing.expectEqual(@as(usize, 0x2000), (try scanner.matchAt(0)).address);
    try expectStoredByteRangeCleared(&scanner.matches.?, 0x1000, 4);
}

test "removeMatchByIndex: uses stored match span instead of current scan data type" {
    var scanner = Scanner.init(std.testing.allocator, std.testing.io);
    defer scanner.deinit();
    scanner.options.scan_data_type = .STRING;

    var matches = try MatchesArray.init(std.testing.allocator, 256);
    try matches.append(0x1000, 0x78, .{ .u32b = true, .s32b = true });
    try matches.append(0x1001, 0x56, .{});
    try matches.append(0x1002, 0x34, .{});
    try matches.append(0x1003, 0x12, .{});
    try matches.append(0x2000, 0xaa, @bitCast(@as(u16, 3)));
    try matches.append(0x2001, 0xbb, .{});
    try matches.append(0x2002, 0xcc, .{});
    try matches.finalize();

    scanner.matches = matches;
    scanner.num_matches = matches.matchCount();

    const removed_numeric = try scanner.removeMatchByIndex(0);
    try std.testing.expect(removed_numeric);
    try std.testing.expectEqual(@as(?usize, null), scanner.findMatchIndexByAddress(0x1000));
    try std.testing.expectEqual(@as(?usize, 0), scanner.findMatchIndexByAddress(0x2000));
    try expectStoredByteRangeCleared(&scanner.matches.?, 0x1000, 4);

    scanner.options.scan_data_type = .INTEGER64;
    const removed_variable = try scanner.removeMatchByIndex(0);
    try std.testing.expect(removed_variable);
    try std.testing.expectEqual(@as(usize, 0), scanner.matchCount());
    try std.testing.expectEqual(@as(?usize, null), scanner.findMatchIndexByAddress(0x2000));
    try std.testing.expect(!scanner.hasMatches());
    try expectStoredByteRangeCleared(&scanner.matches.?, 0x2000, 3);
}

test "removeMatchByAddress: removes full stored match record" {
    var scanner = Scanner.init(std.testing.allocator, std.testing.io);
    defer scanner.deinit();
    scanner.options.scan_data_type = .INTEGER32;

    var matches = try MatchesArray.init(std.testing.allocator, 256);
    try matches.append(0x1000, 0x78, .{ .u32b = true, .s32b = true });
    try matches.append(0x1001, 0x56, .{});
    try matches.append(0x1002, 0x34, .{});
    try matches.append(0x1003, 0x12, .{});
    try matches.append(0x2000, 0xaa, .{ .u8b = true, .s8b = true });
    try matches.finalize();

    scanner.matches = matches;
    scanner.num_matches = matches.matchCount();

    const removed = try scanner.removeMatchByAddress(0x1000);
    try std.testing.expect(removed);
    try std.testing.expectEqual(@as(usize, 1), scanner.matchCount());
    try std.testing.expectEqual(@as(?usize, null), scanner.findMatchIndexByAddress(0x1000));
    try std.testing.expectEqual(@as(?usize, 0), scanner.findMatchIndexByAddress(0x2000));
    try std.testing.expectEqual(@as(usize, 0x2000), (try scanner.matchAt(0)).address);
    try expectStoredByteRangeCleared(&scanner.matches.?, 0x1000, 4);
}

test "removeMatchByIndex: removes full variable-length stored match record" {
    var scanner = Scanner.init(std.testing.allocator, std.testing.io);
    defer scanner.deinit();
    scanner.options.scan_data_type = .BYTEARRAY;

    var matches = try MatchesArray.init(std.testing.allocator, 256);
    try matches.append(0x3000, 0xaa, @bitCast(@as(u16, 3)));
    try matches.append(0x3001, 0xbb, .{});
    try matches.append(0x3002, 0xcc, .{});
    try matches.append(0x4000, 0xdd, @bitCast(@as(u16, 2)));
    try matches.append(0x4001, 0xee, .{});
    try matches.finalize();

    scanner.matches = matches;
    scanner.num_matches = matches.matchCount();

    const removed = try scanner.removeMatchByIndex(0);
    try std.testing.expect(removed);
    try std.testing.expectEqual(@as(usize, 1), scanner.matchCount());
    try std.testing.expectEqual(@as(?usize, null), scanner.findMatchIndexByAddress(0x3000));
    try std.testing.expectEqual(@as(?usize, 0), scanner.findMatchIndexByAddress(0x4000));
    var buf: [2]u8 = undefined;
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0xdd, 0xee }, try scanner.storedMatchBytes(0, &buf));
    try expectStoredByteRangeCleared(&scanner.matches.?, 0x3000, 3);
}

test "removeRegionById: is a no-op for missing id" {
    var scanner = Scanner.init(std.testing.allocator, std.testing.io);
    defer scanner.deinit();

    scanner.regions = try std.testing.allocator.alloc(Region, 1);
    scanner.regions[0] = .{
        .start = 0x1000,
        .size = 0x10,
        .kind = .HEAP,
        .flags = .{ .read = true, .write = true, .exec = false, .shared = false, .private = true },
        .load_addr = 0,
        .id = 1,
        .filename = try std.testing.allocator.dupe(u8, "[heap]"),
    };

    const removed = try scanner.removeRegionById(9);
    try std.testing.expect(!removed);
    try std.testing.expectEqual(@as(usize, 1), scanner.regionCount());
    try std.testing.expectEqual(@as(u32, 1), scanner.regions[0].id);
    try std.testing.expectEqualStrings("[heap]", scanner.regions[0].filename);
}

test "removeRegionsByIdSet: is a no-op for empty ids and missing ids" {
    var scanner = Scanner.init(std.testing.allocator, std.testing.io);
    defer scanner.deinit();

    scanner.regions = try std.testing.allocator.alloc(Region, 1);
    scanner.regions[0] = .{
        .start = 0x1000,
        .size = 0x10,
        .kind = .HEAP,
        .flags = .{ .read = true, .write = true, .exec = false, .shared = false, .private = true },
        .load_addr = 0,
        .id = 1,
        .filename = try std.testing.allocator.dupe(u8, "[heap]"),
    };

    try std.testing.expectEqual(@as(usize, 0), try scanner.removeRegionsByIdSet(&.{}));
    try std.testing.expectEqual(@as(usize, 1), scanner.regionCount());
    try std.testing.expectEqual(@as(usize, 0), try scanner.removeRegionsByIdSet(&.{9}));
    try std.testing.expectEqual(@as(usize, 1), scanner.regionCount());
}

test "initialScanChunkDecision: chooses scan limit and region stop from read shape" {
    const Case = struct {
        name: []const u8,
        region_offset: usize,
        region_size: usize,
        bytes_read: usize,
        read_size: usize,
        overlap: usize,
        expected_scan_limit: usize,
        expected_stop_region: bool,
    };

    const cases = [_]Case{
        .{
            .name = "short read scans all bytes and stops region",
            .region_offset = 0x200,
            .region_size = 0x1000,
            .bytes_read = 0x80,
            .read_size = 0x100,
            .overlap = 8,
            .expected_scan_limit = 0x80,
            .expected_stop_region = true,
        },
        .{
            .name = "full middle read leaves trailing overlap for next chunk",
            .region_offset = 0x200,
            .region_size = 0x1000,
            .bytes_read = 0x100,
            .read_size = 0x100,
            .overlap = 8,
            .expected_scan_limit = 0xf8,
            .expected_stop_region = false,
        },
        .{
            .name = "full end read scans through region end",
            .region_offset = 0xf00,
            .region_size = 0x1000,
            .bytes_read = 0x100,
            .read_size = 0x100,
            .overlap = 8,
            .expected_scan_limit = 0x100,
            .expected_stop_region = false,
        },
        .{
            .name = "read no larger than overlap is scanned instead of underflowing",
            .region_offset = 0x200,
            .region_size = 0x1000,
            .bytes_read = 8,
            .read_size = 8,
            .overlap = 8,
            .expected_scan_limit = 8,
            .expected_stop_region = false,
        },
    };

    for (cases) |case| {
        const decision = initialScanChunkDecision(
            case.region_offset,
            case.region_size,
            case.bytes_read,
            case.read_size,
            case.overlap,
        );
        try std.testing.expectEqual(case.expected_scan_limit, decision.scan_limit);
        try std.testing.expectEqual(case.expected_stop_region, decision.stop_region);
    }
}

test "scanChunkIntoMatches: records numeric matches and trailing bytes" {
    var matches = try MatchesArray.init(std.testing.allocator, 256);
    defer matches.deinit();

    const user = try UserValue.parseNumber("1");
    const routine = scanroutines.chooseRoutine(.INTEGER16, .MATCHEQUALTO, &.{user}, false).?;
    const prepared = PreparedScan{
        .routine = routine,
        .match_type = .MATCHEQUALTO,
        .data_type = .INTEGER16,
    };

    const chunk = [_]u8{ 1, 0, 9, 9, 1, 0 };
    var required_extra: usize = 0;
    var num_matches: usize = 0;

    try scanChunkIntoMatches(&matches, prepared, &.{user}, 0x1000, &chunk, chunk.len, 1, &required_extra, &num_matches);
    try matches.finalize();

    try std.testing.expectEqual(@as(usize, 2), num_matches);
    try std.testing.expectEqual(@as(usize, 2), matches.matchCount());
    try std.testing.expectEqual(@as(usize, 0x1000), matches.nthMatch(0).?.remoteAddress(&matches));
    try std.testing.expectEqual(@as(usize, 0x1004), matches.nthMatch(1).?.remoteAddress(&matches));
    try std.testing.expectEqual(@as(u16, 0), matches.rawMatchInfoBits(0, 1));
    try std.testing.expectEqual(@as(usize, 0), required_extra);
    var stored: [2]u8 = undefined;
    try std.testing.expectEqualSlices(u8, &[_]u8{ 1, 0 }, matches.dataToBytes(0, 0, 2, &stored));
}

test "scanChunkIntoMatches: honors alignment gating" {
    var matches = try MatchesArray.init(std.testing.allocator, 256);
    defer matches.deinit();

    const user = try UserValue.parseNumber("1");
    const routine = scanroutines.chooseRoutine(.INTEGER16, .MATCHEQUALTO, &.{user}, false).?;
    const prepared = PreparedScan{
        .routine = routine,
        .match_type = .MATCHEQUALTO,
        .data_type = .INTEGER16,
    };

    const chunk = [_]u8{
        9, // 0x2000: aligned, not a match
        1, // 0x2001: valid INTEGER16 bytes, but unaligned for alignment 2
        0,
        9, // 0x2003: unaligned, not a match
        1, // 0x2004: valid INTEGER16 bytes and aligned
        0,
    };
    var required_extra: usize = 0;
    var num_matches: usize = 0;

    try scanChunkIntoMatches(&matches, prepared, &.{user}, 0x2000, &chunk, chunk.len, 2, &required_extra, &num_matches);
    try matches.finalize();

    try std.testing.expectEqual(@as(usize, 1), num_matches);
    try std.testing.expectEqual(@as(usize, 1), matches.matchCount());
    try std.testing.expectEqual(@as(usize, 0x2004), matches.nthMatch(0).?.remoteAddress(&matches));
    try std.testing.expectEqual(@as(?usize, null), matches.findMatchIndexByAddress(0x2001));
    try std.testing.expectEqual(@as(usize, 0), required_extra);
}

test "serializeWriteValue: encodes little-endian integer32" {
    const user = try UserValue.parseNumber("0x12345678");
    var scratch: [8]u8 = undefined;
    const bytes = try serializeWriteValue(.INTEGER32, false, user, null, &scratch);

    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x78, 0x56, 0x34, 0x12 }, bytes);
}

test "serializeWriteValue: encodes reverse-endian float32" {
    const user = try UserValue.parseFloat("1.5");
    var scratch: [8]u8 = undefined;
    const bytes = try serializeWriteValue(.FLOAT32, true, user, null, &scratch);

    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x3f, 0xc0, 0x00, 0x00 }, bytes);
}

test "serializeWriteValue: rejects ambiguous anynumber writes" {
    const user = try UserValue.parseNumber("7");
    var scratch: [8]u8 = undefined;

    try std.testing.expectError(ScannerError.UnsupportedWriteDataType, serializeWriteValue(.ANYNUMBER, false, user, null, &scratch));
}

test "serializeWriteValue: enforces variable-length match sizes" {
    const string_user = UserValue{ .string_value = "abc" };
    const bytearray_user = UserValue{
        .bytearray_value = @constCast(&[_]u8{ 0xaa, 0xbb, 0xcc }),
        .wildcard_value = @constCast(&[_]value_mod.Wildcard{ .FIXED, .FIXED, .FIXED }),
    };
    var scratch: [8]u8 = undefined;

    try std.testing.expectError(ScannerError.InvalidWriteLength, serializeWriteValue(.STRING, false, string_user, 4, &scratch));
    try std.testing.expectEqualSlices(u8, "abc", try serializeWriteValue(.STRING, false, string_user, 3, &scratch));

    try std.testing.expectError(ScannerError.InvalidWriteLength, serializeWriteValue(.BYTEARRAY, false, bytearray_user, 2, &scratch));
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0xaa, 0xbb, 0xcc }, try serializeWriteValue(.BYTEARRAY, false, bytearray_user, 3, &scratch));
}

test "matchReadFlags: supports anynumber matches from stored bits" {
    const flags = try matchReadFlags(.ANYNUMBER, MatchFlags.i32b.bits());

    try std.testing.expectEqual(@as(u16, MatchFlags.i32b.bits()), flags.bits());
    try std.testing.expectError(ScannerError.UnsupportedReadDataType, matchReadFlags(.ANYNUMBER, 0));
}

test "storedMatchBytes: rejects too-small buffer for variable-length matches" {
    var scanner = Scanner.init(std.testing.allocator, std.testing.io);
    defer scanner.deinit();
    scanner.options.scan_data_type = .BYTEARRAY;

    var matches = try MatchesArray.init(std.testing.allocator, 256);
    try matches.append(0x6000, 0xaa, @bitCast(@as(u16, 3)));
    try matches.append(0x6001, 0xbb, .{});
    try matches.append(0x6002, 0xcc, .{});
    try matches.finalize();

    scanner.matches = matches;
    scanner.num_matches = matches.matchCount();

    var buf: [2]u8 = undefined;
    try std.testing.expectError(ScannerError.BufferTooSmall, scanner.storedMatchBytes(0, &buf));
}

test "readMatchBytes: rejects too-small buffer before process read" {
    var scanner = Scanner.init(std.testing.allocator, std.testing.io);
    defer scanner.deinit();
    scanner.options.scan_data_type = .BYTEARRAY;

    var matches = try MatchesArray.init(std.testing.allocator, 256);
    try matches.append(0x6000, 0xaa, @bitCast(@as(u16, 3)));
    try matches.append(0x6001, 0xbb, .{});
    try matches.append(0x6002, 0xcc, .{});
    try matches.finalize();

    scanner.matches = matches;
    scanner.num_matches = matches.matchCount();

    var buf: [2]u8 = undefined;
    try std.testing.expectError(ScannerError.BufferTooSmall, scanner.readMatchBytes(0, &buf));
}

test "readNumericMatchValue: rejects variable-length matches" {
    var scanner = Scanner.init(std.testing.allocator, std.testing.io);
    defer scanner.deinit();
    scanner.options.scan_data_type = .STRING;

    var matches = try MatchesArray.init(std.testing.allocator, 256);
    try matches.append(0x7000, 'a', @bitCast(@as(u16, 3)));
    try matches.append(0x7001, 'b', .{});
    try matches.append(0x7002, 'c', .{});
    try matches.finalize();

    scanner.matches = matches;
    scanner.num_matches = matches.matchCount();

    try std.testing.expectError(ScannerError.UnsupportedReadDataType, scanner.readNumericMatchValue(0));
}

test "writeMatch: rejects wrong variable-length replacement before process write" {
    var scanner = Scanner.init(std.testing.allocator, std.testing.io);
    defer scanner.deinit();
    scanner.options.scan_data_type = .STRING;

    var matches = try MatchesArray.init(std.testing.allocator, 256);
    try matches.append(0x7000, 'a', @bitCast(@as(u16, 3)));
    try matches.append(0x7001, 'b', .{});
    try matches.append(0x7002, 'c', .{});
    try matches.finalize();

    scanner.matches = matches;
    scanner.num_matches = matches.matchCount();

    try std.testing.expectError(
        ScannerError.InvalidWriteLength,
        scanner.writeMatch(0, UserValue{ .string_value = "toolong" }),
    );
}
