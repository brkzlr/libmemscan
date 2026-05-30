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

const builtin = @import("builtin");
const std = @import("std");
const pointerscan = @import("pointerscan.zig");
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
pub const MatchesArray = targetmem.MatchesArray;
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
    OptionRequiresReset,
    MatchIndexOutOfRange,
    BufferTooSmall,
    InvalidUserValueCount,
    InvalidAlignment,
    InvalidWriteValue,
    InvalidWriteLength,
    UnsupportedScanCombination,
    UnsupportedReadDataType,
    UnsupportedWriteDataType,
} || ProcessError || StorageError || pointerscan.PointerScanError;

pub const ScanOptions = struct {
    alignment: u16 = 0,
    scan_data_type: ScanDataType = .ANYINTEGER,
    scan_level: ScanLevel = .HEAP_STACK_EXE_BSS,
    reverse_endianness: bool = false,
};

pub const PreparedScan = struct {
    match_type: ScanMatchType,
    data_type: ScanDataType,
    reverse_endianness: bool = false,

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

const UndoMetadata = struct {
    num_matches: usize,
    options: ScanOptions,
};

const UndoFileHeader = extern struct {
    num_matches: u64,
    used_len: u64,
    max_needed_bytes: u64,
    match_count: u64,
    stride: u16,
    alignment: u16,
    scan_data_type: u16,
    scan_level: u16,
    reverse_endianness: u8,
    _padding: [7]u8 = @splat(0),
};

pub const Scanner = struct {
    allocator: Allocator,
    io: std.Io,
    process_handle: ?ProcessHandle = null,
    target_pid: ?std.posix.pid_t = null,
    regions: []Region = &.{},
    matches: ?MatchesArray = null,
    undo_file: ?std.Io.File = null,
    undo_path: ?[]u8 = null,
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
        @atomicStore(bool, &self.stop_flag, false, .monotonic);
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
        @atomicStore(bool, &self.stop_flag, false, .monotonic);
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

    pub fn setDataType(self: *Scanner, data_type: ScanDataType) ScannerError!void {
        if (!self.fresh_session) return ScannerError.OptionRequiresReset;
        self.options.scan_data_type = data_type;
    }

    pub fn setReverseEndianness(self: *Scanner, enabled: bool) ScannerError!void {
        if (!self.fresh_session) return ScannerError.OptionRequiresReset;
        self.options.reverse_endianness = enabled;
    }

    pub fn setAlignment(self: *Scanner, alignment: u16) ScannerError!void {
        if (!self.fresh_session) return ScannerError.OptionRequiresReset;
        self.options.alignment = alignment;
    }

    pub fn setStopFlag(self: *Scanner, stop: bool) void {
        @atomicStore(bool, &self.stop_flag, stop, .monotonic);
    }

    pub fn reset(self: *Scanner) ScannerError!void {
        self.resetMatches();
        self.clearUndoHistory();
        self.scan_progress = 0;
        @atomicStore(bool, &self.stop_flag, false, .monotonic);
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
            .address = location.address,
            .stored_value = decodeValueForTargetEndian(self.options.scan_data_type, self.options.reverse_endianness, location.value(&matches)),
            .raw_match_info_bits = location.raw_match_info_bits,
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
        }
        errdefer self.allocator.free(kept_regions);

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
            const stride = effectiveAlignment(self.options.alignment, self.options.scan_data_type);
            self.matches = try MatchesArray.init(self.allocator, max_needed_bytes, stride);
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
        if (!scanroutines.validateCombo(self.options.scan_data_type, match_type, user_values)) {
            return ScannerError.UnsupportedScanCombination;
        }

        return .{
            .match_type = match_type,
            .data_type = self.options.scan_data_type,
            .reverse_endianness = self.options.reverse_endianness,
        };
    }

    pub fn scan(self: *Scanner, match_type: ScanMatchType, user_values: []const UserValue) ScannerError!void {
        if (self.matches == null or self.num_matches == 0) {
            self.clearUndoHistory();
            // MATCHUPDATE on a fresh session has nothing to refresh.
            // Previously this fell through to initialScan, which allocated empty match storage only to produce no matches.
            // Preserve the observable result (0 matches, scanner no longer fresh) without the wasted allocation.
            // PrepareScan still runs so attachment, regions, and combo validity are checked at the boundary.
            if (match_type == .MATCHUPDATE) {
                _ = try self.prepareScan(match_type, user_values);
                self.fresh_session = false;
                return;
            }
            // Old-value-dependent match types match nothing on a fresh session because there is no prior value to compare against.
            // Skip the memory walk and large match-storage allocation.
            // PrepareScan still enforces attachment/regions/combo (including required user values for MATCHINCREASEDBY/MATCHDECREASEDBY).
            switch (match_type) {
                .MATCHCHANGED,
                .MATCHNOTCHANGED,
                .MATCHINCREASED,
                .MATCHDECREASED,
                .MATCHINCREASEDBY,
                .MATCHDECREASEDBY,
                => {
                    _ = try self.prepareScan(match_type, user_values);
                    self.resetMatches();
                    self.scan_progress = 1.0;
                    @atomicStore(bool, &self.stop_flag, false, .monotonic);
                    self.fresh_session = false;
                    return;
                },
                else => {},
            }
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

    pub fn scanPointers(
        self: *Scanner,
        target_address: usize,
        output_map_path: []const u8,
        options: pointerscan.PointerScanOptions,
    ) ScannerError!u64 {
        if (self.process_handle == null) return ScannerError.NotAttached;
        if (self.regions.len == 0) return ScannerError.NoRegions;
        const handle = &self.process_handle.?;
        const max_read_size = try options.maxChunkReadSize();

        const output_map_file = std.Io.Dir.createFileAbsolute(self.io, output_map_path, .{
            .read = true,
            .truncate = true,
        }) catch return ScannerError.MapCreateFailed;
        var output_file_owned = true;
        errdefer if (output_file_owned) output_map_file.close(self.io);

        var entries: std.ArrayList(pointerscan.PointerEntry) = .empty;
        defer entries.deinit(self.allocator);

        // This type works as a sort of filter for pointer values so when we check each pointer during reads
        // we can immediately determine if the pointed value is inside a readable regions.
        var valid_pointer_values = try pointerscan.ValidPointerValueRanges.init(self.allocator, self.regions);
        defer valid_pointer_values.deinit();

        self.scan_progress = 0;
        @atomicStore(bool, &self.stop_flag, false, .monotonic);
        if (valid_pointer_values.len() != 0) {
            const buffer = self.allocator.alloc(u8, max_read_size) catch return ScannerError.OutOfMemory;
            defer self.allocator.free(buffer);

            const total_bytes = totalRegionBytes(self.regions);

            var processed_bytes: usize = 0;
            for (self.regions) |region| {
                if (!region.flags.read or region.size < options.pointer_width) continue;

                var region_offset: usize = 0;
                while (region_offset < region.size) {
                    if (@atomicLoad(bool, &self.stop_flag, .monotonic)) break;

                    const region_remaining = region.size - region_offset;
                    const read_size = @min(region_remaining, max_read_size);

                    const chunk_address = region.start + region_offset;
                    const bytes_read = handle.read(chunk_address, buffer[0..read_size]) catch break;
                    if (bytes_read == 0) break;

                    const scan_advance = try pointerscan.appendEntriesFromChunk(self.allocator, &entries, chunk_address, buffer[0..bytes_read], options, &valid_pointer_values);
                    if (scan_advance == 0) break;

                    region_offset += scan_advance;
                    processed_bytes += scan_advance;
                    updateProgress(self, processed_bytes, total_bytes);
                }

                if (@atomicLoad(bool, &self.stop_flag, .monotonic)) break;
            }
        }
        self.scan_progress = 1.0;

        var index = try pointerscan.PointerReverseIndex.fromEntries(self.allocator, entries.items);
        defer index.deinit();

        const modules = try pointerscan.moduleBasesFromRegions(self.allocator, self.regions);
        defer self.allocator.free(modules);

        output_file_owned = false;
        var map_writer = try pointerscan.PointerMapWriter.init(self.io, output_map_file, options.pointer_width, modules);
        defer map_writer.deinit();

        var finder = try pointerscan.PointerPathFinder.init(self.allocator, &index, modules, options);
        defer finder.deinit();
        finder.stop_flag = &self.stop_flag;

        try finder.findPathsToValue(target_address, &map_writer);
        try map_writer.finish();

        return finder.results_found;
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

    pub fn readMatchBytes(self: *Scanner, match_index: usize, buf: []u8) ScannerError![]const u8 {
        const record = try self.matchAt(match_index);
        const length = switch (self.options.scan_data_type) {
            .BYTEARRAY, .STRING => if (record.raw_match_info_bits == 0)
                return ScannerError.UnsupportedReadDataType
            else
                record.raw_match_info_bits,
            else => blk: {
                const numeric_length = flagsToNumericLength(@bitCast(record.raw_match_info_bits));
                if (numeric_length == 0) return ScannerError.UnsupportedReadDataType;
                break :blk numeric_length;
            },
        };
        if (buf.len < length) return ScannerError.BufferTooSmall;

        try self.readBytesExact(record.address, buf[0..length]);
        return buf[0..length];
    }

    pub fn readNumericMatchValue(self: *Scanner, match_index: usize) ScannerError!Value {
        const record = try self.matchAt(match_index);
        const flags = try matchReadFlags(self.options.scan_data_type, record.raw_match_info_bits);
        const length = flagsToNumericLength(flags);
        if (length == 0) return ScannerError.UnsupportedReadDataType;

        var value = Value{
            .data = .{ .uint64_value = 0 },
            .flags = flags,
        };
        try self.readBytesExact(record.address, value.data.bytes[0..length]);
        return decodeValueForTargetEndian(self.options.scan_data_type, self.options.reverse_endianness, value);
    }

    pub fn storedMatchBytes(self: *const Scanner, match_index: usize, buf: []u8) ScannerError![]const u8 {
        const matches = self.matches orelse return ScannerError.NoMatches;
        const location = matches.nthMatch(match_index) orelse return ScannerError.MatchIndexOutOfRange;
        const length = storedLengthForExistingMatch(self.options.scan_data_type, location.raw_match_info_bits);
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
                location.raw_match_info_bits,
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
        try self.writeBytes(location.address, data);
    }

    pub fn initialScan(self: *Scanner, match_type: ScanMatchType, user_values: []const UserValue) ScannerError!void {
        const prepared = try self.prepareScan(match_type, user_values);
        const handle = &self.process_handle.?;
        const alignment = effectiveAlignment(self.options.alignment, prepared.data_type);
        const initial_kernel = scanroutines.pickInitialNumericKernel(prepared.data_type, match_type, self.options.reverse_endianness);

        self.resetMatches();
        // Upper bound for dense storage: header + 3 B/byte worst case (stride 1 inline raw_bits).
        var max_needed_bytes: usize = 0;
        for (self.regions) |region| {
            max_needed_bytes += @sizeOf(targetmem.SwathHeader) + region.size * 3;
        }
        const matches = try self.ensureMatchStorage(max_needed_bytes);
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
        @atomicStore(bool, &self.stop_flag, false, .monotonic);

        const total_bytes = totalRegionBytes(self.regions);
        var processed_bytes: usize = 0;
        var required_extra_bytes: usize = 0;

        for (self.regions) |region| {
            var region_offset: usize = 0;

            while (region_offset < region.size) {
                if (@atomicLoad(bool, &self.stop_flag, .monotonic)) break;

                const remaining = region.size - region_offset;
                const read_size = @min(remaining, chunk_payload_size + overlap);
                const bytes_read = handle.read(region.start + region_offset, buffer[0..read_size]) catch 0;
                if (bytes_read == 0) break;
                const scan_chunk = initialScanChunkDecision(region_offset, region.size, bytes_read, read_size, overlap);

                try scanChunkIntoMatches(
                    matches,
                    prepared,
                    initial_kernel,
                    user_values,
                    region.start + region_offset,
                    buffer[0..bytes_read],
                    scan_chunk.scan_limit,
                    alignment,
                    &required_extra_bytes,
                    &self.num_matches,
                );

                region_offset += scan_chunk.scan_limit;
                processed_bytes += scan_chunk.scan_limit;
                updateProgress(self, processed_bytes, total_bytes);

                if (scan_chunk.scan_limit == 0) break;
                if (scan_chunk.stop_region) break;
            }

            required_extra_bytes = 0;
            if (@atomicLoad(bool, &self.stop_flag, .monotonic)) break;
        }

        try matches.finalize();
        self.scan_progress = 1.0;
    }

    pub fn rescanMatches(self: *Scanner, match_type: ScanMatchType, user_values: []const UserValue) ScannerError!void {
        // prepareScan validates attachment, regions, and combo (including the STRING/BYTEARRAY length cap in validateCombo)
        // before any scanner-side intercept.
        const prepared = try self.prepareScan(match_type, user_values);

        if (match_type == .MATCHUPDATE) return self.rescanUpdate();
        if (match_type == .MATCHANY) return self.rescanMatchAny(prepared.data_type);
        if (prepared.data_type == .STRING and match_type == .MATCHEQUALTO) {
            return self.rescanStringEqualTo(user_values[0].string_value.?);
        }
        if (prepared.data_type == .BYTEARRAY and match_type == .MATCHEQUALTO) {
            return self.rescanByteArrayEqualTo(user_values[0].bytearray_value.?, user_values[0].wildcard_value.?);
        }

        // STRING/BYTEARRAY were intercepted above (validateCombo only admits MATCHANY/MATCHEQUALTO/MATCHUPDATE for them),
        // so anything still here is numeric with a fixed width.
        // CHANGED/NOTCHANGED operate purely on byte equality, so the integer fast paths handle floats unchanged.
        // Delta paths pre-select a kernel via "pickFixedDeltaKernel" that branches on data_type/match_type/endian at comptime.
        // ANY-types use width = 8 (max read), where the kernel evaluates every sub-width that fits
        // and the per-location path slices per the candidate's stored width.
        const width: usize = switch (prepared.data_type) {
            .INTEGER8 => 1,
            .INTEGER16 => 2,
            .INTEGER32, .FLOAT32 => 4,
            .INTEGER64, .FLOAT64 => 8,
            .ANYINTEGER, .ANYFLOAT, .ANYNUMBER => 8,
            .BYTEARRAY, .STRING => unreachable,
        };
        switch (match_type) {
            .MATCHEQUALTO,
            .MATCHNOTEQUALTO,
            .MATCHGREATERTHAN,
            .MATCHLESSTHAN,
            .MATCHRANGE,
            => return self.rescanFixedWidthCompare(width, match_type, user_values),
            .MATCHCHANGED => return self.rescanFixedWidthChanged(width),
            .MATCHNOTCHANGED => return self.rescanFixedWidthNotChanged(width),
            .MATCHINCREASED,
            .MATCHDECREASED,
            .MATCHINCREASEDBY,
            .MATCHDECREASEDBY,
            => return self.rescanFixedWidthDelta(width, match_type, user_values),
            .MATCHANY, .MATCHUPDATE => unreachable, // intercepted above
        }
    }

    fn rescanUpdate(self: *Scanner) ScannerError!void {
        const handle = &self.process_handle.?;
        if (self.matches == null) return ScannerError.NoMatches;
        const old_matches = &self.matches.?;
        const total_matches = old_matches.matchCount();

        self.num_matches = 0;
        self.scan_progress = 0;
        @atomicStore(bool, &self.stop_flag, false, .monotonic);

        var new_matches = try MatchesArray.init(self.allocator, old_matches.max_needed_bytes, old_matches.stride);
        errdefer new_matches.deinit();

        var iterator = old_matches.iterator();
        var processed: usize = 0;
        var cache = MemoryCache{};
        var writer = RescanSpanWriter{
            .matches = &new_matches,
            .handle = handle,
            .cache = &cache,
        };

        while (iterator.next()) |location| {
            if (@atomicLoad(bool, &self.stop_flag, .monotonic)) break;

            const stored_len = storedLengthForExistingMatch(self.options.scan_data_type, location.raw_match_info_bits);
            if (stored_len != 0) {
                const memory = cache.peek(handle, location.address, stored_len) catch {
                    processed += 1;
                    updateRescanProgress(self, processed, total_matches);
                    continue;
                };
                if (memory.len >= stored_len) {
                    try writer.appendMatch(location.address, memory[0], stored_len, location.raw_match_info_bits);
                    self.num_matches += 1;
                }
            }

            processed += 1;
            updateRescanProgress(self, processed, total_matches);
        }

        try writer.flushBefore(std.math.maxInt(usize));
        try new_matches.finalize();

        var to_free = self.matches.?;
        self.matches = new_matches;
        to_free.deinit();

        self.scan_progress = 1.0;
    }

    fn rescanMatchAny(self: *Scanner, data_type: ScanDataType) ScannerError!void {
        // MATCHANY revisits existing match addresses only and never discovers new ones.
        // For fixed concrete types it refreshes the current bytes and reasserts the type's flag.
        // For ANY-types it re-broadens to every width that fits the previously-stored length.
        // For STRING/BYTEARRAY it preserves the stored variable length.
        const handle = &self.process_handle.?;
        if (self.matches == null) return ScannerError.NoMatches;
        const old_matches = &self.matches.?;
        const total_matches = old_matches.matchCount();

        self.num_matches = 0;
        self.scan_progress = 0;
        @atomicStore(bool, &self.stop_flag, false, .monotonic);

        var new_matches = try MatchesArray.init(self.allocator, old_matches.max_needed_bytes, old_matches.stride);
        errdefer new_matches.deinit();

        var iterator = old_matches.iterator();
        var processed: usize = 0;
        var cache = MemoryCache{};
        var writer = RescanSpanWriter{
            .matches = &new_matches,
            .handle = handle,
            .cache = &cache,
        };

        while (iterator.next()) |location| {
            if (@atomicLoad(bool, &self.stop_flag, .monotonic)) break;

            const stored_len = storedLengthForExistingMatch(data_type, location.raw_match_info_bits);
            if (stored_len != 0) {
                const memory = cache.peek(handle, location.address, stored_len) catch {
                    processed += 1;
                    updateRescanProgress(self, processed, total_matches);
                    continue;
                };
                if (memory.len >= stored_len) {
                    const new_raw_bits = matchAnyRawBitsForStoredLength(data_type, stored_len);
                    if (new_raw_bits != 0) {
                        try writer.appendMatch(location.address, memory[0], stored_len, new_raw_bits);
                        self.num_matches += 1;
                    }
                }
            }

            processed += 1;
            updateRescanProgress(self, processed, total_matches);
        }

        try writer.flushBefore(std.math.maxInt(usize));
        try new_matches.finalize();

        var to_free = self.matches.?;
        self.matches = new_matches;
        to_free.deinit();

        self.scan_progress = 1.0;
    }

    fn rescanStringEqualTo(self: *Scanner, needle: []const u8) ScannerError!void {
        const handle = &self.process_handle.?;
        if (self.matches == null) return ScannerError.NoMatches;
        const old_matches = &self.matches.?;
        const total_matches = old_matches.matchCount();

        self.num_matches = 0;
        self.scan_progress = 0;
        @atomicStore(bool, &self.stop_flag, false, .monotonic);

        var new_matches = try MatchesArray.init(self.allocator, old_matches.max_needed_bytes, old_matches.stride);
        errdefer new_matches.deinit();

        if (needle.len != 0) {
            // Length fits in u16: validateCombo gated "needle.len <= maxInt(u16)".
            const raw_len: u16 = @intCast(needle.len);
            var iterator = old_matches.iterator();
            var processed: usize = 0;
            var cache = MemoryCache{};
            var writer = RescanSpanWriter{
                .matches = &new_matches,
                .handle = handle,
                .cache = &cache,
            };

            while (iterator.next()) |location| {
                if (@atomicLoad(bool, &self.stop_flag, .monotonic)) break;

                const old_len = storedLengthForExistingMatch(.STRING, location.raw_match_info_bits);
                if (old_len >= needle.len) {
                    // Preserve rescan semantics: read the previously stored length, so a longer new needle cannot
                    // match an older shorter string at the same address.
                    const memory = cache.peek(handle, location.address, old_len) catch {
                        processed += 1;
                        updateRescanProgress(self, processed, total_matches);
                        continue;
                    };
                    if (memory.len >= old_len and std.mem.eql(u8, memory[0..needle.len], needle)) {
                        try writer.appendMatch(location.address, memory[0], needle.len, raw_len);
                        self.num_matches += 1;
                    }
                }

                processed += 1;
                updateRescanProgress(self, processed, total_matches);
            }

            try writer.flushBefore(std.math.maxInt(usize));
        }

        try new_matches.finalize();

        var to_free = self.matches.?;
        self.matches = new_matches;
        to_free.deinit();

        self.scan_progress = 1.0;
    }

    fn rescanByteArrayEqualTo(self: *Scanner, pattern: []const u8, wildcards: []const value_mod.Wildcard) ScannerError!void {
        const handle = &self.process_handle.?;
        if (self.matches == null) return ScannerError.NoMatches;
        const old_matches = &self.matches.?;
        const total_matches = old_matches.matchCount();

        self.num_matches = 0;
        self.scan_progress = 0;
        @atomicStore(bool, &self.stop_flag, false, .monotonic);

        var new_matches = try MatchesArray.init(self.allocator, old_matches.max_needed_bytes, old_matches.stride);
        errdefer new_matches.deinit();

        if (pattern.len != 0 and pattern.len == wildcards.len) {
            // Length fits in u16: validateCombo gated "pattern.len <= maxInt(u16)".
            const raw_len: u16 = @intCast(pattern.len);
            var iterator = old_matches.iterator();
            var processed: usize = 0;
            var cache = MemoryCache{};
            var writer = RescanSpanWriter{
                .matches = &new_matches,
                .handle = handle,
                .cache = &cache,
            };

            while (iterator.next()) |location| {
                if (@atomicLoad(bool, &self.stop_flag, .monotonic)) break;

                const old_len = storedLengthForExistingMatch(.BYTEARRAY, location.raw_match_info_bits);
                if (old_len >= pattern.len) {
                    const memory = cache.peek(handle, location.address, old_len) catch {
                        processed += 1;
                        updateRescanProgress(self, processed, total_matches);
                        continue;
                    };
                    if (memory.len >= old_len and bytearrayMatches(memory[0..pattern.len], pattern, wildcards)) {
                        try writer.appendMatch(location.address, memory[0], pattern.len, raw_len);
                        self.num_matches += 1;
                    }
                }

                processed += 1;
                updateRescanProgress(self, processed, total_matches);
            }

            try writer.flushBefore(std.math.maxInt(usize));
        }

        try new_matches.finalize();

        var to_free = self.matches.?;
        self.matches = new_matches;
        to_free.deinit();

        self.scan_progress = 1.0;
    }

    fn rescanFixedWidthCompare(self: *Scanner, width: usize, match_type: ScanMatchType, user_values: []const UserValue) ScannerError!void {
        if (self.matches == null) return ScannerError.NoMatches;
        const handle = &self.process_handle.?;
        const old_matches = &self.matches.?;
        const total_matches = old_matches.matchCount();

        self.num_matches = 0;
        self.scan_progress = 0;
        @atomicStore(bool, &self.stop_flag, false, .monotonic);

        var new_matches = try MatchesArray.init(self.allocator, old_matches.max_needed_bytes, old_matches.stride);
        errdefer new_matches.deinit();

        var read_cache = MemoryCache{};
        var write_cache = MemoryCache{};
        var writer = RescanSpanWriter{
            .matches = &new_matches,
            .handle = handle,
            .cache = &write_cache,
        };
        const raw_bits_scratch = try self.allocator.alloc(u16, stridedBatchLimit(@sizeOf(u8), old_matches.stride));
        defer self.allocator.free(raw_bits_scratch);

        var processed: usize = 0;
        // Pre-select the concrete compare kernel once per pass.
        // All runtime dispatch on data_type / match_type / endian collapses here,
        // leaving the per-candidate hot loop with a direct function-pointer call.
        const kernel = scanroutines.pickFixedCompareKernel(self.options.scan_data_type, match_type, self.options.reverse_endianness);
        // For fixed concrete numeric MATCHEQUALTO over a full-shared stride-1 segment
        // we can replace the per-candidate kernel call with a direct byte search against pre-serialized needle(s).
        // With stride 1, every offset before "valid" is an old candidate start, so every direct-search hit is in-bounds.
        // Reused across segments, serialize once.
        var primary_buf: [8]u8 = undefined;
        var secondary_buf: [8]u8 = undefined;
        const exact_needles: ?ExactNumericNeedles = if (old_matches.stride == 1 and match_type == .MATCHEQUALTO and user_values.len > 0)
            serializeExactNumericNeedles(self.options.scan_data_type, user_values[0], self.options.reverse_endianness, &primary_buf, &secondary_buf)
        else
            null;
        var segments = old_matches.segmentIterator();
        while (segments.next()) |segment| {
            if (@atomicLoad(bool, &self.stop_flag, .monotonic)) break;
            if (fullSharedSegmentWidth(segment, self.options.scan_data_type, width)) |segment_width| {
                if (exact_needles) |needles| {
                    try self.rescanExactFullSegment(old_matches, segment, segment_width, needles, kernel, user_values, &read_cache, &writer, &processed, total_matches);
                } else {
                    try self.rescanCompareFullSegment(old_matches, segment, segment_width, kernel, user_values, &read_cache, &writer, raw_bits_scratch, &processed, total_matches);
                }
            } else {
                try self.rescanCompareSegmentFallbackFrom(old_matches, segment, 0, width, kernel, user_values, &read_cache, &writer, &processed, total_matches);
            }
            old_matches.releaseStorageBefore(segment.end_offset);
        }

        try writer.flushBefore(std.math.maxInt(usize));
        try new_matches.finalize();

        var to_free = self.matches.?;
        self.matches = new_matches;
        to_free.deinit();

        self.scan_progress = 1.0;
    }

    fn rescanFixedWidthChanged(self: *Scanner, width: usize) ScannerError!void {
        if (self.matches == null) return ScannerError.NoMatches;
        const handle = &self.process_handle.?;
        const old_matches = &self.matches.?;
        const total_matches = old_matches.matchCount();

        self.num_matches = 0;
        self.scan_progress = 0;
        @atomicStore(bool, &self.stop_flag, false, .monotonic);

        var new_matches = try MatchesArray.init(self.allocator, old_matches.max_needed_bytes, old_matches.stride);
        errdefer new_matches.deinit();

        var read_cache = MemoryCache{};
        var write_cache = MemoryCache{};
        var writer = RescanSpanWriter{
            .matches = &new_matches,
            .handle = handle,
            .cache = &write_cache,
        };
        var processed: usize = 0;
        var segments = old_matches.segmentIterator();
        while (segments.next()) |segment| {
            if (@atomicLoad(bool, &self.stop_flag, .monotonic)) break;
            if (fullSharedSegmentWidth(segment, self.options.scan_data_type, width)) |segment_width| {
                const raw_bits = segment.header.shared_raw_bits;
                try self.rescanChangedFullSegment(old_matches, segment, segment_width, raw_bits, &read_cache, &writer, &processed, total_matches);
            } else {
                try self.rescanChangedSegmentFallbackFrom(old_matches, segment, 0, width, &read_cache, &writer, &processed, total_matches);
            }
            old_matches.releaseStorageBefore(segment.end_offset);
        }

        try writer.flushBefore(std.math.maxInt(usize));
        try new_matches.finalize();

        var to_free = self.matches.?;
        self.matches = new_matches;
        to_free.deinit();

        self.scan_progress = 1.0;
    }

    fn rescanFixedWidthDelta(self: *Scanner, width: usize, match_type: ScanMatchType, user_values: []const UserValue) ScannerError!void {
        if (self.matches == null) return ScannerError.NoMatches;
        const handle = &self.process_handle.?;
        const old_matches = &self.matches.?;
        const total_matches = old_matches.matchCount();

        self.num_matches = 0;
        self.scan_progress = 0;
        @atomicStore(bool, &self.stop_flag, false, .monotonic);

        var new_matches = try MatchesArray.init(self.allocator, old_matches.max_needed_bytes, old_matches.stride);
        errdefer new_matches.deinit();

        var read_cache = MemoryCache{};
        var write_cache = MemoryCache{};
        var writer = RescanSpanWriter{
            .matches = &new_matches,
            .handle = handle,
            .cache = &write_cache,
        };
        const raw_bits_scratch = try self.allocator.alloc(u16, stridedBatchLimit(@sizeOf(u8), old_matches.stride));
        defer self.allocator.free(raw_bits_scratch);

        var processed: usize = 0;
        // Pre-select the concrete delta kernel once per pass so the per-candidate hot loop only does a direct function-pointer call.
        const kernel = scanroutines.pickFixedDeltaKernel(self.options.scan_data_type, match_type, self.options.reverse_endianness);
        var segments = old_matches.segmentIterator();
        while (segments.next()) |segment| {
            if (@atomicLoad(bool, &self.stop_flag, .monotonic)) break;
            if (fullSharedSegmentWidth(segment, self.options.scan_data_type, width)) |segment_width| {
                const raw_bits = segment.header.shared_raw_bits;
                try self.rescanDeltaFullSegment(old_matches, segment, segment_width, raw_bits, kernel, match_type, user_values, &read_cache, &writer, raw_bits_scratch, &processed, total_matches);
            } else {
                try self.rescanDeltaSegmentFallbackFrom(old_matches, segment, 0, width, kernel, user_values, &read_cache, &writer, &processed, total_matches);
            }
            old_matches.releaseStorageBefore(segment.end_offset);
        }

        try writer.flushBefore(std.math.maxInt(usize));
        try new_matches.finalize();

        var to_free = self.matches.?;
        self.matches = new_matches;
        to_free.deinit();

        self.scan_progress = 1.0;
    }

    fn rescanFixedWidthNotChanged(self: *Scanner, width: usize) ScannerError!void {
        if (self.matches == null) return ScannerError.NoMatches;
        const matches = &self.matches.?;
        const total_matches = matches.matchCount();

        self.scan_progress = 0;
        @atomicStore(bool, &self.stop_flag, false, .monotonic);

        var cache = MemoryCache{};
        var processed: usize = 0;
        var segments = matches.segmentIterator();
        while (segments.next()) |segment| {
            if (@atomicLoad(bool, &self.stop_flag, .monotonic)) break;
            if (fullSharedSegmentWidth(segment, self.options.scan_data_type, width)) |segment_width| {
                const raw_bits = segment.header.shared_raw_bits;
                self.rescanNotChangedFullSegment(matches, segment, segment_width, raw_bits, &cache, &processed, total_matches);
            } else {
                self.rescanNotChangedSegmentFallbackFrom(matches, segment, 0, width, &cache, &processed, total_matches);
            }
        }

        self.num_matches = matches.matchCount();
        self.scan_progress = 1.0;
    }

    fn rescanCompareFullSegment(
        self: *Scanner,
        old_matches: *const MatchesArray,
        segment: targetmem.SegmentView,
        width: usize,
        kernel: scanroutines.FixedCompareKernel,
        user_values: []const UserValue,
        cache: *MemoryCache,
        writer: *RescanSpanWriter,
        raw_bits_scratch: []u16,
        processed: *usize,
        total_matches: usize,
    ) ScannerError!void {
        const handle = &self.process_handle.?;
        const stride: usize = old_matches.stride;
        var candidate: usize = 0;
        while (candidate < segment.candidate_count) {
            if (@atomicLoad(bool, &self.stop_flag, .monotonic)) break;

            const batch_len = @min(segment.candidate_count - candidate, stridedBatchLimit(width, stride));
            const window_len = stridedWindowLen(batch_len, stride, width);
            const address = segment.first_candidate + candidate * stride;
            const current = cache.peek(handle, address, window_len) catch {
                try self.rescanCompareSegmentFallbackFrom(old_matches, segment, candidate * stride, width, kernel, user_values, cache, writer, processed, total_matches);
                return;
            };
            const valid = stridedValidCandidates(current.len, width, stride, batch_len);
            if (valid == 0) {
                try self.rescanCompareSegmentFallbackFrom(old_matches, segment, candidate * stride, width, kernel, user_values, cache, writer, processed, total_matches);
                return;
            }

            var survivor_count: usize = 0;
            for (0..valid) |i| {
                const byte_offset = i * stride;
                const raw_bits = kernel(current[byte_offset .. byte_offset + width], user_values);
                raw_bits_scratch[i] = raw_bits;
                if (raw_bits != 0) {
                    survivor_count += 1;
                }
            }

            if (survivor_count * 4 >= valid) {
                const stored_len = stridedFirstBytesLen(valid, stride);
                const trailing_end = std.math.add(usize, address, stridedWindowLen(valid, stride, width)) catch return ScannerError.ReadFailed;
                try writer.appendBatch(address, current[0..stored_len], raw_bits_scratch[0..valid], trailing_end);
                self.num_matches += survivor_count;
            } else {
                for (raw_bits_scratch[0..valid], 0..) |raw_bits, i| {
                    if (raw_bits == 0) continue;
                    const matched_len = flagsToNumericLength(@bitCast(raw_bits));
                    const byte_offset = i * stride;
                    try writer.appendMatch(address + byte_offset, current[byte_offset], matched_len, raw_bits);
                    self.num_matches += 1;
                }
            }

            candidate += valid;
            processed.* += valid;
            updateRescanProgress(self, processed.*, total_matches);
            if (valid < batch_len) {
                try self.rescanCompareSegmentFallbackFrom(old_matches, segment, candidate * stride, width, kernel, user_values, cache, writer, processed, total_matches);
                return;
            }
        }
    }

    /// Fixed concrete numeric MATCHEQUALTO over a full-shared stride-1 segment.
    /// Searches the segment's current bytes with "std.mem.indexOfPos" against pre-serialized needle(s)
    /// instead of running the compare kernel at every candidate.
    /// Safe because "fullSharedSegmentWidth" plus stride 1 guarantees every hit before "valid" is in the old candidate set.
    /// Read failures fall back to the iterator path (which uses "kernel") so partial reads still respect the old candidate set.
    fn rescanExactFullSegment(
        self: *Scanner,
        old_matches: *const MatchesArray,
        segment: targetmem.SegmentView,
        width: usize,
        needles: ExactNumericNeedles,
        kernel: scanroutines.FixedCompareKernel,
        user_values: []const UserValue,
        cache: *MemoryCache,
        writer: *RescanSpanWriter,
        processed: *usize,
        total_matches: usize,
    ) ScannerError!void {
        const handle = &self.process_handle.?;
        var candidate: usize = 0;
        while (candidate < segment.candidate_count) {
            if (@atomicLoad(bool, &self.stop_flag, .monotonic)) break;

            const batch_len = @min(segment.candidate_count - candidate, MemoryCache.read_chunk_size - width + 1);
            const window_len = batch_len + width - 1;
            const address = segment.first_candidate + candidate;
            const current = cache.peek(handle, address, window_len) catch {
                try self.rescanCompareSegmentFallbackFrom(old_matches, segment, candidate, width, kernel, user_values, cache, writer, processed, total_matches);
                return;
            };
            const valid = if (current.len >= width) @min(batch_len, current.len - width + 1) else 0;
            if (valid == 0) {
                try self.rescanCompareSegmentFallbackFrom(old_matches, segment, candidate, width, kernel, user_values, cache, writer, processed, total_matches);
                return;
            }

            var hit_primary = std.mem.indexOfPos(u8, current, 0, needles.primary);
            var hit_secondary: ?usize = if (needles.secondary) |sec| std.mem.indexOfPos(u8, current, 0, sec) else null;

            while (true) {
                var h: usize = undefined;
                var consumed_primary: bool = undefined;
                if (hit_primary) |h1| {
                    if (hit_secondary) |h2| {
                        if (h1 <= h2) {
                            h = h1;
                            consumed_primary = true;
                        } else {
                            h = h2;
                            consumed_primary = false;
                        }
                    } else {
                        h = h1;
                        consumed_primary = true;
                    }
                } else if (hit_secondary) |h2| {
                    h = h2;
                    consumed_primary = false;
                } else break;
                if (h >= valid) break;
                // Collapse self-overlapping primary runs, e.g. exact zero in zero-filled memory.
                if (consumed_primary) {
                    var burst_end = h + 1;
                    while (burst_end < valid and
                        std.mem.eql(u8, current[burst_end .. burst_end + needles.primary.len], needles.primary)) : (burst_end += 1)
                    {}
                    if (burst_end > h + 1) {
                        const burst_len = burst_end - h;
                        try writer.flushBefore(address + h);
                        try writer.matches.appendRun(address + h, current[h..burst_end], needles.raw_bits, burst_len);
                        self.num_matches += burst_len;
                        writer.pending_next = address + burst_end;
                        const trailing_offset = burst_end - 1 + width;
                        const trailing_end = std.math.add(usize, address, trailing_offset) catch return ScannerError.ReadFailed;
                        writer.pending_end = @max(writer.pending_end, trailing_end);
                        hit_primary = std.mem.indexOfPos(u8, current, burst_end, needles.primary);
                        if (hit_secondary) |h2| {
                            if (h2 < burst_end) {
                                hit_secondary = std.mem.indexOfPos(u8, current, burst_end, needles.secondary.?);
                            }
                        }
                        continue;
                    }
                    hit_primary = std.mem.indexOfPos(u8, current, h + 1, needles.primary);
                } else {
                    hit_secondary = std.mem.indexOfPos(u8, current, h + 1, needles.secondary.?);
                }

                try writer.appendMatch(address + h, current[h], width, needles.raw_bits);
                self.num_matches += 1;
            }

            candidate += valid;
            processed.* += valid;
            updateRescanProgress(self, processed.*, total_matches);
            if (valid < batch_len) {
                try self.rescanCompareSegmentFallbackFrom(old_matches, segment, candidate, width, kernel, user_values, cache, writer, processed, total_matches);
                return;
            }
        }
    }

    fn rescanCompareSegmentFallbackFrom(
        self: *Scanner,
        old_matches: *const MatchesArray,
        segment: targetmem.SegmentView,
        start_index: usize,
        width: usize,
        kernel: scanroutines.FixedCompareKernel,
        user_values: []const UserValue,
        cache: *MemoryCache,
        writer: *RescanSpanWriter,
        processed: *usize,
        total_matches: usize,
    ) ScannerError!void {
        const handle = &self.process_handle.?;
        const data_type = self.options.scan_data_type;
        var iterator = old_matches.iteratorFrom(segment.swath_offset);
        while (iterator.next()) |location| {
            if (@atomicLoad(bool, &self.stop_flag, .monotonic) or location.swath_offset != segment.swath_offset) break;
            if (location.index < start_index) continue;

            // For fixed-width data types stored_len == width always.
            // For ANY-types it is the candidate's per-flag width (1/2/4/8).
            // The kernel reads only as many bytes as were originally stored, and the new matched_len is
            // derived from the surviving flags so dense storage stays compact.
            const stored_len = storedLengthForExistingMatch(data_type, location.raw_match_info_bits);
            if (stored_len != 0 and stored_len <= width) {
                const memory = cache.peek(handle, location.address, stored_len) catch {
                    processed.* += 1;
                    updateRescanProgress(self, processed.*, total_matches);
                    continue;
                };
                if (memory.len >= stored_len) {
                    const raw_bits = kernel(memory[0..stored_len], user_values);
                    if (raw_bits != 0) {
                        const matched_len = flagsToNumericLength(@bitCast(raw_bits));
                        try writer.appendMatch(location.address, memory[0], matched_len, raw_bits);
                        self.num_matches += 1;
                    }
                }
            }

            processed.* += 1;
            updateRescanProgress(self, processed.*, total_matches);
        }
    }

    fn rescanChangedFullSegment(
        self: *Scanner,
        old_matches: *const MatchesArray,
        segment: targetmem.SegmentView,
        width: usize,
        raw_bits: u16,
        cache: *MemoryCache,
        writer: *RescanSpanWriter,
        processed: *usize,
        total_matches: usize,
    ) ScannerError!void {
        const handle = &self.process_handle.?;
        const stride: usize = old_matches.stride;
        var old_buf: [MemoryCache.read_chunk_size]u8 = undefined;
        var candidate: usize = 0;
        while (candidate < segment.candidate_count) {
            if (@atomicLoad(bool, &self.stop_flag, .monotonic)) break;

            const batch_len = @min(segment.candidate_count - candidate, stridedBatchLimit(width, stride));
            const window_len = stridedWindowLen(batch_len, stride, width);
            const byte_index = candidate * stride;
            const address = segment.first_candidate + byte_index;
            const old = old_matches.dataToBytes(segment.swath_offset, byte_index, window_len, &old_buf);
            const valid = stridedValidCandidates(old.len, width, stride, batch_len);
            if (valid == 0) {
                try self.rescanChangedSegmentFallbackFrom(old_matches, segment, byte_index, width, cache, writer, processed, total_matches);
                return;
            }

            const valid_window_len = stridedWindowLen(valid, stride, width);
            const current = cache.peek(handle, address, valid_window_len) catch {
                try self.rescanChangedSegmentFallbackFrom(old_matches, segment, byte_index, width, cache, writer, processed, total_matches);
                return;
            };

            if (stride == 1 and !std.mem.eql(u8, current[0..valid_window_len], old[0..valid_window_len])) {
                var diff_count: usize = 0;
                for (0..width) |i| {
                    if (current[i] != old[i]) diff_count += 1;
                }
                for (0..valid) |i| {
                    if (diff_count != 0) {
                        try writer.appendMatch(address + i, current[i], width, raw_bits);
                        self.num_matches += 1;
                    }
                    if (i + width < valid_window_len) {
                        if (current[i] != old[i]) diff_count -= 1;
                        if (current[i + width] != old[i + width]) diff_count += 1;
                    }
                }
            } else if (stride != 1) {
                for (0..valid) |i| {
                    const byte_offset = i * stride;
                    if (!std.mem.eql(u8, current[byte_offset .. byte_offset + width], old[byte_offset .. byte_offset + width])) {
                        try writer.appendMatch(address + byte_offset, current[byte_offset], width, raw_bits);
                        self.num_matches += 1;
                    }
                }
            }

            candidate += valid;
            processed.* += valid;
            updateRescanProgress(self, processed.*, total_matches);
            if (valid < batch_len) {
                try self.rescanChangedSegmentFallbackFrom(old_matches, segment, candidate * stride, width, cache, writer, processed, total_matches);
                return;
            }
        }
    }

    fn rescanChangedSegmentFallbackFrom(
        self: *Scanner,
        old_matches: *const MatchesArray,
        segment: targetmem.SegmentView,
        start_index: usize,
        width: usize,
        cache: *MemoryCache,
        writer: *RescanSpanWriter,
        processed: *usize,
        total_matches: usize,
    ) ScannerError!void {
        const handle = &self.process_handle.?;
        const data_type = self.options.scan_data_type;
        var old_bytes: [8]u8 = undefined;
        var iterator = old_matches.iteratorFrom(segment.swath_offset);
        while (iterator.next()) |location| {
            if (@atomicLoad(bool, &self.stop_flag, .monotonic) or location.swath_offset != segment.swath_offset) break;
            if (location.index < start_index) continue;

            // For fixed-width types stored_len == width.
            // For ANY-types it is the candidate's per-flag width.
            // CHANGED never narrows flags so raw_bits and stored width carry through.
            const stored_len = storedLengthForExistingMatch(data_type, location.raw_match_info_bits);
            if (stored_len != 0 and stored_len <= width) {
                const memory = cache.peek(handle, location.address, stored_len) catch {
                    processed.* += 1;
                    updateRescanProgress(self, processed.*, total_matches);
                    continue;
                };
                const old = old_matches.dataToBytes(location.swath_offset, location.index, stored_len, &old_bytes);
                if (old.len == stored_len and memory.len >= stored_len and !std.mem.eql(u8, memory[0..stored_len], old)) {
                    try writer.appendMatch(location.address, memory[0], stored_len, location.raw_match_info_bits);
                    self.num_matches += 1;
                }
            }

            processed.* += 1;
            updateRescanProgress(self, processed.*, total_matches);
        }
    }

    fn rescanDeltaFullSegment(
        self: *Scanner,
        old_matches: *const MatchesArray,
        segment: targetmem.SegmentView,
        width: usize,
        raw_bits: u16,
        kernel: scanroutines.FixedDeltaKernel,
        match_type: ScanMatchType,
        user_values: []const UserValue,
        cache: *MemoryCache,
        writer: *RescanSpanWriter,
        raw_bits_scratch: []u16,
        processed: *usize,
        total_matches: usize,
    ) ScannerError!void {
        const handle = &self.process_handle.?;
        const any_number_full = self.options.scan_data_type == .ANYNUMBER and width == 8;
        const split_float_windows = (self.options.scan_data_type == .ANYFLOAT or any_number_full) and width == 8;
        const i8_raw_bits = if (any_number_full) raw_bits & MatchFlags.i8b.bits() else 0;
        const i16_raw_bits = if (any_number_full) raw_bits & MatchFlags.i16b.bits() else 0;
        const i32_raw_bits = if (any_number_full) raw_bits & MatchFlags.i32b.bits() else 0;
        const i64_raw_bits = if (any_number_full) raw_bits & MatchFlags.i64b.bits() else 0;
        const f32_raw_bits = if (split_float_windows) raw_bits & (MatchFlags{ .f32b = true }).bits() else 0;
        const f64_raw_bits = if (split_float_windows) raw_bits & (MatchFlags{ .f64b = true }).bits() else 0;
        const i8_kernel = if (any_number_full)
            scanroutines.pickFixedDeltaKernel(.INTEGER8, match_type, self.options.reverse_endianness)
        else
            undefined;
        const i16_kernel = if (any_number_full)
            scanroutines.pickFixedDeltaKernel(.INTEGER16, match_type, self.options.reverse_endianness)
        else
            undefined;
        const i32_kernel = if (any_number_full)
            scanroutines.pickFixedDeltaKernel(.INTEGER32, match_type, self.options.reverse_endianness)
        else
            undefined;
        const i64_kernel = if (any_number_full)
            scanroutines.pickFixedDeltaKernel(.INTEGER64, match_type, self.options.reverse_endianness)
        else
            undefined;
        const f32_kernel = if (split_float_windows)
            scanroutines.pickFixedDeltaKernel(.FLOAT32, match_type, self.options.reverse_endianness)
        else
            undefined;
        const f64_kernel = if (split_float_windows)
            scanroutines.pickFixedDeltaKernel(.FLOAT64, match_type, self.options.reverse_endianness)
        else
            undefined;
        const stride: usize = old_matches.stride;
        var old_buf: [MemoryCache.read_chunk_size]u8 = undefined;
        var candidate: usize = 0;
        while (candidate < segment.candidate_count) {
            if (@atomicLoad(bool, &self.stop_flag, .monotonic)) break;

            const batch_len = @min(segment.candidate_count - candidate, stridedBatchLimit(width, stride));
            const window_len = stridedWindowLen(batch_len, stride, width);
            const byte_index = candidate * stride;
            const address = segment.first_candidate + byte_index;
            const old = old_matches.dataToBytes(segment.swath_offset, byte_index, window_len, &old_buf);
            const valid = stridedValidCandidates(old.len, width, stride, batch_len);
            if (valid == 0) {
                try self.rescanDeltaSegmentFallbackFrom(old_matches, segment, byte_index, width, kernel, user_values, cache, writer, processed, total_matches);
                return;
            }

            const valid_window_len = stridedWindowLen(valid, stride, width);
            const current = cache.peek(handle, address, valid_window_len) catch {
                try self.rescanDeltaSegmentFallbackFrom(old_matches, segment, byte_index, width, kernel, user_values, cache, writer, processed, total_matches);
                return;
            };

            if (stride != 1) {
                var survivor_count: usize = 0;
                for (0..valid) |i| {
                    const byte_offset = i * stride;
                    const new_raw_bits = kernel(current[byte_offset .. byte_offset + width], old[byte_offset .. byte_offset + width], raw_bits, user_values);
                    raw_bits_scratch[i] = new_raw_bits;
                    if (new_raw_bits != 0) survivor_count += 1;
                }

                if (survivor_count * 4 >= valid) {
                    const stored_len = stridedFirstBytesLen(valid, stride);
                    const trailing_end = std.math.add(usize, address, valid_window_len) catch return ScannerError.ReadFailed;
                    try writer.appendBatch(address, current[0..stored_len], raw_bits_scratch[0..valid], trailing_end);
                    self.num_matches += survivor_count;
                } else if (survivor_count != 0) {
                    for (raw_bits_scratch[0..valid], 0..) |new_raw_bits, i| {
                        if (new_raw_bits == 0) continue;
                        const matched_len = flagsToNumericLength(@bitCast(new_raw_bits));
                        const byte_offset = i * stride;
                        try writer.appendMatch(address + byte_offset, current[byte_offset], matched_len, new_raw_bits);
                        self.num_matches += 1;
                    }
                }

                candidate += valid;
                processed.* += valid;
                updateRescanProgress(self, processed.*, total_matches);
                if (valid < batch_len) {
                    try self.rescanDeltaSegmentFallbackFrom(old_matches, segment, candidate * stride, width, kernel, user_values, cache, writer, processed, total_matches);
                    return;
                }
                continue;
            }

            // Candidates whose value-width window is byte-identical to the stored bytes cannot have increased or decreased
            // (true for both int and float, including NaN: identical bits -> identical value or both NaN, neither > nor <).
            // Gate the per-candidate delta computation on the sliding diff_count window so we only pay for the kernel on actually-changed windows.
            var survivor_count: usize = 0;
            if (!std.mem.eql(u8, current[0..valid_window_len], old[0..valid_window_len])) {
                if (any_number_full) {
                    var diff_count1: usize = 0;
                    var diff_count2: usize = 0;
                    var diff_count4: usize = 0;
                    var diff_count8: usize = 0;
                    for (0..8) |i| {
                        if (current[i] != old[i]) {
                            diff_count8 += 1;
                            if (i < 4) diff_count4 += 1;
                            if (i < 2) diff_count2 += 1;
                            if (i == 0) diff_count1 += 1;
                        }
                    }
                    for (0..valid) |i| {
                        raw_bits_scratch[i] = 0;
                        var new_raw_bits: u16 = 0;
                        if (diff_count1 != 0 and i8_raw_bits != 0) {
                            new_raw_bits |= i8_kernel(current[i .. i + 1], old[i .. i + 1], i8_raw_bits, user_values);
                        }
                        if (diff_count2 != 0 and i16_raw_bits != 0) {
                            new_raw_bits |= i16_kernel(current[i .. i + 2], old[i .. i + 2], i16_raw_bits, user_values);
                        }
                        if (diff_count4 != 0) {
                            if (i32_raw_bits != 0) {
                                new_raw_bits |= i32_kernel(current[i .. i + 4], old[i .. i + 4], i32_raw_bits, user_values);
                            }
                            if (f32_raw_bits != 0) {
                                new_raw_bits |= f32_kernel(current[i .. i + 4], old[i .. i + 4], f32_raw_bits, user_values);
                            }
                        }
                        if (diff_count8 != 0) {
                            if (i64_raw_bits != 0) {
                                new_raw_bits |= i64_kernel(current[i .. i + 8], old[i .. i + 8], i64_raw_bits, user_values);
                            }
                            if (f64_raw_bits != 0) {
                                new_raw_bits |= f64_kernel(current[i .. i + 8], old[i .. i + 8], f64_raw_bits, user_values);
                            }
                        }
                        if (new_raw_bits != 0) {
                            raw_bits_scratch[i] = new_raw_bits;
                            survivor_count += 1;
                        }
                        if (i + 1 < valid) {
                            if (current[i] != old[i]) {
                                diff_count1 -= 1;
                                diff_count2 -= 1;
                                diff_count4 -= 1;
                                diff_count8 -= 1;
                            }
                            if (current[i + 1] != old[i + 1]) diff_count1 += 1;
                            if (current[i + 2] != old[i + 2]) diff_count2 += 1;
                            if (current[i + 4] != old[i + 4]) diff_count4 += 1;
                            if (current[i + 8] != old[i + 8]) diff_count8 += 1;
                        }
                    }
                } else if (split_float_windows) {
                    var diff_count_f32: usize = 0;
                    var diff_count_f64: usize = 0;
                    for (0..8) |i| {
                        if (current[i] != old[i]) {
                            diff_count_f64 += 1;
                            if (i < 4) diff_count_f32 += 1;
                        }
                    }
                    for (0..valid) |i| {
                        raw_bits_scratch[i] = 0;
                        var new_raw_bits: u16 = 0;
                        if (diff_count_f32 != 0 and f32_raw_bits != 0) {
                            new_raw_bits |= f32_kernel(current[i .. i + 4], old[i .. i + 4], f32_raw_bits, user_values);
                        }
                        if (diff_count_f64 != 0 and f64_raw_bits != 0) {
                            new_raw_bits |= f64_kernel(current[i .. i + 8], old[i .. i + 8], f64_raw_bits, user_values);
                        }
                        if (new_raw_bits != 0) {
                            raw_bits_scratch[i] = new_raw_bits;
                            survivor_count += 1;
                        }
                        if (i + 1 < valid) {
                            if (current[i] != old[i]) {
                                diff_count_f32 -= 1;
                                diff_count_f64 -= 1;
                            }
                            if (current[i + 4] != old[i + 4]) diff_count_f32 += 1;
                            if (current[i + 8] != old[i + 8]) diff_count_f64 += 1;
                        }
                    }
                } else {
                    var diff_count: usize = 0;
                    for (0..width) |i| {
                        if (current[i] != old[i]) diff_count += 1;
                    }
                    for (0..valid) |i| {
                        raw_bits_scratch[i] = 0;
                        if (diff_count != 0) {
                            const new_raw_bits = kernel(current[i .. i + width], old[i .. i + width], raw_bits, user_values);
                            if (new_raw_bits != 0) {
                                raw_bits_scratch[i] = new_raw_bits;
                                survivor_count += 1;
                            }
                        }
                        if (i + width < valid_window_len) {
                            if (current[i] != old[i]) diff_count -= 1;
                            if (current[i + width] != old[i + width]) diff_count += 1;
                        }
                    }
                }
            }
            if (survivor_count * 4 >= valid) {
                const trailing_end = std.math.add(usize, address, valid_window_len) catch return ScannerError.ReadFailed;
                try writer.appendBatch(address, current[0..valid], raw_bits_scratch[0..valid], trailing_end);
                self.num_matches += survivor_count;
            } else if (survivor_count != 0) {
                for (raw_bits_scratch[0..valid], 0..) |new_raw_bits, i| {
                    if (new_raw_bits == 0) continue;
                    const matched_len = flagsToNumericLength(@bitCast(new_raw_bits));
                    try writer.appendMatch(address + i, current[i], matched_len, new_raw_bits);
                    self.num_matches += 1;
                }
            }

            candidate += valid;
            processed.* += valid;
            updateRescanProgress(self, processed.*, total_matches);
            if (valid < batch_len) {
                try self.rescanDeltaSegmentFallbackFrom(old_matches, segment, candidate * stride, width, kernel, user_values, cache, writer, processed, total_matches);
                return;
            }
        }
    }

    fn rescanDeltaSegmentFallbackFrom(
        self: *Scanner,
        old_matches: *const MatchesArray,
        segment: targetmem.SegmentView,
        start_index: usize,
        width: usize,
        kernel: scanroutines.FixedDeltaKernel,
        user_values: []const UserValue,
        cache: *MemoryCache,
        writer: *RescanSpanWriter,
        processed: *usize,
        total_matches: usize,
    ) ScannerError!void {
        const handle = &self.process_handle.?;
        const data_type = self.options.scan_data_type;
        var old_bytes: [8]u8 = undefined;
        var iterator = old_matches.iteratorFrom(segment.swath_offset);
        while (iterator.next()) |location| {
            if (@atomicLoad(bool, &self.stop_flag, .monotonic) or location.swath_offset != segment.swath_offset) break;
            if (location.index < start_index) continue;

            // For fixed-width types stored_len == width.
            // For ANY-types it is the candidate's per-flag width.
            // The kernel reads only the stored bytes, and the new matched_len is derived from the
            // surviving flags so dense storage stays compact.
            const stored_len = storedLengthForExistingMatch(data_type, location.raw_match_info_bits);
            if (stored_len != 0 and stored_len <= width) {
                const memory = cache.peek(handle, location.address, stored_len) catch {
                    processed.* += 1;
                    updateRescanProgress(self, processed.*, total_matches);
                    continue;
                };
                const old = old_matches.dataToBytes(location.swath_offset, location.index, stored_len, &old_bytes);
                if (old.len == stored_len and memory.len >= stored_len) {
                    const raw_bits = kernel(memory[0..stored_len], old, location.raw_match_info_bits, user_values);
                    if (raw_bits != 0) {
                        const matched_len = flagsToNumericLength(@bitCast(raw_bits));
                        try writer.appendMatch(location.address, memory[0], matched_len, raw_bits);
                        self.num_matches += 1;
                    }
                }
            }

            processed.* += 1;
            updateRescanProgress(self, processed.*, total_matches);
        }
    }

    fn rescanNotChangedFullSegment(
        self: *Scanner,
        matches: *MatchesArray,
        segment: targetmem.SegmentView,
        width: usize,
        raw_bits: u16,
        cache: *MemoryCache,
        processed: *usize,
        total_matches: usize,
    ) void {
        const handle = &self.process_handle.?;
        const stride: usize = matches.stride;
        var old_buf: [MemoryCache.read_chunk_size]u8 = undefined;
        var candidate: usize = 0;
        while (candidate < segment.candidate_count) {
            if (@atomicLoad(bool, &self.stop_flag, .monotonic)) break;

            const batch_len = @min(segment.candidate_count - candidate, stridedBatchLimit(width, stride));
            const window_len = stridedWindowLen(batch_len, stride, width);
            const byte_index = candidate * stride;
            const address = segment.first_candidate + byte_index;
            const old = matches.dataToBytes(segment.swath_offset, byte_index, window_len, &old_buf);
            const valid = stridedValidCandidates(old.len, width, stride, batch_len);
            if (valid == 0) {
                self.rescanNotChangedSegmentFallbackFrom(matches, segment, byte_index, width, cache, processed, total_matches);
                return;
            }

            const valid_window_len = stridedWindowLen(valid, stride, width);
            const current = cache.peek(handle, address, valid_window_len) catch {
                self.rescanNotChangedSegmentFallbackFrom(matches, segment, byte_index, width, cache, processed, total_matches);
                return;
            };

            if (stride == 1 and !std.mem.eql(u8, current[0..valid_window_len], old[0..valid_window_len])) {
                var diff_count: usize = 0;
                for (0..width) |i| {
                    if (current[i] != old[i]) diff_count += 1;
                }
                for (0..valid) |i| {
                    if (diff_count != 0) {
                        matches.removeMatch(.{
                            .swath_offset = segment.swath_offset,
                            .index = candidate + i,
                            .address = address + i,
                            .raw_match_info_bits = raw_bits,
                        });
                    }
                    if (i + width < valid_window_len) {
                        if (current[i] != old[i]) diff_count -= 1;
                        if (current[i + width] != old[i + width]) diff_count += 1;
                    }
                }
            } else if (stride != 1) {
                for (0..valid) |i| {
                    const byte_offset = i * stride;
                    if (!std.mem.eql(u8, current[byte_offset .. byte_offset + width], old[byte_offset .. byte_offset + width])) {
                        matches.removeMatch(.{
                            .swath_offset = segment.swath_offset,
                            .index = byte_index + byte_offset,
                            .address = address + byte_offset,
                            .raw_match_info_bits = raw_bits,
                        });
                    }
                }
            }

            candidate += valid;
            processed.* += valid;
            updateRescanProgress(self, processed.*, total_matches);
            if (valid < batch_len) {
                self.rescanNotChangedSegmentFallbackFrom(matches, segment, candidate * stride, width, cache, processed, total_matches);
                return;
            }
        }
    }

    fn rescanNotChangedSegmentFallbackFrom(
        self: *Scanner,
        matches: *MatchesArray,
        segment: targetmem.SegmentView,
        start_index: usize,
        width: usize,
        cache: *MemoryCache,
        processed: *usize,
        total_matches: usize,
    ) void {
        const handle = &self.process_handle.?;
        const data_type = self.options.scan_data_type;
        var old_bytes: [8]u8 = undefined;
        var iterator = matches.iteratorFrom(segment.swath_offset);
        while (iterator.next()) |location| {
            if (@atomicLoad(bool, &self.stop_flag, .monotonic) or location.swath_offset != segment.swath_offset) break;
            if (location.index < start_index) continue;

            // For fixed-width types stored_len == width.
            // For ANY-types it is the candidate's per-flag width.
            const keep = keep: {
                const stored_len = storedLengthForExistingMatch(data_type, location.raw_match_info_bits);
                if (stored_len == 0 or stored_len > width) break :keep false;
                const memory = cache.peek(handle, location.address, stored_len) catch break :keep false;
                const old = matches.dataToBytes(location.swath_offset, location.index, stored_len, &old_bytes);
                break :keep old.len == stored_len and memory.len >= stored_len and std.mem.eql(u8, memory[0..stored_len], old);
            };
            if (!keep) matches.removeMatch(location);

            processed.* += 1;
            updateRescanProgress(self, processed.*, total_matches);
        }
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

    fn ensureUndoFile(self: *Scanner) ScannerError!*std.Io.File {
        if (self.undo_file == null) {
            const cache_dir = cache_dir: {
                switch (builtin.os.tag) {
                    .linux => {
                        if (std.c.getenv("XDG_CACHE_HOME")) |xdg_cache_home_raw| {
                            const xdg_cache_home = std.mem.span(xdg_cache_home_raw);
                            if (xdg_cache_home.len != 0 and std.fs.path.isAbsolute(xdg_cache_home)) {
                                break :cache_dir std.fs.path.join(self.allocator, &.{ xdg_cache_home, "libmemscan" }) catch return ScannerError.OutOfMemory;
                            }
                        }

                        const home = std.mem.span(std.c.getenv("HOME") orelse return ScannerError.UndoIoFailed);
                        if (home.len == 0 or !std.fs.path.isAbsolute(home)) return ScannerError.UndoIoFailed;
                        break :cache_dir std.fs.path.join(self.allocator, &.{ home, ".cache", "libmemscan" }) catch return ScannerError.OutOfMemory;
                    },
                    .macos => {
                        const home = std.mem.span(std.c.getenv("HOME") orelse return ScannerError.UndoIoFailed);
                        if (home.len == 0 or !std.fs.path.isAbsolute(home)) return ScannerError.UndoIoFailed;
                        break :cache_dir std.fs.path.join(self.allocator, &.{ home, "Library", "Caches", "libmemscan" }) catch return ScannerError.OutOfMemory;
                    },
                    else => @compileError("Unsupported platform: " ++ @tagName(builtin.os.tag)),
                }
            };
            defer self.allocator.free(cache_dir);

            std.Io.Dir.createDirPath(.cwd(), self.io, cache_dir) catch return ScannerError.UndoIoFailed;
            const undo_path = std.fs.path.join(self.allocator, &.{ cache_dir, "libmemscan-undo.bin" }) catch return ScannerError.OutOfMemory;
            errdefer self.allocator.free(undo_path);

            self.undo_file = std.Io.Dir.createFileAbsolute(self.io, undo_path, .{
                .read = true,
                .truncate = true,
            }) catch return ScannerError.UndoIoFailed;
            self.undo_path = undo_path;
        }

        return &self.undo_file.?;
    }

    fn closeUndoFile(self: *Scanner) void {
        if (self.undo_file) |file| {
            file.close(self.io);
            self.undo_file = null;
        }
        if (self.undo_path) |path| {
            std.Io.Dir.deleteFileAbsolute(self.io, path) catch {};
            self.allocator.free(path);
            self.undo_path = null;
        }
    }

    fn saveCurrentMatchesForUndo(self: *Scanner) ScannerError!void {
        if (self.matches == null) return ScannerError.NoMatches;
        const matches = &self.matches.?;
        try matches.finalize();
        const file = try self.ensureUndoFile();
        const header = UndoFileHeader{
            .num_matches = self.num_matches,
            .used_len = matches.used_len,
            .max_needed_bytes = matches.max_needed_bytes,
            .match_count = matches.match_count,
            .stride = matches.stride,
            .alignment = self.options.alignment,
            .scan_data_type = @intFromEnum(self.options.scan_data_type),
            .scan_level = @intFromEnum(self.options.scan_level),
            .reverse_endianness = @intFromBool(self.options.reverse_endianness),
        };

        file.setLength(self.io, 0) catch return ScannerError.UndoIoFailed;
        file.writePositionalAll(self.io, std.mem.asBytes(&header), 0) catch return ScannerError.UndoIoFailed;
        var write_offset: u64 = @sizeOf(UndoFileHeader);
        for (matches.chunks.items) |chunk| {
            if (chunk.base >= matches.used_len) break;
            const storage = chunk.data[0..@min(chunk.data.len, matches.used_len - chunk.base)];
            file.writePositionalAll(self.io, storage, write_offset) catch return ScannerError.UndoIoFailed;
            write_offset += storage.len;
        }
        self.undo_available = true;
    }

    fn loadUndoMatches(self: *Scanner) ScannerError!UndoMetadata {
        const file = self.undo_file orelse return ScannerError.NoUndo;

        var header: UndoFileHeader = undefined;
        const header_bytes = file.readPositionalAll(self.io, std.mem.asBytes(&header), 0) catch return ScannerError.UndoIoFailed;
        if (header_bytes != @sizeOf(UndoFileHeader)) return ScannerError.UndoCorrupt;

        const used_len: usize = header.used_len;
        const max_needed_bytes: usize = header.max_needed_bytes;
        const match_count: usize = header.match_count;

        if (self.matches) |*matches| {
            if (matches.stride != header.stride or matches.capacity_len < used_len) self.resetMatches();
        }

        const created_matches = self.matches == null;
        if (created_matches) {
            self.matches = try MatchesArray.init(self.allocator, max_needed_bytes, header.stride);
        }
        errdefer if (created_matches) self.resetMatches();

        const matches = &self.matches.?;
        try matches.resetForStorageLoad(used_len, max_needed_bytes, match_count);
        var read_offset: u64 = @sizeOf(UndoFileHeader);
        for (matches.chunks.items) |*chunk| {
            if (chunk.base >= matches.used_len) break;
            const storage = chunk.data[0..@min(chunk.data.len, matches.used_len - chunk.base)];
            const storage_bytes = file.readPositionalAll(self.io, storage, read_offset) catch return ScannerError.UndoIoFailed;
            if (storage_bytes != storage.len) return ScannerError.UndoCorrupt;
            read_offset += storage.len;
        }

        return .{
            .num_matches = header.num_matches,
            .options = .{
                .alignment = header.alignment,
                .scan_data_type = @enumFromInt(header.scan_data_type),
                .scan_level = @enumFromInt(header.scan_level),
                .reverse_endianness = header.reverse_endianness != 0,
            },
        };
    }
};

const MemoryCache = struct {
    // Large enough to avoid millions of tiny positional reads during rescan,
    // with a required-length fallback for mappings that end before the prefetch.
    const read_chunk_size: usize = 64 * 1024;
    const max_size: usize = read_chunk_size * 2;

    cache: [max_size]u8 = @splat(0),
    size: usize = 0,
    base: ?usize = null,

    fn peek(self: *MemoryCache, handle: *ProcessHandle, addr: usize, length: usize) ScannerError![]const u8 {
        const request_end = std.math.add(usize, addr, length) catch return ScannerError.ReadFailed;

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
            const required_len = request_end - target_address;
            if (read_len == 0) return ScannerError.ReadFailed;
            const nread = handle.read(target_address, self.cache[self.size .. self.size + read_len]) catch blk: {
                if (read_len <= required_len) return ScannerError.ReadFailed;
                break :blk handle.read(target_address, self.cache[self.size .. self.size + required_len]) catch return ScannerError.ReadFailed;
            };
            if (nread == 0) return ScannerError.ReadFailed;
            self.size += nread;
            if (nread < read_len) break;
        }

        const base = self.base orelse return ScannerError.ReadFailed;
        if (addr >= base + self.size or request_end > base + self.size) return ScannerError.ReadFailed;
        return self.cache[(addr - base)..self.size];
    }
};

const RescanSpanWriter = struct {
    matches: *MatchesArray,
    handle: *ProcessHandle,
    cache: *MemoryCache,
    pending_next: usize = 0,
    pending_end: usize = 0,

    fn appendMatch(self: *RescanSpanWriter, address: usize, first_byte: u8, matched_len: usize, raw_bits: u16) ScannerError!void {
        try self.flushBefore(address);
        try self.matches.appendRaw(address, first_byte, raw_bits);

        const span_end = std.math.add(usize, address, matched_len) catch return ScannerError.ReadFailed;
        self.pending_next = std.math.add(usize, address, 1) catch return ScannerError.ReadFailed;
        self.pending_end = @max(self.pending_end, span_end);
    }

    fn appendBatch(self: *RescanSpanWriter, address: usize, old_values: []const u8, raw_bits_per_candidate: []const u16, trailing_end: usize) ScannerError!void {
        try self.flushBefore(address);
        try self.matches.appendRescanBatch(address, old_values, raw_bits_per_candidate);

        self.pending_next = std.math.add(usize, address, old_values.len) catch return ScannerError.ReadFailed;
        self.pending_end = @max(self.pending_end, trailing_end);
    }

    fn flushBefore(self: *RescanSpanWriter, limit: usize) ScannerError!void {
        const target = @min(limit, self.pending_end);
        while (self.pending_next < target) {
            const request_len = @min(target - self.pending_next, MemoryCache.read_chunk_size);
            const memory = self.cache.peek(self.handle, self.pending_next, request_len) catch {
                self.pending_next = target;
                return;
            };
            const available = @min(target - self.pending_next, memory.len);
            if (available == 0) {
                self.pending_next = target;
                return;
            }
            for (memory[0..available]) |byte| {
                try self.matches.appendRaw(self.pending_next, byte, 0);
                self.pending_next += 1;
            }
        }
        if (self.pending_next >= self.pending_end) {
            self.pending_end = self.pending_next;
        }
    }
};

fn scanChunkIntoMatches(
    matches: *MatchesArray,
    prepared: PreparedScan,
    initial_kernel: ?scanroutines.InitialNumericKernel,
    user_values: []const UserValue,
    base_address: usize,
    chunk: []const u8,
    scan_limit: usize,
    alignment: u16,
    required_extra_bytes: *usize,
    num_matches: *usize,
) ScannerError!void {
    var offset: usize = 0;
    if (prepared.match_type == .MATCHANY) {
        const raw_bits = switch (prepared.data_type) {
            .INTEGER8 => MatchFlags.i8b.bits(),
            .INTEGER16 => MatchFlags.i16b.bits(),
            .INTEGER32 => MatchFlags.i32b.bits(),
            .INTEGER64 => MatchFlags.i64b.bits(),
            .FLOAT32 => (MatchFlags{ .f32b = true }).bits(),
            .FLOAT64 => (MatchFlags{ .f64b = true }).bits(),
            .ANYINTEGER, .ANYFLOAT, .ANYNUMBER, .BYTEARRAY, .STRING => 0,
        };
        if (raw_bits != 0) {
            const width = prepared.maxMatchLength(user_values);
            if (width >= alignment) {
                const matchable_len = if (chunk.len >= width) @min(scan_limit, chunk.len - width + 1) else 0;
                const first_candidate = blk: {
                    if (matchable_len == 0) break :blk base_address;
                    if (alignment <= 1) break :blk base_address;
                    const rem = base_address % alignment;
                    break :blk if (rem == 0) base_address else base_address + (alignment - rem);
                };
                const match_candidate_count = blk: {
                    if (matchable_len == 0) break :blk 0;
                    const end = base_address + matchable_len;
                    if (first_candidate >= end) break :blk 0;
                    break :blk (end - first_candidate + alignment - 1) / alignment;
                };
                const pending_prefix = @min(required_extra_bytes.*, scan_limit);
                if (match_candidate_count == 0) {
                    if (pending_prefix > 0) {
                        try matches.appendRun(base_address, chunk[0..pending_prefix], raw_bits, 0);
                        required_extra_bytes.* -= pending_prefix;
                    }
                    return;
                }

                const first_offset = first_candidate - base_address;
                const last_offset = first_offset + (match_candidate_count - 1) * alignment;
                const last_end = last_offset + width;
                const store_start = if (pending_prefix > 0) 0 else first_offset;
                const store_end = @max(pending_prefix, @min(scan_limit, last_end));
                try matches.appendRun(base_address + store_start, chunk[store_start..store_end], raw_bits, match_candidate_count);
                num_matches.* += match_candidate_count;
                required_extra_bytes.* = if (last_end > scan_limit) last_end - scan_limit else 0;
                return;
            }
        }

        const full_any_raw_bits = switch (prepared.data_type) {
            .ANYINTEGER => MatchFlags.integer.bits(),
            .ANYFLOAT => MatchFlags.float.bits(),
            .ANYNUMBER => MatchFlags.all.bits(),
            else => 0,
        };
        if (full_any_raw_bits != 0) {
            const width = prepared.maxMatchLength(user_values);
            if (width >= alignment) {
                const matchable_len = if (chunk.len >= width) @min(scan_limit, chunk.len - width + 1) else 0;
                const first_candidate = blk: {
                    if (matchable_len == 0) break :blk base_address;
                    if (alignment <= 1) break :blk base_address;
                    const rem = base_address % alignment;
                    break :blk if (rem == 0) base_address else base_address + (alignment - rem);
                };
                const match_candidate_count = blk: {
                    if (matchable_len == 0) break :blk 0;
                    const end = base_address + matchable_len;
                    if (first_candidate >= end) break :blk 0;
                    break :blk (end - first_candidate + alignment - 1) / alignment;
                };
                const pending_prefix = @min(required_extra_bytes.*, scan_limit);
                if (match_candidate_count != 0) {
                    const first_offset = first_candidate - base_address;
                    const last_offset = first_offset + (match_candidate_count - 1) * alignment;
                    const next_candidate_offset = last_offset + alignment;
                    const store_start = if (pending_prefix > 0) 0 else first_offset;
                    const store_end = @max(pending_prefix, @min(scan_limit, next_candidate_offset));
                    try matches.appendRun(base_address + store_start, chunk[store_start..store_end], full_any_raw_bits, match_candidate_count);
                    num_matches.* += match_candidate_count;
                    offset = store_end;
                    const last_end = last_offset + width;
                    required_extra_bytes.* = if (last_end > store_end) last_end - store_end else 0;
                }
            }
        }

        // STRING / BYTEARRAY MATCHANY: Each match's stored length is min(chunk.len - candidate_offset, maxInt(u16)).
        // In the common chunk (initialScan reads an overlap of maxInt(u16), so chunk.len exceeds scan_limit by max_len)
        // every candidate has the full max_len and a single appendRun records them all.
        // In tail chunks lengths shrink and a per-candidate walk preserves trailing-span bytes the same way the
        // STRING / BYTEARRAY MATCHEQUALTO paths below do.
        if (prepared.data_type == .STRING or prepared.data_type == .BYTEARRAY) {
            const max_len: usize = std.math.maxInt(u16);
            const max_len_bits: u16 = std.math.maxInt(u16);
            const first_offset: usize = blk: {
                if (alignment <= 1) break :blk 0;
                const rem = base_address % alignment;
                break :blk if (rem == 0) 0 else alignment - rem;
            };
            const pending_prefix = @min(required_extra_bytes.*, scan_limit);

            // Common chunk: every candidate in [first_offset, scan_limit) has at least max_len bytes after it (overlap reserved by caller).
            if (chunk.len + 1 >= scan_limit + max_len) {
                if (first_offset >= scan_limit) {
                    if (pending_prefix > 0) {
                        try matches.appendRun(base_address, chunk[0..pending_prefix], max_len_bits, 0);
                        required_extra_bytes.* -= pending_prefix;
                    }
                    return;
                }
                const bulk_count = (scan_limit - first_offset - 1) / alignment + 1;
                const last_offset = first_offset + (bulk_count - 1) * alignment;
                const last_end = last_offset + max_len;
                const store_start = if (pending_prefix > 0) 0 else first_offset;
                const store_end = @max(pending_prefix, @min(scan_limit, last_end));
                try matches.appendRun(base_address + store_start, chunk[store_start..store_end], max_len_bits, bulk_count);
                num_matches.* += bulk_count;
                required_extra_bytes.* = if (last_end > scan_limit) last_end - scan_limit else 0;
                return;
            }

            // Tail chunk: per-candidate walk.
            var pending_next: usize = 0;
            var pending_end = required_extra_bytes.*;
            var candidate_offset: usize = first_offset;
            while (candidate_offset < scan_limit and candidate_offset < chunk.len) : (candidate_offset += alignment) {
                const raw_len_usize = @min(chunk.len - candidate_offset, max_len);
                const raw_len: u16 = @intCast(raw_len_usize);

                while (pending_next < candidate_offset and pending_next < pending_end) : (pending_next += 1) {
                    try matches.appendRaw(base_address + pending_next, chunk[pending_next], 0);
                }

                try matches.appendRaw(base_address + candidate_offset, chunk[candidate_offset], raw_len);
                num_matches.* += 1;
                pending_next = candidate_offset + 1;
                pending_end = @max(pending_end, candidate_offset + raw_len_usize);
            }

            const flush_end = @min(pending_end, scan_limit);
            while (pending_next < flush_end) : (pending_next += 1) {
                try matches.appendRaw(base_address + pending_next, chunk[pending_next], 0);
            }
            required_extra_bytes.* = if (pending_end > scan_limit) pending_end - scan_limit else 0;
            return;
        }
    }

    if (prepared.data_type == .STRING and prepared.match_type == .MATCHEQUALTO) {
        const needle = user_values[0].string_value orelse return;
        if (needle.len == 0) {
            required_extra_bytes.* = 0;
            return;
        }

        // Length fits in u16: validateCombo gated "needle.len <= maxInt(u16)".
        const raw_len: u16 = @intCast(needle.len);
        var pending_next: usize = 0;
        var pending_end = required_extra_bytes.*;
        var search_pos: usize = 0;
        while (std.mem.indexOfPos(u8, chunk, search_pos, needle)) |hit| {
            if (hit >= scan_limit) break;
            search_pos = hit + 1;
            const absolute_address = base_address + hit;
            if (alignment != 1 and absolute_address % alignment != 0) continue;

            while (pending_next < hit and pending_next < pending_end) : (pending_next += 1) {
                try matches.appendRaw(base_address + pending_next, chunk[pending_next], 0);
            }

            try matches.appendRaw(absolute_address, chunk[hit], raw_len);
            num_matches.* += 1;
            pending_next = hit + 1;
            pending_end = @max(pending_end, hit + needle.len);
        }

        const flush_end = @min(pending_end, scan_limit);
        while (pending_next < flush_end) : (pending_next += 1) {
            try matches.appendRaw(base_address + pending_next, chunk[pending_next], 0);
        }
        required_extra_bytes.* = if (pending_end > scan_limit) pending_end - scan_limit else 0;
        return;
    }

    if (prepared.data_type == .BYTEARRAY and prepared.match_type == .MATCHEQUALTO) {
        const pattern = user_values[0].bytearray_value orelse return;
        const wildcards = user_values[0].wildcard_value orelse return;
        if (pattern.len == 0 or pattern.len != wildcards.len) {
            required_extra_bytes.* = 0;
            return;
        }

        // Length fits in u16: validateCombo gated "pattern.len <= maxInt(u16)".
        const raw_len: u16 = @intCast(pattern.len);
        var pending_next: usize = 0;
        var pending_end = required_extra_bytes.*;

        // Pick the longest contiguous FIXED-byte run in the pattern as the search anchor.
        // A single-byte anchor (the old behaviour) is a worst case when that byte is common (e.g. 0x00 in C string padding)
        // and also can't use std.mem.indexOfPos' multi-byte memmem acceleration.
        // Longest-run wins both: it suppresses false anchor hits and lets indexOfPos rip through dense chunks.
        // A no-FIXED pattern (rare but legal) falls through to the all-wildcard aligned walk below.
        var anchor_start: usize = 0;
        var anchor_len: usize = 0;
        var cur_start: usize = 0;
        var cur_len: usize = 0;
        for (wildcards, 0..) |wildcard, i| {
            if (wildcard == .FIXED) {
                if (cur_len == 0) cur_start = i;
                cur_len += 1;
                if (cur_len > anchor_len) {
                    anchor_start = cur_start;
                    anchor_len = cur_len;
                }
            } else {
                cur_len = 0;
            }
        }

        if (anchor_len > 0) {
            const needle = pattern[anchor_start .. anchor_start + anchor_len];
            var search_pos: usize = anchor_start;
            while (std.mem.indexOfPos(u8, chunk, search_pos, needle)) |hit| {
                if (hit < anchor_start) {
                    search_pos = hit + 1;
                    continue;
                }
                const start = hit - anchor_start;
                if (start >= scan_limit) break;
                search_pos = hit + 1;
                if (start + pattern.len > chunk.len) continue;

                const absolute_address = base_address + start;
                if (alignment != 1 and absolute_address % alignment != 0) continue;
                if (!bytearrayMatches(chunk[start .. start + pattern.len], pattern, wildcards)) continue;

                while (pending_next < start and pending_next < pending_end) : (pending_next += 1) {
                    try matches.appendRaw(base_address + pending_next, chunk[pending_next], 0);
                }

                try matches.appendRaw(absolute_address, chunk[start], raw_len);
                num_matches.* += 1;
                pending_next = start + 1;
                pending_end = @max(pending_end, start + pattern.len);
            }
        } else {
            const matchable_len = if (chunk.len >= pattern.len) @min(scan_limit, chunk.len - pattern.len + 1) else 0;
            var start: usize = 0;
            while (start < matchable_len) : (start += 1) {
                const absolute_address = base_address + start;
                if (alignment != 1 and absolute_address % alignment != 0) continue;
                if (!bytearrayMatches(chunk[start .. start + pattern.len], pattern, wildcards)) continue;

                while (pending_next < start and pending_next < pending_end) : (pending_next += 1) {
                    try matches.appendRaw(base_address + pending_next, chunk[pending_next], 0);
                }

                try matches.appendRaw(absolute_address, chunk[start], raw_len);
                num_matches.* += 1;
                pending_next = start + 1;
                pending_end = @max(pending_end, start + pattern.len);
            }
        }

        const flush_end = @min(pending_end, scan_limit);
        while (pending_next < flush_end) : (pending_next += 1) {
            try matches.appendRaw(base_address + pending_next, chunk[pending_next], 0);
        }
        required_extra_bytes.* = if (pending_end > scan_limit) pending_end - scan_limit else 0;
        return;
    }

    // Fixed concrete numeric MATCHEQUALTO: serialize the target value(s) once and search the chunk
    // with std.mem.indexOfPos instead of running the compare kernel at every candidate.
    // Preserves alignment filtering, overlap (search advances by hit+1), and the trailing-byte pending-span pattern.
    // Float zero exact uses two needles for +0.0 and -0.0 (different bit patterns, equal under the kernel's ""==" semantics).
    // Float NaN exact matches nothing.
    // ANY-numeric MATCHEQUALTO returns null from serialize and falls through to the kernel path below because it spans multiple widths.
    if (prepared.match_type == .MATCHEQUALTO) {
        var primary_buf: [8]u8 = undefined;
        var secondary_buf: [8]u8 = undefined;
        if (serializeExactNumericNeedles(prepared.data_type, user_values[0], prepared.reverse_endianness, &primary_buf, &secondary_buf)) |needles| {
            var pending_next: usize = 0;
            var pending_end = required_extra_bytes.*;
            var hit_primary = std.mem.indexOfPos(u8, chunk, 0, needles.primary);
            var hit_secondary: ?usize = if (needles.secondary) |sec| std.mem.indexOfPos(u8, chunk, 0, sec) else null;

            while (true) {
                var h: usize = undefined;
                var consumed_primary: bool = undefined;
                if (hit_primary) |h1| {
                    if (hit_secondary) |h2| {
                        if (h1 <= h2) {
                            h = h1;
                            consumed_primary = true;
                        } else {
                            h = h2;
                            consumed_primary = false;
                        }
                    } else {
                        h = h1;
                        consumed_primary = true;
                    }
                } else if (hit_secondary) |h2| {
                    h = h2;
                    consumed_primary = false;
                } else break;
                if (h >= scan_limit) break;
                if (consumed_primary) {
                    hit_primary = std.mem.indexOfPos(u8, chunk, h + 1, needles.primary);
                } else {
                    hit_secondary = std.mem.indexOfPos(u8, chunk, h + 1, needles.secondary.?);
                }

                const absolute_address = base_address + h;
                if (alignment != 1 and absolute_address % alignment != 0) continue;

                while (pending_next < h and pending_next < pending_end) : (pending_next += 1) {
                    try matches.appendRaw(base_address + pending_next, chunk[pending_next], 0);
                }

                // Burst-append: when we just consumed a primary hit, scan forward for consecutive
                // aligned primary matches and emit them in one appendRun rather than per-match appendRaw.
                // Only self-overlapping (uniform) needles can produce such bursts, e.g. +0.0 / integer
                // zero in zero-padded regions, but any user value with that property benefits.
                // The secondary needle (when present, only for float +/-0) differs from primary by at least one byte,
                // so it cannot match inside a uniform burst region; defensive re-search keeps the invariant explicit.
                if (consumed_primary) {
                    const step: usize = alignment;
                    var burst_end = h + step;
                    while (burst_end < scan_limit and burst_end + needles.primary.len <= chunk.len and
                        std.mem.eql(u8, chunk[burst_end .. burst_end + needles.primary.len], needles.primary)) : (burst_end += step)
                    {}
                    if (burst_end > h + step) {
                        const burst_len = (burst_end - h) / step;
                        try matches.appendRun(absolute_address, chunk[h..burst_end], needles.raw_bits, burst_len);
                        num_matches.* += burst_len;
                        pending_next = burst_end;
                        pending_end = @max(pending_end, burst_end - step + needles.primary.len);
                        hit_primary = std.mem.indexOfPos(u8, chunk, burst_end, needles.primary);
                        if (hit_secondary) |s2| {
                            if (s2 < burst_end) {
                                hit_secondary = std.mem.indexOfPos(u8, chunk, burst_end, needles.secondary.?);
                            }
                        }
                        continue;
                    }
                }

                try matches.appendRaw(absolute_address, chunk[h], needles.raw_bits);
                num_matches.* += 1;
                pending_next = h + 1;
                pending_end = @max(pending_end, h + needles.primary.len);
            }

            const flush_end = @min(pending_end, scan_limit);
            while (pending_next < flush_end) : (pending_next += 1) {
                try matches.appendRaw(base_address + pending_next, chunk[pending_next], 0);
            }
            required_extra_bytes.* = if (pending_end > scan_limit) pending_end - scan_limit else 0;
            return;
        }
    }

    // All other combos go through a pre-selected initial kernel.
    // MATCHANY, STRING/BYTEARRAY MATCHEQUALTO are intercepted above,
    // and fixed concrete numeric MATCHEQUALTO is intercepted directly above this block.
    // MATCHUPDATE and old-value-dependent match types are short-circuited in scan() before reaching here.
    // STRING/BYTEARRAY non-EQUALTO combos are rejected by validateCombo.
    // That leaves numeric MATCHNOTEQUALTO/GT/LT/RANGE and the ANY-numeric MATCHEQUALTO multi-width case,
    // which pickInitialNumericKernel always covers.
    // ANY-numeric MATCHANY falls through here from the bulk path above with "offset" set to the first unprocessed (aligned)
    // candidate so the tail-zone gets shorter-width raw_bits from the kernel instead of the full-width bulk raw_bits.
    const kernel = initial_kernel.?;
    const first_aligned_offset: usize = blk: {
        if (alignment <= 1) break :blk offset;
        const rem = base_address % alignment;
        const from_zero: usize = if (rem == 0) 0 else alignment - rem;
        break :blk @max(offset, from_zero);
    };
    var pending_next: usize = offset;
    var pending_end = offset + required_extra_bytes.*;

    var candidate_offset: usize = first_aligned_offset;
    while (candidate_offset < scan_limit) : (candidate_offset += alignment) {
        const raw_bits = kernel(chunk[candidate_offset..], user_values);
        if (raw_bits == 0) continue;
        const matched_len = storedLengthForExistingMatch(prepared.data_type, raw_bits);

        while (pending_next < candidate_offset and pending_next < pending_end) : (pending_next += 1) {
            try matches.appendRaw(base_address + pending_next, chunk[pending_next], 0);
        }

        try matches.appendRaw(base_address + candidate_offset, chunk[candidate_offset], raw_bits);
        num_matches.* += 1;
        pending_next = candidate_offset + 1;
        pending_end = @max(pending_end, candidate_offset + matched_len);
    }

    const flush_end = @min(pending_end, scan_limit);
    while (pending_next < flush_end) : (pending_next += 1) {
        try matches.appendRaw(base_address + pending_next, chunk[pending_next], 0);
    }
    required_extra_bytes.* = if (pending_end > scan_limit) pending_end - scan_limit else 0;
}

fn storedLengthForExistingMatch(data_type: ScanDataType, raw_bits: u16) usize {
    return switch (data_type) {
        .BYTEARRAY, .STRING => raw_bits,
        else => flagsToNumericLength(@bitCast(raw_bits)),
    };
}

const ExactNumericNeedles = struct {
    primary: []const u8,
    secondary: ?[]const u8,
    raw_bits: u16,
};

/// Serializes a fixed concrete numeric MATCHEQUALTO target into 1-2 byte needles plus the raw_bits to record alongside each match.
/// Returns null for unsupported data types (ANY-numeric, STRING, BYTEARRAY),
/// for float NaN (matches nothing under "=="), and for user-value flag sets that have no usable bit for this data type.
/// Float zero produces two needles (+0.0 and -0.0), which have different bit patterns but compare equal under "==".
fn serializeExactNumericNeedles(
    data_type: ScanDataType,
    user_value: UserValue,
    reverse_endianness: bool,
    primary_buf: *[8]u8,
    secondary_buf: *[8]u8,
) ?ExactNumericNeedles {
    const needle_width: usize = switch (data_type) {
        .INTEGER8 => 1,
        .INTEGER16 => 2,
        .INTEGER32, .FLOAT32 => 4,
        .INTEGER64, .FLOAT64 => 8,
        else => return null,
    };
    const flags = user_value.flags;
    const raw_bits_mask: u16 = switch (data_type) {
        .INTEGER8 => MatchFlags.i8b.bits(),
        .INTEGER16 => MatchFlags.i16b.bits(),
        .INTEGER32 => MatchFlags.i32b.bits(),
        .INTEGER64 => MatchFlags.i64b.bits(),
        .FLOAT32 => (MatchFlags{ .f32b = true }).bits(),
        .FLOAT64 => (MatchFlags{ .f64b = true }).bits(),
        else => unreachable,
    };
    const raw_bits: u16 = flags.bits() & raw_bits_mask;
    if (raw_bits == 0) return null;

    var secondary: ?[]const u8 = null;
    switch (data_type) {
        .INTEGER8 => {
            // When both signed and unsigned flags are set the needle is only valid if the bit patterns agree.
            // parseNumber always emits matching payloads, but a contrived UserValue could disagree, so fall back
            // to the general kernel rather than silently mis-record raw_bits.
            const signed_bits: u8 = @bitCast(user_value.int8_value);
            if (flags.u8b and flags.s8b and signed_bits != user_value.uint8_value) return null;
            primary_buf[0] = if (flags.u8b) user_value.uint8_value else signed_bits;
        },
        .INTEGER16 => {
            const signed_bits: u16 = @bitCast(user_value.int16_value);
            if (flags.u16b and flags.s16b and signed_bits != user_value.uint16_value) return null;
            const v: u16 = if (flags.u16b) user_value.uint16_value else signed_bits;
            std.mem.writeInt(u16, primary_buf[0..2], if (reverse_endianness) @byteSwap(v) else v, .native);
        },
        .INTEGER32 => {
            const signed_bits: u32 = @bitCast(user_value.int32_value);
            if (flags.u32b and flags.s32b and signed_bits != user_value.uint32_value) return null;
            const v: u32 = if (flags.u32b) user_value.uint32_value else signed_bits;
            std.mem.writeInt(u32, primary_buf[0..4], if (reverse_endianness) @byteSwap(v) else v, .native);
        },
        .INTEGER64 => {
            const signed_bits: u64 = @bitCast(user_value.int64_value);
            if (flags.u64b and flags.s64b and signed_bits != user_value.uint64_value) return null;
            const v: u64 = if (flags.u64b) user_value.uint64_value else signed_bits;
            std.mem.writeInt(u64, primary_buf[0..8], if (reverse_endianness) @byteSwap(v) else v, .native);
        },
        .FLOAT32 => {
            const v = user_value.float32_value;
            if (std.math.isNan(v)) return null;
            // Zero compares equal across +0.0 and -0.0, so always emit both bit patterns
            // regardless of which sign the user supplied otherwise a -0.0 input would produce identical
            // primary+secondary needles and the dual-cursor loop would double-emit the same address.
            const primary_bits: u32 = if (v == 0.0) 0 else @bitCast(v);
            std.mem.writeInt(u32, primary_buf[0..4], if (reverse_endianness) @byteSwap(primary_bits) else primary_bits, .native);
            if (v == 0.0) {
                const neg_zero: f32 = -0.0;
                const neg_bits: u32 = @bitCast(neg_zero);
                std.mem.writeInt(u32, secondary_buf[0..4], if (reverse_endianness) @byteSwap(neg_bits) else neg_bits, .native);
                secondary = secondary_buf[0..4];
            }
        },
        .FLOAT64 => {
            const v = user_value.float64_value;
            if (std.math.isNan(v)) return null;
            const primary_bits: u64 = if (v == 0.0) 0 else @bitCast(v);
            std.mem.writeInt(u64, primary_buf[0..8], if (reverse_endianness) @byteSwap(primary_bits) else primary_bits, .native);
            if (v == 0.0) {
                const neg_zero: f64 = -0.0;
                const neg_bits: u64 = @bitCast(neg_zero);
                std.mem.writeInt(u64, secondary_buf[0..8], if (reverse_endianness) @byteSwap(neg_bits) else neg_bits, .native);
                secondary = secondary_buf[0..8];
            }
        },
        else => unreachable,
    }
    return .{ .primary = primary_buf[0..needle_width], .secondary = secondary, .raw_bits = raw_bits };
}

/// MATCHANY rescan flag computation: re-broadens to every width that fits in the previously-stored byte length.
/// Concrete fixed types yield exactly their own flag (stored_len == width).
/// ANY-types yield every sub-width that fits.
/// STRING/BYTEARRAY pass the stored length through as raw_bits.
fn matchAnyRawBitsForStoredLength(data_type: ScanDataType, stored_len: usize) u16 {
    return switch (data_type) {
        .INTEGER8 => if (stored_len >= 1) MatchFlags.i8b.bits() else 0,
        .INTEGER16 => if (stored_len >= 2) MatchFlags.i16b.bits() else 0,
        .INTEGER32 => if (stored_len >= 4) MatchFlags.i32b.bits() else 0,
        .INTEGER64 => if (stored_len >= 8) MatchFlags.i64b.bits() else 0,
        .FLOAT32 => if (stored_len >= 4) (MatchFlags{ .f32b = true }).bits() else 0,
        .FLOAT64 => if (stored_len >= 8) (MatchFlags{ .f64b = true }).bits() else 0,
        .ANYINTEGER => scanroutines.anyIntegerInitialBits(stored_len),
        .ANYFLOAT => scanroutines.anyFloatInitialBits(stored_len),
        .ANYNUMBER => scanroutines.anyIntegerInitialBits(stored_len) | scanroutines.anyFloatInitialBits(stored_len),
        .BYTEARRAY, .STRING => if (stored_len <= std.math.maxInt(u16)) @intCast(stored_len) else 0,
    };
}

fn bytearrayMatches(memory: []const u8, pattern: []const u8, wildcards: []const value_mod.Wildcard) bool {
    if (pattern.len != wildcards.len or memory.len < pattern.len) return false;
    for (pattern, wildcards, 0..) |byte, wildcard, i| {
        if (byte != (memory[i] & @intFromEnum(wildcard))) return false;
    }
    return true;
}

fn fullSharedSegmentWidth(segment: targetmem.SegmentView, data_type: ScanDataType, max_width: usize) ?usize {
    if (segment.header.match_count == 0 or
        segment.first_candidate != segment.header.first_byte_in_child or
        segment.header.layout != .shared_raw_bits or
        segment.header.exception_count != 0 or
        segment.header.match_count != segment.candidate_count)
    {
        return null;
    }

    const stored_width = storedLengthForExistingMatch(data_type, segment.header.shared_raw_bits);
    if (stored_width == 0 or stored_width > max_width) return null;
    return switch (data_type) {
        .ANYINTEGER, .ANYFLOAT, .ANYNUMBER => stored_width,
        .INTEGER8, .INTEGER16, .INTEGER32, .INTEGER64, .FLOAT32, .FLOAT64 => if (stored_width == max_width) stored_width else null,
        .BYTEARRAY, .STRING => null,
    };
}

fn stridedBatchLimit(width: usize, stride: usize) usize {
    std.debug.assert(stride != 0);
    std.debug.assert(width <= MemoryCache.read_chunk_size);
    return 1 + (MemoryCache.read_chunk_size - width) / stride;
}

fn stridedWindowLen(candidate_count: usize, stride: usize, width: usize) usize {
    std.debug.assert(candidate_count != 0);
    return (candidate_count - 1) * stride + width;
}

fn stridedFirstBytesLen(candidate_count: usize, stride: usize) usize {
    std.debug.assert(candidate_count != 0);
    return (candidate_count - 1) * stride + 1;
}

fn stridedValidCandidates(byte_len: usize, width: usize, stride: usize, batch_len: usize) usize {
    std.debug.assert(stride != 0);
    if (byte_len < width) return 0;
    return @min(batch_len, 1 + (byte_len - width) / stride);
}

inline fn updateProgress(scanner: *Scanner, processed: usize, total: usize) void {
    if (total == 0) {
        scanner.scan_progress = 1.0;
        return;
    }
    const processed_float: f64 = @floatFromInt(processed);
    const total_float: f64 = @floatFromInt(total);
    scanner.scan_progress = @min(1.0, processed_float / total_float);
}

inline fn updateRescanProgress(scanner: *Scanner, processed: usize, total_matches: usize) void {
    if (processed & 0x3fff == 0) {
        updateProgress(scanner, processed, total_matches);
    }
}

fn matchReadFlags(data_type: ScanDataType, raw_bits: u16) ScannerError!MatchFlags {
    return switch (data_type) {
        .BYTEARRAY, .STRING => ScannerError.UnsupportedReadDataType,
        .ANYINTEGER, .ANYFLOAT, .ANYNUMBER => blk: {
            const flags: MatchFlags = @bitCast(raw_bits);
            if (flags.bits() == 0) return ScannerError.UnsupportedReadDataType;
            break :blk flags;
        },
        .INTEGER8 => MatchFlags.i8b,
        .INTEGER16 => MatchFlags.i16b,
        .INTEGER32 => MatchFlags.i32b,
        .INTEGER64 => MatchFlags.i64b,
        .FLOAT32 => .{ .f32b = true },
        .FLOAT64 => .{ .f64b = true },
    };
}

fn decodeValueForTargetEndian(data_type: ScanDataType, reverse_endianness: bool, value: Value) Value {
    if (!reverse_endianness) return value;

    const width: usize = switch (data_type) {
        .INTEGER8 => if ((value.flags.bits() & MatchFlags.i8b.bits()) != 0) 1 else return value,
        .INTEGER16 => if ((value.flags.bits() & MatchFlags.i16b.bits()) != 0) 2 else return value,
        .INTEGER32 => if ((value.flags.bits() & MatchFlags.i32b.bits()) != 0) 4 else return value,
        .INTEGER64 => if ((value.flags.bits() & MatchFlags.i64b.bits()) != 0) 8 else return value,
        .FLOAT32 => if (value.flags.f32b) 4 else return value,
        .FLOAT64 => if (value.flags.f64b) 8 else return value,
        .ANYINTEGER, .ANYFLOAT, .ANYNUMBER => blk: {
            // These types carry cumulative flags (every width the value fits), so the stored bytes are the widest interpretation.
            const w = flagsToNumericLength(value.flags);
            if (w == 0) return value;
            break :blk w;
        },
        .BYTEARRAY, .STRING => return value,
    };

    var result = value;
    switch (width) {
        1 => {},
        2 => result.data.uint16_value = @byteSwap(result.data.uint16_value),
        4 => result.data.uint32_value = @byteSwap(result.data.uint32_value),
        8 => result.data.uint64_value = @byteSwap(result.data.uint64_value),
        else => unreachable,
    }
    return result;
}

fn serializeWriteValue(
    data_type: ScanDataType,
    reverse_endianness: bool,
    user_value: UserValue,
    expected_length: ?usize,
    scratch: *[8]u8,
) ScannerError![]const u8 {
    return switch (data_type) {
        .INTEGER8 => blk: {
            if (user_value.flags.u8b) {
                scratch[0] = user_value.uint8_value;
            } else if (user_value.flags.s8b) {
                scratch[0] = @bitCast(user_value.int8_value);
            } else {
                return ScannerError.InvalidWriteValue;
            }
            break :blk scratch[0..1];
        },
        .INTEGER16 => blk: {
            var value: u16 = if (user_value.flags.u16b)
                user_value.uint16_value
            else if (user_value.flags.s16b)
                @bitCast(user_value.int16_value)
            else
                return ScannerError.InvalidWriteValue;
            if (reverse_endianness) value = @byteSwap(value);
            std.mem.writeInt(u16, scratch[0..2], value, .native);
            break :blk scratch[0..2];
        },
        .INTEGER32 => blk: {
            var value: u32 = if (user_value.flags.u32b)
                user_value.uint32_value
            else if (user_value.flags.s32b)
                @bitCast(user_value.int32_value)
            else
                return ScannerError.InvalidWriteValue;
            if (reverse_endianness) value = @byteSwap(value);
            std.mem.writeInt(u32, scratch[0..4], value, .native);
            break :blk scratch[0..4];
        },
        .INTEGER64 => blk: {
            var value: u64 = if (user_value.flags.u64b)
                user_value.uint64_value
            else if (user_value.flags.s64b)
                @bitCast(user_value.int64_value)
            else
                return ScannerError.InvalidWriteValue;
            if (reverse_endianness) value = @byteSwap(value);
            std.mem.writeInt(u64, scratch[0..8], value, .native);
            break :blk scratch[0..8];
        },
        .FLOAT32 => blk: {
            if (!user_value.flags.f32b) return ScannerError.InvalidWriteValue;
            var value: u32 = @bitCast(user_value.float32_value);
            if (reverse_endianness) value = @byteSwap(value);
            std.mem.writeInt(u32, scratch[0..4], value, .native);
            break :blk scratch[0..4];
        },
        .FLOAT64 => blk: {
            if (!user_value.flags.f64b) return ScannerError.InvalidWriteValue;
            var value: u64 = @bitCast(user_value.float64_value);
            if (reverse_endianness) value = @byteSwap(value);
            std.mem.writeInt(u64, scratch[0..8], value, .native);
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

fn effectiveAlignment(alignment: u16, data_type: ScanDataType) u16 {
    if (alignment != 0) return alignment;
    return switch (data_type) {
        .INTEGER16 => 2,
        .INTEGER32, .FLOAT32 => 4,
        .INTEGER64, .FLOAT64 => 8,
        else => 1,
    };
}

fn regionIdIncluded(region_id: u32, region_ids: []const usize) bool {
    for (region_ids) |candidate| {
        if (region_id == candidate) return true;
    }
    return false;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

fn attachScannerToTestMemory(scanner: *Scanner, allocator: Allocator, memory: []u8) !void {
    const pid = std.c.getpid();
    scanner.process_handle = ProcessHandle.attach(scanner.io, pid) catch |err| switch (err) {
        ProcessError.AttachFailed => return error.SkipZigTest,
        else => return err,
    };

    scanner.regions = try allocator.alloc(Region, 1);
    scanner.regions[0] = .{
        .start = @intFromPtr(memory.ptr),
        .size = memory.len,
        .kind = .HEAP,
        .flags = .{ .read = true, .write = true, .exec = false, .shared = false, .private = true },
        .load_addr = 0,
        .id = 0,
        .filename = try allocator.dupe(u8, ""),
    };
}

test "Init: starts detached with defaults" {
    var scanner = Scanner.init(std.testing.allocator, std.testing.io);
    defer scanner.deinit();

    try std.testing.expect(scanner.process_handle == null);
    try std.testing.expect(scanner.target_pid == null);
    try std.testing.expectEqual(0, scanner.regionCount());
    try std.testing.expectEqual(0, scanner.matchCount());
    try std.testing.expect(!scanner.hasMatches());
    try std.testing.expect(!scanner.undo_available);
    try std.testing.expect(scanner.fresh_session);
    try std.testing.expect(!@atomicLoad(bool, &scanner.stop_flag, .monotonic));
    try std.testing.expectEqual(0, scanner.scan_progress);
    try std.testing.expectEqual(0, scanner.options.alignment);
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

test "scan MATCHUPDATE requires attachment on fresh session" {
    var scanner = Scanner.init(std.testing.allocator, std.testing.io);
    defer scanner.deinit();

    try std.testing.expect(scanner.fresh_session);
    try std.testing.expectError(ScannerError.NotAttached, scanner.scan(.MATCHUPDATE, &.{}));
    // Boundary check must run before fresh_session is flipped.
    try std.testing.expect(scanner.fresh_session);
}

test "scan MATCHCHANGED on fresh session returns empty without allocating" {
    const allocator = std.testing.allocator;

    var memory: [16]u8 = @splat(0);
    var scanner = Scanner.init(allocator, std.testing.io);
    defer scanner.deinit();
    scanner.options.scan_data_type = .INTEGER32;
    try attachScannerToTestMemory(&scanner, allocator, &memory);

    try std.testing.expect(scanner.matches == null);
    try scanner.scan(.MATCHCHANGED, &.{});

    // No matches and no allocated storage, old-value rescans on a fresh
    // session match nothing by definition, so we skip the memory walk.
    try std.testing.expectEqual(0, scanner.matchCount());
    try std.testing.expect(scanner.matches == null);
    try std.testing.expect(!scanner.fresh_session);
    const complete_progress: f32 = 1.0;
    try std.testing.expectEqual(complete_progress, scanner.scan_progress);
}

test "scan fresh MATCHINCREASEDBY still validates required user value count" {
    const allocator = std.testing.allocator;

    var memory: [16]u8 = @splat(0);
    var scanner = Scanner.init(allocator, std.testing.io);
    defer scanner.deinit();
    scanner.options.scan_data_type = .INTEGER32;
    try attachScannerToTestMemory(&scanner, allocator, &memory);

    // MATCHINCREASEDBY requires user_values.
    // The short-circuit must not bypass validateCombo, so an empty value list still surfaces the combo error.
    try std.testing.expectError(ScannerError.UnsupportedScanCombination, scanner.scan(.MATCHINCREASEDBY, &.{}));
    try std.testing.expect(scanner.fresh_session);
}

test "scan fresh MATCHCHANGED still requires attachment" {
    var scanner = Scanner.init(std.testing.allocator, std.testing.io);
    defer scanner.deinit();
    scanner.options.scan_data_type = .INTEGER32;

    try std.testing.expectError(ScannerError.NotAttached, scanner.scan(.MATCHCHANGED, &.{}));
    try std.testing.expect(scanner.fresh_session);
}

test "scanPointers: scans process memory and writes direct and nested pointer paths" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    const memory = try allocator.alignedAlloc(u8, std.mem.Alignment.of(usize), 0x100);
    defer allocator.free(memory);
    @memset(memory, 0);

    const base_address = @intFromPtr(memory.ptr);
    const middle_pointer_address = base_address + 0x40;
    const target_address = base_address + 0x90;

    std.mem.writeInt(usize, memory[0x10..][0..@sizeOf(usize)], middle_pointer_address - 0x10, .native);
    std.mem.writeInt(usize, memory[0x40..][0..@sizeOf(usize)], target_address - 0x8, .native);

    const pid = std.c.getpid();
    var scanner = Scanner.init(allocator, io);
    defer scanner.deinit();

    // Open the process directly so this test can install one synthetic region below.
    // Scanner.attach would reload the full process map and make it wasteful.
    scanner.process_handle = ProcessHandle.attach(io, pid) catch |err| switch (err) {
        ProcessError.AttachFailed => return error.SkipZigTest,
        else => return err,
    };
    scanner.target_pid = pid;
    scanner.fresh_session = true;

    scanner.regions = try allocator.alloc(Region, 1);
    scanner.regions[0] = .{
        .start = base_address,
        .size = memory.len,
        .kind = .EXE,
        .flags = .{ .read = true, .write = true, .exec = false, .shared = false, .private = true },
        .load_addr = base_address,
        .id = 0,
        .filename = try allocator.dupe(u8, "/tmp/libmemscan-pointer-test-module"),
    };

    var random_bytes: [8]u8 = undefined;
    io.random(&random_bytes);
    var map_path_buffer: [128]u8 = undefined;
    const map_path = try std.fmt.bufPrint(&map_path_buffer, "/tmp/libmemscan-pointer-scan-{d}-{x}.lmptr", .{
        pid,
        std.mem.readInt(u64, &random_bytes, .native),
    });
    defer std.Io.Dir.deleteFileAbsolute(io, map_path) catch {};

    const paths_found = try scanner.scanPointers(target_address, map_path, .{
        .pointer_width = @sizeOf(usize),
        .max_depth = 2,
        .max_positive_offset = 0x20,
    });
    try std.testing.expectEqual(2, paths_found);
    try std.testing.expectEqual(1, scanner.scan_progress);

    const read_file = try std.Io.Dir.openFileAbsolute(io, map_path, .{});
    var reader = try pointerscan.PointerMapReader.init(allocator, io, read_file);
    defer reader.deinit();

    var out = std.Io.Writer.Allocating.init(allocator);
    defer out.deinit();
    try reader.dumpText(&out.writer);

    try std.testing.expectEqualStrings(
        \\libmemscan-pointer-test-module+0x40 -> 0x8
        \\libmemscan-pointer-test-module+0x10 -> 0x10 -> 0x8
        \\
    , out.written());
}

test "ensureMatchStorage: allocates lazily" {
    var scanner = Scanner.init(std.testing.allocator, std.testing.io);
    defer scanner.deinit();

    const matches = try scanner.ensureMatchStorage(256);
    try std.testing.expectEqual(0, matches.matchCount());
    try std.testing.expect(scanner.matches != null);
    try std.testing.expectEqual(0, matches.capacity_len);
    try std.testing.expectEqual(256, matches.max_needed_bytes);

    const reused = try scanner.ensureMatchStorage(512);
    try std.testing.expectEqual(0, reused.capacity_len);
    try std.testing.expectEqual(256, reused.max_needed_bytes);
}

test "setters update scanner options" {
    var scanner = Scanner.init(std.testing.allocator, std.testing.io);
    defer scanner.deinit();

    try scanner.setDataType(.FLOAT64);
    try scanner.setScanLevel(.ALL_RW);
    try scanner.setReverseEndianness(true);
    scanner.setStopFlag(true);

    try std.testing.expectEqual(ScanDataType.FLOAT64, scanner.options.scan_data_type);
    try std.testing.expectEqual(ScanLevel.ALL_RW, scanner.options.scan_level);
    try std.testing.expect(scanner.options.reverse_endianness);
    try std.testing.expect(@atomicLoad(bool, &scanner.stop_flag, .monotonic));
}

test "setDataType: requires a fresh session" {
    var scanner = Scanner.init(std.testing.allocator, std.testing.io);
    defer scanner.deinit();

    try scanner.setDataType(.FLOAT64);
    try std.testing.expectEqual(ScanDataType.FLOAT64, scanner.options.scan_data_type);

    scanner.fresh_session = false;
    try std.testing.expectError(ScannerError.OptionRequiresReset, scanner.setDataType(.INTEGER16));
    try std.testing.expectEqual(ScanDataType.FLOAT64, scanner.options.scan_data_type);
}

test "setReverseEndianness: requires a fresh session" {
    var scanner = Scanner.init(std.testing.allocator, std.testing.io);
    defer scanner.deinit();

    try scanner.setReverseEndianness(true);
    try std.testing.expect(scanner.options.reverse_endianness);

    scanner.fresh_session = false;
    try std.testing.expectError(ScannerError.OptionRequiresReset, scanner.setReverseEndianness(false));
    try std.testing.expect(scanner.options.reverse_endianness);
}

test "setAlignment: requires a fresh session" {
    var scanner = Scanner.init(std.testing.allocator, std.testing.io);
    defer scanner.deinit();

    try scanner.setAlignment(4);
    const expected_alignment: u16 = 4;
    try std.testing.expectEqual(expected_alignment, scanner.options.alignment);

    scanner.fresh_session = false;
    try std.testing.expectError(ScannerError.OptionRequiresReset, scanner.setAlignment(8));
    try std.testing.expectEqual(expected_alignment, scanner.options.alignment);
}

test "match helpers expose stored match ergonomically" {
    var scanner = Scanner.init(std.testing.allocator, std.testing.io);
    defer scanner.deinit();

    var matches = try MatchesArray.init(std.testing.allocator, 256, 1);
    try matches.append(0x4000, 0x78, .{ .u32b = true, .s32b = true });
    try matches.append(0x4001, 0x56, .{});
    try matches.append(0x4002, 0x34, .{});
    try matches.append(0x4003, 0x12, .{});
    try matches.finalize();

    scanner.matches = matches;
    scanner.num_matches = matches.matchCount();

    const first = try scanner.matchAt(0);
    try std.testing.expectEqual(0, first.index);
    try std.testing.expectEqual(0x4000, first.address);
    try std.testing.expectEqual((MatchFlags{ .u32b = true, .s32b = true }).bits(), first.raw_match_info_bits);
    try std.testing.expectEqual((MatchFlags{ .u32b = true, .s32b = true }).bits(), first.stored_value.flags.bits());
    try std.testing.expectEqual(0x12345678, first.stored_value.data.uint32_value);
    try std.testing.expectEqual(0, scanner.findMatchIndexByAddress(0x4000).?);
    try std.testing.expectEqual(null, scanner.findMatchIndexByAddress(0x4001));
    try std.testing.expectEqual(1, scanner.matchCount());
    try std.testing.expect(scanner.hasMatches());
    try std.testing.expectError(ScannerError.MatchIndexOutOfRange, scanner.matchAt(1));
}

test "storedMatchBytes: returns raw stored bytes" {
    var scanner = Scanner.init(std.testing.allocator, std.testing.io);
    defer scanner.deinit();

    var numeric_matches = try MatchesArray.init(std.testing.allocator, 256, 1);
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

    var byte_matches = try MatchesArray.init(std.testing.allocator, 256, 1);
    try byte_matches.appendRaw(0x6000, 0xaa, 3);
    try byte_matches.append(0x6001, 0xbb, .{});
    try byte_matches.append(0x6002, 0xcc, .{});
    try byte_matches.finalize();

    scanner.matches = byte_matches;
    scanner.num_matches = byte_matches.matchCount();
    scanner.options.scan_data_type = .BYTEARRAY;

    var byte_buf: [3]u8 = undefined;
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0xaa, 0xbb, 0xcc }, try scanner.storedMatchBytes(0, &byte_buf));
}

test "clearUndoHistory: clears cache-file backed undo state" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var scanner = Scanner.init(std.testing.allocator, std.testing.io);
    defer scanner.deinit();
    scanner.undo_file = try tmp.dir.createFile(scanner.io, "undo.bin", .{ .read = true, .truncate = true });

    var matches = try MatchesArray.init(std.testing.allocator, 256, 1);
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
    try std.testing.expectEqual(0, try undo_file.length(scanner.io));
    var byte: [1]u8 = undefined;
    try std.testing.expectEqual(0, try undo_file.readPositionalAll(scanner.io, &byte, 0));
}

test "undoLastScan: restores previous match list and options" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var scanner = Scanner.init(std.testing.allocator, std.testing.io);
    defer scanner.deinit();
    scanner.undo_file = try tmp.dir.createFile(scanner.io, "undo.bin", .{ .read = true, .truncate = true });

    var old_matches = try MatchesArray.init(std.testing.allocator, 256, 1);
    try old_matches.append(0x7100, 0x11, .{ .u8b = true, .s8b = true });
    try old_matches.finalize();

    var current_matches = try MatchesArray.init(std.testing.allocator, 256, 1);
    var current_matches_owned = true;
    errdefer if (current_matches_owned) current_matches.deinit();
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
    const current_match_count = current_matches.matchCount();
    scanner.matches = current_matches;
    current_matches_owned = false;
    scanner.num_matches = current_match_count;
    scanner.options = .{
        .alignment = 1,
        .scan_data_type = .FLOAT64,
        .scan_level = .ALL,
        .reverse_endianness = false,
    };

    try scanner.undoLastScan();

    try std.testing.expect(!scanner.undo_available);
    try std.testing.expectEqual(1, scanner.matchCount());
    try std.testing.expectEqual(4, scanner.options.alignment);
    try std.testing.expectEqual(ScanDataType.INTEGER8, scanner.options.scan_data_type);
    try std.testing.expectEqual(ScanLevel.ALL_RW, scanner.options.scan_level);
    try std.testing.expect(scanner.options.reverse_endianness);
    try std.testing.expectEqual(1, scanner.scan_progress);

    const restored = try scanner.matchAt(0);
    try std.testing.expectEqual(0x7100, restored.address);
    try std.testing.expectEqual(0x11, restored.stored_value.data.uint8_value);
}

test "snapshot: requires a fresh reset state" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var scanner = Scanner.init(std.testing.allocator, std.testing.io);
    defer scanner.deinit();
    scanner.undo_file = try tmp.dir.createFile(scanner.io, "undo.bin", .{ .read = true, .truncate = true });

    scanner.fresh_session = false;
    try std.testing.expectError(ScannerError.SnapshotRequiresReset, scanner.snapshot());

    var matches = try MatchesArray.init(std.testing.allocator, 256, 1);
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
    try std.testing.expectEqual(0, scanner.matchCount());
    try std.testing.expectEqual(0, scanner.scan_progress);
    try std.testing.expect(!@atomicLoad(bool, &scanner.stop_flag, .monotonic));
}

test "rescanMatches: shrinks integer matches and stores current values" {
    const allocator = std.testing.allocator;

    const memory = try allocator.alignedAlloc(u8, std.mem.Alignment.of(u32), 16);
    defer allocator.free(memory);
    @memset(memory, 0);
    std.mem.writeInt(u32, memory[0..4], 0x11111111, .native);
    std.mem.writeInt(u32, memory[8..12], 0x22222222, .native);

    var scanner = Scanner.init(allocator, std.testing.io);
    defer scanner.deinit();
    scanner.options.scan_data_type = .INTEGER32;

    const pid = std.c.getpid();
    scanner.process_handle = ProcessHandle.attach(scanner.io, pid) catch |err| switch (err) {
        ProcessError.AttachFailed => return error.SkipZigTest,
        else => return err,
    };

    const base_address = @intFromPtr(memory.ptr);
    scanner.regions = try allocator.alloc(Region, 1);
    scanner.regions[0] = .{
        .start = base_address,
        .size = memory.len,
        .kind = .HEAP,
        .flags = .{ .read = true, .write = true, .exec = false, .shared = false, .private = true },
        .load_addr = 0,
        .id = 0,
        .filename = try allocator.dupe(u8, ""),
    };

    var matches = try MatchesArray.init(allocator, 256, 1);
    for ([_]usize{ 0, 8 }) |offset| {
        try matches.append(base_address + offset, memory[offset], MatchFlags.i32b);
        for (1..4) |i| {
            try matches.append(base_address + offset + i, memory[offset + i], .{});
        }
    }
    try matches.finalize();

    scanner.matches = matches;

    std.mem.writeInt(u32, memory[8..12], 0x33333333, .native);
    try scanner.rescanMatches(.MATCHCHANGED, &.{});

    try std.testing.expectEqual(1, scanner.matchCount());
    const kept = try scanner.matchAt(0);
    try std.testing.expectEqual(base_address + 8, kept.address);
    try std.testing.expectEqual(0x33333333, kept.stored_value.data.uint32_value);
}

test "rescanMatches: update refreshes anynumber bytes and preserves narrowed flags" {
    const allocator = std.testing.allocator;

    var memory = [_]u8{ 0x34, 0x12 };
    var scanner = Scanner.init(allocator, std.testing.io);
    defer scanner.deinit();
    scanner.options.scan_data_type = .ANYNUMBER;
    try attachScannerToTestMemory(&scanner, allocator, &memory);

    const base_address = @intFromPtr(&memory);
    const old_bytes = [_]u8{ 0xcd, 0xab };
    const raw_bits = (MatchFlags{ .u16b = true }).bits();
    var matches = try MatchesArray.init(allocator, 256, 1);
    try matches.appendRun(base_address, &old_bytes, raw_bits, 1);
    try matches.finalize();
    scanner.matches = matches;
    scanner.num_matches = matches.matchCount();

    try scanner.rescanMatches(.MATCHUPDATE, &.{});

    try scanner.matches.?.validate();
    try std.testing.expectEqual(1, scanner.matchCount());
    try std.testing.expectEqual(raw_bits, (try scanner.matchAt(0)).raw_match_info_bits);
    var stored: [2]u8 = undefined;
    try std.testing.expectEqualSlices(u8, &memory, try scanner.storedMatchBytes(0, &stored));
}

test "rescanMatches: update refreshes overlapping string bytes" {
    const allocator = std.testing.allocator;

    var memory = [_]u8{ 'a', 'b', 'c', 'd', 'e', 'f' };
    var scanner = Scanner.init(allocator, std.testing.io);
    defer scanner.deinit();
    scanner.options.scan_data_type = .STRING;
    try attachScannerToTestMemory(&scanner, allocator, &memory);

    const base_address = @intFromPtr(&memory);
    const old_bytes = [_]u8{ 'x', 'x', 'x', 'x', 'y', 'y' };
    const raw_len: u16 = 4;
    var matches = try MatchesArray.init(allocator, 256, 1);
    for (old_bytes, 0..) |byte, i| {
        const raw_bits = if (i == 0 or i == 2) raw_len else 0;
        try matches.appendRaw(base_address + i, byte, raw_bits);
    }
    try matches.finalize();
    scanner.matches = matches;
    scanner.num_matches = matches.matchCount();

    try scanner.rescanMatches(.MATCHUPDATE, &.{});

    try scanner.matches.?.validate();
    try std.testing.expectEqual(2, scanner.matchCount());
    var first: [4]u8 = undefined;
    var second: [4]u8 = undefined;
    try std.testing.expectEqualSlices(u8, memory[0..4], try scanner.storedMatchBytes(0, &first));
    try std.testing.expectEqualSlices(u8, memory[2..6], try scanner.storedMatchBytes(1, &second));
    try std.testing.expectEqual(raw_len, (try scanner.matchAt(0)).raw_match_info_bits);
    try std.testing.expectEqual(raw_len, (try scanner.matchAt(1)).raw_match_info_bits);
}

test "rescanMatches: update refreshes bytearray bytes and preserves length" {
    const allocator = std.testing.allocator;

    var memory = [_]u8{ 0xaa, 0xbb, 0xcc };
    var scanner = Scanner.init(allocator, std.testing.io);
    defer scanner.deinit();
    scanner.options.scan_data_type = .BYTEARRAY;
    try attachScannerToTestMemory(&scanner, allocator, &memory);

    const base_address = @intFromPtr(&memory);
    const old_bytes = [_]u8{ 0x11, 0x22, 0x33 };
    const raw_len: u16 = old_bytes.len;
    var matches = try MatchesArray.init(allocator, 256, 1);
    try matches.appendRun(base_address, &old_bytes, raw_len, 1);
    try matches.finalize();
    scanner.matches = matches;
    scanner.num_matches = matches.matchCount();

    try scanner.rescanMatches(.MATCHUPDATE, &.{});

    try scanner.matches.?.validate();
    try std.testing.expectEqual(1, scanner.matchCount());
    try std.testing.expectEqual(raw_len, (try scanner.matchAt(0)).raw_match_info_bits);
    var stored: [3]u8 = undefined;
    try std.testing.expectEqualSlices(u8, &memory, try scanner.storedMatchBytes(0, &stored));
}

test "rescanMatches: MATCHANY refreshes fixed INTEGER32 bytes and asserts type flag" {
    const allocator = std.testing.allocator;

    var memory: [4]u8 = undefined;
    std.mem.writeInt(u32, &memory, 0xdeadbeef, .native);
    var scanner = Scanner.init(allocator, std.testing.io);
    defer scanner.deinit();
    scanner.options.scan_data_type = .INTEGER32;
    try attachScannerToTestMemory(&scanner, allocator, &memory);

    const base_address = @intFromPtr(&memory);
    var old_bytes: [4]u8 = undefined;
    std.mem.writeInt(u32, &old_bytes, 0x11223344, .native);
    var matches = try MatchesArray.init(allocator, 256, 1);
    try matches.appendRun(base_address, &old_bytes, MatchFlags.i32b.bits(), 1);
    try matches.finalize();
    scanner.matches = matches;
    scanner.num_matches = matches.matchCount();

    try scanner.rescanMatches(.MATCHANY, &.{});

    try scanner.matches.?.validate();
    try std.testing.expectEqual(1, scanner.matchCount());
    try std.testing.expectEqual(MatchFlags.i32b.bits(), (try scanner.matchAt(0)).raw_match_info_bits);
    var stored: [4]u8 = undefined;
    try std.testing.expectEqualSlices(u8, &memory, try scanner.storedMatchBytes(0, &stored));
}

test "rescanMatches: MATCHANY on ANYINTEGER re-broadens only widths fitting stored length" {
    const allocator = std.testing.allocator;

    var memory = [_]u8{ 0x34, 0x12 };
    var scanner = Scanner.init(allocator, std.testing.io);
    defer scanner.deinit();
    scanner.options.scan_data_type = .ANYINTEGER;
    try attachScannerToTestMemory(&scanner, allocator, &memory);

    const base_address = @intFromPtr(&memory);
    const old_bytes = [_]u8{ 0xcd, 0xab };
    // Narrowed to a single 16-bit width: stored_len == 2.
    const narrowed_bits = MatchFlags.i16b.bits();
    var matches = try MatchesArray.init(allocator, 256, 1);
    try matches.appendRun(base_address, &old_bytes, narrowed_bits, 1);
    try matches.finalize();
    scanner.matches = matches;
    scanner.num_matches = matches.matchCount();

    try scanner.rescanMatches(.MATCHANY, &.{});

    try scanner.matches.?.validate();
    try std.testing.expectEqual(1, scanner.matchCount());
    // stored_len == 2 -> only i8b and i16b widths fit. i32b/i64b must not appear.
    const expected_bits = MatchFlags.i8b.bits() | MatchFlags.i16b.bits();
    try std.testing.expectEqual(expected_bits, (try scanner.matchAt(0)).raw_match_info_bits);
    var stored: [2]u8 = undefined;
    try std.testing.expectEqualSlices(u8, &memory, try scanner.storedMatchBytes(0, &stored));
}

test "rescanMatches: MATCHANY on STRING preserves stored length and refreshes bytes" {
    const allocator = std.testing.allocator;

    var memory = [_]u8{ 'a', 'b', 'c', 'd' };
    var scanner = Scanner.init(allocator, std.testing.io);
    defer scanner.deinit();
    scanner.options.scan_data_type = .STRING;
    try attachScannerToTestMemory(&scanner, allocator, &memory);

    const base_address = @intFromPtr(&memory);
    const old_bytes = [_]u8{ 'x', 'x', 'x', 'x' };
    const raw_len: u16 = old_bytes.len;
    var matches = try MatchesArray.init(allocator, 256, 1);
    try matches.appendRun(base_address, &old_bytes, raw_len, 1);
    try matches.finalize();
    scanner.matches = matches;
    scanner.num_matches = matches.matchCount();

    try scanner.rescanMatches(.MATCHANY, &.{});

    try scanner.matches.?.validate();
    try std.testing.expectEqual(1, scanner.matchCount());
    try std.testing.expectEqual(raw_len, (try scanner.matchAt(0)).raw_match_info_bits);
    var stored: [4]u8 = undefined;
    try std.testing.expectEqualSlices(u8, &memory, try scanner.storedMatchBytes(0, &stored));
}

test "rescanMatches: string exact can shrink stored length" {
    const allocator = std.testing.allocator;

    var memory = [_]u8{ 'a', 'b', 'c', 'd', 'e' };
    var scanner = Scanner.init(allocator, std.testing.io);
    defer scanner.deinit();
    scanner.options.scan_data_type = .STRING;
    try attachScannerToTestMemory(&scanner, allocator, &memory);

    const base_address = @intFromPtr(&memory);
    const old_bytes = [_]u8{ 'x', 'x', 'x', 'x', 'x' };
    var matches = try MatchesArray.init(allocator, 256, 1);
    try matches.appendRun(base_address, &old_bytes, old_bytes.len, 1);
    try matches.finalize();
    scanner.matches = matches;
    scanner.num_matches = matches.matchCount();

    const user = UserValue{ .string_value = "abc" };
    try scanner.rescanMatches(.MATCHEQUALTO, &.{user});

    try scanner.matches.?.validate();
    try std.testing.expectEqual(1, scanner.matchCount());
    try std.testing.expectEqual(3, (try scanner.matchAt(0)).raw_match_info_bits);
    var stored: [3]u8 = undefined;
    try std.testing.expectEqualSlices(u8, "abc", try scanner.storedMatchBytes(0, &stored));
}

test "rescanMatches: string exact preserves previous-length read limit" {
    const allocator = std.testing.allocator;

    var memory = [_]u8{ 'a', 'b', 'c', 'd' };
    var scanner = Scanner.init(allocator, std.testing.io);
    defer scanner.deinit();
    scanner.options.scan_data_type = .STRING;
    try attachScannerToTestMemory(&scanner, allocator, &memory);

    const base_address = @intFromPtr(&memory);
    const old_bytes = [_]u8{ 'a', 'b', 'c' };
    var matches = try MatchesArray.init(allocator, 256, 1);
    try matches.appendRun(base_address, &old_bytes, old_bytes.len, 1);
    try matches.finalize();
    scanner.matches = matches;
    scanner.num_matches = matches.matchCount();

    const user = UserValue{ .string_value = "abcd" };
    try scanner.rescanMatches(.MATCHEQUALTO, &.{user});

    try scanner.matches.?.validate();
    try std.testing.expectEqual(0, scanner.matchCount());
}

test "rescanMatches: string exact preserves overlapping survivors" {
    const allocator = std.testing.allocator;

    var memory = [_]u8{ 'a', 'b', 'a', 'b', 'a' };
    var scanner = Scanner.init(allocator, std.testing.io);
    defer scanner.deinit();
    scanner.options.scan_data_type = .STRING;
    try attachScannerToTestMemory(&scanner, allocator, &memory);

    const base_address = @intFromPtr(&memory);
    const old_bytes = [_]u8{ 'x', 'x', 'x', 'x', 'x' };
    const raw_len: u16 = 3;
    var matches = try MatchesArray.init(allocator, 256, 1);
    for (old_bytes, 0..) |byte, i| {
        const raw_bits = if (i == 0 or i == 2) raw_len else 0;
        try matches.appendRaw(base_address + i, byte, raw_bits);
    }
    try matches.finalize();
    scanner.matches = matches;
    scanner.num_matches = matches.matchCount();

    const user = UserValue{ .string_value = "aba" };
    try scanner.rescanMatches(.MATCHEQUALTO, &.{user});

    try scanner.matches.?.validate();
    try std.testing.expectEqual(2, scanner.matchCount());
    try std.testing.expectEqual(base_address, (try scanner.matchAt(0)).address);
    try std.testing.expectEqual(base_address + 2, (try scanner.matchAt(1)).address);
    var first: [3]u8 = undefined;
    var second: [3]u8 = undefined;
    try std.testing.expectEqualSlices(u8, "aba", try scanner.storedMatchBytes(0, &first));
    try std.testing.expectEqualSlices(u8, "aba", try scanner.storedMatchBytes(1, &second));
}

test "rescanMatches: bytearray exact can shrink stored length" {
    const allocator = std.testing.allocator;

    var memory = [_]u8{ 0xaa, 0xbb, 0xcc, 0xdd };
    var scanner = Scanner.init(allocator, std.testing.io);
    defer scanner.deinit();
    scanner.options.scan_data_type = .BYTEARRAY;
    try attachScannerToTestMemory(&scanner, allocator, &memory);

    const base_address = @intFromPtr(&memory);
    const old_bytes = [_]u8{ 0x11, 0x22, 0x33, 0x44 };
    var matches = try MatchesArray.init(allocator, 256, 1);
    try matches.appendRun(base_address, &old_bytes, old_bytes.len, 1);
    try matches.finalize();
    scanner.matches = matches;
    scanner.num_matches = matches.matchCount();

    const pattern = [_]u8{ 0xaa, 0xbb };
    const wildcards = [_]value_mod.Wildcard{ .FIXED, .FIXED };
    const user = UserValue{ .bytearray_value = &pattern, .wildcard_value = &wildcards };
    try scanner.rescanMatches(.MATCHEQUALTO, &.{user});

    try scanner.matches.?.validate();
    try std.testing.expectEqual(1, scanner.matchCount());
    try std.testing.expectEqual(2, (try scanner.matchAt(0)).raw_match_info_bits);
    var stored: [2]u8 = undefined;
    try std.testing.expectEqualSlices(u8, &pattern, try scanner.storedMatchBytes(0, &stored));
}

test "rescanMatches: bytearray exact preserves previous-length read limit" {
    const allocator = std.testing.allocator;

    var memory = [_]u8{ 0xaa, 0xbb, 0xcc };
    var scanner = Scanner.init(allocator, std.testing.io);
    defer scanner.deinit();
    scanner.options.scan_data_type = .BYTEARRAY;
    try attachScannerToTestMemory(&scanner, allocator, &memory);

    const base_address = @intFromPtr(&memory);
    const old_bytes = [_]u8{ 0xaa, 0xbb };
    var matches = try MatchesArray.init(allocator, 256, 1);
    try matches.appendRun(base_address, &old_bytes, old_bytes.len, 1);
    try matches.finalize();
    scanner.matches = matches;
    scanner.num_matches = matches.matchCount();

    const pattern = [_]u8{ 0xaa, 0xbb, 0xcc };
    const wildcards = [_]value_mod.Wildcard{ .FIXED, .FIXED, .FIXED };
    const user = UserValue{ .bytearray_value = &pattern, .wildcard_value = &wildcards };
    try scanner.rescanMatches(.MATCHEQUALTO, &.{user});

    try scanner.matches.?.validate();
    try std.testing.expectEqual(0, scanner.matchCount());
}

test "rescanMatches: bytearray exact preserves wildcard predicate" {
    const allocator = std.testing.allocator;

    var memory = [_]u8{ 0xaa, 0x77, 0xcc };
    var scanner = Scanner.init(allocator, std.testing.io);
    defer scanner.deinit();
    scanner.options.scan_data_type = .BYTEARRAY;
    try attachScannerToTestMemory(&scanner, allocator, &memory);

    const base_address = @intFromPtr(&memory);
    const old_bytes = [_]u8{ 0x11, 0x22, 0x33 };
    var matches = try MatchesArray.init(allocator, 256, 1);
    try matches.appendRun(base_address, &old_bytes, old_bytes.len, 1);
    try matches.finalize();
    scanner.matches = matches;
    scanner.num_matches = matches.matchCount();

    const pattern = [_]u8{ 0xaa, 0x00, 0xcc };
    const wildcards = [_]value_mod.Wildcard{ .FIXED, .WILDCARD, .FIXED };
    const user = UserValue{ .bytearray_value = &pattern, .wildcard_value = &wildcards };
    try scanner.rescanMatches(.MATCHEQUALTO, &.{user});

    try scanner.matches.?.validate();
    try std.testing.expectEqual(1, scanner.matchCount());
    var stored: [3]u8 = undefined;
    try std.testing.expectEqualSlices(u8, &memory, try scanner.storedMatchBytes(0, &stored));
}

test "rescanMatches: string exact rejects oversized needle" {
    const allocator = std.testing.allocator;

    var memory = [_]u8{ 'a', 'b', 'c' };
    var scanner = Scanner.init(allocator, std.testing.io);
    defer scanner.deinit();
    scanner.options.scan_data_type = .STRING;
    try attachScannerToTestMemory(&scanner, allocator, &memory);

    const base_address = @intFromPtr(&memory);
    const old_bytes = [_]u8{ 'a', 'b', 'c' };
    var matches = try MatchesArray.init(allocator, 256, 1);
    try matches.appendRun(base_address, &old_bytes, old_bytes.len, 1);
    try matches.finalize();
    scanner.matches = matches;
    scanner.num_matches = matches.matchCount();
    const original_count = scanner.matchCount();

    const big = try allocator.alloc(u8, std.math.maxInt(u16) + 1);
    defer allocator.free(big);
    @memset(big, 'a');
    const user = UserValue{ .string_value = big };

    try std.testing.expectError(ScannerError.UnsupportedScanCombination, scanner.rescanMatches(.MATCHEQUALTO, &.{user}));

    // Validation must fail before any mutation to existing matches.
    try scanner.matches.?.validate();
    try std.testing.expectEqual(original_count, scanner.matchCount());
}

test "rescanMatches: bytearray exact rejects oversized pattern" {
    const allocator = std.testing.allocator;

    var memory = [_]u8{ 0xaa, 0xbb, 0xcc };
    var scanner = Scanner.init(allocator, std.testing.io);
    defer scanner.deinit();
    scanner.options.scan_data_type = .BYTEARRAY;
    try attachScannerToTestMemory(&scanner, allocator, &memory);

    const base_address = @intFromPtr(&memory);
    const old_bytes = [_]u8{ 0xaa, 0xbb, 0xcc };
    var matches = try MatchesArray.init(allocator, 256, 1);
    try matches.appendRun(base_address, &old_bytes, old_bytes.len, 1);
    try matches.finalize();
    scanner.matches = matches;
    scanner.num_matches = matches.matchCount();
    const original_count = scanner.matchCount();

    const big_pattern = try allocator.alloc(u8, std.math.maxInt(u16) + 1);
    defer allocator.free(big_pattern);
    @memset(big_pattern, 0xaa);
    const big_wildcards = try allocator.alloc(value_mod.Wildcard, std.math.maxInt(u16) + 1);
    defer allocator.free(big_wildcards);
    @memset(big_wildcards, .FIXED);
    const user = UserValue{ .bytearray_value = big_pattern, .wildcard_value = big_wildcards };

    try std.testing.expectError(ScannerError.UnsupportedScanCombination, scanner.rescanMatches(.MATCHEQUALTO, &.{user}));

    // Validation must fail before any mutation to existing matches.
    try scanner.matches.?.validate();
    try std.testing.expectEqual(original_count, scanner.matchCount());
}

test "rescanMatches: preserves overlapping survivor spans" {
    const allocator = std.testing.allocator;

    var memory: [8]u8 = @splat(0);
    var scanner = Scanner.init(allocator, std.testing.io);
    defer scanner.deinit();
    scanner.options.scan_data_type = .INTEGER32;
    try attachScannerToTestMemory(&scanner, allocator, &memory);

    const base_address = @intFromPtr(&memory);
    var matches = try MatchesArray.init(allocator, 256, 1);
    try matches.append(base_address, memory[0], MatchFlags.i32b);
    try matches.append(base_address + 1, memory[1], MatchFlags.i32b);
    try matches.append(base_address + 2, memory[2], .{});
    try matches.append(base_address + 3, memory[3], .{});
    try matches.append(base_address + 4, memory[4], .{});
    try matches.finalize();
    scanner.matches = matches;
    scanner.num_matches = matches.matchCount();

    memory[0] = 1;
    memory[4] = 2;
    try scanner.rescanMatches(.MATCHCHANGED, &.{});

    try scanner.matches.?.validate();
    try std.testing.expectEqual(2, scanner.matchCount());
    try std.testing.expectEqual(base_address, (try scanner.matchAt(0)).address);
    try std.testing.expectEqual(base_address + 1, (try scanner.matchAt(1)).address);
    try std.testing.expectEqual(5, scanner.matches.?.storedByteCount());
    try std.testing.expectEqual(1, (try scanner.matchAt(0)).stored_value.data.uint32_value);
    try std.testing.expectEqual(0x02000000, (try scanner.matchAt(1)).stored_value.data.uint32_value);
}

test "rescanMatches: fixed integer changed batches full stride-one segment" {
    const allocator = std.testing.allocator;

    var memory: [16]u8 = @splat(0);
    var scanner = Scanner.init(allocator, std.testing.io);
    defer scanner.deinit();
    scanner.options.scan_data_type = .INTEGER32;
    try attachScannerToTestMemory(&scanner, allocator, &memory);

    const base_address = @intFromPtr(&memory);
    var matches = try MatchesArray.init(allocator, 256, 1);
    try matches.appendRun(base_address, &memory, MatchFlags.i32b.bits(), memory.len);
    try matches.finalize();
    scanner.matches = matches;
    scanner.num_matches = matches.matchCount();

    memory[5] = 1;
    try scanner.rescanMatches(.MATCHCHANGED, &.{});

    try scanner.matches.?.validate();
    try std.testing.expectEqual(4, scanner.matchCount());
    try std.testing.expectEqual(base_address + 2, (try scanner.matchAt(0)).address);
    try std.testing.expectEqual(base_address + 3, (try scanner.matchAt(1)).address);
    try std.testing.expectEqual(base_address + 4, (try scanner.matchAt(2)).address);
    try std.testing.expectEqual(base_address + 5, (try scanner.matchAt(3)).address);
}

test "rescanMatches: fixed integer exact stride one and stride four agree on aligned matches" {
    const allocator = std.testing.allocator;

    var memory: [24]u8 align(4) = @splat(0);
    std.mem.writeInt(u32, memory[4..8], 5, .native);
    std.mem.writeInt(u32, memory[12..16], 5, .native);

    const user = UserValue{
        .int32_value = 5,
        .uint32_value = 5,
        .flags = MatchFlags.i32b,
    };
    const expected_offsets = [_]usize{ 4, 12 };

    {
        var scanner = Scanner.init(allocator, std.testing.io);
        defer scanner.deinit();
        scanner.options.scan_data_type = .INTEGER32;
        try attachScannerToTestMemory(&scanner, allocator, &memory);

        const base_address = @intFromPtr(&memory);
        const old_values: [16]u8 = @splat(0);
        var matches = try MatchesArray.init(allocator, 256, 1);
        try matches.appendRun(base_address, &old_values, MatchFlags.i32b.bits(), old_values.len);
        try matches.finalize();
        scanner.matches = matches;
        scanner.num_matches = matches.matchCount();

        try scanner.rescanMatches(.MATCHEQUALTO, &.{user});

        try scanner.matches.?.validate();
        try std.testing.expectEqual(expected_offsets.len, scanner.matchCount());
        for (expected_offsets, 0..) |offset, i| {
            const record = try scanner.matchAt(i);
            try std.testing.expectEqual(base_address + offset, record.address);
            try std.testing.expectEqual(MatchFlags.i32b.bits(), record.raw_match_info_bits);
        }
    }

    {
        var scanner = Scanner.init(allocator, std.testing.io);
        defer scanner.deinit();
        scanner.options.alignment = 4;
        scanner.options.scan_data_type = .INTEGER32;
        try attachScannerToTestMemory(&scanner, allocator, &memory);

        const base_address = @intFromPtr(&memory);
        const old_values: [16]u8 = @splat(0);
        var matches = try MatchesArray.init(allocator, 256, 4);
        try matches.appendRun(base_address, &old_values, MatchFlags.i32b.bits(), old_values.len / 4);
        try matches.finalize();
        scanner.matches = matches;
        scanner.num_matches = matches.matchCount();

        try scanner.rescanMatches(.MATCHEQUALTO, &.{user});

        try scanner.matches.?.validate();
        try std.testing.expectEqual(expected_offsets.len, scanner.matchCount());
        for (expected_offsets, 0..) |offset, i| {
            const record = try scanner.matchAt(i);
            try std.testing.expectEqual(base_address + offset, record.address);
            try std.testing.expectEqual(MatchFlags.i32b.bits(), record.raw_match_info_bits);
        }
    }
}

test "rescanMatches: fixed integer dense align-four rescans use candidate stride" {
    const allocator = std.testing.allocator;
    const raw_bits = MatchFlags.i32b.bits();
    const old_values: [16]u8 = @splat(0);

    {
        var memory: [16]u8 align(4) = @splat(0);
        var scanner = Scanner.init(allocator, std.testing.io);
        defer scanner.deinit();
        scanner.options.alignment = 4;
        scanner.options.scan_data_type = .INTEGER32;
        try attachScannerToTestMemory(&scanner, allocator, &memory);

        const base_address = @intFromPtr(&memory);
        var matches = try MatchesArray.init(allocator, 256, 4);
        try matches.appendRun(base_address, &old_values, raw_bits, old_values.len / 4);
        try matches.finalize();
        scanner.matches = matches;
        scanner.num_matches = matches.matchCount();

        std.mem.writeInt(u32, memory[4..8], 1, .native);
        std.mem.writeInt(u32, memory[12..16], 1, .native);
        try scanner.rescanMatches(.MATCHCHANGED, &.{});

        try scanner.matches.?.validate();
        try std.testing.expectEqual(2, scanner.matchCount());
        try std.testing.expectEqual(base_address + 4, (try scanner.matchAt(0)).address);
        try std.testing.expectEqual(base_address + 12, (try scanner.matchAt(1)).address);
    }

    {
        var memory: [16]u8 align(4) = @splat(0);
        var scanner = Scanner.init(allocator, std.testing.io);
        defer scanner.deinit();
        scanner.options.alignment = 4;
        scanner.options.scan_data_type = .INTEGER32;
        try attachScannerToTestMemory(&scanner, allocator, &memory);

        const base_address = @intFromPtr(&memory);
        var matches = try MatchesArray.init(allocator, 256, 4);
        try matches.appendRun(base_address, &old_values, raw_bits, old_values.len / 4);
        try matches.finalize();
        scanner.matches = matches;
        scanner.num_matches = matches.matchCount();

        std.mem.writeInt(u32, memory[0..4], 1, .native);
        std.mem.writeInt(u32, memory[8..12], 1, .native);
        const delta = UserValue{
            .int32_value = 1,
            .uint32_value = 1,
            .flags = MatchFlags.i32b,
        };
        try scanner.rescanMatches(.MATCHINCREASEDBY, &.{delta});

        try scanner.matches.?.validate();
        try std.testing.expectEqual(2, scanner.matchCount());
        try std.testing.expectEqual(base_address, (try scanner.matchAt(0)).address);
        try std.testing.expectEqual(base_address + 8, (try scanner.matchAt(1)).address);
    }

    {
        var memory: [16]u8 align(4) = @splat(0);
        var scanner = Scanner.init(allocator, std.testing.io);
        defer scanner.deinit();
        scanner.options.alignment = 4;
        scanner.options.scan_data_type = .INTEGER32;
        try attachScannerToTestMemory(&scanner, allocator, &memory);

        const base_address = @intFromPtr(&memory);
        var matches = try MatchesArray.init(allocator, 256, 4);
        try matches.appendRun(base_address, &old_values, raw_bits, old_values.len / 4);
        try matches.finalize();
        scanner.matches = matches;
        scanner.num_matches = matches.matchCount();

        std.mem.writeInt(u32, memory[4..8], 1, .native);
        try scanner.rescanMatches(.MATCHNOTCHANGED, &.{});

        try scanner.matches.?.validate();
        try std.testing.expectEqual(3, scanner.matchCount());
        try std.testing.expectEqual(base_address, (try scanner.matchAt(0)).address);
        try std.testing.expectEqual(base_address + 8, (try scanner.matchAt(1)).address);
        try std.testing.expectEqual(base_address + 12, (try scanner.matchAt(2)).address);
        try std.testing.expectEqual(null, scanner.matches.?.findMatchIndexByAddress(base_address + 4));
    }
}

test "rescanMatches: fixed integer exact dense batch preserves trailing bytes" {
    const allocator = std.testing.allocator;

    var memory: [24]u8 = @splat(1);
    var scanner = Scanner.init(allocator, std.testing.io);
    defer scanner.deinit();
    scanner.options.scan_data_type = .INTEGER32;
    try attachScannerToTestMemory(&scanner, allocator, &memory);

    const base_address = @intFromPtr(&memory);
    const old_values: [16]u8 = @splat(0);
    var matches = try MatchesArray.init(allocator, 256, 1);
    try matches.appendRun(base_address, &old_values, MatchFlags.i32b.bits(), old_values.len);
    try matches.finalize();
    scanner.matches = matches;
    scanner.num_matches = matches.matchCount();

    const user = UserValue{
        .int32_value = 0x01010101,
        .uint32_value = 0x01010101,
        .flags = MatchFlags.i32b,
    };
    try scanner.rescanMatches(.MATCHEQUALTO, &.{user});

    try scanner.matches.?.validate();
    try std.testing.expectEqual(16, scanner.matchCount());
    try std.testing.expectEqual(19, scanner.matches.?.storedByteCount());
    try std.testing.expectEqual(0x01010101, (try scanner.matchAt(15)).stored_value.data.uint32_value);
}

test "rescanMatches: fixed integer exact full segment direct search confines hits to prior match set" {
    const allocator = std.testing.allocator;

    // 64 KiB buffer of zeros so the cache's chunk-sized read stays inside our controlled memory,
    // no risk of stumbling on stray 0x42 bytes belonging to other process state.
    // Place the target value 0x42 twice: once inside the 4-candidate segment and once outside it but inside the read window.
    const buffer = try allocator.alloc(u8, MemoryCache.read_chunk_size);
    defer allocator.free(buffer);
    @memset(buffer, 0);
    buffer[0] = 0x42;
    buffer[8] = 0x42;

    var scanner = Scanner.init(allocator, std.testing.io);
    defer scanner.deinit();
    scanner.options.scan_data_type = .INTEGER32;
    try attachScannerToTestMemory(&scanner, allocator, buffer);

    const base_address = @intFromPtr(buffer.ptr);
    // Full stride-1 width-4 segment of exactly 4 candidates (offsets 0..3).
    // appendRun with len==candidate_count yields match_count==candidate_count,
    // which is what fullSharedSegmentWidth requires before dispatching into
    // the indexOfPos-based rescanExactFullSegment path.
    const old_values: [4]u8 = @splat(0);
    var matches = try MatchesArray.init(allocator, 256, 1);
    try matches.appendRun(base_address, &old_values, MatchFlags.i32b.bits(), old_values.len);
    try matches.finalize();
    scanner.matches = matches;
    scanner.num_matches = matches.matchCount();

    const user = UserValue{
        .int32_value = 0x42,
        .uint32_value = 0x42,
        .flags = MatchFlags.i32b,
    };
    try scanner.rescanMatches(.MATCHEQUALTO, &.{user});

    try scanner.matches.?.validate();
    // Only the in-segment 0x42 survives. indexOfPos can see the 0x42 at offset 8 in the read window,
    // but the "h >= valid" guard inside rescanExactFullSegment rejects it because candidate index 8 was never
    // in the prior match set.
    try std.testing.expectEqual(1, scanner.matchCount());
    try std.testing.expectEqual(base_address, (try scanner.matchAt(0)).address);
    try std.testing.expectEqual(null, scanner.matches.?.findMatchIndexByAddress(base_address + 8));
}

test "rescanMatches: fixed integer exact full segment direct search honors reverse endian" {
    const allocator = std.testing.allocator;

    var buffer: [8]u8 = undefined;
    const target: u32 = 0x12345678;
    std.mem.writeInt(u32, buffer[0..4], @byteSwap(target), .native);
    std.mem.writeInt(u32, buffer[4..8], target, .native);

    var scanner = Scanner.init(allocator, std.testing.io);
    defer scanner.deinit();
    scanner.options.alignment = 4;
    scanner.options.scan_data_type = .INTEGER32;
    scanner.options.reverse_endianness = true;
    try attachScannerToTestMemory(&scanner, allocator, &buffer);

    const base_address = @intFromPtr(&buffer);
    const old_values: [8]u8 = @splat(0);
    var matches = try MatchesArray.init(allocator, 256, 4);
    try matches.appendRun(base_address, &old_values, MatchFlags.i32b.bits(), old_values.len / 4);
    try matches.finalize();
    scanner.matches = matches;
    scanner.num_matches = matches.matchCount();

    const user = try UserValue.parseNumber("0x12345678");
    try scanner.rescanMatches(.MATCHEQUALTO, &.{user});

    try scanner.matches.?.validate();
    try std.testing.expectEqual(1, scanner.matchCount());
    const record = try scanner.matchAt(0);
    try std.testing.expectEqual(base_address, record.address);
    try std.testing.expectEqual(target, record.stored_value.data.uint32_value);
    const current = try scanner.readNumericMatchValue(0);
    try std.testing.expectEqual(target, current.data.uint32_value);
    var stored: [4]u8 = undefined;
    try std.testing.expectEqualSlices(u8, buffer[0..4], try scanner.storedMatchBytes(0, &stored));
    try std.testing.expectEqual(null, scanner.matches.?.findMatchIndexByAddress(base_address + 4));
}

test "rescanMatches: FLOAT32 exact full segment burst keeps both zero signs" {
    const allocator = std.testing.allocator;

    // 25 stride-1 candidates inside a 64 KiB scratch buffer:
    //   offsets 0..12 : +0.0 burst in zero-filled memory
    //   offsets 17..19: shorter +0.0 burst after the stop byte
    //   offset 20     : -0.0
    //   offset 24     : final +0.0
    const buffer = try allocator.alloc(u8, MemoryCache.read_chunk_size);
    defer allocator.free(buffer);
    @memset(buffer, 0);
    buffer[16] = 0xcc;
    buffer[23] = 0x80;

    var scanner = Scanner.init(allocator, std.testing.io);
    defer scanner.deinit();
    scanner.options.scan_data_type = .FLOAT32;
    try attachScannerToTestMemory(&scanner, allocator, buffer);

    const base_address = @intFromPtr(buffer.ptr);
    const old_values: [25]u8 = @splat(0);
    var matches = try MatchesArray.init(allocator, 256, 1);
    try matches.appendRun(base_address, &old_values, (MatchFlags{ .f32b = true }).bits(), old_values.len);
    try matches.finalize();
    scanner.matches = matches;
    scanner.num_matches = matches.matchCount();

    const user = UserValue{
        .float32_value = -0.0,
        .flags = .{ .f32b = true },
    };
    try scanner.rescanMatches(.MATCHEQUALTO, &.{user});

    try scanner.matches.?.validate();
    try std.testing.expectEqual(18, scanner.matchCount());
    try std.testing.expectEqual(base_address, (try scanner.matchAt(0)).address);
    try std.testing.expectEqual(base_address + 12, (try scanner.matchAt(12)).address);
    try std.testing.expectEqual(base_address + 17, (try scanner.matchAt(13)).address);
    try std.testing.expectEqual(base_address + 20, (try scanner.matchAt(16)).address);
    try std.testing.expectEqual(base_address + 24, (try scanner.matchAt(17)).address);
    var stored: [4]u8 = undefined;
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0, 0, 0, 0 }, try scanner.storedMatchBytes(12, &stored));
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0, 0, 0, 0x80 }, try scanner.storedMatchBytes(16, &stored));
}

test "rescanMatches: compare dense batch followed by sparse survivor" {
    const allocator = std.testing.allocator;

    const dense_candidates = MemoryCache.read_chunk_size - @sizeOf(u32) + 1;
    const sparse_offset = dense_candidates + 8;
    const candidate_count = dense_candidates + 17;
    const total_bytes = candidate_count + @sizeOf(u32) - 1;

    const memory = try allocator.alloc(u8, total_bytes);
    defer allocator.free(memory);
    @memset(memory, 2);
    @memset(memory[0 .. dense_candidates + @sizeOf(u32) - 1], 1);
    @memset(memory[sparse_offset .. sparse_offset + @sizeOf(u32)], 1);

    var scanner = Scanner.init(allocator, std.testing.io);
    defer scanner.deinit();
    scanner.options.scan_data_type = .INTEGER32;
    try attachScannerToTestMemory(&scanner, allocator, memory);

    const old_values = try allocator.alloc(u8, candidate_count);
    defer allocator.free(old_values);
    @memset(old_values, 0);

    const base_address = @intFromPtr(memory.ptr);
    var matches = try MatchesArray.init(allocator, total_bytes * 4, 1);
    try matches.appendRun(base_address, old_values, MatchFlags.i32b.bits(), old_values.len);
    try matches.finalize();
    scanner.matches = matches;
    scanner.num_matches = matches.matchCount();

    const user = UserValue{
        .int32_value = 0x01010101,
        .uint32_value = 0x01010101,
        .flags = MatchFlags.i32b,
    };
    try scanner.rescanMatches(.MATCHEQUALTO, &.{user});

    try scanner.matches.?.validate();
    try std.testing.expectEqual(dense_candidates + 1, scanner.matchCount());
    const sparse = try scanner.matchAt(dense_candidates);
    try std.testing.expectEqual(base_address + sparse_offset, sparse.address);
    try std.testing.expectEqual(0x01010101, sparse.stored_value.data.uint32_value);
}

test "rescanMatches: fixed integer range narrows signed and unsigned flags" {
    const allocator = std.testing.allocator;

    var memory: [4]u8 = undefined;
    std.mem.writeInt(u32, &memory, 5, .native);

    var scanner = Scanner.init(allocator, std.testing.io);
    defer scanner.deinit();
    scanner.options.scan_data_type = .INTEGER32;
    try attachScannerToTestMemory(&scanner, allocator, &memory);

    const base_address = @intFromPtr(&memory);
    var matches = try MatchesArray.init(allocator, 256, 1);
    try matches.appendRun(base_address, &memory, MatchFlags.i32b.bits(), 1);
    try matches.finalize();
    scanner.matches = matches;
    scanner.num_matches = matches.matchCount();

    const lower = try UserValue.parseNumber("-10");
    const upper = try UserValue.parseNumber("10");
    try scanner.rescanMatches(.MATCHRANGE, &.{ lower, upper });

    try scanner.matches.?.validate();
    try std.testing.expectEqual(1, scanner.matchCount());
    const record = try scanner.matchAt(0);
    try std.testing.expectEqual(base_address, record.address);
    try std.testing.expectEqual((MatchFlags{ .s32b = true }).bits(), record.raw_match_info_bits);
}

test "rescanMatches: fixed integer increased batches full stride-one segment" {
    const allocator = std.testing.allocator;

    var memory: [16]u8 = @splat(0);
    var scanner = Scanner.init(allocator, std.testing.io);
    defer scanner.deinit();
    scanner.options.scan_data_type = .INTEGER32;
    try attachScannerToTestMemory(&scanner, allocator, &memory);

    const base_address = @intFromPtr(&memory);
    var matches = try MatchesArray.init(allocator, 256, 1);
    try matches.appendRun(base_address, &memory, MatchFlags.i32b.bits(), memory.len);
    try matches.finalize();
    scanner.matches = matches;
    scanner.num_matches = matches.matchCount();

    // memory[5] = 1 changes the values seen by candidates 2..5 (their 4-byte windows cover index 5).
    // Old value at each of those positions was 0.
    // Every new value is positive (1, 256, 65536, 16777216 on little-endian), so all four survive MATCHINCREASED.
    // Candidates whose windows don't touch index 5 have unchanged bytes -> diff_count stays 0 and the delta
    // routine is skipped entirely.
    memory[5] = 1;
    try scanner.rescanMatches(.MATCHINCREASED, &.{});

    try scanner.matches.?.validate();
    try std.testing.expectEqual(4, scanner.matchCount());
    try std.testing.expectEqual(base_address + 2, (try scanner.matchAt(0)).address);
    try std.testing.expectEqual(base_address + 3, (try scanner.matchAt(1)).address);
    try std.testing.expectEqual(base_address + 4, (try scanner.matchAt(2)).address);
    try std.testing.expectEqual(base_address + 5, (try scanner.matchAt(3)).address);
    // Old raw bits had both signed and unsigned flags.
    // Going from 0 to a positive value is "increased" under both interpretations,
    // so both flags should survive on each match.
    try std.testing.expectEqual(MatchFlags.i32b.bits(), (try scanner.matchAt(0)).raw_match_info_bits);
    try std.testing.expectEqual(MatchFlags.i32b.bits(), (try scanner.matchAt(3)).raw_match_info_bits);
}

test "rescanMatches: fixed integer unchanged batches full stride-one segment" {
    const allocator = std.testing.allocator;

    var memory: [16]u8 = @splat(0);
    var scanner = Scanner.init(allocator, std.testing.io);
    defer scanner.deinit();
    scanner.options.scan_data_type = .INTEGER32;
    try attachScannerToTestMemory(&scanner, allocator, &memory);

    const base_address = @intFromPtr(&memory);
    var matches = try MatchesArray.init(allocator, 256, 1);
    try matches.appendRun(base_address, &memory, MatchFlags.i32b.bits(), memory.len);
    try matches.finalize();
    scanner.matches = matches;
    scanner.num_matches = matches.matchCount();

    const old_used_len = scanner.matches.?.used_len;
    memory[5] = 1;
    try scanner.rescanMatches(.MATCHNOTCHANGED, &.{});

    // Width 4 means candidates whose window covers position 5 (indices 2..5) are removed by the batch path.
    // Candidates 13..15 have short stored bytes and are removed by the fallback path.
    // Survivors: 0,1,6,7,8,9,10,11,12.
    try scanner.matches.?.validate();
    try std.testing.expectEqual(9, scanner.matchCount());
    try std.testing.expectEqual(base_address, (try scanner.matchAt(0)).address);
    try std.testing.expectEqual(base_address + 1, (try scanner.matchAt(1)).address);
    try std.testing.expectEqual(base_address + 6, (try scanner.matchAt(2)).address);
    try std.testing.expectEqual(base_address + 12, (try scanner.matchAt(8)).address);
    try std.testing.expectEqual(old_used_len, scanner.matches.?.used_len);
}

test "rescanMatches: float32 changed batches full stride-one segment" {
    const allocator = std.testing.allocator;

    var memory: [16]u8 = @splat(0);
    var scanner = Scanner.init(allocator, std.testing.io);
    defer scanner.deinit();
    scanner.options.scan_data_type = .FLOAT32;
    try attachScannerToTestMemory(&scanner, allocator, &memory);

    const base_address = @intFromPtr(&memory);
    var matches = try MatchesArray.init(allocator, 256, 1);
    const f32_flag = (MatchFlags{ .f32b = true }).bits();
    try matches.appendRun(base_address, &memory, f32_flag, memory.len);
    try matches.finalize();
    scanner.matches = matches;
    scanner.num_matches = matches.matchCount();

    // CHANGED uses byte equality (type-agnostic).
    // Same expectations as the INTEGER32 case: candidates whose 4-byte window covers index 5 survive.
    memory[5] = 1;
    try scanner.rescanMatches(.MATCHCHANGED, &.{});

    try scanner.matches.?.validate();
    try std.testing.expectEqual(4, scanner.matchCount());
    try std.testing.expectEqual(base_address + 2, (try scanner.matchAt(0)).address);
    try std.testing.expectEqual(base_address + 5, (try scanner.matchAt(3)).address);
    try std.testing.expectEqual(f32_flag, (try scanner.matchAt(0)).raw_match_info_bits);
}

test "rescanMatches: float32 unchanged batches full stride-one segment" {
    const allocator = std.testing.allocator;

    var memory: [16]u8 = @splat(0);
    var scanner = Scanner.init(allocator, std.testing.io);
    defer scanner.deinit();
    scanner.options.scan_data_type = .FLOAT32;
    try attachScannerToTestMemory(&scanner, allocator, &memory);

    const base_address = @intFromPtr(&memory);
    var matches = try MatchesArray.init(allocator, 256, 1);
    const f32_flag = (MatchFlags{ .f32b = true }).bits();
    try matches.appendRun(base_address, &memory, f32_flag, memory.len);
    try matches.finalize();
    scanner.matches = matches;
    scanner.num_matches = matches.matchCount();

    const old_used_len = scanner.matches.?.used_len;
    memory[5] = 1;
    try scanner.rescanMatches(.MATCHNOTCHANGED, &.{});

    // Same survivor pattern as the INTEGER32 NOTCHANGED test.
    // Byte equality makes float and integer behavior identical for CHANGED/NOTCHANGED.
    try scanner.matches.?.validate();
    try std.testing.expectEqual(9, scanner.matchCount());
    try std.testing.expectEqual(old_used_len, scanner.matches.?.used_len);
}

test "rescanMatches: float32 increased batches full stride-one segment" {
    const allocator = std.testing.allocator;

    var memory: [16]u8 = @splat(0);
    var scanner = Scanner.init(allocator, std.testing.io);
    defer scanner.deinit();
    scanner.options.scan_data_type = .FLOAT32;
    try attachScannerToTestMemory(&scanner, allocator, &memory);

    const base_address = @intFromPtr(&memory);
    var matches = try MatchesArray.init(allocator, 256, 1);
    const f32_flag = (MatchFlags{ .f32b = true }).bits();
    try matches.appendRun(base_address, &memory, f32_flag, memory.len);
    try matches.finalize();
    scanner.matches = matches;
    scanner.num_matches = matches.matchCount();

    // memory[5] = 1 with surrounding zero bytes makes every 4-byte window
    // touching index 5 decode as a strictly-positive f32 (one normal value,
    // three positive denormals).
    // Old value was 0.0 for all candidates.
    // The diff_count gate skips windows that didn't see the changed byte.
    memory[5] = 1;
    try scanner.rescanMatches(.MATCHINCREASED, &.{});

    try scanner.matches.?.validate();
    try std.testing.expectEqual(4, scanner.matchCount());
    try std.testing.expectEqual(base_address + 2, (try scanner.matchAt(0)).address);
    try std.testing.expectEqual(base_address + 5, (try scanner.matchAt(3)).address);
    try std.testing.expectEqual(f32_flag, (try scanner.matchAt(0)).raw_match_info_bits);
}

test "rescanMatches: fixed integer unchanged prunes in place" {
    const allocator = std.testing.allocator;

    var memory: [8]u8 = @splat(0);
    var scanner = Scanner.init(allocator, std.testing.io);
    defer scanner.deinit();
    scanner.options.scan_data_type = .INTEGER32;
    try attachScannerToTestMemory(&scanner, allocator, &memory);

    const base_address = @intFromPtr(&memory);
    var matches = try MatchesArray.init(allocator, 256, 1);
    try matches.append(base_address, memory[0], MatchFlags.i32b);
    try matches.append(base_address + 1, memory[1], MatchFlags.i32b);
    try matches.append(base_address + 2, memory[2], .{});
    try matches.append(base_address + 3, memory[3], .{});
    try matches.append(base_address + 4, memory[4], .{});
    try matches.finalize();
    scanner.matches = matches;
    scanner.num_matches = matches.matchCount();

    const old_used_len = scanner.matches.?.used_len;
    memory[4] = 1;
    try scanner.rescanMatches(.MATCHNOTCHANGED, &.{});

    try scanner.matches.?.validate();
    try std.testing.expectEqual(1, scanner.matchCount());
    try std.testing.expectEqual(base_address, (try scanner.matchAt(0)).address);
    try std.testing.expectEqual(0, (try scanner.matchAt(0)).stored_value.data.uint32_value);
    try std.testing.expectEqual(old_used_len, scanner.matches.?.used_len);
}

test "rescanMatches: fixed integer changed reads old bytes across segment boundary" {
    const allocator = std.testing.allocator;
    const dense_segment_payload = 2 * 1024 * 1024;

    const memory = try allocator.alignedAlloc(u8, std.mem.Alignment.of(u64), dense_segment_payload + 8);
    defer allocator.free(memory);
    @memset(memory, 0);

    var scanner = Scanner.init(allocator, std.testing.io);
    defer scanner.deinit();
    scanner.options.scan_data_type = .INTEGER64;
    try attachScannerToTestMemory(&scanner, allocator, memory);

    const base_address = @intFromPtr(memory.ptr);
    const match_offset = dense_segment_payload - 4;
    const match_address = base_address + match_offset;

    var matches = try MatchesArray.init(allocator, memory.len * 3, 4);
    try matches.appendRun(base_address, memory[0..match_offset], 0, 0);
    var old_bytes: [8]u8 = undefined;
    std.mem.writeInt(u64, &old_bytes, 0x1111111122222222, .native);
    try matches.appendRun(match_address, &old_bytes, MatchFlags.i64b.bits(), 1);
    try matches.finalize();
    scanner.matches = matches;
    scanner.num_matches = matches.matchCount();

    std.mem.writeInt(u64, memory[match_offset .. match_offset + 8], 0x3333333344444444, .native);
    try scanner.rescanMatches(.MATCHCHANGED, &.{});

    try scanner.matches.?.validate();
    try std.testing.expectEqual(1, scanner.matchCount());
    try std.testing.expectEqual(match_address, (try scanner.matchAt(0)).address);
    try std.testing.expectEqual(0x3333333344444444, (try scanner.matchAt(0)).stored_value.data.uint64_value);
}

test "rescanMatches: fixed integer unchanged removes mismatched raw width" {
    const allocator = std.testing.allocator;

    var memory: [4]u8 = @splat(0);
    var scanner = Scanner.init(allocator, std.testing.io);
    defer scanner.deinit();
    scanner.options.scan_data_type = .INTEGER32;
    try attachScannerToTestMemory(&scanner, allocator, &memory);

    const base_address = @intFromPtr(&memory);
    var matches = try MatchesArray.init(allocator, 256, 1);
    try matches.append(base_address, memory[0], MatchFlags.i16b);
    try matches.finalize();
    scanner.matches = matches;
    scanner.num_matches = matches.matchCount();

    try scanner.rescanMatches(.MATCHNOTCHANGED, &.{});

    try scanner.matches.?.validate();
    try std.testing.expectEqual(0, scanner.matchCount());
    var iter = scanner.matches.?.iterator();
    try std.testing.expect(iter.next() == null);
}

test "rescanMatches: fixed integer unchanged leaves empty swath iterable" {
    const allocator = std.testing.allocator;

    var memory: [8]u8 = @splat(0);
    var scanner = Scanner.init(allocator, std.testing.io);
    defer scanner.deinit();
    scanner.options.scan_data_type = .INTEGER32;
    try attachScannerToTestMemory(&scanner, allocator, &memory);

    const base_address = @intFromPtr(&memory);
    var matches = try MatchesArray.init(allocator, 256, 1);
    try matches.append(base_address, memory[0], MatchFlags.i32b);
    try matches.append(base_address + 1, memory[1], .{});
    try matches.append(base_address + 2, memory[2], .{});
    try matches.append(base_address + 3, memory[3], .{});
    try matches.append(base_address + 4, memory[4], MatchFlags.i32b);
    try matches.append(base_address + 5, memory[5], .{});
    try matches.append(base_address + 6, memory[6], .{});
    try matches.append(base_address + 7, memory[7], .{});
    try matches.finalize();
    scanner.matches = matches;
    scanner.num_matches = matches.matchCount();

    memory[0] = 1;
    memory[4] = 2;
    try scanner.rescanMatches(.MATCHNOTCHANGED, &.{});

    try scanner.matches.?.validate();
    try std.testing.expectEqual(0, scanner.matchCount());
    var iter = scanner.matches.?.iterator();
    try std.testing.expect(iter.next() == null);
}

test "rescanMatches: fixed integer increased rebuilds signed and unsigned flags" {
    const allocator = std.testing.allocator;

    var memory: [4]u8 = undefined;
    std.mem.writeInt(u32, &memory, 0x80000000, .native);

    var scanner = Scanner.init(allocator, std.testing.io);
    defer scanner.deinit();
    scanner.options.scan_data_type = .INTEGER32;
    try attachScannerToTestMemory(&scanner, allocator, &memory);

    const base_address = @intFromPtr(&memory);
    var old_bytes: [4]u8 = undefined;
    std.mem.writeInt(u32, &old_bytes, 0x7fffffff, .native);

    var matches = try MatchesArray.init(allocator, 256, 1);
    try matches.appendRun(base_address, &old_bytes, MatchFlags.i32b.bits(), 1);
    try matches.finalize();
    scanner.matches = matches;
    scanner.num_matches = matches.matchCount();

    try scanner.rescanMatches(.MATCHINCREASED, &.{});

    try scanner.matches.?.validate();
    try std.testing.expectEqual(1, scanner.matchCount());
    const record = try scanner.matchAt(0);
    try std.testing.expectEqual((MatchFlags{ .u32b = true }).bits(), record.raw_match_info_bits);
    try std.testing.expectEqual(0x80000000, record.stored_value.data.uint32_value);
}

test "rescanMatches: fixed integer decreased rebuilds signed and unsigned flags" {
    const allocator = std.testing.allocator;

    var memory: [4]u8 = undefined;
    std.mem.writeInt(u32, &memory, 0x80000000, .native);

    var scanner = Scanner.init(allocator, std.testing.io);
    defer scanner.deinit();
    scanner.options.scan_data_type = .INTEGER32;
    try attachScannerToTestMemory(&scanner, allocator, &memory);

    const base_address = @intFromPtr(&memory);
    var old_bytes: [4]u8 = undefined;
    std.mem.writeInt(u32, &old_bytes, 0x7fffffff, .native);

    var matches = try MatchesArray.init(allocator, 256, 1);
    try matches.appendRun(base_address, &old_bytes, MatchFlags.i32b.bits(), 1);
    try matches.finalize();
    scanner.matches = matches;
    scanner.num_matches = matches.matchCount();

    try scanner.rescanMatches(.MATCHDECREASED, &.{});

    try scanner.matches.?.validate();
    try std.testing.expectEqual(1, scanner.matchCount());
    const record = try scanner.matchAt(0);
    try std.testing.expectEqual((MatchFlags{ .s32b = true }).bits(), record.raw_match_info_bits);
    try std.testing.expectEqual(std.math.minInt(i32), record.stored_value.data.int32_value);
}

test "rescanMatches: fixed integer increaseby and decreaseby use user delta" {
    const allocator = std.testing.allocator;

    var memory: [4]u8 = undefined;
    std.mem.writeInt(u32, &memory, 15, .native);

    var scanner = Scanner.init(allocator, std.testing.io);
    defer scanner.deinit();
    scanner.options.scan_data_type = .INTEGER32;
    try attachScannerToTestMemory(&scanner, allocator, &memory);

    const base_address = @intFromPtr(&memory);
    var old_bytes: [4]u8 = undefined;
    std.mem.writeInt(u32, &old_bytes, 10, .native);

    var matches = try MatchesArray.init(allocator, 256, 1);
    try matches.appendRun(base_address, &old_bytes, MatchFlags.i32b.bits(), 1);
    try matches.finalize();
    scanner.matches = matches;
    scanner.num_matches = matches.matchCount();

    const delta = UserValue{
        .int32_value = 5,
        .uint32_value = 5,
        .flags = MatchFlags.i32b,
    };
    try scanner.rescanMatches(.MATCHINCREASEDBY, &.{delta});

    try scanner.matches.?.validate();
    try std.testing.expectEqual(1, scanner.matchCount());
    try std.testing.expectEqual(MatchFlags.i32b.bits(), (try scanner.matchAt(0)).raw_match_info_bits);

    std.mem.writeInt(u32, &memory, 10, .native);
    try scanner.rescanMatches(.MATCHDECREASEDBY, &.{delta});

    try scanner.matches.?.validate();
    try std.testing.expectEqual(1, scanner.matchCount());
    try std.testing.expectEqual(MatchFlags.i32b.bits(), (try scanner.matchAt(0)).raw_match_info_bits);
}

test "rescanMatches: anyinteger reverse-endian increased decodes old bytes symmetrically" {
    const allocator = std.testing.allocator;

    var memory: [2]u8 = undefined;
    const current_value: u16 = 0x0100;
    std.mem.writeInt(u16, &memory, @byteSwap(current_value), .native);

    var scanner = Scanner.init(allocator, std.testing.io);
    defer scanner.deinit();
    scanner.options.scan_data_type = .ANYINTEGER;
    scanner.options.reverse_endianness = true;
    try attachScannerToTestMemory(&scanner, allocator, &memory);

    const base_address = @intFromPtr(&memory);
    var old_bytes: [2]u8 = undefined;
    const old_value: u16 = 0x0080;
    std.mem.writeInt(u16, &old_bytes, @byteSwap(old_value), .native);

    var matches = try MatchesArray.init(allocator, 256, 1);
    try matches.appendRun(base_address, &old_bytes, (MatchFlags{ .u16b = true }).bits(), 1);
    try matches.finalize();
    scanner.matches = matches;
    scanner.num_matches = matches.matchCount();

    try scanner.rescanMatches(.MATCHINCREASED, &.{});

    try scanner.matches.?.validate();
    try std.testing.expectEqual(1, scanner.matchCount());
    try std.testing.expectEqual((MatchFlags{ .u16b = true }).bits(), (try scanner.matchAt(0)).raw_match_info_bits);
}

test "rescanMatches: anyinteger reverse-endian increaseby decodes old bytes symmetrically" {
    const allocator = std.testing.allocator;

    var memory: [4]u8 = undefined;
    const current_value: u32 = 15;
    std.mem.writeInt(u32, &memory, @byteSwap(current_value), .native);

    var scanner = Scanner.init(allocator, std.testing.io);
    defer scanner.deinit();
    scanner.options.scan_data_type = .ANYINTEGER;
    scanner.options.reverse_endianness = true;
    try attachScannerToTestMemory(&scanner, allocator, &memory);

    const base_address = @intFromPtr(&memory);
    var old_bytes: [4]u8 = undefined;
    const old_value: u32 = 10;
    std.mem.writeInt(u32, &old_bytes, @byteSwap(old_value), .native);

    var matches = try MatchesArray.init(allocator, 256, 1);
    try matches.appendRun(base_address, &old_bytes, (MatchFlags{ .u32b = true }).bits(), 1);
    try matches.finalize();
    scanner.matches = matches;
    scanner.num_matches = matches.matchCount();

    const delta = UserValue{
        .uint32_value = 5,
        .flags = .{ .u32b = true },
    };
    try scanner.rescanMatches(.MATCHINCREASEDBY, &.{delta});

    try scanner.matches.?.validate();
    try std.testing.expectEqual(1, scanner.matchCount());
    try std.testing.expectEqual((MatchFlags{ .u32b = true }).bits(), (try scanner.matchAt(0)).raw_match_info_bits);
}

test "rescanMatches: anyfloat reverse-endian increased decodes old bytes symmetrically" {
    const allocator = std.testing.allocator;

    var memory: [4]u8 = undefined;
    const current_value: f32 = 2.0;
    const current_bits: u32 = @bitCast(current_value);
    std.mem.writeInt(u32, &memory, @byteSwap(current_bits), .native);

    var scanner = Scanner.init(allocator, std.testing.io);
    defer scanner.deinit();
    scanner.options.scan_data_type = .ANYFLOAT;
    scanner.options.reverse_endianness = true;
    try attachScannerToTestMemory(&scanner, allocator, &memory);

    const base_address = @intFromPtr(&memory);
    var old_bytes: [4]u8 = undefined;
    const old_value: f32 = 1.0;
    const old_bits: u32 = @bitCast(old_value);
    std.mem.writeInt(u32, &old_bytes, @byteSwap(old_bits), .native);

    var matches = try MatchesArray.init(allocator, 256, 1);
    try matches.appendRun(base_address, &old_bytes, (MatchFlags{ .f32b = true }).bits(), 1);
    try matches.finalize();
    scanner.matches = matches;
    scanner.num_matches = matches.matchCount();

    try scanner.rescanMatches(.MATCHINCREASED, &.{});

    try scanner.matches.?.validate();
    try std.testing.expectEqual(1, scanner.matchCount());
    try std.testing.expectEqual((MatchFlags{ .f32b = true }).bits(), (try scanner.matchAt(0)).raw_match_info_bits);
}

test "matchAt: anyinteger reverse-endian decodes multi-width match by widest stored width" {
    const allocator = std.testing.allocator;

    // ANY types stores cumulative flags (every width the value fits),
    // so the stored bytes are the widest interpretation and must be byteswapped by that full width.
    const host_value: u64 = 0x0102030405060708;
    var stored_bytes: [8]u8 = undefined;
    std.mem.writeInt(u64, &stored_bytes, @byteSwap(host_value), .native);

    var scanner = Scanner.init(allocator, std.testing.io);
    defer scanner.deinit();
    scanner.options.scan_data_type = .ANYINTEGER;
    scanner.options.reverse_endianness = true;

    const base_address = @intFromPtr(&stored_bytes);
    var matches = try MatchesArray.init(allocator, 256, 1);
    try matches.appendRun(base_address, &stored_bytes, MatchFlags.integer.bits(), 1);
    try matches.finalize();
    scanner.matches = matches;
    scanner.num_matches = matches.matchCount();

    const record = try scanner.matchAt(0);
    try std.testing.expectEqual(MatchFlags.integer.bits(), record.raw_match_info_bits);
    try std.testing.expectEqual(host_value, record.stored_value.data.uint64_value);
}

test "rescanMatches: anyfloat delta full segment gates unchanged f32 window" {
    const allocator = std.testing.allocator;

    var memory: [8]u8 = undefined;
    var old_bytes: [8]u8 = undefined;
    if (builtin.cpu.arch.endian() == .little) {
        const old_value: f64 = 1.0;
        const current_value: f64 = 2.0;
        std.mem.writeInt(u64, &old_bytes, @bitCast(old_value), .native);
        std.mem.writeInt(u64, &memory, @bitCast(current_value), .native);
    } else {
        std.mem.writeInt(u64, &old_bytes, 0x3ff0000000000000, .native);
        std.mem.writeInt(u64, &memory, 0x3ff0000000000001, .native);
    }
    try std.testing.expectEqualSlices(u8, old_bytes[0..4], memory[0..4]);

    var scanner = Scanner.init(allocator, std.testing.io);
    defer scanner.deinit();
    scanner.options.scan_data_type = .ANYFLOAT;
    try attachScannerToTestMemory(&scanner, allocator, &memory);

    const base_address = @intFromPtr(&memory);
    var matches = try MatchesArray.init(allocator, 256, 1);
    try matches.appendRun(base_address, &old_bytes, MatchFlags.float.bits(), old_bytes.len);
    try matches.finalize();
    scanner.matches = matches;
    scanner.num_matches = matches.matchCount();

    try scanner.rescanMatches(.MATCHINCREASED, &.{});

    try scanner.matches.?.validate();
    try std.testing.expectEqual(1, scanner.matchCount());
    try std.testing.expectEqual((MatchFlags{ .f64b = true }).bits(), (try scanner.matchAt(0)).raw_match_info_bits);
}

test "rescanMatches: anyfloat unchanged uses bit equality for identical NaN" {
    const allocator = std.testing.allocator;

    var memory: [4]u8 = undefined;
    const nan_bits: u32 = 0x7fc00001;
    std.mem.writeInt(u32, &memory, nan_bits, .native);

    var scanner = Scanner.init(allocator, std.testing.io);
    defer scanner.deinit();
    scanner.options.scan_data_type = .ANYFLOAT;
    try attachScannerToTestMemory(&scanner, allocator, &memory);

    const base_address = @intFromPtr(&memory);
    var old_bytes: [4]u8 = undefined;
    std.mem.writeInt(u32, &old_bytes, nan_bits, .native);

    var matches = try MatchesArray.init(allocator, 256, 1);
    try matches.appendRun(base_address, &old_bytes, (MatchFlags{ .f32b = true }).bits(), 1);
    try matches.finalize();
    scanner.matches = matches;
    scanner.num_matches = matches.matchCount();

    try scanner.rescanMatches(.MATCHNOTCHANGED, &.{});

    try scanner.matches.?.validate();
    try std.testing.expectEqual(1, scanner.matchCount());
    try std.testing.expectEqual((MatchFlags{ .f32b = true }).bits(), (try scanner.matchAt(0)).raw_match_info_bits);
}

test "rescanMatches: anyinteger changed preserves dual signed and unsigned flags" {
    const allocator = std.testing.allocator;

    var memory: [4]u8 = undefined;
    std.mem.writeInt(u32, &memory, 200, .native);

    var scanner = Scanner.init(allocator, std.testing.io);
    defer scanner.deinit();
    scanner.options.scan_data_type = .ANYINTEGER;
    try attachScannerToTestMemory(&scanner, allocator, &memory);

    const base_address = @intFromPtr(&memory);
    var old_bytes: [4]u8 = undefined;
    std.mem.writeInt(u32, &old_bytes, 100, .native);

    const stored_flags = MatchFlags{ .s32b = true, .u32b = true };
    var matches = try MatchesArray.init(allocator, 256, 1);
    try matches.appendRun(base_address, &old_bytes, stored_flags.bits(), 1);
    try matches.finalize();
    scanner.matches = matches;
    scanner.num_matches = matches.matchCount();

    try scanner.rescanMatches(.MATCHCHANGED, &.{});

    try scanner.matches.?.validate();
    try std.testing.expectEqual(1, scanner.matchCount());
    try std.testing.expectEqual(stored_flags.bits(), (try scanner.matchAt(0)).raw_match_info_bits);
}

test "rescanMatches: anyinteger notchanged preserves matching stored sub-width" {
    const allocator = std.testing.allocator;

    var memory: [4]u8 = undefined;
    std.mem.writeInt(u32, &memory, 0xdeadbeef, .native);

    var scanner = Scanner.init(allocator, std.testing.io);
    defer scanner.deinit();
    scanner.options.scan_data_type = .ANYINTEGER;
    try attachScannerToTestMemory(&scanner, allocator, &memory);

    const base_address = @intFromPtr(&memory);
    // Stored as u16b: only the low two bytes are checked for equality.
    // Memory matches those two bytes so the candidate is preserved at its sub-width.
    var old_bytes: [2]u8 = undefined;
    std.mem.writeInt(u16, &old_bytes, @truncate(0xdeadbeef), .native);

    var matches = try MatchesArray.init(allocator, 256, 1);
    try matches.appendRun(base_address, &old_bytes, (MatchFlags{ .u16b = true }).bits(), 1);
    try matches.finalize();
    scanner.matches = matches;
    scanner.num_matches = matches.matchCount();

    try scanner.rescanMatches(.MATCHNOTCHANGED, &.{});

    try scanner.matches.?.validate();
    try std.testing.expectEqual(1, scanner.matchCount());
    try std.testing.expectEqual((MatchFlags{ .u16b = true }).bits(), (try scanner.matchAt(0)).raw_match_info_bits);
}

test "rescanMatches: anyinteger narrow full segment uses max candidate batch" {
    const allocator = std.testing.allocator;
    const candidate_count = MemoryCache.read_chunk_size;
    const max_storage = 128 * 1024;

    const memory = try allocator.alloc(u8, candidate_count);
    defer allocator.free(memory);
    @memset(memory, 7);

    const old_values = try allocator.alloc(u8, candidate_count);
    defer allocator.free(old_values);
    @memset(old_values, 0);

    var scanner = Scanner.init(allocator, std.testing.io);
    defer scanner.deinit();
    scanner.options.alignment = 1;
    scanner.options.scan_data_type = .ANYINTEGER;
    try attachScannerToTestMemory(&scanner, allocator, memory);

    var matches = try MatchesArray.init(allocator, max_storage, 1);
    try matches.appendRun(@intFromPtr(memory.ptr), old_values, MatchFlags.i8b.bits(), candidate_count);
    try matches.finalize();
    scanner.matches = matches;
    scanner.num_matches = matches.matchCount();

    const equal_to = try UserValue.parseNumber("7");
    try scanner.rescanMatches(.MATCHEQUALTO, &.{equal_to});

    try scanner.matches.?.validate();
    try std.testing.expectEqual(candidate_count, scanner.matchCount());

    @memset(memory, 8);
    try scanner.rescanMatches(.MATCHINCREASED, &.{});

    try scanner.matches.?.validate();
    try std.testing.expectEqual(candidate_count, scanner.matchCount());
}

test "fullSharedSegmentWidth: accepts ANY sub-width shared segments" {
    var matches = try MatchesArray.init(std.testing.allocator, 256, 1);
    defer matches.deinit();

    const old_values: [8]u8 = @splat(0);
    try matches.appendRun(0x1000, &old_values, MatchFlags.i16b.bits(), old_values.len);
    try matches.finalize();

    var segments = matches.segmentIterator();
    const segment = segments.next().?;
    try std.testing.expectEqual(2, fullSharedSegmentWidth(segment, .ANYINTEGER, 8).?);
    try std.testing.expectEqual(2, fullSharedSegmentWidth(segment, .ANYNUMBER, 8).?);
    try std.testing.expectEqual(2, fullSharedSegmentWidth(segment, .INTEGER16, 2).?);
    try std.testing.expect(fullSharedSegmentWidth(segment, .INTEGER64, 8) == null);
}

test "rescanMatches: anynumber increased keeps integer survivor and drops NaN float flag" {
    const allocator = std.testing.allocator;

    // Both old and current bytes are valid qNaN bit patterns (0x7fc0...) that also happen to be valid integers.
    // Integer-wise current > old.
    // Float-wise both are NaN so any ordering compares false.
    // INCREASED should keep u32b and drop f32b, which proves the ANYNUMBER delta kernel unions int and float
    // independently per the stored flags.
    var memory: [4]u8 = undefined;
    std.mem.writeInt(u32, &memory, 0x7fc00002, .native);

    var scanner = Scanner.init(allocator, std.testing.io);
    defer scanner.deinit();
    scanner.options.scan_data_type = .ANYNUMBER;
    try attachScannerToTestMemory(&scanner, allocator, &memory);

    const base_address = @intFromPtr(&memory);
    var old_bytes: [4]u8 = undefined;
    std.mem.writeInt(u32, &old_bytes, 0x7fc00001, .native);

    const stored_flags = MatchFlags{ .u32b = true, .f32b = true };
    var matches = try MatchesArray.init(allocator, 256, 1);
    try matches.appendRun(base_address, &old_bytes, stored_flags.bits(), 1);
    try matches.finalize();
    scanner.matches = matches;
    scanner.num_matches = matches.matchCount();

    try scanner.rescanMatches(.MATCHINCREASED, &.{});

    try scanner.matches.?.validate();
    try std.testing.expectEqual(1, scanner.matchCount());
    try std.testing.expectEqual((MatchFlags{ .u32b = true }).bits(), (try scanner.matchAt(0)).raw_match_info_bits);
}

test "rescanMatches: anynumber delta full segment gates unchanged sub-width windows" {
    const allocator = std.testing.allocator;

    var memory: [8]u8 = undefined;
    var old_bytes: [8]u8 = undefined;
    if (builtin.cpu.arch.endian() == .little) {
        const old_value: f64 = 1.0;
        const current_value: f64 = 2.0;
        std.mem.writeInt(u64, &old_bytes, @bitCast(old_value), .native);
        std.mem.writeInt(u64, &memory, @bitCast(current_value), .native);
    } else {
        std.mem.writeInt(u64, &old_bytes, 0x3ff0000000000000, .native);
        std.mem.writeInt(u64, &memory, 0x3ff0000000000001, .native);
    }
    try std.testing.expectEqualSlices(u8, old_bytes[0..4], memory[0..4]);

    var scanner = Scanner.init(allocator, std.testing.io);
    defer scanner.deinit();
    scanner.options.scan_data_type = .ANYNUMBER;
    try attachScannerToTestMemory(&scanner, allocator, &memory);

    const base_address = @intFromPtr(&memory);
    var matches = try MatchesArray.init(allocator, 256, 1);
    try matches.appendRun(base_address, &old_bytes, MatchFlags.all.bits(), old_bytes.len);
    try matches.finalize();
    scanner.matches = matches;
    scanner.num_matches = matches.matchCount();

    try scanner.rescanMatches(.MATCHINCREASED, &.{});

    try scanner.matches.?.validate();
    try std.testing.expectEqual(1, scanner.matchCount());
    const flags: MatchFlags = @bitCast((try scanner.matchAt(0)).raw_match_info_bits);
    try std.testing.expect(!flags.u8b);
    try std.testing.expect(!flags.s8b);
    try std.testing.expect(!flags.u16b);
    try std.testing.expect(!flags.s16b);
    try std.testing.expect(!flags.u32b);
    try std.testing.expect(!flags.s32b);
    try std.testing.expect(!flags.f32b);
    try std.testing.expect(flags.u64b);
    try std.testing.expect(flags.s64b);
    try std.testing.expect(flags.f64b);
}

test "rescanMatches: stores non-surviving overlap as trailing bytes" {
    const allocator = std.testing.allocator;

    var memory: [8]u8 = @splat(0);
    var scanner = Scanner.init(allocator, std.testing.io);
    defer scanner.deinit();
    scanner.options.scan_data_type = .INTEGER32;
    try attachScannerToTestMemory(&scanner, allocator, &memory);

    const base_address = @intFromPtr(&memory);
    var matches = try MatchesArray.init(allocator, 256, 1);
    try matches.append(base_address, memory[0], MatchFlags.i32b);
    try matches.append(base_address + 1, memory[1], MatchFlags.i32b);
    try matches.append(base_address + 2, memory[2], .{});
    try matches.append(base_address + 3, memory[3], .{});
    try matches.append(base_address + 4, memory[4], .{});
    try matches.finalize();
    scanner.matches = matches;
    scanner.num_matches = matches.matchCount();

    memory[0] = 1;
    try scanner.rescanMatches(.MATCHCHANGED, &.{});

    try scanner.matches.?.validate();
    try std.testing.expectEqual(1, scanner.matchCount());
    try std.testing.expectEqual(base_address, (try scanner.matchAt(0)).address);
    try std.testing.expectEqual(null, scanner.findMatchIndexByAddress(base_address + 1));
    try std.testing.expectEqual(4, scanner.matches.?.storedByteCount());
    try std.testing.expectEqual(1, (try scanner.matchAt(0)).stored_value.data.uint32_value);
}

test "rescanMatches: carries trailing bytes across non-surviving matches" {
    const allocator = std.testing.allocator;

    var memory: [12]u8 = @splat(0);
    var scanner = Scanner.init(allocator, std.testing.io);
    defer scanner.deinit();
    scanner.options.scan_data_type = .INTEGER32;
    try attachScannerToTestMemory(&scanner, allocator, &memory);

    const base_address = @intFromPtr(&memory);
    var matches = try MatchesArray.init(allocator, 256, 1);
    for (memory, 0..) |byte, i| {
        const flags = if (i == 0 or i == 2 or i == 4 or i == 8) MatchFlags.i32b else MatchFlags{};
        try matches.append(base_address + i, byte, flags);
    }
    try matches.finalize();
    scanner.matches = matches;
    scanner.num_matches = matches.matchCount();

    memory[0] = 1;
    memory[8] = 2;
    try scanner.rescanMatches(.MATCHCHANGED, &.{});

    try scanner.matches.?.validate();
    try std.testing.expectEqual(2, scanner.matchCount());
    try std.testing.expectEqual(base_address, (try scanner.matchAt(0)).address);
    try std.testing.expectEqual(base_address + 8, (try scanner.matchAt(1)).address);
    try std.testing.expectEqual(12, scanner.matches.?.storedByteCount());
    try std.testing.expectEqual(1, (try scanner.matchAt(0)).stored_value.data.uint32_value);
    try std.testing.expectEqual(2, (try scanner.matchAt(1)).stored_value.data.uint32_value);
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

    var matches = try MatchesArray.init(std.testing.allocator, 256, 1);
    try matches.append(0x1000, 0xaa, .{ .u8b = true, .s8b = true });
    try matches.append(0x1008, 0xbb, .{ .u8b = true, .s8b = true });
    try matches.append(0x2000, 0xcc, .{ .u8b = true, .s8b = true });
    try matches.finalize();

    scanner.matches = matches;
    scanner.num_matches = matches.matchCount();

    const removed = try scanner.removeRegionById(1);
    try std.testing.expect(removed);
    try std.testing.expectEqual(1, scanner.regionCount());
    try std.testing.expectEqual(1, scanner.matchCount());
    try std.testing.expectEqual(2, scanner.regions[0].id);
    try std.testing.expectEqual(0x2000, (try scanner.matchAt(0)).address);
    try std.testing.expectEqual(null, scanner.findMatchIndexByAddress(0x1000));
    try std.testing.expectEqual(null, scanner.findMatchIndexByAddress(0x1008));
}

fn expectNoMatchBitsInRange(matches: *const MatchesArray, start_address: usize, len: usize) !void {
    var offset: usize = 0;
    while (offset < len) : (offset += 1) {
        const address = start_address + offset;
        var found = false;
        var iter = matches.storedByteIterator();
        while (iter.next()) |stored| {
            if (stored.address != address) continue;
            try std.testing.expectEqual(0, stored.raw_match_info_bits);
            found = true;
            break;
        }
        try std.testing.expect(found);
    }
}

test "removeMatchByIndex: clears selected match bits" {
    var scanner = Scanner.init(std.testing.allocator, std.testing.io);
    defer scanner.deinit();
    scanner.options.scan_data_type = .INTEGER32;

    var matches = try MatchesArray.init(std.testing.allocator, 256, 1);
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
    try std.testing.expectEqual(1, scanner.matchCount());
    try std.testing.expectEqual(null, scanner.findMatchIndexByAddress(0x1000));
    try std.testing.expectEqual(0, scanner.findMatchIndexByAddress(0x2000));
    try std.testing.expectEqual(0x2000, (try scanner.matchAt(0)).address);
    try expectNoMatchBitsInRange(&scanner.matches.?, 0x1000, 4);
}

test "removeMatchByIndex: ignores current scan data type" {
    var scanner = Scanner.init(std.testing.allocator, std.testing.io);
    defer scanner.deinit();
    scanner.options.scan_data_type = .STRING;

    var matches = try MatchesArray.init(std.testing.allocator, 256, 1);
    try matches.append(0x1000, 0x78, .{ .u32b = true, .s32b = true });
    try matches.append(0x1001, 0x56, .{});
    try matches.append(0x1002, 0x34, .{});
    try matches.append(0x1003, 0x12, .{});
    try matches.appendRaw(0x2000, 0xaa, 3);
    try matches.append(0x2001, 0xbb, .{});
    try matches.append(0x2002, 0xcc, .{});
    try matches.finalize();

    scanner.matches = matches;
    scanner.num_matches = matches.matchCount();

    const removed_numeric = try scanner.removeMatchByIndex(0);
    try std.testing.expect(removed_numeric);
    try std.testing.expectEqual(null, scanner.findMatchIndexByAddress(0x1000));
    try std.testing.expectEqual(0, scanner.findMatchIndexByAddress(0x2000));
    try expectNoMatchBitsInRange(&scanner.matches.?, 0x1000, 4);

    scanner.options.scan_data_type = .INTEGER64;
    const removed_variable = try scanner.removeMatchByIndex(0);
    try std.testing.expect(removed_variable);
    try std.testing.expectEqual(0, scanner.matchCount());
    try std.testing.expectEqual(null, scanner.findMatchIndexByAddress(0x2000));
    try std.testing.expect(!scanner.hasMatches());
    try expectNoMatchBitsInRange(&scanner.matches.?, 0x2000, 3);
}

test "removeMatchByAddress: clears selected match bits" {
    var scanner = Scanner.init(std.testing.allocator, std.testing.io);
    defer scanner.deinit();
    scanner.options.scan_data_type = .INTEGER32;

    var matches = try MatchesArray.init(std.testing.allocator, 256, 1);
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
    try std.testing.expectEqual(1, scanner.matchCount());
    try std.testing.expectEqual(null, scanner.findMatchIndexByAddress(0x1000));
    try std.testing.expectEqual(0, scanner.findMatchIndexByAddress(0x2000));
    try std.testing.expectEqual(0x2000, (try scanner.matchAt(0)).address);
    try expectNoMatchBitsInRange(&scanner.matches.?, 0x1000, 4);
}

test "removeMatchByIndex: clears selected variable-length match bits" {
    var scanner = Scanner.init(std.testing.allocator, std.testing.io);
    defer scanner.deinit();
    scanner.options.scan_data_type = .BYTEARRAY;

    var matches = try MatchesArray.init(std.testing.allocator, 256, 1);
    try matches.appendRaw(0x3000, 0xaa, 3);
    try matches.append(0x3001, 0xbb, .{});
    try matches.append(0x3002, 0xcc, .{});
    try matches.appendRaw(0x4000, 0xdd, 2);
    try matches.append(0x4001, 0xee, .{});
    try matches.finalize();

    scanner.matches = matches;
    scanner.num_matches = matches.matchCount();

    const removed = try scanner.removeMatchByIndex(0);
    try std.testing.expect(removed);
    try std.testing.expectEqual(1, scanner.matchCount());
    try std.testing.expectEqual(null, scanner.findMatchIndexByAddress(0x3000));
    try std.testing.expectEqual(0, scanner.findMatchIndexByAddress(0x4000));
    var buf: [2]u8 = undefined;
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0xdd, 0xee }, try scanner.storedMatchBytes(0, &buf));
    try expectNoMatchBitsInRange(&scanner.matches.?, 0x3000, 3);
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
    try std.testing.expectEqual(1, scanner.regionCount());
    try std.testing.expectEqual(1, scanner.regions[0].id);
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

    try std.testing.expectEqual(0, try scanner.removeRegionsByIdSet(&.{}));
    try std.testing.expectEqual(1, scanner.regionCount());
    try std.testing.expectEqual(0, try scanner.removeRegionsByIdSet(&.{9}));
    try std.testing.expectEqual(1, scanner.regionCount());
}

test "initialScanChunkDecision: chooses scan limit and region stop from read shape" {
    const Case = struct {
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
            .region_offset = 0x200,
            .region_size = 0x1000,
            .bytes_read = 0x80,
            .read_size = 0x100,
            .overlap = 8,
            .expected_scan_limit = 0x80,
            .expected_stop_region = true,
        },
        .{
            .region_offset = 0x200,
            .region_size = 0x1000,
            .bytes_read = 0x100,
            .read_size = 0x100,
            .overlap = 8,
            .expected_scan_limit = 0xf8,
            .expected_stop_region = false,
        },
        .{
            .region_offset = 0xf00,
            .region_size = 0x1000,
            .bytes_read = 0x100,
            .read_size = 0x100,
            .overlap = 8,
            .expected_scan_limit = 0x100,
            .expected_stop_region = false,
        },
        .{
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

test "effectiveAlignment: resolves auto alignment by data type" {
    try std.testing.expectEqual(1, effectiveAlignment(0, .INTEGER8));
    try std.testing.expectEqual(2, effectiveAlignment(0, .INTEGER16));
    try std.testing.expectEqual(4, effectiveAlignment(0, .INTEGER32));
    try std.testing.expectEqual(8, effectiveAlignment(0, .INTEGER64));
    try std.testing.expectEqual(4, effectiveAlignment(0, .FLOAT32));
    try std.testing.expectEqual(8, effectiveAlignment(0, .FLOAT64));
    try std.testing.expectEqual(1, effectiveAlignment(0, .ANYINTEGER));
    try std.testing.expectEqual(16, effectiveAlignment(16, .INTEGER32));
}

test "scanChunkIntoMatches: records numeric matches and trailing bytes" {
    var matches = try MatchesArray.init(std.testing.allocator, 256, 1);
    defer matches.deinit();

    const user = try UserValue.parseNumber("1");
    const prepared = PreparedScan{
        .match_type = .MATCHEQUALTO,
        .data_type = .INTEGER16,
    };

    const chunk = [_]u8{ 1, 0, 9, 9, 1, 0 };
    var required_extra: usize = 0;
    var num_matches: usize = 0;

    try scanChunkIntoMatches(&matches, prepared, scanroutines.pickInitialNumericKernel(.INTEGER16, .MATCHEQUALTO, false), &.{user}, 0x1000, &chunk, chunk.len, 1, &required_extra, &num_matches);
    try matches.finalize();

    try std.testing.expectEqual(2, num_matches);
    try std.testing.expectEqual(2, matches.matchCount());
    try std.testing.expectEqual(0x1000, matches.nthMatch(0).?.address);
    try std.testing.expectEqual(0x1004, matches.nthMatch(1).?.address);
    var iter = matches.storedByteIterator();
    _ = iter.next();
    try std.testing.expectEqual(0, iter.next().?.raw_match_info_bits);
    try std.testing.expectEqual(0, required_extra);
    var stored: [2]u8 = undefined;
    try std.testing.expectEqualSlices(u8, &[_]u8{ 1, 0 }, matches.dataToBytes(0, 0, 2, &stored));
}

test "scanChunkIntoMatches: honors alignment gating" {
    var matches = try MatchesArray.init(std.testing.allocator, 256, 1);
    defer matches.deinit();

    const user = try UserValue.parseNumber("1");
    const prepared = PreparedScan{
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

    try scanChunkIntoMatches(&matches, prepared, scanroutines.pickInitialNumericKernel(.INTEGER16, .MATCHEQUALTO, false), &.{user}, 0x2000, &chunk, chunk.len, 2, &required_extra, &num_matches);
    try matches.finalize();

    try std.testing.expectEqual(1, num_matches);
    try std.testing.expectEqual(1, matches.matchCount());
    try std.testing.expectEqual(0x2004, matches.nthMatch(0).?.address);
    try std.testing.expectEqual(null, matches.findMatchIndexByAddress(0x2001));
    try std.testing.expectEqual(0, required_extra);
}

test "scanChunkIntoMatches: INTEGER32 MATCHEQUALTO at alignment 4 stores trailing bytes per aligned match and skips gaps" {
    var matches = try MatchesArray.init(std.testing.allocator, 256, 4);
    defer matches.deinit();

    const user = try UserValue.parseNumber("1");
    const prepared = PreparedScan{
        .match_type = .MATCHEQUALTO,
        .data_type = .INTEGER32,
    };

    // Two INTEGER32 matches for value 1 (LE = 1,0,0,0) at offsets 0 and 8,
    // separated by a 4-byte gap of non-matching bytes at offset 4.
    // With candidate stepping at alignment 4 only offsets 0, 4, 8 invoke the kernel.
    // The gap bytes 4-7 sit outside any match's pending window and must not be stored.
    const chunk = [_]u8{ 1, 0, 0, 0, 9, 9, 9, 9, 1, 0, 0, 0 };
    var required_extra: usize = 0;
    var num_matches: usize = 0;

    try scanChunkIntoMatches(&matches, prepared, scanroutines.pickInitialNumericKernel(.INTEGER32, .MATCHEQUALTO, false), &.{user}, 0x4000, &chunk, chunk.len, 4, &required_extra, &num_matches);
    try matches.finalize();

    try std.testing.expectEqual(2, num_matches);
    try std.testing.expectEqual(2, matches.matchCount());
    try std.testing.expectEqual(0x4000, matches.nthMatch(0).?.address);
    try std.testing.expectEqual(0x4008, matches.nthMatch(1).?.address);
    // The gap candidates at 0x4004 were exercised by the kernel and rejected (no spurious match registered there).
    try std.testing.expectEqual(null, matches.findMatchIndexByAddress(0x4004));
    try std.testing.expectEqual(0, required_extra);
    // Each match's 4 trailing bytes reconstruct the original INTEGER32 LE bytes for value 1.
    var stored: [4]u8 = undefined;
    const loc0 = matches.nthMatch(0).?;
    const loc1 = matches.nthMatch(1).?;
    try std.testing.expectEqualSlices(u8, &[_]u8{ 1, 0, 0, 0 }, matches.dataToBytes(loc0.swath_offset, loc0.index, 4, &stored));
    try std.testing.expectEqualSlices(u8, &[_]u8{ 1, 0, 0, 0 }, matches.dataToBytes(loc1.swath_offset, loc1.index, 4, &stored));
}

test "scanChunkIntoMatches: numeric MATCHEQUALTO carries chunk-boundary trailing bytes across calls" {
    var matches = try MatchesArray.init(std.testing.allocator, 256, 1);
    defer matches.deinit();

    const user = try UserValue.parseNumber("1");
    const prepared = PreparedScan{
        .match_type = .MATCHEQUALTO,
        .data_type = .INTEGER32,
    };

    // First chunk has an INTEGER32 match for value 1 at offset 3 (the value's LE bytes span offsets 3..7).
    // scan_limit=4 means only the match byte at offset 3 is part of this chunk's window.
    // Bytes 4..7 are overlap-only.
    // required_extra should be set to 3 on exit so the next chunk records them as trailing bytes.
    const first_chunk = [_]u8{ 9, 9, 9, 1, 0, 0, 0 };
    var required_extra: usize = 0;
    var num_matches: usize = 0;

    try scanChunkIntoMatches(&matches, prepared, scanroutines.pickInitialNumericKernel(.INTEGER32, .MATCHEQUALTO, false), &.{user}, 0x5000, &first_chunk, 4, 1, &required_extra, &num_matches);
    try std.testing.expectEqual(1, num_matches);
    try std.testing.expectEqual(3, required_extra);

    // Second chunk starts at 0x5004 (right after first chunk's scan_limit).
    // Its first 3 bytes are the carried trailing bytes for the prior match
    // and must be stored with raw_bits=0. No new matches in this chunk.
    const second_chunk = [_]u8{ 0, 0, 0, 9, 9, 9 };
    try scanChunkIntoMatches(&matches, prepared, scanroutines.pickInitialNumericKernel(.INTEGER32, .MATCHEQUALTO, false), &.{user}, 0x5004, &second_chunk, second_chunk.len, 1, &required_extra, &num_matches);
    try matches.finalize();

    try std.testing.expectEqual(1, num_matches);
    try std.testing.expectEqual(1, matches.matchCount());
    try std.testing.expectEqual(0x5003, matches.nthMatch(0).?.address);
    // 1 match byte + 3 trailing bytes carried across the boundary = 4 stored.
    try std.testing.expectEqual(4, matches.storedByteCount());
    try std.testing.expectEqual(0, required_extra);
    var stored: [4]u8 = undefined;
    const loc = matches.nthMatch(0).?;
    try std.testing.expectEqualSlices(u8, &[_]u8{ 1, 0, 0, 0 }, matches.dataToBytes(loc.swath_offset, loc.index, 4, &stored));
}

test "scanChunkIntoMatches: INTEGER32 MATCHEQUALTO direct search records overlapping matches at align 1" {
    var matches = try MatchesArray.init(std.testing.allocator, 256, 1);
    defer matches.deinit();

    const user = try UserValue.parseNumber("0x01010101");
    const prepared = PreparedScan{
        .match_type = .MATCHEQUALTO,
        .data_type = .INTEGER32,
    };

    // 6 consecutive 0x01 bytes contain INTEGER32 0x01010101 at offsets 0, 1, 2 (overlapping).
    // The indexOfPos-based path must advance by hit+1 to find every overlap and
    // not skip past matches like a stride-of-width loop would.
    const chunk = [_]u8{ 1, 1, 1, 1, 1, 1, 9 };
    var required_extra: usize = 0;
    var num_matches: usize = 0;

    try scanChunkIntoMatches(&matches, prepared, scanroutines.pickInitialNumericKernel(.INTEGER32, .MATCHEQUALTO, false), &.{user}, 0x1000, &chunk, chunk.len, 1, &required_extra, &num_matches);
    try matches.finalize();

    try std.testing.expectEqual(3, num_matches);
    try std.testing.expectEqual(0x1000, matches.nthMatch(0).?.address);
    try std.testing.expectEqual(0x1001, matches.nthMatch(1).?.address);
    try std.testing.expectEqual(0x1002, matches.nthMatch(2).?.address);
    try std.testing.expectEqual(0, required_extra);
}

test "scanChunkIntoMatches: INTEGER32 MATCHEQUALTO direct search honors alignment 4" {
    var matches = try MatchesArray.init(std.testing.allocator, 256, 4);
    defer matches.deinit();

    const user = try UserValue.parseNumber("0x42");
    const prepared = PreparedScan{
        .match_type = .MATCHEQUALTO,
        .data_type = .INTEGER32,
    };

    // INTEGER32 needle [0x42, 0, 0, 0] appears at offsets 0 (aligned), 5 (unaligned), and 12 (aligned).
    // The alignment gate must reject the h=5 hit even though indexOfPos finds it.
    const chunk = [_]u8{ 0x42, 0, 0, 0, 9, 0x42, 0, 0, 0, 9, 9, 9, 0x42, 0, 0, 0 };
    var required_extra: usize = 0;
    var num_matches: usize = 0;

    try scanChunkIntoMatches(&matches, prepared, scanroutines.pickInitialNumericKernel(.INTEGER32, .MATCHEQUALTO, false), &.{user}, 0x2000, &chunk, chunk.len, 4, &required_extra, &num_matches);
    try matches.finalize();

    try std.testing.expectEqual(2, num_matches);
    try std.testing.expectEqual(0x2000, matches.nthMatch(0).?.address);
    try std.testing.expectEqual(0x200c, matches.nthMatch(1).?.address);
    try std.testing.expectEqual(null, matches.findMatchIndexByAddress(0x2005));
}

test "scanChunkIntoMatches: INTEGER32 MATCHEQUALTO direct search honors reverse endian" {
    var matches = try MatchesArray.init(std.testing.allocator, 256, 4);
    defer matches.deinit();

    const user = try UserValue.parseNumber("0x12345678");
    const prepared = PreparedScan{
        .match_type = .MATCHEQUALTO,
        .data_type = .INTEGER32,
        .reverse_endianness = true,
    };

    var chunk: [8]u8 = undefined;
    const target: u32 = 0x12345678;
    std.mem.writeInt(u32, chunk[0..4], @byteSwap(target), .native);
    std.mem.writeInt(u32, chunk[4..8], target, .native);
    var required_extra: usize = 0;
    var num_matches: usize = 0;

    try scanChunkIntoMatches(&matches, prepared, scanroutines.pickInitialNumericKernel(.INTEGER32, .MATCHEQUALTO, true), &.{user}, 0x2400, &chunk, chunk.len, 4, &required_extra, &num_matches);
    try matches.finalize();

    try std.testing.expectEqual(1, num_matches);
    try std.testing.expectEqual(0x2400, matches.nthMatch(0).?.address);
    try std.testing.expectEqual(null, matches.findMatchIndexByAddress(0x2404));
}

test "scanChunkIntoMatches: INTEGER32 MATCHEQUALTO with disagreeing signed and unsigned fields falls back to general kernel" {
    var matches = try MatchesArray.init(std.testing.allocator, 256, 1);
    defer matches.deinit();

    // A contrived UserValue where int32_value and uint32_value disagree.
    // The needle path cannot represent both interpretations as a single byte pattern.
    // Without the fix it would silently pick uint32_value and still record both flags.
    // The fix returns null from the needle serializer so the general kernel runs and
    // only records the flag whose value actually matches the memory.
    const user = UserValue{
        .int32_value = -1,
        .uint32_value = 42,
        .flags = .{ .s32b = true, .u32b = true },
    };
    const prepared = PreparedScan{
        .match_type = .MATCHEQUALTO,
        .data_type = .INTEGER32,
    };

    // Memory contains the bit pattern of 42 (only the u32 interpretation matches).
    const chunk = [_]u8{ 0x2A, 0, 0, 0 };
    var required_extra: usize = 0;
    var num_matches: usize = 0;

    try scanChunkIntoMatches(&matches, prepared, scanroutines.pickInitialNumericKernel(.INTEGER32, .MATCHEQUALTO, false), &.{user}, 0x4000, &chunk, chunk.len, 1, &required_extra, &num_matches);
    try matches.finalize();

    try std.testing.expectEqual(1, num_matches);
    const m = matches.nthMatch(0).?;
    try std.testing.expectEqual(0x4000, m.address);
    const recorded: MatchFlags = @bitCast(m.raw_match_info_bits);
    try std.testing.expect(recorded.u32b);
    try std.testing.expect(!recorded.s32b);
}

test "scanChunkIntoMatches: FLOAT32 MATCHEQUALTO zero matches positive and negative zero bit patterns" {
    var matches = try MatchesArray.init(std.testing.allocator, 256, 1);
    defer matches.deinit();

    // parseNumber("0") sets f32b/f64b with float32_value = 0.0.
    const user = try UserValue.parseNumber("0");
    const prepared = PreparedScan{
        .match_type = .MATCHEQUALTO,
        .data_type = .FLOAT32,
    };

    // +0.0 bit pattern = 0x00000000 (bytes 0,0,0,0).
    // -0.0 bit pattern = 0x80000000 (LE bytes 0,0,0,0x80).
    // Both compare equal to 0.0 under "==", so the dual-needle path should
    // register matches at offsets 0 (+0.0), 4 (-0.0), and 8 (+0.0).
    var chunk: [12]u8 = @splat(0);
    chunk[7] = 0x80;
    var required_extra: usize = 0;
    var num_matches: usize = 0;

    try scanChunkIntoMatches(&matches, prepared, scanroutines.pickInitialNumericKernel(.FLOAT32, .MATCHEQUALTO, false), &.{user}, 0x3000, &chunk, chunk.len, 4, &required_extra, &num_matches);
    try matches.finalize();

    try std.testing.expectEqual(3, num_matches);
    try std.testing.expectEqual(0x3000, matches.nthMatch(0).?.address);
    try std.testing.expectEqual(0x3004, matches.nthMatch(1).?.address);
    try std.testing.expectEqual(0x3008, matches.nthMatch(2).?.address);
}

test "scanChunkIntoMatches: FLOAT32 MATCHEQUALTO negative-zero input still matches both signs once" {
    var matches = try MatchesArray.init(std.testing.allocator, 256, 1);
    defer matches.deinit();

    // User passes -0.0 explicitly (parseNumber("0") would give +0.0).
    // Under "==" semantics, -0.0 still equals both +0.0 and -0.0, so the
    // serializer must emit BOTH bit patterns regardless of which sign the user supplied.
    // If primary and secondary needles collapsed to the same pattern,
    // the dual-cursor loop would emit the same address twice.
    const user = UserValue{
        .float32_value = -0.0,
        .flags = .{ .f32b = true },
    };
    const prepared = PreparedScan{
        .match_type = .MATCHEQUALTO,
        .data_type = .FLOAT32,
    };

    var chunk: [12]u8 = @splat(0);
    chunk[7] = 0x80;
    var required_extra: usize = 0;
    var num_matches: usize = 0;

    try scanChunkIntoMatches(&matches, prepared, scanroutines.pickInitialNumericKernel(.FLOAT32, .MATCHEQUALTO, false), &.{user}, 0x3000, &chunk, chunk.len, 4, &required_extra, &num_matches);
    try matches.finalize();

    try std.testing.expectEqual(3, num_matches);
    try std.testing.expectEqual(0x3000, matches.nthMatch(0).?.address);
    try std.testing.expectEqual(0x3004, matches.nthMatch(1).?.address);
    try std.testing.expectEqual(0x3008, matches.nthMatch(2).?.address);
}

test "scanChunkIntoMatches: FLOAT64 MATCHEQUALTO negative-zero input still matches both signs once" {
    var matches = try MatchesArray.init(std.testing.allocator, 256, 1);
    defer matches.deinit();

    const user = UserValue{
        .float64_value = -0.0,
        .flags = .{ .f64b = true },
    };
    const prepared = PreparedScan{
        .match_type = .MATCHEQUALTO,
        .data_type = .FLOAT64,
    };

    // 24 bytes: +0.0 at offset 0, -0.0 at offset 8, +0.0 at offset 16.
    var chunk: [24]u8 = @splat(0);
    chunk[15] = 0x80; // MSB of -0.0 little-endian f64 bit pattern
    var required_extra: usize = 0;
    var num_matches: usize = 0;

    try scanChunkIntoMatches(&matches, prepared, scanroutines.pickInitialNumericKernel(.FLOAT64, .MATCHEQUALTO, false), &.{user}, 0x3000, &chunk, chunk.len, 8, &required_extra, &num_matches);
    try matches.finalize();

    try std.testing.expectEqual(3, num_matches);
    try std.testing.expectEqual(0x3000, matches.nthMatch(0).?.address);
    try std.testing.expectEqual(0x3008, matches.nthMatch(1).?.address);
    try std.testing.expectEqual(0x3010, matches.nthMatch(2).?.address);
}

test "scanChunkIntoMatches: FLOAT32 MATCHEQUALTO NaN never matches" {
    var matches = try MatchesArray.init(std.testing.allocator, 256, 1);
    defer matches.deinit();

    const nan_value = std.math.nan(f32);
    const user = UserValue{
        .float32_value = nan_value,
        .flags = .{ .f32b = true },
    };
    const prepared = PreparedScan{
        .match_type = .MATCHEQUALTO,
        .data_type = .FLOAT32,
    };

    // Chunk holds the same NaN bit pattern. Under "==" semantics, NaN never equals anything (including itself),
    // so the direct-search path must serialize-to-null and the fallback kernel must reject the candidate.
    var chunk: [4]u8 = undefined;
    const nan_bits: u32 = @bitCast(nan_value);
    std.mem.writeInt(u32, &chunk, nan_bits, .native);
    var required_extra: usize = 0;
    var num_matches: usize = 0;

    try scanChunkIntoMatches(&matches, prepared, scanroutines.pickInitialNumericKernel(.FLOAT32, .MATCHEQUALTO, false), &.{user}, 0x4000, &chunk, chunk.len, 1, &required_extra, &num_matches);
    try matches.finalize();

    try std.testing.expectEqual(0, num_matches);
}

test "scanChunkIntoMatches: FLOAT32 MATCHEQUALTO zero burst-appends a long zero region at align 1" {
    var matches = try MatchesArray.init(std.testing.allocator, 4096, 1);
    defer matches.deinit();

    const user = try UserValue.parseNumber("0");
    const prepared = PreparedScan{
        .match_type = .MATCHEQUALTO,
        .data_type = .FLOAT32,
    };

    // 64 zero bytes: the +0.0 needle is [0,0,0,0] and matches at every offset 0..=60 (61 overlapping matches).
    // The dual-cursor direct-search loop must collapse these into one appendRun call rather than 61 appendRaw calls.
    // No -0.0 (0x80 byte) anywhere, so the secondary cursor is null at start
    // and stays null, which exercises the consumed_primary burst path in isolation.
    var chunk: [64]u8 = @splat(0);
    var required_extra: usize = 0;
    var num_matches: usize = 0;

    try scanChunkIntoMatches(&matches, prepared, scanroutines.pickInitialNumericKernel(.FLOAT32, .MATCHEQUALTO, false), &.{user}, 0x4000, &chunk, chunk.len, 1, &required_extra, &num_matches);
    try matches.finalize();
    try matches.validate();

    try std.testing.expectEqual(61, num_matches);
    try std.testing.expectEqual(0x4000, matches.nthMatch(0).?.address);
    try std.testing.expectEqual(0x4000 + 60, matches.nthMatch(60).?.address);
    // Every emitted match must keep the same +0.0 raw_bits.
    const first: MatchFlags = @bitCast(matches.nthMatch(0).?.raw_match_info_bits);
    const last: MatchFlags = @bitCast(matches.nthMatch(60).?.raw_match_info_bits);
    try std.testing.expect(first.f32b);
    try std.testing.expect(last.f32b);
    try std.testing.expectEqual(0, required_extra);
}

test "scanChunkIntoMatches: FLOAT32 zero burst followed by isolated -0.0 keeps dual-cursor invariant" {
    var matches = try MatchesArray.init(std.testing.allocator, 4096, 1);
    defer matches.deinit();

    const user = try UserValue.parseNumber("0");
    const prepared = PreparedScan{
        .match_type = .MATCHEQUALTO,
        .data_type = .FLOAT32,
    };

    // Layout (28 bytes total, align 1):
    //   offset 0..15: zeros            -> +0.0 matches at 0..=12 (13 matches)
    //   offset 16..19: stop byte 0xCC at 16, then zeros (no match alignment)
    //   offset 20..23: -0.0 little-endian -> {0,0,0,0x80}, matches secondary
    //   offset 24..27: zeros            -> +0.0 match at 24 only (chunk ends)
    // With needle.primary.len = 4, scan_limit = chunk.len = 28, the last valid start offset is 24.
    // Verifies (a) burst at the front, (b) secondary still discovered after burst advances hit_primary past it,
    // (c) trailing +0.0 singleton after the secondary still emits.
    var chunk: [28]u8 = @splat(0);
    chunk[16] = 0xCC;
    chunk[23] = 0x80;
    var required_extra: usize = 0;
    var num_matches: usize = 0;

    try scanChunkIntoMatches(&matches, prepared, scanroutines.pickInitialNumericKernel(.FLOAT32, .MATCHEQUALTO, false), &.{user}, 0x5000, &chunk, chunk.len, 1, &required_extra, &num_matches);
    try matches.finalize();
    try matches.validate();

    // Expected matches:
    //   +0.0 burst:  0,1,2,3,4,5,6,7,8,9,10,11,12   (13)
    //   +0.0 single: 17,18,19                       (3) - zeros after 0xCC
    //   -0.0 single: 20                              (1) - [0,0,0,0x80]
    //   +0.0 single: 24                              (1) - final {0,0,0,0}
    // Total: 18.
    try std.testing.expectEqual(18, num_matches);
    try std.testing.expectEqual(0x5000, matches.nthMatch(0).?.address);
    try std.testing.expectEqual(0x5000 + 12, matches.nthMatch(12).?.address);
    try std.testing.expectEqual(0x5000 + 17, matches.nthMatch(13).?.address);
    try std.testing.expectEqual(0x5000 + 20, matches.nthMatch(16).?.address);
    try std.testing.expectEqual(0x5000 + 24, matches.nthMatch(17).?.address);
}

test "scanChunkIntoMatches: INTEGER32 zero search records every overlapping match at align 1" {
    var matches = try MatchesArray.init(std.testing.allocator, 4096, 1);
    defer matches.deinit();

    const user = try UserValue.parseNumber("0");
    const prepared = PreparedScan{
        .match_type = .MATCHEQUALTO,
        .data_type = .INTEGER32,
    };

    // 16 zero bytes followed by a non-zero sentinel.
    // INTEGER32 zero needle is [0,0,0,0]; with chunk[16] = 0xFF, the last valid start position is 12.
    // So 13 overlapping matches at offsets 0..=12.
    var chunk: [17]u8 = @splat(0);
    chunk[16] = 0xFF;
    var required_extra: usize = 0;
    var num_matches: usize = 0;

    try scanChunkIntoMatches(&matches, prepared, scanroutines.pickInitialNumericKernel(.INTEGER32, .MATCHEQUALTO, false), &.{user}, 0x6000, &chunk, chunk.len, 1, &required_extra, &num_matches);
    try matches.finalize();
    try matches.validate();

    try std.testing.expectEqual(13, num_matches);
    try std.testing.expectEqual(0x6000, matches.nthMatch(0).?.address);
    try std.testing.expectEqual(0x6000 + 12, matches.nthMatch(12).?.address);
}

test "scanChunkIntoMatches: FLOAT32 zero burst-appends aligned run at align 4" {
    var matches = try MatchesArray.init(std.testing.allocator, 4096, 4);
    defer matches.deinit();

    const user = try UserValue.parseNumber("0");
    const prepared = PreparedScan{
        .match_type = .MATCHEQUALTO,
        .data_type = .FLOAT32,
    };

    var chunk: [64]u8 = @splat(0);
    var required_extra: usize = 0;
    var num_matches: usize = 0;

    try scanChunkIntoMatches(&matches, prepared, scanroutines.pickInitialNumericKernel(.FLOAT32, .MATCHEQUALTO, false), &.{user}, 0x7000, &chunk, chunk.len, 4, &required_extra, &num_matches);
    try matches.finalize();
    try matches.validate();

    try std.testing.expectEqual(16, num_matches);
    try std.testing.expectEqual(0x7000, matches.nthMatch(0).?.address);
    try std.testing.expectEqual(0x7000 + 60, matches.nthMatch(15).?.address);
    try std.testing.expectEqual(64, matches.storedByteCount());
    try std.testing.expectEqual(0, required_extra);
}

test "scanChunkIntoMatches: INTEGER64 zero burst at align 4 preserves final trailing bytes" {
    var matches = try MatchesArray.init(std.testing.allocator, 4096, 4);
    defer matches.deinit();

    const user = try UserValue.parseNumber("0");
    const prepared = PreparedScan{
        .match_type = .MATCHEQUALTO,
        .data_type = .INTEGER64,
    };

    var chunk: [25]u8 = @splat(0);
    chunk[24] = 0xff;
    var required_extra: usize = 0;
    var num_matches: usize = 0;

    try scanChunkIntoMatches(&matches, prepared, scanroutines.pickInitialNumericKernel(.INTEGER64, .MATCHEQUALTO, false), &.{user}, 0x8000, &chunk, chunk.len, 4, &required_extra, &num_matches);
    try matches.finalize();
    try matches.validate();

    try std.testing.expectEqual(5, num_matches);
    try std.testing.expectEqual(0x8000, matches.nthMatch(0).?.address);
    try std.testing.expectEqual(0x8000 + 16, matches.nthMatch(4).?.address);
    try std.testing.expectEqual(24, matches.storedByteCount());
    try std.testing.expectEqual(0, required_extra);
}

test "scanChunkIntoMatches: bulk MATCHANY records align-1 numeric run" {
    var matches = try MatchesArray.init(std.testing.allocator, 4096, 1);
    defer matches.deinit();

    const prepared = PreparedScan{
        .match_type = .MATCHANY,
        .data_type = .INTEGER32,
    };

    const chunk = [_]u8{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 };
    var required_extra: usize = 0;
    var num_matches: usize = 0;

    try scanChunkIntoMatches(&matches, prepared, scanroutines.pickInitialNumericKernel(.INTEGER32, .MATCHANY, false), &.{}, 0x3000, &chunk, chunk.len, 1, &required_extra, &num_matches);
    try matches.finalize();

    try matches.validate();
    try std.testing.expectEqual(13, num_matches);
    try std.testing.expectEqual(13, matches.matchCount());
    try std.testing.expectEqual(16, matches.storedByteCount());
    try std.testing.expectEqual(0, required_extra);
    try std.testing.expectEqual(0x300c, matches.nthMatch(12).?.address);
}

test "scanChunkIntoMatches: bulk MATCHANY preserves align-4 numeric run" {
    var matches = try MatchesArray.init(std.testing.allocator, 4096, 4);
    defer matches.deinit();

    const prepared = PreparedScan{
        .match_type = .MATCHANY,
        .data_type = .INTEGER32,
    };

    const chunk = [_]u8{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 };
    var required_extra: usize = 0;
    var num_matches: usize = 0;

    try scanChunkIntoMatches(&matches, prepared, scanroutines.pickInitialNumericKernel(.INTEGER32, .MATCHANY, false), &.{}, 0x4000, &chunk, chunk.len, 4, &required_extra, &num_matches);
    try matches.finalize();

    try matches.validate();
    try std.testing.expectEqual(4, num_matches);
    try std.testing.expectEqual(4, matches.matchCount());
    try std.testing.expectEqual(16, matches.storedByteCount());
    try std.testing.expectEqual(0, required_extra);
    try std.testing.expectEqual(0x400c, matches.nthMatch(3).?.address);
}

test "scanChunkIntoMatches: bulk MATCHANY skips unaligned leading bytes" {
    var matches = try MatchesArray.init(std.testing.allocator, 4096, 4);
    defer matches.deinit();

    const prepared = PreparedScan{
        .match_type = .MATCHANY,
        .data_type = .INTEGER32,
    };

    const chunk = [_]u8{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 };
    var required_extra: usize = 0;
    var num_matches: usize = 0;

    try scanChunkIntoMatches(&matches, prepared, scanroutines.pickInitialNumericKernel(.INTEGER32, .MATCHANY, false), &.{}, 0x4001, &chunk, chunk.len, 4, &required_extra, &num_matches);
    try matches.finalize();

    try matches.validate();
    try std.testing.expectEqual(3, num_matches);
    try std.testing.expectEqual(3, matches.matchCount());
    try std.testing.expectEqual(12, matches.storedByteCount());
    try std.testing.expectEqual(0x4004, matches.nthMatch(0).?.address);
    try std.testing.expectEqual(0x400c, matches.nthMatch(2).?.address);
}

test "scanChunkIntoMatches: ANYNUMBER MATCHANY bulk run preserves tail widths" {
    var matches = try MatchesArray.init(std.testing.allocator, 4096, 1);
    defer matches.deinit();

    const prepared = PreparedScan{
        .match_type = .MATCHANY,
        .data_type = .ANYNUMBER,
    };

    const chunk = [_]u8{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 };
    var required_extra: usize = 0;
    var num_matches: usize = 0;

    try scanChunkIntoMatches(&matches, prepared, scanroutines.pickInitialNumericKernel(.ANYNUMBER, .MATCHANY, false), &.{}, 0x5000, &chunk, chunk.len, 1, &required_extra, &num_matches);
    try matches.finalize();

    try matches.validate();
    try std.testing.expectEqual(10, num_matches);
    try std.testing.expectEqual(10, matches.matchCount());
    try std.testing.expectEqual(MatchFlags.all.bits(), matches.nthMatch(0).?.raw_match_info_bits);
    try std.testing.expectEqual(MatchFlags.all.bits(), matches.nthMatch(2).?.raw_match_info_bits);
    try std.testing.expectEqual((MatchFlags{ .u8b = true, .s8b = true }).bits(), matches.nthMatch(9).?.raw_match_info_bits);
}

test "scanChunkIntoMatches: string exact preserves overlapping matches" {
    var matches = try MatchesArray.init(std.testing.allocator, 4096, 1);
    defer matches.deinit();

    const user = UserValue{ .string_value = "ana" };
    const prepared = PreparedScan{
        .match_type = .MATCHEQUALTO,
        .data_type = .STRING,
    };

    const chunk = "banana";
    var required_extra: usize = 0;
    var num_matches: usize = 0;

    try scanChunkIntoMatches(&matches, prepared, null, &.{user}, 0x6000, chunk, chunk.len, 1, &required_extra, &num_matches);
    try matches.finalize();

    try matches.validate();
    try std.testing.expectEqual(2, num_matches);
    try std.testing.expectEqual(2, matches.matchCount());
    try std.testing.expectEqual(0x6001, matches.nthMatch(0).?.address);
    try std.testing.expectEqual(0x6003, matches.nthMatch(1).?.address);
    try std.testing.expectEqual(5, matches.storedByteCount());
    var first: [3]u8 = undefined;
    var second: [3]u8 = undefined;
    const first_match = matches.nthMatch(0).?;
    const second_match = matches.nthMatch(1).?;
    try std.testing.expectEqualSlices(u8, "ana", matches.dataToBytes(first_match.swath_offset, first_match.index, 3, &first));
    try std.testing.expectEqualSlices(u8, "ana", matches.dataToBytes(second_match.swath_offset, second_match.index, 3, &second));
}

test "scanChunkIntoMatches: string exact respects alignment" {
    var matches = try MatchesArray.init(std.testing.allocator, 4096, 1);
    defer matches.deinit();

    const user = UserValue{ .string_value = "aba" };
    const prepared = PreparedScan{
        .match_type = .MATCHEQUALTO,
        .data_type = .STRING,
    };

    const chunk = "xabaaba";
    var required_extra: usize = 0;
    var num_matches: usize = 0;

    try scanChunkIntoMatches(&matches, prepared, null, &.{user}, 0x7000, chunk, chunk.len, 4, &required_extra, &num_matches);
    try matches.finalize();

    try matches.validate();
    try std.testing.expectEqual(1, num_matches);
    try std.testing.expectEqual(1, matches.matchCount());
    try std.testing.expectEqual(0x7004, matches.nthMatch(0).?.address);
    try std.testing.expectEqual(0, required_extra);
}

test "scanChunkIntoMatches: string exact carries chunk-boundary trailing bytes" {
    var matches = try MatchesArray.init(std.testing.allocator, 4096, 1);
    defer matches.deinit();

    const user = UserValue{ .string_value = "abcd" };
    const prepared = PreparedScan{
        .match_type = .MATCHEQUALTO,
        .data_type = .STRING,
    };

    const first_chunk = "xxabcd";
    const second_chunk = "cdzz";
    var required_extra: usize = 0;
    var num_matches: usize = 0;

    try scanChunkIntoMatches(&matches, prepared, null, &.{user}, 0x8000, first_chunk, 4, 1, &required_extra, &num_matches);
    try std.testing.expectEqual(2, required_extra);
    try scanChunkIntoMatches(&matches, prepared, null, &.{user}, 0x8004, second_chunk, second_chunk.len, 1, &required_extra, &num_matches);
    try matches.finalize();

    try matches.validate();
    try std.testing.expectEqual(1, num_matches);
    try std.testing.expectEqual(1, matches.matchCount());
    try std.testing.expectEqual(0x8002, matches.nthMatch(0).?.address);
    try std.testing.expectEqual(0, required_extra);
    var stored: [4]u8 = undefined;
    const location = matches.nthMatch(0).?;
    try std.testing.expectEqualSlices(u8, "abcd", matches.dataToBytes(location.swath_offset, location.index, 4, &stored));
}

test "scanChunkIntoMatches: bytearray exact preserves overlapping matches" {
    var matches = try MatchesArray.init(std.testing.allocator, 4096, 1);
    defer matches.deinit();

    const pattern = [_]u8{ 0xaa, 0xbb, 0xaa };
    const wildcards = [_]value_mod.Wildcard{ .FIXED, .FIXED, .FIXED };
    const user = UserValue{ .bytearray_value = &pattern, .wildcard_value = &wildcards };
    const prepared = PreparedScan{
        .match_type = .MATCHEQUALTO,
        .data_type = .BYTEARRAY,
    };

    const chunk = [_]u8{ 0xaa, 0xbb, 0xaa, 0xbb, 0xaa };
    var required_extra: usize = 0;
    var num_matches: usize = 0;

    try scanChunkIntoMatches(&matches, prepared, null, &.{user}, 0x9000, &chunk, chunk.len, 1, &required_extra, &num_matches);
    try matches.finalize();

    try matches.validate();
    try std.testing.expectEqual(2, num_matches);
    try std.testing.expectEqual(2, matches.matchCount());
    try std.testing.expectEqual(0x9000, matches.nthMatch(0).?.address);
    try std.testing.expectEqual(0x9002, matches.nthMatch(1).?.address);
    var first: [3]u8 = undefined;
    var second: [3]u8 = undefined;
    const first_match = matches.nthMatch(0).?;
    const second_match = matches.nthMatch(1).?;
    try std.testing.expectEqualSlices(u8, &pattern, matches.dataToBytes(first_match.swath_offset, first_match.index, 3, &first));
    try std.testing.expectEqualSlices(u8, &pattern, matches.dataToBytes(second_match.swath_offset, second_match.index, 3, &second));
}

test "scanChunkIntoMatches: bytearray exact honors wildcard predicate" {
    var matches = try MatchesArray.init(std.testing.allocator, 4096, 1);
    defer matches.deinit();

    const pattern = [_]u8{ 0xaa, 0x00, 0xcc };
    const wildcards = [_]value_mod.Wildcard{ .FIXED, .WILDCARD, .FIXED };
    const user = UserValue{ .bytearray_value = &pattern, .wildcard_value = &wildcards };
    const prepared = PreparedScan{
        .match_type = .MATCHEQUALTO,
        .data_type = .BYTEARRAY,
    };

    const chunk = [_]u8{ 0xaa, 0x77, 0xcc, 0xaa, 0x88, 0xcd };
    var required_extra: usize = 0;
    var num_matches: usize = 0;

    try scanChunkIntoMatches(&matches, prepared, null, &.{user}, 0xa000, &chunk, chunk.len, 1, &required_extra, &num_matches);
    try matches.finalize();

    try matches.validate();
    try std.testing.expectEqual(1, num_matches);
    try std.testing.expectEqual(1, matches.matchCount());
    try std.testing.expectEqual(0xa000, matches.nthMatch(0).?.address);
}

test "scanChunkIntoMatches: bytearray wildcard slots require zero pattern bytes" {
    var matches = try MatchesArray.init(std.testing.allocator, 4096, 1);
    defer matches.deinit();

    const pattern = [_]u8{ 0xaa, 0xff, 0xcc };
    const wildcards = [_]value_mod.Wildcard{ .FIXED, .WILDCARD, .FIXED };
    const user = UserValue{ .bytearray_value = &pattern, .wildcard_value = &wildcards };
    const prepared = PreparedScan{
        .match_type = .MATCHEQUALTO,
        .data_type = .BYTEARRAY,
    };

    const chunk = [_]u8{ 0xaa, 0x77, 0xcc };
    var required_extra: usize = 0;
    var num_matches: usize = 0;

    try scanChunkIntoMatches(&matches, prepared, null, &.{user}, 0xb000, &chunk, chunk.len, 1, &required_extra, &num_matches);
    try matches.finalize();

    try matches.validate();
    try std.testing.expectEqual(0, num_matches);
    try std.testing.expectEqual(0, matches.matchCount());
}

test "scanChunkIntoMatches: bytearray exact picks longest fixed run when it's not at index 0" {
    var matches = try MatchesArray.init(std.testing.allocator, 4096, 1);
    defer matches.deinit();

    // Pattern: [0x00, WILD, 0xDE, 0xAD, 0xBE, 0xEF].
    // The longest contiguous FIXED run is [0xDE, 0xAD, 0xBE, 0xEF] at index 2,
    // so the anchor search should find the full occurrence without iterating over the leading 0x00 noise.
    // Convention: pattern bytes at WILDCARD positions are 0
    // (bytearrayMatches ANDs memory with the wildcard mask, which is zero for WILDCARD slots).
    const pattern = [_]u8{ 0x00, 0x00, 0xde, 0xad, 0xbe, 0xef };
    const wildcards = [_]value_mod.Wildcard{ .FIXED, .WILDCARD, .FIXED, .FIXED, .FIXED, .FIXED };
    const user = UserValue{ .bytearray_value = &pattern, .wildcard_value = &wildcards };
    const prepared = PreparedScan{
        .match_type = .MATCHEQUALTO,
        .data_type = .BYTEARRAY,
    };

    // Lots of 0x00 noise so a single-byte anchor would iterate over every zero.
    // Only one full pattern occurrence (with 0x77 at the wildcard slot),
    // starting at offset 8. start = hit(10) - anchor_start(2) = 8.
    const chunk = [_]u8{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0x00, 0x77, 0xde, 0xad, 0xbe, 0xef, 0x00, 0x00, 0x00 };
    var required_extra: usize = 0;
    var num_matches: usize = 0;

    try scanChunkIntoMatches(&matches, prepared, null, &.{user}, 0xf000, &chunk, chunk.len, 1, &required_extra, &num_matches);
    try matches.finalize();

    try matches.validate();
    try std.testing.expectEqual(1, num_matches);
    try std.testing.expectEqual(1, matches.matchCount());
    try std.testing.expectEqual(0xf008, matches.nthMatch(0).?.address);
    var stored: [6]u8 = undefined;
    const m = matches.nthMatch(0).?;
    try std.testing.expectEqualSlices(u8, chunk[8..14], matches.dataToBytes(m.swath_offset, m.index, 6, &stored));
}

test "scanChunkIntoMatches: bytearray exact no-wildcard finds overlapping matches via multi-byte indexOfPos" {
    var matches = try MatchesArray.init(std.testing.allocator, 4096, 1);
    defer matches.deinit();

    // All-FIXED pattern -> anchor_len == pattern.len, so the search needle is the full pattern itself.
    // Overlapping occurrences must still be detected (search_pos = hit + 1, not hit + pattern.len).
    const pattern = [_]u8{ 0xab, 0xcd, 0xab };
    const wildcards = [_]value_mod.Wildcard{ .FIXED, .FIXED, .FIXED };
    const user = UserValue{ .bytearray_value = &pattern, .wildcard_value = &wildcards };
    const prepared = PreparedScan{
        .match_type = .MATCHEQUALTO,
        .data_type = .BYTEARRAY,
    };

    const chunk = [_]u8{ 0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd, 0xab };
    var required_extra: usize = 0;
    var num_matches: usize = 0;

    try scanChunkIntoMatches(&matches, prepared, null, &.{user}, 0xf100, &chunk, chunk.len, 1, &required_extra, &num_matches);
    try matches.finalize();

    try matches.validate();
    try std.testing.expectEqual(3, num_matches);
    try std.testing.expectEqual(0xf100, matches.nthMatch(0).?.address);
    try std.testing.expectEqual(0xf102, matches.nthMatch(1).?.address);
    try std.testing.expectEqual(0xf104, matches.nthMatch(2).?.address);
}

test "scanChunkIntoMatches: bytearray all-wildcard respects alignment" {
    var matches = try MatchesArray.init(std.testing.allocator, 4096, 1);
    defer matches.deinit();

    const pattern = [_]u8{ 0x00, 0x00 };
    const wildcards = [_]value_mod.Wildcard{ .WILDCARD, .WILDCARD };
    const user = UserValue{ .bytearray_value = &pattern, .wildcard_value = &wildcards };
    const prepared = PreparedScan{
        .match_type = .MATCHEQUALTO,
        .data_type = .BYTEARRAY,
    };

    const chunk = [_]u8{ 1, 2, 3, 4, 5, 6, 7 };
    var required_extra: usize = 0;
    var num_matches: usize = 0;

    try scanChunkIntoMatches(&matches, prepared, null, &.{user}, 0xc001, &chunk, chunk.len, 2, &required_extra, &num_matches);
    try matches.finalize();

    try matches.validate();
    try std.testing.expectEqual(3, num_matches);
    try std.testing.expectEqual(3, matches.matchCount());
    try std.testing.expectEqual(0xc002, matches.nthMatch(0).?.address);
    try std.testing.expectEqual(0xc006, matches.nthMatch(2).?.address);
}

test "scanChunkIntoMatches: bytearray exact carries chunk-boundary trailing bytes" {
    var matches = try MatchesArray.init(std.testing.allocator, 4096, 1);
    defer matches.deinit();

    const pattern = [_]u8{ 0xaa, 0xbb, 0xcc, 0xdd };
    const wildcards = [_]value_mod.Wildcard{ .FIXED, .FIXED, .FIXED, .FIXED };
    const user = UserValue{ .bytearray_value = &pattern, .wildcard_value = &wildcards };
    const prepared = PreparedScan{
        .match_type = .MATCHEQUALTO,
        .data_type = .BYTEARRAY,
    };

    const first_chunk = [_]u8{ 0x11, 0x22, 0xaa, 0xbb, 0xcc, 0xdd };
    const second_chunk = [_]u8{ 0xcc, 0xdd, 0x33 };
    var required_extra: usize = 0;
    var num_matches: usize = 0;

    try scanChunkIntoMatches(&matches, prepared, null, &.{user}, 0xd000, &first_chunk, 4, 1, &required_extra, &num_matches);
    try std.testing.expectEqual(2, required_extra);
    try scanChunkIntoMatches(&matches, prepared, null, &.{user}, 0xd004, &second_chunk, second_chunk.len, 1, &required_extra, &num_matches);
    try matches.finalize();

    try matches.validate();
    try std.testing.expectEqual(1, num_matches);
    try std.testing.expectEqual(1, matches.matchCount());
    try std.testing.expectEqual(0xd002, matches.nthMatch(0).?.address);
    try std.testing.expectEqual(0, required_extra);
    var stored: [4]u8 = undefined;
    const location = matches.nthMatch(0).?;
    try std.testing.expectEqualSlices(u8, &pattern, matches.dataToBytes(location.swath_offset, location.index, 4, &stored));
}

test "scanChunkIntoMatches: string MATCHANY tail records shrinking lengths per aligned candidate" {
    var matches = try MatchesArray.init(std.testing.allocator, 4096, 1);
    defer matches.deinit();

    // chunk.len < scan_limit + maxInt(u16) -> tail path.
    // With chunk.len == 6 each candidate stores "chunk.len - offset" bytes as its variable length.
    const chunk = [_]u8{ 'a', 'b', 'c', 'd', 'e', 'f' };
    const prepared = PreparedScan{
        .match_type = .MATCHANY,
        .data_type = .STRING,
    };
    var required_extra: usize = 0;
    var num_matches: usize = 0;

    try scanChunkIntoMatches(&matches, prepared, null, &.{}, 0xe000, &chunk, chunk.len, 1, &required_extra, &num_matches);
    try matches.finalize();

    try matches.validate();
    try std.testing.expectEqual(6, num_matches);
    try std.testing.expectEqual(6, matches.matchCount());
    try std.testing.expectEqual(6, matches.storedByteCount());
    try std.testing.expectEqual(0xe000, matches.nthMatch(0).?.address);
    try std.testing.expectEqual(6, matches.nthMatch(0).?.raw_match_info_bits);
    try std.testing.expectEqual(0xe005, matches.nthMatch(5).?.address);
    try std.testing.expectEqual(1, matches.nthMatch(5).?.raw_match_info_bits);
    try std.testing.expectEqual(0, required_extra);
}

test "scanChunkIntoMatches: bytearray MATCHANY tail honors alignment and records shrinking lengths" {
    var matches = try MatchesArray.init(std.testing.allocator, 4096, 1);
    defer matches.deinit();

    const chunk = [_]u8{ 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18 };
    const prepared = PreparedScan{
        .match_type = .MATCHANY,
        .data_type = .BYTEARRAY,
    };
    var required_extra: usize = 0;
    var num_matches: usize = 0;

    // base 0xe001 with alignment 4 -> first candidate at offset 3 (abs 0xe004), then 0xe008.
    // Each gets raw_bits == remaining chunk bytes after it.
    try scanChunkIntoMatches(&matches, prepared, null, &.{}, 0xe001, &chunk, chunk.len, 4, &required_extra, &num_matches);
    try matches.finalize();

    try matches.validate();
    try std.testing.expectEqual(2, num_matches);
    try std.testing.expectEqual(2, matches.matchCount());
    try std.testing.expectEqual(0xe004, matches.nthMatch(0).?.address);
    try std.testing.expectEqual(6, matches.nthMatch(0).?.raw_match_info_bits);
    try std.testing.expectEqual(0xe008, matches.nthMatch(1).?.address);
    try std.testing.expectEqual(2, matches.nthMatch(1).?.raw_match_info_bits);
    try std.testing.expectEqual(0, required_extra);
}

test "scanChunkIntoMatches: string MATCHANY common-chunk bulk records maxInt(u16) per candidate" {
    var matches = try MatchesArray.init(std.testing.allocator, 1 << 18, 1);
    defer matches.deinit();

    // chunk.len + 1 >= scan_limit + maxInt(u16) -> common path.
    // Smallest shape: scan_limit = 1, chunk.len = maxInt(u16).
    // Single candidate at offset 0 with raw_bits = maxInt(u16), required_extra carries the rest.
    const chunk_len: usize = std.math.maxInt(u16);
    const chunk = try std.testing.allocator.alloc(u8, chunk_len);
    defer std.testing.allocator.free(chunk);
    for (chunk, 0..) |*b, i| b.* = @truncate(i);

    const prepared = PreparedScan{
        .match_type = .MATCHANY,
        .data_type = .STRING,
    };
    var required_extra: usize = 0;
    var num_matches: usize = 0;

    try scanChunkIntoMatches(&matches, prepared, null, &.{}, 0xf0000000, chunk, 1, 1, &required_extra, &num_matches);
    try matches.finalize();

    try matches.validate();
    try std.testing.expectEqual(1, num_matches);
    try std.testing.expectEqual(1, matches.matchCount());
    try std.testing.expectEqual(0xf0000000, matches.nthMatch(0).?.address);
    try std.testing.expectEqual(std.math.maxInt(u16), matches.nthMatch(0).?.raw_match_info_bits);
    try std.testing.expectEqual(std.math.maxInt(u16) - 1, required_extra);
}

test "scanChunkIntoMatches: bytearray MATCHANY tail records consecutive chunks independently" {
    var matches = try MatchesArray.init(std.testing.allocator, 4096, 1);
    defer matches.deinit();

    const first_chunk = [_]u8{ 0xa0, 0xa1, 0xa2 };
    const second_chunk = [_]u8{ 0xa3, 0xa4 };
    const prepared = PreparedScan{
        .match_type = .MATCHANY,
        .data_type = .BYTEARRAY,
    };
    var required_extra: usize = 0;
    var num_matches: usize = 0;

    // Tail chunks only know bytes present in the current chunk,
    // so each candidate records the remaining bytes after its own start.
    // No carry is needed between these two tail calls.
    try scanChunkIntoMatches(&matches, prepared, null, &.{}, 0xe100, &first_chunk, first_chunk.len, 1, &required_extra, &num_matches);
    try std.testing.expectEqual(3, num_matches);
    try std.testing.expectEqual(0, required_extra); // pending_end clamped to scan_limit == chunk.len

    try scanChunkIntoMatches(&matches, prepared, null, &.{}, 0xe103, &second_chunk, second_chunk.len, 1, &required_extra, &num_matches);
    try matches.finalize();

    try matches.validate();
    try std.testing.expectEqual(5, num_matches);
    try std.testing.expectEqual(5, matches.matchCount());
    try std.testing.expectEqual(0xe100, matches.nthMatch(0).?.address);
    try std.testing.expectEqual(0xe104, matches.nthMatch(4).?.address);
    try std.testing.expectEqual(2, matches.nthMatch(3).?.raw_match_info_bits);
    try std.testing.expectEqual(1, matches.nthMatch(4).?.raw_match_info_bits);
}

test "serializeWriteValue: writes native-endian integer32 when not reversing" {
    const user = try UserValue.parseNumber("0x12345678");
    var scratch: [8]u8 = undefined;
    const bytes = try serializeWriteValue(.INTEGER32, false, user, null, &scratch);

    const expected_len: usize = 4;
    const expected_value: u32 = 0x12345678;
    try std.testing.expectEqual(expected_len, bytes.len);
    try std.testing.expectEqual(expected_value, std.mem.readInt(u32, bytes[0..4], .native));
}

test "serializeWriteValue: writes reverse-of-native float32 when reversing" {
    const user = try UserValue.parseFloat("1.5");
    var scratch: [8]u8 = undefined;
    const bytes = try serializeWriteValue(.FLOAT32, true, user, null, &scratch);

    // With reverse_endianness=true the bytes are the byte-swapped form of the float's bit pattern.
    // Reading them back as native must yield byteSwap(bits).
    const sample: f32 = 1.5;
    const sample_bits: u32 = @bitCast(sample);
    const expected_bits = @byteSwap(sample_bits);
    const expected_len: usize = 4;
    try std.testing.expectEqual(expected_len, bytes.len);
    try std.testing.expectEqual(expected_bits, std.mem.readInt(u32, bytes[0..4], .native));
}

test "serializeWriteValue: rejects ambiguous anynumber writes" {
    const user = try UserValue.parseNumber("7");
    var scratch: [8]u8 = undefined;

    try std.testing.expectError(ScannerError.UnsupportedWriteDataType, serializeWriteValue(.ANYNUMBER, false, user, null, &scratch));
}

test "serializeWriteValue: enforces variable-length match sizes" {
    const string_user = UserValue{ .string_value = "abc" };
    const bytearray_user = UserValue{
        .bytearray_value = &[_]u8{ 0xaa, 0xbb, 0xcc },
        .wildcard_value = &[_]value_mod.Wildcard{ .FIXED, .FIXED, .FIXED },
    };
    var scratch: [8]u8 = undefined;

    try std.testing.expectError(ScannerError.InvalidWriteLength, serializeWriteValue(.STRING, false, string_user, 4, &scratch));
    try std.testing.expectEqualSlices(u8, "abc", try serializeWriteValue(.STRING, false, string_user, 3, &scratch));

    try std.testing.expectError(ScannerError.InvalidWriteLength, serializeWriteValue(.BYTEARRAY, false, bytearray_user, 2, &scratch));
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0xaa, 0xbb, 0xcc }, try serializeWriteValue(.BYTEARRAY, false, bytearray_user, 3, &scratch));
}

test "matchReadFlags: supports anynumber matches from stored bits" {
    const flags = try matchReadFlags(.ANYNUMBER, MatchFlags.i32b.bits());

    try std.testing.expectEqual(MatchFlags.i32b.bits(), flags.bits());
    try std.testing.expectError(ScannerError.UnsupportedReadDataType, matchReadFlags(.ANYNUMBER, 0));
}

test "storedMatchBytes: rejects too-small buffer for variable-length matches" {
    var scanner = Scanner.init(std.testing.allocator, std.testing.io);
    defer scanner.deinit();
    scanner.options.scan_data_type = .BYTEARRAY;

    var matches = try MatchesArray.init(std.testing.allocator, 256, 1);
    try matches.appendRaw(0x6000, 0xaa, 3);
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

    var matches = try MatchesArray.init(std.testing.allocator, 256, 1);
    try matches.appendRaw(0x6000, 0xaa, 3);
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

    var matches = try MatchesArray.init(std.testing.allocator, 256, 1);
    try matches.appendRaw(0x7000, 'a', 3);
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

    var matches = try MatchesArray.init(std.testing.allocator, 256, 1);
    try matches.appendRaw(0x7000, 'a', 3);
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
