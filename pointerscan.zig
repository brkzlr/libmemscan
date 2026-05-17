//! Pointer scanning structures and logic.

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

const Allocator = std.mem.Allocator;

pub const PointerScanError = error{
    InvalidMapData,
    InvalidMapFormat,
    InvalidOptions,
    UnsupportedMapVersion,
    ModuleIndexOutOfRange,
    MapCreateFailed,
    MapReadFailed,
    MapWriteFailed,
    OutOfMemory,
};

pub const ModuleBase = struct {
    name: []const u8,
    base: usize,
    size: usize,
};

pub const PointerEntry = struct {
    address: usize, // Where was this pointer found?
    value: usize, // What is this pointer pointing to?
};

pub const PointerScanOptions = struct {
    const chunk_size = 1 << 20;

    /// Width of pointers read from target memory. 4 for 32-bit targets and 8 for 64-bit targets.
    pointer_width: u8 = @sizeOf(usize),
    /// Endianness used when decoding pointer values from target memory.
    endianness: std.builtin.Endian = .native,
    /// Maximum number of offsets in a result path.
    max_depth: u8 = 5,
    /// Maximum positive offset allowed at each pointer dereference.
    max_positive_offset: usize = 2048,
    /// Maximum negative offset allowed at each pointer dereference.
    max_negative_offset: usize = 0,
    /// Optional cap on result paths emitted by one scan.
    max_results: ?u64 = null,
    /// If true, only emit paths whose base address is inside a module.
    module_base_only: bool = true,

    pub fn validate(self: PointerScanOptions) PointerScanError!void {
        if (self.pointer_width != 4 and self.pointer_width != 8) return PointerScanError.InvalidOptions;
        if (self.max_depth == 0) return PointerScanError.InvalidOptions;
    }

    pub fn maxChunkReadSize(self: PointerScanOptions) PointerScanError!usize {
        try self.validate();
        // Read overlap bytes so pointers starting near the end of a chunk can still be decoded.
        return std.math.add(usize, chunk_size, self.pointer_width - 1) catch PointerScanError.InvalidOptions;
    }
};

pub const ValidPointerValueRanges = struct {
    const Range = struct {
        start: usize,
        end: usize,

        fn lessThan(_: void, lhs: Range, rhs: Range) bool {
            if (lhs.start == rhs.start) return lhs.end < rhs.end;
            return lhs.start < rhs.start;
        }
    };

    allocator: Allocator,
    ranges: []Range,

    pub fn init(allocator: Allocator, regions: []const process.Region) PointerScanError!ValidPointerValueRanges {
        var ranges = allocator.alloc(Range, regions.len) catch return PointerScanError.OutOfMemory;
        errdefer allocator.free(ranges);

        var range_count: usize = 0;
        for (regions) |region| {
            if (!region.flags.read) continue;
            if (region.size == 0) continue;
            const end = region.start +| region.size;

            ranges[range_count] = .{ .start = region.start, .end = end };
            range_count += 1;
        }

        const populated_ranges = ranges[0..range_count];
        std.mem.sortUnstable(Range, populated_ranges, {}, Range.lessThan);

        // Merge overlapping or touching ranges so each pointer value check can use one binary search.
        var merged_len: usize = 0;
        if (populated_ranges.len != 0) {
            merged_len = 1;
            for (populated_ranges[1..]) |range| {
                const current = &ranges[merged_len - 1];
                if (range.start <= current.end) {
                    current.end = @max(current.end, range.end);
                } else {
                    ranges[merged_len] = range;
                    merged_len += 1;
                }
            }
        }
        ranges = allocator.realloc(ranges, merged_len) catch return PointerScanError.OutOfMemory;

        return .{
            .allocator = allocator,
            .ranges = ranges,
        };
    }

    pub fn deinit(self: *ValidPointerValueRanges) void {
        self.allocator.free(self.ranges);
    }

    pub fn contains(self: *const ValidPointerValueRanges, value: usize) bool {
        var left: usize = 0;
        var right = self.ranges.len;

        while (left < right) {
            const mid = left + (right - left) / 2;
            if (self.ranges[mid].start <= value) {
                left = mid + 1;
            } else {
                right = mid;
            }
        }

        if (left == 0) return false;
        const range = self.ranges[left - 1];
        return value < range.end;
    }

    pub fn len(self: *const ValidPointerValueRanges) usize {
        return self.ranges.len;
    }
};

pub const PointerReverseIndex = struct {
    allocator: Allocator,
    entries: []PointerEntry,

    pub fn fromEntries(allocator: Allocator, entries: []const PointerEntry) PointerScanError!PointerReverseIndex {
        const owned_entries = allocator.alloc(PointerEntry, entries.len) catch return PointerScanError.OutOfMemory;
        errdefer allocator.free(owned_entries);

        @memcpy(owned_entries, entries);

        // Reverse scans need range lookups by pointed-to value, then stable address order inside each value.
        const EntryOrder = struct {
            fn lessThan(_: void, lhs: PointerEntry, rhs: PointerEntry) bool {
                if (lhs.value == rhs.value) return lhs.address < rhs.address;
                return lhs.value < rhs.value;
            }
        };
        std.mem.sortUnstable(PointerEntry, owned_entries, {}, EntryOrder.lessThan);

        return .{
            .allocator = allocator,
            .entries = owned_entries,
        };
    }

    pub fn deinit(self: *PointerReverseIndex) void {
        self.allocator.free(self.entries);
    }
};

pub const PointerBase = union(enum) {
    module: ModuleRef,
    absolute: usize,

    pub const ModuleRef = struct {
        module_index: u32,
        offset: i64,
    };
};

pub const PointerPath = struct {
    base: PointerBase,
    offsets: []const i64,

    pub fn formatText(self: PointerPath, modules: []const ModuleBase, writer: *std.Io.Writer) !void {
        switch (self.base) {
            .module => |base_ref| {
                if (base_ref.module_index >= modules.len) return error.ModuleIndexOutOfRange;
                try writer.print("{s}", .{modules[base_ref.module_index].name});
                try writeSignedHexOffset(writer, base_ref.offset, true);
            },
            .absolute => |address| try writer.print("0x{X}", .{address}),
        }

        for (self.offsets) |offset| {
            try writer.writeAll(" -> ");
            try writeSignedHexOffset(writer, offset, false);
        }
    }

    fn writeSignedHexOffset(writer: *std.Io.Writer, offset: i64, comptime include_plus_sign: bool) !void {
        if (offset < 0) {
            try writer.print("-0x{X}", .{@abs(offset)});
        } else if (include_plus_sign) {
            try writer.print("+0x{X}", .{offset});
        } else {
            try writer.print("0x{X}", .{offset});
        }
    }
};

pub const OwnedPointerPath = struct {
    path: PointerPath,
    allocator: Allocator,

    pub fn deinit(self: *OwnedPointerPath) void {
        self.allocator.free(self.path.offsets);
    }
};

pub fn appendEntriesFromChunk(
    allocator: Allocator,
    entries: *std.ArrayList(PointerEntry),
    chunk_address: usize,
    buffer: []const u8,
    options: PointerScanOptions,
    valid_pointer_values: *const ValidPointerValueRanges,
) PointerScanError!usize {
    try options.validate();
    const pointer_size: usize = options.pointer_width;

    if (buffer.len < pointer_size) return 0;
    const scan_advance = if (buffer.len > PointerScanOptions.chunk_size)
        PointerScanOptions.chunk_size
    else
        buffer.len - pointer_size + 1;

    const alignment = chunk_address % pointer_size;
    var local_offset = if (alignment == 0) 0 else pointer_size - alignment;
    while (local_offset < scan_advance) : (local_offset += pointer_size) {
        if (buffer.len - local_offset < pointer_size) break;

        const value: usize = switch (pointer_size) {
            4 => std.mem.readInt(u32, buffer[local_offset..][0..4], options.endianness),
            8 => std.math.cast(usize, std.mem.readInt(u64, buffer[local_offset..][0..8], options.endianness)) orelse continue,
            else => unreachable,
        };
        if (!valid_pointer_values.contains(value)) continue;

        entries.append(allocator, .{
            .address = std.math.add(usize, chunk_address, local_offset) catch return PointerScanError.InvalidOptions,
            .value = value,
        }) catch return PointerScanError.OutOfMemory;
    }

    return scan_advance;
}

/// Returns module bases whose names borrow from `regions`.
/// Caller owns the returned slice.
pub fn moduleBasesFromRegions(allocator: Allocator, regions: []const process.Region) PointerScanError![]ModuleBase {
    const ModuleIdentity = struct {
        filename: []const u8,
        load_addr: usize,
    };

    var modules: std.ArrayList(ModuleBase) = .empty;
    errdefer modules.deinit(allocator);

    var identities: std.ArrayList(ModuleIdentity) = .empty;
    defer identities.deinit(allocator);

    for (regions) |region| {
        if (!region.flags.read or region.filename.len == 0) continue;
        if (region.kind != .EXE and region.kind != .CODE) continue;

        const region_end = region.start +| region.size;
        if (region_end <= region.load_addr) continue;

        for (identities.items) |identity| {
            if (identity.load_addr == region.load_addr and std.mem.eql(u8, identity.filename, region.filename)) {
                break;
            }
        } else {
            identities.append(allocator, .{
                .filename = region.filename,
                .load_addr = region.load_addr,
            }) catch return PointerScanError.OutOfMemory;
            modules.append(allocator, .{
                .name = std.Io.Dir.path.basename(region.filename),
                .base = region.load_addr,
                .size = 0,
            }) catch return PointerScanError.OutOfMemory;
        }
    }

    for (regions) |region| {
        if (!region.flags.read or region.filename.len == 0) continue;

        const region_end = region.start +| region.size;
        if (region_end <= region.load_addr) continue;

        var module_index: ?usize = null;
        for (identities.items, 0..) |identity, index| {
            if (identity.load_addr == region.load_addr and std.mem.eql(u8, identity.filename, region.filename)) {
                module_index = index;
                break;
            }
        }

        if (module_index) |index| {
            const module = &modules.items[index];
            const module_size = region_end - module.base;
            if (module_size > module.size) module.size = module_size;
        }
    }

    return modules.toOwnedSlice(allocator) catch return PointerScanError.OutOfMemory;
}

const PointerBaseKind = enum(u8) {
    module = 0,
    absolute = 1,
};

// Maybe change this struct to only contain header values for easier writing/reading to the map file
// and move the helper values elsewhere.
const PointerMapHeader = struct {
    const size = 24;

    // Fixed map file header fields.
    const magic = "LBMEMPTR";
    const version: u16 = 1;
    const version_field_offset = 8;
    const pointer_width_field_offset = 10;
    const module_count_field_offset = 12;
    const path_count_field_offset = 16;

    // Encoding and validation values.
    const endianness = .little;
    const max_modules = std.math.maxInt(u16) + 1;
    const max_module_name_len = std.Io.Dir.max_name_bytes;
    const max_offsets_per_path = std.math.maxInt(u8); // max u8 because PointerScanOptions.max_depth is an u8
};

pub const PointerMapWriter = struct {
    io: std.Io,
    file: std.Io.File,
    next_offset: u64,
    module_count: u32,
    path_count: u64 = 0,
    finished: bool = false,
    failed: bool = false,

    /// Takes ownership of `file` as `deinit` will close it.
    pub fn init(io: std.Io, file: std.Io.File, pointer_width: u8, modules: []const ModuleBase) PointerScanError!PointerMapWriter {
        errdefer file.close(io);

        if (pointer_width != 4 and pointer_width != 8) return PointerScanError.InvalidMapData;
        if (modules.len > PointerMapHeader.max_modules) return PointerScanError.InvalidMapData;
        for (modules) |module| {
            if (module.name.len > PointerMapHeader.max_module_name_len) return PointerScanError.InvalidMapData;
        }

        const module_count: u32 = @intCast(modules.len);
        var writer = PointerMapWriter{
            .io = io,
            .file = file,
            .next_offset = 0,
            .module_count = module_count,
        };

        // Write the fixed header first. Final path count is patched in finish().
        var header: [PointerMapHeader.size]u8 = @splat(0);
        @memcpy(header[0..PointerMapHeader.magic.len], PointerMapHeader.magic);
        std.mem.writeInt(u16, header[PointerMapHeader.version_field_offset..][0..2], PointerMapHeader.version, PointerMapHeader.endianness);
        header[PointerMapHeader.pointer_width_field_offset] = pointer_width;
        std.mem.writeInt(u32, header[PointerMapHeader.module_count_field_offset..][0..4], module_count, PointerMapHeader.endianness);
        try writer.appendBytes(&header);

        // Write the modules section:
        // - base address (u64)
        // - size (u64)
        // - name length (u32)
        // - name (variable)
        // repeated for each module, module_count being written in the header above.
        for (modules) |module| {
            const module_entry_fixed_size = @sizeOf(u64) + @sizeOf(u64) + @sizeOf(u32);
            var module_entry: [module_entry_fixed_size + PointerMapHeader.max_module_name_len]u8 = undefined;
            std.mem.writeInt(u64, module_entry[0..8], module.base, PointerMapHeader.endianness);
            std.mem.writeInt(u64, module_entry[8..16], module.size, PointerMapHeader.endianness);
            std.mem.writeInt(u32, module_entry[16..20], @intCast(module.name.len), PointerMapHeader.endianness);
            @memcpy(module_entry[module_entry_fixed_size..][0..module.name.len], module.name);
            try writer.appendBytes(module_entry[0 .. module_entry_fixed_size + module.name.len]);
        }

        return writer;
    }

    pub fn deinit(self: *PointerMapWriter) void {
        if (!self.finished and !self.failed) {
            self.finish() catch {};
        }
        self.file.close(self.io);
    }

    pub fn append(self: *PointerMapWriter, path: PointerPath) PointerScanError!void {
        if (self.failed) return PointerScanError.MapWriteFailed;
        if (self.finished) return PointerScanError.InvalidMapData;
        if (path.offsets.len > PointerMapHeader.max_offsets_per_path) return PointerScanError.InvalidMapData;
        if (self.path_count == std.math.maxInt(u64)) return PointerScanError.InvalidMapData;

        // Path record layout:
        // - base kind (u8)
        // - reserved ([3]u8)
        // - module index (u32)
        // - payload containing module offset or absolute base address (u64)
        // - offset count (u32)
        // - offsets[offset count] (i64 each)
        const path_record_fixed_size = 4 + @sizeOf(u32) + @sizeOf(u64) + @sizeOf(u32);
        const record_size = path_record_fixed_size + path.offsets.len * @sizeOf(i64);

        const encoded_base: struct {
            kind: PointerBaseKind,
            module_index: u32,
            payload: u64,
        } = switch (path.base) {
            .module => |base_ref| blk: {
                if (base_ref.module_index >= self.module_count) return PointerScanError.InvalidMapData;
                break :blk .{
                    .kind = .module,
                    .module_index = base_ref.module_index,
                    .payload = @bitCast(base_ref.offset),
                };
            },
            .absolute => |address| .{
                .kind = .absolute,
                .module_index = 0,
                .payload = address,
            },
        };

        var record: [path_record_fixed_size + PointerMapHeader.max_offsets_per_path * @sizeOf(i64)]u8 = undefined;
        record[0] = @intFromEnum(encoded_base.kind);
        @memset(record[1..4], 0);
        std.mem.writeInt(u32, record[4..8], encoded_base.module_index, PointerMapHeader.endianness);
        std.mem.writeInt(u64, record[8..16], encoded_base.payload, PointerMapHeader.endianness);
        std.mem.writeInt(u32, record[16..20], @intCast(path.offsets.len), PointerMapHeader.endianness);

        var offset_start: usize = path_record_fixed_size;
        for (path.offsets) |offset| {
            std.mem.writeInt(i64, record[offset_start..][0..8], offset, PointerMapHeader.endianness);
            offset_start += @sizeOf(i64);
        }
        try self.appendBytes(record[0..record_size]);

        self.path_count += 1;
    }

    pub fn finish(self: *PointerMapWriter) PointerScanError!void {
        if (self.failed) return PointerScanError.MapWriteFailed;
        if (self.finished) return;

        var buf: [8]u8 = undefined;
        std.mem.writeInt(u64, &buf, self.path_count, PointerMapHeader.endianness);
        try self.writeBytesAt(PointerMapHeader.path_count_field_offset, &buf);
        self.finished = true;
    }

    fn appendBytes(self: *PointerMapWriter, bytes: []const u8) PointerScanError!void {
        const next_offset = std.math.add(u64, self.next_offset, bytes.len) catch return PointerScanError.InvalidMapData;
        try self.writeBytesAt(self.next_offset, bytes);
        self.next_offset = next_offset;
    }

    fn writeBytesAt(self: *PointerMapWriter, at: u64, bytes: []const u8) PointerScanError!void {
        self.file.writePositionalAll(self.io, bytes, at) catch {
            self.failed = true;
            return PointerScanError.MapWriteFailed;
        };
    }
};

pub const PointerMapReader = struct {
    allocator: Allocator,
    io: std.Io,
    file: std.Io.File,
    pointer_width: u8,
    path_count: u64,
    paths_start: u64,
    next_offset: u64,
    remaining_paths: u64,
    modules: []ModuleBase,

    /// Takes ownership of `file` as `deinit` will close it.
    pub fn init(allocator: Allocator, io: std.Io, file: std.Io.File) PointerScanError!PointerMapReader {
        var reader = PointerMapReader{
            .allocator = allocator,
            .io = io,
            .file = file,
            .pointer_width = 0,
            .path_count = 0,
            .paths_start = 0,
            .next_offset = 0,
            .remaining_paths = 0,
            .modules = &.{},
        };
        errdefer reader.deinit();

        var header: [PointerMapHeader.size]u8 = undefined;
        try reader.consumeBytes(&header);
        if (!std.mem.eql(u8, header[0..PointerMapHeader.magic.len], PointerMapHeader.magic)) return PointerScanError.InvalidMapFormat;

        const file_version = std.mem.readInt(u16, header[PointerMapHeader.version_field_offset..][0..2], PointerMapHeader.endianness);
        if (file_version != PointerMapHeader.version) return PointerScanError.UnsupportedMapVersion;

        reader.pointer_width = header[PointerMapHeader.pointer_width_field_offset];
        if (reader.pointer_width != 4 and reader.pointer_width != 8) return PointerScanError.InvalidMapFormat;

        const module_count = std.mem.readInt(u32, header[PointerMapHeader.module_count_field_offset..][0..4], PointerMapHeader.endianness);
        if (module_count > PointerMapHeader.max_modules) return PointerScanError.InvalidMapFormat;
        reader.path_count = std.mem.readInt(u64, header[PointerMapHeader.path_count_field_offset..][0..8], PointerMapHeader.endianness);

        reader.modules = allocator.alloc(ModuleBase, module_count) catch return PointerScanError.OutOfMemory;
        @memset(reader.modules, .{ .name = &.{}, .base = 0, .size = 0 });

        for (reader.modules) |*module| {
            const module_entry_fixed_size = @sizeOf(u64) + @sizeOf(u64) + @sizeOf(u32);
            var module_entry: [module_entry_fixed_size]u8 = undefined;
            try reader.consumeBytes(&module_entry);

            module.base = std.math.cast(usize, std.mem.readInt(u64, module_entry[0..8], PointerMapHeader.endianness)) orelse return PointerScanError.InvalidMapFormat;
            module.size = std.math.cast(usize, std.mem.readInt(u64, module_entry[8..16], PointerMapHeader.endianness)) orelse return PointerScanError.InvalidMapFormat;
            const name_len: usize = std.mem.readInt(u32, module_entry[16..20], PointerMapHeader.endianness);
            if (name_len > PointerMapHeader.max_module_name_len) return PointerScanError.InvalidMapFormat;
            module.name = blk: {
                const name = allocator.alloc(u8, name_len) catch return PointerScanError.OutOfMemory;
                errdefer allocator.free(name);
                try reader.consumeBytes(name);
                break :blk name;
            };
        }

        reader.paths_start = reader.next_offset;
        reader.remaining_paths = reader.path_count;
        return reader;
    }

    pub fn deinit(self: *PointerMapReader) void {
        for (self.modules) |module| {
            self.allocator.free(module.name);
        }
        self.allocator.free(self.modules);
        self.file.close(self.io);
    }

    pub fn reset(self: *PointerMapReader) void {
        self.next_offset = self.paths_start;
        self.remaining_paths = self.path_count;
    }

    pub fn next(self: *PointerMapReader) PointerScanError!?OwnedPointerPath {
        if (self.remaining_paths == 0) return null;

        const path_record_fixed_size = 4 + @sizeOf(u32) + @sizeOf(u64) + @sizeOf(u32);
        var record: [path_record_fixed_size]u8 = undefined;
        try self.consumeBytes(&record);

        const kind_raw = record[0];
        if (!std.mem.allEqual(u8, record[1..4], 0)) return PointerScanError.InvalidMapFormat;
        const module_index = std.mem.readInt(u32, record[4..8], PointerMapHeader.endianness);
        const base_payload = std.mem.readInt(u64, record[8..16], PointerMapHeader.endianness);
        const base: PointerBase = switch (kind_raw) {
            @intFromEnum(PointerBaseKind.module) => blk: {
                if (module_index >= self.modules.len) return PointerScanError.InvalidMapFormat;
                break :blk .{ .module = .{
                    .module_index = module_index,
                    .offset = @bitCast(base_payload),
                } };
            },
            @intFromEnum(PointerBaseKind.absolute) => blk: {
                if (module_index != 0) return PointerScanError.InvalidMapFormat;
                break :blk .{ .absolute = std.math.cast(usize, base_payload) orelse return PointerScanError.InvalidMapFormat };
            },
            else => return PointerScanError.InvalidMapFormat,
        };

        const offset_count: usize = std.mem.readInt(u32, record[16..20], PointerMapHeader.endianness);
        if (offset_count > PointerMapHeader.max_offsets_per_path) return PointerScanError.InvalidMapFormat;
        const offsets = self.allocator.alloc(i64, offset_count) catch return PointerScanError.OutOfMemory;
        errdefer self.allocator.free(offsets);

        var offset_bytes: [PointerMapHeader.max_offsets_per_path * @sizeOf(i64)]u8 = undefined;
        const offset_bytes_len = offset_count * @sizeOf(i64);
        try self.consumeBytes(offset_bytes[0..offset_bytes_len]);
        for (offsets, 0..) |*offset_value, offset_index| {
            const offset_start = offset_index * @sizeOf(i64);
            offset_value.* = std.mem.readInt(i64, offset_bytes[offset_start..][0..8], PointerMapHeader.endianness);
        }

        self.remaining_paths -= 1;
        return .{
            .path = .{
                .base = base,
                .offsets = offsets,
            },
            .allocator = self.allocator,
        };
    }

    pub fn dumpText(self: *PointerMapReader, writer: *std.Io.Writer) !void {
        while (try self.next()) |owned_path_value| {
            var owned_path = owned_path_value;
            defer owned_path.deinit();

            try owned_path.path.formatText(self.modules, writer);
            try writer.writeByte('\n');
        }
    }

    fn consumeBytes(self: *PointerMapReader, bytes: []u8) PointerScanError!void {
        const next_offset = std.math.add(u64, self.next_offset, bytes.len) catch return PointerScanError.InvalidMapFormat;
        const nread = self.file.readPositionalAll(self.io, bytes, self.next_offset) catch return PointerScanError.MapReadFailed;
        if (nread != bytes.len) return PointerScanError.InvalidMapFormat;
        self.next_offset = next_offset;
    }
};

pub fn findPointerPaths(
    allocator: Allocator,
    reverse_index: *const PointerReverseIndex,
    modules: []const ModuleBase,
    options: PointerScanOptions,
    target_address: usize,
    map_writer: *PointerMapWriter,
) PointerScanError!u64 {
    var finder = try PointerPathFinder.init(allocator, reverse_index, modules, options);
    defer finder.deinit();

    try finder.findPathsToValue(target_address, map_writer);
    return finder.results_found;
}

const PointerPathFinder = struct {
    allocator: Allocator,
    reverse_index: *const PointerReverseIndex,
    modules: []const ModuleBase,
    options: PointerScanOptions,
    offset_stack: std.ArrayList(i64) = .empty,
    address_stack: std.ArrayList(usize) = .empty,
    path_offsets: []i64 = &.{},
    results_found: u64 = 0,

    fn init(allocator: Allocator, reverse_index: *const PointerReverseIndex, modules: []const ModuleBase, options: PointerScanOptions) PointerScanError!PointerPathFinder {
        try options.validate();

        var finder = PointerPathFinder{
            .allocator = allocator,
            .reverse_index = reverse_index,
            .modules = modules,
            .options = options,
        };
        errdefer finder.deinit();

        try finder.offset_stack.ensureTotalCapacityPrecise(allocator, options.max_depth);
        try finder.address_stack.ensureTotalCapacityPrecise(allocator, options.max_depth);
        finder.path_offsets = allocator.alloc(i64, options.max_depth) catch return PointerScanError.OutOfMemory;

        return finder;
    }

    fn deinit(self: *PointerPathFinder) void {
        self.offset_stack.deinit(self.allocator);
        self.address_stack.deinit(self.allocator);
        self.allocator.free(self.path_offsets);
    }

    fn findPathsToValue(self: *PointerPathFinder, target_address: usize, map_writer: *PointerMapWriter) PointerScanError!void {
        if (self.reachedResultLimit()) return;

        const lowest_candidate_value = target_address -| self.options.max_positive_offset;
        const highest_candidate_value = target_address +| self.options.max_negative_offset;

        // Lower-bound the first observed value so we don't search the entire array.
        var entry_index: usize = 0;
        var end = self.reverse_index.entries.len;
        while (entry_index < end) {
            const mid = entry_index + (end - entry_index) / 2;
            if (self.reverse_index.entries[mid].value < lowest_candidate_value) {
                entry_index = mid + 1;
            } else {
                end = mid;
            }
        }

        while (entry_index < self.reverse_index.entries.len) : (entry_index += 1) {
            const candidate = self.reverse_index.entries[entry_index];
            if (candidate.value > highest_candidate_value) break;

            const offset: i64 = if (target_address >= candidate.value) blk: {
                const difference = target_address - candidate.value;
                if (difference > std.math.maxInt(i64)) continue;
                break :blk @intCast(difference);
            } else blk: {
                const difference = candidate.value - target_address;
                if (difference - 1 > std.math.maxInt(i64)) continue;
                const magnitude: i64 = @intCast(difference - 1);
                break :blk -magnitude - 1;
            };

            // Skip existing addresses to avoid cyclic loops.
            if (std.mem.indexOfScalar(usize, self.address_stack.items, candidate.address) != null) continue;

            try self.offset_stack.appendBounded(offset);
            defer _ = self.offset_stack.pop();

            try self.address_stack.appendBounded(candidate.address);
            defer _ = self.address_stack.pop();

            const path_base: ?PointerBase = blk: {
                for (self.modules, 0..) |module, module_index| {
                    if (candidate.address < module.base) continue;

                    const module_offset = candidate.address - module.base;
                    if (module_offset >= module.size) continue;
                    if (module_offset > std.math.maxInt(i64)) continue;
                    if (module_index > std.math.maxInt(u32)) continue;

                    break :blk .{ .module = .{
                        .module_index = @intCast(module_index),
                        .offset = @intCast(module_offset),
                    } };
                }

                if (!self.options.module_base_only) break :blk .{ .absolute = candidate.address };
                break :blk null;
            };

            if (path_base) |resolved_base| {
                const offset_count = self.offset_stack.items.len;
                for (0..offset_count) |offset_index| {
                    self.path_offsets[offset_index] = self.offset_stack.items[offset_count - offset_index - 1];
                }

                try map_writer.append(.{
                    .base = resolved_base,
                    .offsets = self.path_offsets[0..offset_count],
                });
                self.results_found += 1;

                if (self.reachedResultLimit()) return;
            }

            if (self.offset_stack.items.len < self.options.max_depth) {
                try self.findPathsToValue(candidate.address, map_writer);
                if (self.reachedResultLimit()) return;
            }
        }
    }

    fn reachedResultLimit(self: *const PointerPathFinder) bool {
        if (self.options.max_results) |max_results| {
            return self.results_found >= max_results;
        }
        return false;
    }
};

/// Writes paths from "current_file" that also appear in "previous_file".
/// Takes ownership of all three files.
pub fn comparePointerMaps(
    allocator: Allocator,
    io: std.Io,
    previous_file: std.Io.File,
    current_file: std.Io.File,
    output_file: std.Io.File,
) PointerScanError!u64 {
    var current_file_owned = true;
    var output_file_owned = true;
    errdefer {
        if (current_file_owned) current_file.close(io);
        if (output_file_owned) output_file.close(io);
    }

    var previous_reader = try PointerMapReader.init(allocator, io, previous_file);
    defer previous_reader.deinit();

    current_file_owned = false;
    var current_reader = try PointerMapReader.init(allocator, io, current_file);
    defer current_reader.deinit();

    if (previous_reader.pointer_width != current_reader.pointer_width) return PointerScanError.InvalidMapData;

    var previous_paths = std.StringHashMap(void).init(allocator);
    defer {
        var key_iter = previous_paths.keyIterator();
        while (key_iter.next()) |key| {
            allocator.free(key.*);
        }
        previous_paths.deinit();
    }

    while (try previous_reader.next()) |owned_path_value| {
        var owned_path = owned_path_value;
        defer owned_path.deinit();

        const key = try pointerPathTextAlloc(allocator, owned_path.path, previous_reader.modules);
        const entry = previous_paths.getOrPut(key) catch {
            allocator.free(key);
            return PointerScanError.OutOfMemory;
        };
        if (entry.found_existing) {
            allocator.free(key);
        }
    }

    output_file_owned = false;
    var writer = try PointerMapWriter.init(io, output_file, current_reader.pointer_width, current_reader.modules);
    defer writer.deinit();

    while (try current_reader.next()) |owned_path_value| {
        var owned_path = owned_path_value;
        defer owned_path.deinit();

        const key = try pointerPathTextAlloc(allocator, owned_path.path, current_reader.modules);
        defer allocator.free(key);

        if (previous_paths.fetchRemove(key)) |entry| {
            allocator.free(entry.key);
            try writer.append(owned_path.path);
        }
    }

    try writer.finish();
    return writer.path_count;
}

fn pointerPathTextAlloc(allocator: Allocator, path: PointerPath, modules: []const ModuleBase) PointerScanError![]u8 {
    var out = std.Io.Writer.Allocating.init(allocator);
    defer out.deinit();

    path.formatText(modules, &out.writer) catch |err| switch (err) {
        error.WriteFailed => return PointerScanError.OutOfMemory,
        error.ModuleIndexOutOfRange => return PointerScanError.InvalidMapFormat,
    };
    return out.toOwnedSlice() catch return PointerScanError.OutOfMemory;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const test_readable_flags = process.RegionFlags{ .read = true, .write = false, .exec = false, .shared = false, .private = true };
const test_unreadable_flags = process.RegionFlags{ .read = false, .write = false, .exec = false, .shared = false, .private = true };
const test_module_record_header_size = @sizeOf(u64) + @sizeOf(u64) + @sizeOf(u32);
const test_path_record_header_size = 4 + @sizeOf(u32) + @sizeOf(u64) + @sizeOf(u32);

fn writeTestMapHeader(io: std.Io, file: std.Io.File, pointer_width: u8, module_count: u32, path_count: u64) !void {
    var header: [PointerMapHeader.size]u8 = @splat(0);
    @memcpy(header[0..PointerMapHeader.magic.len], PointerMapHeader.magic);
    std.mem.writeInt(u16, header[PointerMapHeader.version_field_offset..][0..2], PointerMapHeader.version, PointerMapHeader.endianness);
    header[PointerMapHeader.pointer_width_field_offset] = pointer_width;
    std.mem.writeInt(u32, header[PointerMapHeader.module_count_field_offset..][0..4], module_count, PointerMapHeader.endianness);
    std.mem.writeInt(u64, header[PointerMapHeader.path_count_field_offset..][0..8], path_count, PointerMapHeader.endianness);
    try file.writePositionalAll(io, &header, 0);
}

fn expectMapText(io: std.Io, dir: std.Io.Dir, file_name: []const u8, expected: []const u8) !void {
    const read_file = try dir.openFile(io, file_name, .{});
    var reader = try PointerMapReader.init(std.testing.allocator, io, read_file);
    defer reader.deinit();

    var out = std.Io.Writer.Allocating.init(std.testing.allocator);
    defer out.deinit();

    try reader.dumpText(&out.writer);
    try std.testing.expectEqualStrings(expected, out.written());
}

fn expectReaderInitError(expected_error: PointerScanError, io: std.Io, dir: std.Io.Dir, file_name: []const u8) !void {
    const read_file = try dir.openFile(io, file_name, .{});
    try std.testing.expectError(expected_error, PointerMapReader.init(std.testing.allocator, io, read_file));
}

fn expectInvalidPathRecord(io: std.Io, dir: std.Io.Dir, file_name: []const u8) !void {
    const read_file = try dir.openFile(io, file_name, .{});
    var reader = try PointerMapReader.init(std.testing.allocator, io, read_file);
    defer reader.deinit();

    try std.testing.expectError(PointerScanError.InvalidMapFormat, reader.next());
}

test "PointerPath.formatText: uses 0x-prefixed hex offsets" {
    const modules = [_]ModuleBase{
        .{ .name = "game.exe", .base = 0x100000, .size = 0x20000 },
    };
    const path = PointerPath{
        .base = .{ .module = .{ .module_index = 0, .offset = 0x1A2B30 } },
        .offsets = &.{ 0x18, 0x20, 0x8 },
    };

    var out = std.Io.Writer.Allocating.init(std.testing.allocator);
    defer out.deinit();

    try path.formatText(&modules, &out.writer);
    try std.testing.expectEqualStrings("game.exe+0x1A2B30 -> 0x18 -> 0x20 -> 0x8", out.written());
}

test "PointerPath.formatText: supports absolute bases and negative offsets" {
    const path = PointerPath{
        .base = .{ .absolute = 0x7FFDF0012000 },
        .offsets = &.{ 0x28, -0x10 },
    };

    var out = std.Io.Writer.Allocating.init(std.testing.allocator);
    defer out.deinit();

    try path.formatText(&.{}, &out.writer);
    try std.testing.expectEqualStrings("0x7FFDF0012000 -> 0x28 -> -0x10", out.written());
}

test "PointerPath.formatText: rejects out-of-range module references" {
    const modules = [_]ModuleBase{
        .{ .name = "game.exe", .base = 0x100000, .size = 0x20000 },
    };
    const path = PointerPath{
        .base = .{ .module = .{ .module_index = 1, .offset = 0 } },
        .offsets = &.{},
    };

    var out = std.Io.Writer.Allocating.init(std.testing.allocator);
    defer out.deinit();

    try std.testing.expectError(PointerScanError.ModuleIndexOutOfRange, path.formatText(&modules, &out.writer));
    try std.testing.expectEqualStrings("", out.written());
}

test "PointerScanOptions: validates public scan limits and chunk read size" {
    try (PointerScanOptions{}).validate();
    try std.testing.expectError(PointerScanError.InvalidOptions, (PointerScanOptions{ .pointer_width = 3 }).validate());
    try std.testing.expectError(PointerScanError.InvalidOptions, (PointerScanOptions{ .max_depth = 0 }).validate());
    try std.testing.expectEqual(PointerScanOptions.chunk_size + 3, try (PointerScanOptions{ .pointer_width = 4 }).maxChunkReadSize());
    try std.testing.expectEqual(PointerScanOptions.chunk_size + 7, try (PointerScanOptions{ .pointer_width = 8 }).maxChunkReadSize());
}

test "PointerReverseIndex: sorts entries by pointed value then address" {
    const entries = [_]PointerEntry{
        .{ .address = 0x3000, .value = 0x2000 },
        .{ .address = 0x2000, .value = 0x1000 },
        .{ .address = 0x1000, .value = 0x1000 },
    };

    var index = try PointerReverseIndex.fromEntries(std.testing.allocator, &entries);
    defer index.deinit();

    const expected = [_]PointerEntry{
        .{ .address = 0x1000, .value = 0x1000 },
        .{ .address = 0x2000, .value = 0x1000 },
        .{ .address = 0x3000, .value = 0x2000 },
    };
    try std.testing.expectEqualSlices(PointerEntry, &expected, index.entries);
}

test "findPointerPaths: finds static paths from synthetic entries" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const io = std.testing.io;
    const modules = [_]ModuleBase{
        .{ .name = "game.exe", .base = 0x2000, .size = 0x100 },
    };
    const entries = [_]PointerEntry{
        .{ .address = 0x1000, .value = 0x5000 },
        .{ .address = 0x2000, .value = 0x1000 },
    };

    var index = try PointerReverseIndex.fromEntries(std.testing.allocator, &entries);
    defer index.deinit();

    {
        const file = try tmp.dir.createFile(io, "scan.lmptr", .{ .read = true, .truncate = true });
        var writer = try PointerMapWriter.init(io, file, 8, &modules);
        defer writer.deinit();

        const found = try findPointerPaths(std.testing.allocator, &index, &modules, .{
            .max_depth = 3,
            .max_positive_offset = 0x100,
        }, 0x5020, &writer);
        try std.testing.expectEqual(1, found);
        try writer.finish();
    }

    try expectMapText(io, tmp.dir, "scan.lmptr", "game.exe+0x0 -> 0x0 -> 0x20\n");
}

test "findPointerPaths: emits absolute bases when module bases are optional" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const io = std.testing.io;
    const entries = [_]PointerEntry{
        .{ .address = 0x3000, .value = 0x6000 },
    };

    var index = try PointerReverseIndex.fromEntries(std.testing.allocator, &entries);
    defer index.deinit();

    {
        const file = try tmp.dir.createFile(io, "module-only.lmptr", .{ .read = true, .truncate = true });
        var writer = try PointerMapWriter.init(io, file, 8, &.{});
        defer writer.deinit();

        const found = try findPointerPaths(std.testing.allocator, &index, &.{}, .{
            .max_depth = 1,
            .max_positive_offset = 0x40,
        }, 0x6020, &writer);
        try std.testing.expectEqual(0, found);
        try writer.finish();
    }

    {
        const file = try tmp.dir.createFile(io, "absolute.lmptr", .{ .read = true, .truncate = true });
        var writer = try PointerMapWriter.init(io, file, 8, &.{});
        defer writer.deinit();

        const found = try findPointerPaths(std.testing.allocator, &index, &.{}, .{
            .max_depth = 1,
            .max_positive_offset = 0x40,
            .module_base_only = false,
        }, 0x6020, &writer);
        try std.testing.expectEqual(1, found);
        try writer.finish();
    }

    try expectMapText(io, tmp.dir, "absolute.lmptr", "0x3000 -> 0x20\n");
}

test "findPointerPaths: avoids cyclic paths" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const io = std.testing.io;
    const modules = [_]ModuleBase{
        .{ .name = "game.exe", .base = 0x1000, .size = 0x2000 },
    };
    const entries = [_]PointerEntry{
        .{ .address = 0x1000, .value = 0x2000 },
        .{ .address = 0x2000, .value = 0x1000 },
    };

    var index = try PointerReverseIndex.fromEntries(std.testing.allocator, &entries);
    defer index.deinit();

    {
        const file = try tmp.dir.createFile(io, "cycles.lmptr", .{ .read = true, .truncate = true });
        var writer = try PointerMapWriter.init(io, file, 8, &modules);
        defer writer.deinit();

        const found = try findPointerPaths(std.testing.allocator, &index, &modules, .{
            .max_depth = 4,
            .max_positive_offset = 0,
        }, 0x2000, &writer);
        try std.testing.expectEqual(2, found);
        try writer.finish();
    }

    try expectMapText(
        io,
        tmp.dir,
        "cycles.lmptr",
        "game.exe+0x0 -> 0x0\n" ++
            "game.exe+0x1000 -> 0x0 -> 0x0\n",
    );
}

test "moduleBasesFromRegions: groups readable module regions by image load" {
    const regions = [_]process.Region{
        .{ .start = 0x2800, .size = 0x100, .kind = .MISC, .flags = test_readable_flags, .load_addr = 0x1000, .id = 0, .filename = "/bin/game" },
        .{ .start = 0x1000, .size = 0x100, .kind = .EXE, .flags = test_readable_flags, .load_addr = 0x1000, .id = 1, .filename = "/bin/game" },
        .{ .start = 0x2000, .size = 0x80, .kind = .CODE, .flags = test_readable_flags, .load_addr = 0x1000, .id = 2, .filename = "/bin/game" },
        .{ .start = 0x3100, .size = 0x100, .kind = .MISC, .flags = test_readable_flags, .load_addr = 0x3000, .id = 3, .filename = "/bin/game" },
        .{ .start = 0x5100, .size = 0x100, .kind = .CODE, .flags = test_readable_flags, .load_addr = 0x5000, .id = 4, .filename = "/lib/foo" },
        .{ .start = 0x6100, .size = 0x100, .kind = .MISC, .flags = test_readable_flags, .load_addr = 0x6000, .id = 5, .filename = "/dev/zero (deleted)" },
        .{ .start = 0x7000, .size = 0x100, .kind = .HEAP, .flags = test_readable_flags, .load_addr = 0x7000, .id = 6, .filename = "[heap]" },
        .{ .start = 0x7800, .size = 0x100, .kind = .HEAP, .flags = test_readable_flags, .load_addr = 0x7800, .id = 7, .filename = "" },
        .{ .start = 0x8000, .size = 0x100, .kind = .CODE, .flags = test_unreadable_flags, .load_addr = 0x8000, .id = 8, .filename = "/lib/hidden" },
        .{ .start = 0x9000, .size = 0, .kind = .CODE, .flags = test_readable_flags, .load_addr = 0x9000, .id = 9, .filename = "/lib/empty" },
        .{ .start = 0xA000, .size = 0x100, .kind = .CODE, .flags = test_readable_flags, .load_addr = 0xA200, .id = 10, .filename = "/lib/bad-load" },
    };

    const modules = try moduleBasesFromRegions(std.testing.allocator, &regions);
    defer std.testing.allocator.free(modules);

    try std.testing.expectEqual(2, modules.len);
    try std.testing.expectEqualStrings("game", modules[0].name);
    try std.testing.expectEqual(0x1000, modules[0].base);
    try std.testing.expectEqual(0x1900, modules[0].size);
    try std.testing.expectEqualStrings("foo", modules[1].name);
    try std.testing.expectEqual(0x5000, modules[1].base);
    try std.testing.expectEqual(0x200, modules[1].size);
}

test "ValidPointerValueRanges: merges ranges and checks containment" {
    const regions = [_]process.Region{
        .{ .start = 0x3000, .size = 0x100, .kind = .HEAP, .flags = test_readable_flags, .load_addr = 0x3000, .id = 0, .filename = "" },
        .{ .start = 0x1000, .size = 0x100, .kind = .HEAP, .flags = test_readable_flags, .load_addr = 0x1000, .id = 1, .filename = "" },
        .{ .start = 0x1080, .size = 0x100, .kind = .HEAP, .flags = test_readable_flags, .load_addr = 0x1080, .id = 2, .filename = "" },
        .{ .start = 0x1180, .size = 0x80, .kind = .HEAP, .flags = test_readable_flags, .load_addr = 0x1180, .id = 3, .filename = "" },
        .{ .start = 0x4000, .size = 0x100, .kind = .HEAP, .flags = test_unreadable_flags, .load_addr = 0x4000, .id = 4, .filename = "" },
        .{ .start = 0x5000, .size = 0, .kind = .HEAP, .flags = test_readable_flags, .load_addr = 0x5000, .id = 5, .filename = "" },
    };

    var ranges = try ValidPointerValueRanges.init(std.testing.allocator, &regions);
    defer ranges.deinit();

    try std.testing.expectEqual(2, ranges.len());
    try std.testing.expect(ranges.contains(0x1000));
    try std.testing.expect(ranges.contains(0x11FF));
    try std.testing.expect(!ranges.contains(0x1200));
    try std.testing.expect(!ranges.contains(0x1800));
    try std.testing.expect(ranges.contains(0x3000));
    try std.testing.expect(!ranges.contains(0x3100));
    try std.testing.expect(!ranges.contains(0x4000));
}

test "appendEntriesFromChunk: decodes pointer width, endianness, alignment, and valid pointer value ranges" {
    const regions = [_]process.Region{
        .{ .start = 0x1000, .size = 0x100, .kind = .HEAP, .flags = test_readable_flags, .load_addr = 0x1000, .id = 0, .filename = "" },
        .{ .start = 0x2000, .size = 0x100, .kind = .HEAP, .flags = test_readable_flags, .load_addr = 0x2000, .id = 1, .filename = "" },
    };
    var valid_pointer_values = try ValidPointerValueRanges.init(std.testing.allocator, &regions);
    defer valid_pointer_values.deinit();

    var entries: std.ArrayList(PointerEntry) = .empty;
    defer entries.deinit(std.testing.allocator);

    var le32: [16]u8 = @splat(0);
    std.mem.writeInt(u32, le32[0..4], 0x1010, .little);
    std.mem.writeInt(u32, le32[4..8], 0x9999, .little);
    std.mem.writeInt(u32, le32[8..12], 0x2020, .little);
    const le32_advance = try appendEntriesFromChunk(std.testing.allocator, &entries, 0x4000, &le32, .{
        .pointer_width = 4,
        .endianness = .little,
    }, &valid_pointer_values);

    try std.testing.expectEqual(13, le32_advance);
    try std.testing.expectEqual(2, entries.items.len);
    try std.testing.expectEqual(0x4000, entries.items[0].address);
    try std.testing.expectEqual(0x1010, entries.items[0].value);
    try std.testing.expectEqual(0x4008, entries.items[1].address);
    try std.testing.expectEqual(0x2020, entries.items[1].value);

    entries.clearRetainingCapacity();

    var be64: [16]u8 = @splat(0);
    std.mem.writeInt(u64, be64[8..16], 0x2018, .big);
    const be64_advance = try appendEntriesFromChunk(std.testing.allocator, &entries, 0x5000, &be64, .{
        .pointer_width = 8,
        .endianness = .big,
    }, &valid_pointer_values);

    try std.testing.expectEqual(9, be64_advance);
    try std.testing.expectEqual(1, entries.items.len);
    try std.testing.expectEqual(0x5008, entries.items[0].address);
    try std.testing.expectEqual(0x2018, entries.items[0].value);

    entries.clearRetainingCapacity();

    var misaligned: [8]u8 = @splat(0);
    std.mem.writeInt(u32, misaligned[0..4], 0x1010, .little);
    std.mem.writeInt(u32, misaligned[3..7], 0x2020, .little);
    const misaligned_advance = try appendEntriesFromChunk(std.testing.allocator, &entries, 0x6001, &misaligned, .{
        .pointer_width = 4,
        .endianness = .little,
    }, &valid_pointer_values);

    try std.testing.expectEqual(5, misaligned_advance);
    try std.testing.expectEqual(1, entries.items.len);
    try std.testing.expectEqual(0x6004, entries.items[0].address);
    try std.testing.expectEqual(0x2020, entries.items[0].value);
}

test "appendEntriesFromChunk: uses overlap bytes" {
    const regions = [_]process.Region{
        .{ .start = 0x1000, .size = 0x100, .kind = .HEAP, .flags = test_readable_flags, .load_addr = 0x1000, .id = 0, .filename = "" },
    };
    var valid_pointer_values = try ValidPointerValueRanges.init(std.testing.allocator, &regions);
    defer valid_pointer_values.deinit();

    var entries: std.ArrayList(PointerEntry) = .empty;
    defer entries.deinit(std.testing.allocator);

    var overlap: [7]u8 = @splat(0);
    std.mem.writeInt(u32, overlap[3..7], 0x1020, .little);
    const scan_advance = try appendEntriesFromChunk(std.testing.allocator, &entries, 0x7001, &overlap, .{
        .pointer_width = 4,
        .endianness = .little,
    }, &valid_pointer_values);

    try std.testing.expectEqual(4, scan_advance);
    try std.testing.expectEqual(1, entries.items.len);
    try std.testing.expectEqual(0x7004, entries.items[0].address);
    try std.testing.expectEqual(0x1020, entries.items[0].value);
}

test "appendEntriesFromChunk: validates public options" {
    var entries: std.ArrayList(PointerEntry) = .empty;
    defer entries.deinit(std.testing.allocator);

    var valid_pointer_values = try ValidPointerValueRanges.init(std.testing.allocator, &.{});
    defer valid_pointer_values.deinit();

    const bytes: [8]u8 = @splat(0);
    try std.testing.expectError(
        PointerScanError.InvalidOptions,
        appendEntriesFromChunk(std.testing.allocator, &entries, 0x1000, &bytes, .{
            .pointer_width = 0,
        }, &valid_pointer_values),
    );
}

test "appendEntriesFromChunk: returns zero advance when buffer is smaller than pointer width" {
    var entries: std.ArrayList(PointerEntry) = .empty;
    defer entries.deinit(std.testing.allocator);

    var valid_pointer_values = try ValidPointerValueRanges.init(std.testing.allocator, &.{});
    defer valid_pointer_values.deinit();

    const bytes: [3]u8 = @splat(0);
    const scan_advance = try appendEntriesFromChunk(std.testing.allocator, &entries, 0x1000, &bytes, .{
        .pointer_width = 4,
    }, &valid_pointer_values);

    try std.testing.expectEqual(0, scan_advance);
    try std.testing.expectEqual(0, entries.items.len);
}

test "findPointerPaths: supports negative offsets and result limits" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const io = std.testing.io;
    const modules = [_]ModuleBase{
        .{ .name = "game.exe", .base = 0x2000, .size = 0x100 },
    };
    const entries = [_]PointerEntry{
        .{ .address = 0x2010, .value = 0x5040 },
        .{ .address = 0x2020, .value = 0x5040 },
    };

    var index = try PointerReverseIndex.fromEntries(std.testing.allocator, &entries);
    defer index.deinit();

    {
        const file = try tmp.dir.createFile(io, "scan.lmptr", .{ .read = true, .truncate = true });
        var writer = try PointerMapWriter.init(io, file, 8, &modules);
        defer writer.deinit();

        const found = try findPointerPaths(std.testing.allocator, &index, &modules, .{
            .max_depth = 1,
            .max_positive_offset = 0,
            .max_negative_offset = 0x40,
            .max_results = 1,
        }, 0x5020, &writer);
        try std.testing.expectEqual(1, found);
        try writer.finish();
    }

    try expectMapText(io, tmp.dir, "scan.lmptr", "game.exe+0x10 -> -0x20\n");
}

test "PointerMapWriter: validates map inputs and finished state" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const io = std.testing.io;
    const modules = [_]ModuleBase{
        .{ .name = "game.exe", .base = 0x100000, .size = 0x20000 },
    };

    {
        const file = try tmp.dir.createFile(io, "bad-width.lmptr", .{ .read = true, .truncate = true });
        try std.testing.expectError(PointerScanError.InvalidMapData, PointerMapWriter.init(io, file, 3, &.{}));
    }

    {
        const long_name: [PointerMapHeader.max_module_name_len + 1]u8 = @splat('a');
        const bad_modules = [_]ModuleBase{
            .{ .name = &long_name, .base = 0x1000, .size = 0x100 },
        };

        const file = try tmp.dir.createFile(io, "long-name.lmptr", .{ .read = true, .truncate = true });
        try std.testing.expectError(PointerScanError.InvalidMapData, PointerMapWriter.init(io, file, 8, &bad_modules));
    }

    {
        const file = try tmp.dir.createFile(io, "bad-module-index.lmptr", .{ .read = true, .truncate = true });
        var writer = try PointerMapWriter.init(io, file, 8, &modules);
        defer writer.deinit();

        try std.testing.expectError(PointerScanError.InvalidMapData, writer.append(.{
            .base = .{ .module = .{ .module_index = 1, .offset = 0 } },
            .offsets = &.{},
        }));
    }

    {
        const file = try tmp.dir.createFile(io, "too-many-offsets.lmptr", .{ .read = true, .truncate = true });
        var writer = try PointerMapWriter.init(io, file, 8, &modules);
        defer writer.deinit();

        const offsets: [PointerMapHeader.max_offsets_per_path + 1]i64 = @splat(0);
        try std.testing.expectError(PointerScanError.InvalidMapData, writer.append(.{
            .base = .{ .absolute = 0x1000 },
            .offsets = &offsets,
        }));
    }

    {
        const file = try tmp.dir.createFile(io, "finished.lmptr", .{ .read = true, .truncate = true });
        var writer = try PointerMapWriter.init(io, file, 8, &modules);
        defer writer.deinit();

        try writer.finish();
        try writer.finish();
        try std.testing.expectError(PointerScanError.InvalidMapData, writer.append(.{
            .base = .{ .absolute = 0x1000 },
            .offsets = &.{},
        }));
    }
}

test "PointerMapWriter/Reader: round-trips paths, dumps text, and supports reset" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const io = std.testing.io;
    const modules = [_]ModuleBase{
        .{ .name = "game.exe", .base = 0x100000, .size = 0x20000 },
        .{ .name = "libfoo.so", .base = 0x700000, .size = 0x30000 },
    };

    {
        const file = try tmp.dir.createFile(io, "scan.lmptr", .{ .read = true, .truncate = true });
        var writer = try PointerMapWriter.init(io, file, 8, &modules);
        defer writer.deinit();

        try writer.append(.{
            .base = .{ .module = .{ .module_index = 0, .offset = 0x1A2B30 } },
            .offsets = &.{ 0x18, 0x20, 0x8 },
        });

        try writer.append(.{
            .base = .{ .module = .{ .module_index = 1, .offset = 0x4812C0 } },
            .offsets = &.{ 0x30, -0x10, 0x48 },
        });

        try writer.append(.{
            .base = .{ .absolute = 0x7FFDF0012000 },
            .offsets = &.{ 0x28, 0x10 },
        });

        try writer.finish();
    }

    const read_file = try tmp.dir.openFile(io, "scan.lmptr", .{});
    var reader = try PointerMapReader.init(std.testing.allocator, io, read_file);
    defer reader.deinit();

    try std.testing.expectEqual(8, reader.pointer_width);
    try std.testing.expectEqual(3, reader.path_count);
    try std.testing.expectEqual(2, reader.modules.len);
    try std.testing.expectEqualStrings("game.exe", reader.modules[0].name);
    try std.testing.expectEqualStrings("libfoo.so", reader.modules[1].name);

    var out = std.Io.Writer.Allocating.init(std.testing.allocator);
    defer out.deinit();

    try reader.dumpText(&out.writer);
    try std.testing.expectEqualStrings(
        "game.exe+0x1A2B30 -> 0x18 -> 0x20 -> 0x8\n" ++
            "libfoo.so+0x4812C0 -> 0x30 -> -0x10 -> 0x48\n" ++
            "0x7FFDF0012000 -> 0x28 -> 0x10\n",
        out.written(),
    );

    try std.testing.expect((try reader.next()) == null);

    reader.reset();
    var second_dump = std.Io.Writer.Allocating.init(std.testing.allocator);
    defer second_dump.deinit();

    try reader.dumpText(&second_dump.writer);
    try std.testing.expectEqualStrings(out.written(), second_dump.written());
}

test "comparePointerMaps: writes matching current paths even if module order changes" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const io = std.testing.io;
    const previous_modules = [_]ModuleBase{
        .{ .name = "game.exe", .base = 0x100000, .size = 0x20000 },
        .{ .name = "libfoo.so", .base = 0x700000, .size = 0x30000 },
    };
    const current_modules = [_]ModuleBase{
        .{ .name = "libfoo.so", .base = 0x710000, .size = 0x30000 },
        .{ .name = "game.exe", .base = 0x120000, .size = 0x20000 },
    };
    const game_offsets = [_]i64{0x18};
    const lib_offsets = [_]i64{ 0x20, 0x8 };
    const unique_offsets = [_]i64{0x30};

    {
        const file = try tmp.dir.createFile(io, "previous.lmptr", .{ .read = true, .truncate = true });
        var writer = try PointerMapWriter.init(io, file, 8, &previous_modules);
        defer writer.deinit();

        try writer.append(.{ .base = .{ .module = .{ .module_index = 0, .offset = 0x100 } }, .offsets = &game_offsets });
        try writer.append(.{ .base = .{ .module = .{ .module_index = 1, .offset = 0x40 } }, .offsets = &lib_offsets });
        try writer.append(.{ .base = .{ .module = .{ .module_index = 0, .offset = 0x200 } }, .offsets = &unique_offsets });
        try writer.finish();
    }

    {
        const file = try tmp.dir.createFile(io, "current.lmptr", .{ .read = true, .truncate = true });
        var writer = try PointerMapWriter.init(io, file, 8, &current_modules);
        defer writer.deinit();

        try writer.append(.{ .base = .{ .module = .{ .module_index = 1, .offset = 0x100 } }, .offsets = &game_offsets });
        try writer.append(.{ .base = .{ .module = .{ .module_index = 0, .offset = 0x40 } }, .offsets = &lib_offsets });
        try writer.append(.{ .base = .{ .module = .{ .module_index = 1, .offset = 0x300 } }, .offsets = &unique_offsets });
        try writer.append(.{ .base = .{ .module = .{ .module_index = 1, .offset = 0x100 } }, .offsets = &game_offsets });
        try writer.finish();
    }

    const previous_file = try tmp.dir.openFile(io, "previous.lmptr", .{});
    const current_file = try tmp.dir.openFile(io, "current.lmptr", .{});
    const output_file = try tmp.dir.createFile(io, "stable.lmptr", .{ .read = true, .truncate = true });
    const paths_found = try comparePointerMaps(std.testing.allocator, io, previous_file, current_file, output_file);
    try std.testing.expectEqual(2, paths_found);

    try expectMapText(
        io,
        tmp.dir,
        "stable.lmptr",
        "game.exe+0x100 -> 0x18\n" ++
            "libfoo.so+0x40 -> 0x20 -> 0x8\n",
    );
}

test "PointerMapReader: rejects invalid header and module records" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const io = std.testing.io;

    {
        const file = try tmp.dir.createFile(io, "truncated.lmptr", .{ .read = true, .truncate = true });
        file.close(io);

        try expectReaderInitError(PointerScanError.InvalidMapFormat, io, tmp.dir, "truncated.lmptr");
    }

    {
        const file = try tmp.dir.createFile(io, "magic.lmptr", .{ .read = true, .truncate = true });
        var header: [PointerMapHeader.size]u8 = @splat(0);
        @memcpy(header[0..PointerMapHeader.magic.len], "NOTAPTR!");
        std.mem.writeInt(u16, header[PointerMapHeader.version_field_offset..][0..2], PointerMapHeader.version, PointerMapHeader.endianness);
        header[PointerMapHeader.pointer_width_field_offset] = 8;
        try file.writePositionalAll(io, &header, 0);
        file.close(io);

        try expectReaderInitError(PointerScanError.InvalidMapFormat, io, tmp.dir, "magic.lmptr");
    }

    {
        const file = try tmp.dir.createFile(io, "version.lmptr", .{ .read = true, .truncate = true });
        try writeTestMapHeader(io, file, 8, 0, 0);
        var version: [2]u8 = undefined;
        std.mem.writeInt(u16, &version, PointerMapHeader.version + 1, PointerMapHeader.endianness);
        try file.writePositionalAll(io, &version, PointerMapHeader.version_field_offset);
        file.close(io);

        try expectReaderInitError(PointerScanError.UnsupportedMapVersion, io, tmp.dir, "version.lmptr");
    }

    {
        const file = try tmp.dir.createFile(io, "pointer-width.lmptr", .{ .read = true, .truncate = true });
        try writeTestMapHeader(io, file, 3, 0, 0);
        file.close(io);

        try expectReaderInitError(PointerScanError.InvalidMapFormat, io, tmp.dir, "pointer-width.lmptr");
    }

    {
        const file = try tmp.dir.createFile(io, "modules.lmptr", .{ .read = true, .truncate = true });
        try writeTestMapHeader(io, file, 8, PointerMapHeader.max_modules + 1, 0);
        file.close(io);

        try expectReaderInitError(PointerScanError.InvalidMapFormat, io, tmp.dir, "modules.lmptr");
    }

    {
        const file = try tmp.dir.createFile(io, "name.lmptr", .{ .read = true, .truncate = true });
        try writeTestMapHeader(io, file, 8, 1, 0);

        var module_header: [test_module_record_header_size]u8 = @splat(0);
        std.mem.writeInt(u64, module_header[0..8], 0x1000, PointerMapHeader.endianness);
        std.mem.writeInt(u64, module_header[8..16], 0x100, PointerMapHeader.endianness);
        std.mem.writeInt(u32, module_header[16..20], PointerMapHeader.max_module_name_len + 1, PointerMapHeader.endianness);
        try file.writePositionalAll(io, &module_header, PointerMapHeader.size);
        file.close(io);

        try expectReaderInitError(PointerScanError.InvalidMapFormat, io, tmp.dir, "name.lmptr");
    }

    {
        const file = try tmp.dir.createFile(io, "truncated-name.lmptr", .{ .read = true, .truncate = true });
        try writeTestMapHeader(io, file, 8, 1, 0);

        var module_header: [test_module_record_header_size]u8 = @splat(0);
        std.mem.writeInt(u64, module_header[0..8], 0x1000, PointerMapHeader.endianness);
        std.mem.writeInt(u64, module_header[8..16], 0x100, PointerMapHeader.endianness);
        std.mem.writeInt(u32, module_header[16..20], 4, PointerMapHeader.endianness);
        try file.writePositionalAll(io, &module_header, PointerMapHeader.size);
        try file.writePositionalAll(io, "ab", PointerMapHeader.size + test_module_record_header_size);
        file.close(io);

        try expectReaderInitError(PointerScanError.InvalidMapFormat, io, tmp.dir, "truncated-name.lmptr");
    }
}

test "PointerMapReader: rejects corrupt path records" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const io = std.testing.io;

    {
        const file = try tmp.dir.createFile(io, "truncated-record.lmptr", .{ .read = true, .truncate = true });
        try writeTestMapHeader(io, file, 8, 0, 1);
        file.close(io);

        try expectInvalidPathRecord(io, tmp.dir, "truncated-record.lmptr");
    }

    {
        const file = try tmp.dir.createFile(io, "offsets.lmptr", .{ .read = true, .truncate = true });
        try writeTestMapHeader(io, file, 8, 0, 1);

        var record: [test_path_record_header_size]u8 = @splat(0);
        record[0] = @intFromEnum(PointerBaseKind.absolute);
        std.mem.writeInt(u64, record[8..16], 0x1000, PointerMapHeader.endianness);
        std.mem.writeInt(u32, record[16..20], PointerMapHeader.max_offsets_per_path + 1, PointerMapHeader.endianness);
        try file.writePositionalAll(io, &record, PointerMapHeader.size);
        file.close(io);

        try expectInvalidPathRecord(io, tmp.dir, "offsets.lmptr");
    }

    {
        const file = try tmp.dir.createFile(io, "reserved.lmptr", .{ .read = true, .truncate = true });
        try writeTestMapHeader(io, file, 8, 0, 1);

        var record: [test_path_record_header_size]u8 = @splat(0);
        record[0] = @intFromEnum(PointerBaseKind.absolute);
        record[1] = 1;
        try file.writePositionalAll(io, &record, PointerMapHeader.size);
        file.close(io);

        try expectInvalidPathRecord(io, tmp.dir, "reserved.lmptr");
    }

    {
        const file = try tmp.dir.createFile(io, "kind.lmptr", .{ .read = true, .truncate = true });
        try writeTestMapHeader(io, file, 8, 0, 1);

        var record: [test_path_record_header_size]u8 = @splat(0);
        record[0] = 0xFF;
        try file.writePositionalAll(io, &record, PointerMapHeader.size);
        file.close(io);

        try expectInvalidPathRecord(io, tmp.dir, "kind.lmptr");
    }

    {
        const file = try tmp.dir.createFile(io, "absolute-module-index.lmptr", .{ .read = true, .truncate = true });
        try writeTestMapHeader(io, file, 8, 0, 1);

        var record: [test_path_record_header_size]u8 = @splat(0);
        record[0] = @intFromEnum(PointerBaseKind.absolute);
        std.mem.writeInt(u32, record[4..8], 1, PointerMapHeader.endianness);
        try file.writePositionalAll(io, &record, PointerMapHeader.size);
        file.close(io);

        try expectInvalidPathRecord(io, tmp.dir, "absolute-module-index.lmptr");
    }

    {
        const file = try tmp.dir.createFile(io, "module-index.lmptr", .{ .read = true, .truncate = true });
        try writeTestMapHeader(io, file, 8, 0, 1);

        var record: [test_path_record_header_size]u8 = @splat(0);
        record[0] = @intFromEnum(PointerBaseKind.module);
        try file.writePositionalAll(io, &record, PointerMapHeader.size);
        file.close(io);

        try expectInvalidPathRecord(io, tmp.dir, "module-index.lmptr");
    }

    {
        const file = try tmp.dir.createFile(io, "truncated-offsets.lmptr", .{ .read = true, .truncate = true });
        try writeTestMapHeader(io, file, 8, 0, 1);

        var record: [test_path_record_header_size]u8 = @splat(0);
        record[0] = @intFromEnum(PointerBaseKind.absolute);
        std.mem.writeInt(u32, record[16..20], 1, PointerMapHeader.endianness);
        try file.writePositionalAll(io, &record, PointerMapHeader.size);
        file.close(io);

        try expectInvalidPathRecord(io, tmp.dir, "truncated-offsets.lmptr");
    }
}
