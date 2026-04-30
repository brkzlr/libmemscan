//! Swath-based match storage

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
const value_mod = @import("value.zig");

const MatchFlags = value_mod.MatchFlags;
const Value = value_mod.Value;

const Allocator = std.mem.Allocator;

pub const StorageError = error{
    OutOfMemory,
    ExceedsMaximumSize,
};

/// Single match struct.
pub const OldValueAndMatchInfo = extern struct {
    old_value: u8 = 0,
    _padding: u8 = 0,
    match_info_bits: u16 = 0,

    pub fn matchInfo(self: OldValueAndMatchInfo) MatchFlags {
        return @bitCast(self.match_info_bits);
    }

    pub fn setMatchInfo(self: *align(1) OldValueAndMatchInfo, flags: MatchFlags) void {
        self.match_info_bits = flags.bits();
    }

    pub fn isMatch(self: OldValueAndMatchInfo) bool {
        return self.match_info_bits != 0;
    }
};

pub const SwathHeader = extern struct {
    first_byte_in_child: usize = 0,
    number_of_bytes: usize = 0,
};

/// Location of a match in a MatchesArray (swath).
pub const MatchLocation = struct {
    swath_offset: usize,
    index: usize,

    pub fn remoteAddress(self: MatchLocation, matches: *const MatchesArray) usize {
        return matches.remoteAddressOfNthElement(self.swath_offset, self.index);
    }

    pub fn value(self: MatchLocation, matches: *const MatchesArray) Value {
        return matches.dataToValue(self.swath_offset, self.index);
    }

    pub fn rawMatchInfoBits(self: MatchLocation, matches: *const MatchesArray) u16 {
        return matches.rawMatchInfoBits(self.swath_offset, self.index);
    }
};

pub const MatchIterator = struct {
    matches: *const MatchesArray,
    swath_offset: usize = 0,
    index: usize = 0,

    pub fn next(self: *MatchIterator) ?MatchLocation {
        while (true) {
            const swath = self.matches.swathAtConst(self.swath_offset);
            if (swath.first_byte_in_child == 0) return null;

            while (self.index < swath.number_of_bytes) : (self.index += 1) {
                if (!self.matches.entryAtConst(self.swath_offset, self.index).isMatch()) continue;

                const location = MatchLocation{
                    .swath_offset = self.swath_offset,
                    .index = self.index,
                };
                self.index += 1;
                return location;
            }

            self.swath_offset = self.matches.localAddressBeyondLastElement(self.swath_offset);
            self.index = 0;
        }
    }
};

pub const StoredByte = struct {
    swath_offset: usize,
    index: usize,
    address: usize,
    old_value: u8,
    raw_match_info_bits: u16,

    pub fn isMatch(self: StoredByte) bool {
        return self.raw_match_info_bits != 0;
    }
};

pub const StoredByteIterator = struct {
    matches: *const MatchesArray,
    swath_offset: usize = 0,
    index: usize = 0,

    pub fn next(self: *StoredByteIterator) ?StoredByte {
        while (true) {
            const swath = self.matches.swathAtConst(self.swath_offset);
            if (swath.first_byte_in_child == 0) return null;

            if (self.index < swath.number_of_bytes) {
                const entry = self.matches.entryAtConst(self.swath_offset, self.index);
                const item = StoredByte{
                    .swath_offset = self.swath_offset,
                    .index = self.index,
                    .address = swath.first_byte_in_child + self.index,
                    .old_value = entry.old_value,
                    .raw_match_info_bits = entry.match_info_bits,
                };
                self.index += 1;
                return item;
            }

            self.swath_offset = self.matches.localAddressBeyondLastElement(self.swath_offset);
            self.index = 0;
        }
    }
};

pub const MatchesArray = struct {
    allocator: Allocator,
    storage: []align(@alignOf(SwathHeader)) u8,
    used_len: usize,
    max_needed_bytes: usize,
    tail_swath_offset: usize,
    match_count: usize,

    const swath_header_size = @sizeOf(SwathHeader);
    const entry_size = @sizeOf(OldValueAndMatchInfo);
    const new_swath_cost = swath_header_size + entry_size;
    pub fn init(allocator: Allocator, max_needed_bytes: usize) StorageError!MatchesArray {
        const storage = allocator.alignedAlloc(u8, std.mem.Alignment.of(SwathHeader), swath_header_size) catch return StorageError.OutOfMemory;
        @memset(storage, 0);

        return .{
            .allocator = allocator,
            .storage = storage,
            .used_len = swath_header_size,
            .max_needed_bytes = max_needed_bytes,
            .tail_swath_offset = 0,
            .match_count = 0,
        };
    }

    pub fn deinit(self: *MatchesArray) void {
        self.allocator.free(self.storage);
        self.* = undefined;
    }

    pub fn append(self: *MatchesArray, remote_address: usize, old_value: u8, match_info: MatchFlags) StorageError!void {
        try self.appendInternal(remote_address, old_value, match_info, true);
    }

    pub fn finalize(self: *MatchesArray) StorageError!void {
        try self.resizeStorage(self.used_len);
    }

    pub fn matchCount(self: *const MatchesArray) usize {
        return self.match_count;
    }

    pub fn iterator(self: *const MatchesArray) MatchIterator {
        return .{ .matches = self };
    }

    pub fn storedByteIterator(self: *const MatchesArray) StoredByteIterator {
        return .{ .matches = self };
    }

    pub fn usedBytes(self: *const MatchesArray) usize {
        return self.used_len;
    }

    pub fn nthMatch(self: *const MatchesArray, n: usize) ?MatchLocation {
        var seen: usize = 0;
        var swath_offset: usize = 0;

        while (true) {
            const swath = self.swathAtConst(swath_offset);
            if (swath.first_byte_in_child == 0) return null;

            var index: usize = 0;
            while (index < swath.number_of_bytes) : (index += 1) {
                if (!self.entryAtConst(swath_offset, index).isMatch()) continue;
                if (seen == n) {
                    return .{
                        .swath_offset = swath_offset,
                        .index = index,
                    };
                }
                seen += 1;
            }

            swath_offset = self.localAddressBeyondLastElement(swath_offset);
        }
    }

    pub fn findMatchIndexByAddress(self: *const MatchesArray, address: usize) ?usize {
        var iter = self.iterator();
        var index: usize = 0;
        while (iter.next()) |location| : (index += 1) {
            if (location.remoteAddress(self) == address) return index;
        }
        return null;
    }

    pub fn deleteInAddressRange(self: *MatchesArray, start_address: usize, end_address: usize) StorageError!void {
        // TODO: Should maybe change this if region removals become used a lot as
        // it rewrites packed match storage while reading it
        var read_swath_offset: usize = 0;
        var read_swath = self.swathAtConst(0).*;

        self.tail_swath_offset = 0;
        self.match_count = 0;
        self.used_len = swath_header_size;
        self.writeSentinel(0);

        while (read_swath.first_byte_in_child != 0) {
            var index: usize = 0;
            while (index < read_swath.number_of_bytes) : (index += 1) {
                const address = read_swath.first_byte_in_child + index;
                if (address >= start_address and address < end_address) continue;

                const entry = self.entryAtConst(read_swath_offset, index).*;
                try self.appendInternal(address, entry.old_value, entry.matchInfo(), false);
            }

            read_swath_offset = self.localAddressBeyondLastElementWithLength(read_swath_offset, read_swath.number_of_bytes);
            read_swath = self.swathAtConst(read_swath_offset).*;
        }

        try self.finalize();
    }

    pub fn dataToBytes(self: *const MatchesArray, swath_offset: usize, index: usize, byte_length: usize, buf: []u8) []const u8 {
        if (buf.len == 0) return buf;

        const swath = self.swathAtConst(swath_offset);
        const available = swath.number_of_bytes - index;
        const length = @min(@min(available, byte_length), buf.len);

        var written: usize = 0;
        while (written < length) : (written += 1) {
            buf[written] = self.entryAtConst(swath_offset, index + written).old_value;
        }

        return buf[0..written];
    }

    pub fn dataToValue(self: *const MatchesArray, swath_offset: usize, index: usize) Value {
        const swath = self.swathAtConst(swath_offset);
        return self.dataToValueAux(swath_offset, index, swath.number_of_bytes);
    }

    pub fn rawMatchInfoBits(self: *const MatchesArray, swath_offset: usize, index: usize) u16 {
        return self.entryAtConst(swath_offset, index).match_info_bits;
    }

    pub fn removeMatch(self: *MatchesArray, location: MatchLocation) void {
        const swath = self.swathAt(location.swath_offset);

        var end_index = location.index + 1;
        while (end_index < swath.number_of_bytes) : (end_index += 1) {
            if (self.entryAtConst(location.swath_offset, end_index).isMatch()) break;
        }

        var index = location.index;
        while (index < end_index) : (index += 1) {
            self.entryAt(location.swath_offset, index).* = .{};
        }

        std.debug.assert(self.match_count > 0);
        self.match_count -= 1;
    }

    fn appendInternal(self: *MatchesArray, remote_address: usize, old_value: u8, match_info: MatchFlags, allow_growth: bool) StorageError!void {
        var swath_offset = self.tail_swath_offset;
        var swath = self.swathAt(swath_offset);

        if (swath.number_of_bytes == 0) {
            std.debug.assert(swath.first_byte_in_child == 0);
            try self.ensureCapacity(swath_offset + swath_header_size + entry_size + swath_header_size, allow_growth);
            swath = self.swathAt(swath_offset);
            swath.first_byte_in_child = remote_address;
        } else {
            const last_address = self.remoteAddressOfLastElement(swath_offset);
            std.debug.assert(remote_address > last_address);

            const local_index_excess = remote_address - last_address;
            const local_address_excess = local_index_excess * entry_size;

            if (local_address_excess >= new_swath_cost) {
                swath_offset = self.localAddressBeyondLastElement(swath_offset);
                try self.ensureCapacity(swath_offset + swath_header_size + entry_size + swath_header_size, allow_growth);
                self.tail_swath_offset = swath_offset;
                swath = self.swathAt(swath_offset);
                swath.* = .{
                    .first_byte_in_child = remote_address,
                    .number_of_bytes = 0,
                };
            } else {
                try self.ensureCapacity(self.localAddressBeyondLastElement(swath_offset) + local_address_excess + swath_header_size, allow_growth);
                swath = self.swathAt(swath_offset);

                if (local_index_excess > 1) {
                    const gap_start = self.entryByteOffset(swath_offset, swath.number_of_bytes);
                    const gap_len = (local_index_excess - 1) * entry_size;
                    @memset(self.storage[gap_start .. gap_start + gap_len], 0);
                    swath.number_of_bytes += local_index_excess - 1;
                }
            }
        }

        const entry = self.entryAt(swath_offset, swath.number_of_bytes);
        entry.old_value = old_value;
        entry.setMatchInfo(match_info);
        swath.number_of_bytes += 1;

        if (match_info.hasAny()) {
            self.match_count += 1;
        }

        const sentinel_offset = self.localAddressBeyondLastElement(swath_offset);
        self.writeSentinel(sentinel_offset);
        self.used_len = sentinel_offset + swath_header_size;
        self.tail_swath_offset = swath_offset;
    }

    fn ensureCapacity(self: *MatchesArray, required: usize, allow_growth: bool) StorageError!void {
        if (required <= self.storage.len) return;
        if (!allow_growth) return StorageError.ExceedsMaximumSize;

        var new_capacity = if (self.storage.len == 0) swath_header_size else self.storage.len;
        while (new_capacity < required) {
            new_capacity *= 2;
        }

        if (self.max_needed_bytes != 0 and new_capacity > self.max_needed_bytes) {
            if (required > self.max_needed_bytes) return StorageError.ExceedsMaximumSize;
            new_capacity = self.max_needed_bytes;
        }

        try self.resizeStorage(new_capacity);
    }

    fn resizeStorage(self: *MatchesArray, new_capacity: usize) StorageError!void {
        if (new_capacity == self.storage.len) return;
        if (new_capacity < self.used_len) return StorageError.ExceedsMaximumSize;

        const new_storage = self.allocator.alignedAlloc(u8, std.mem.Alignment.of(SwathHeader), new_capacity) catch return StorageError.OutOfMemory;
        @memcpy(new_storage[0..self.used_len], self.storage[0..self.used_len]);
        if (new_capacity > self.used_len) {
            @memset(new_storage[self.used_len..], 0);
        }
        self.allocator.free(self.storage);
        self.storage = new_storage;
    }

    fn dataToValueAux(self: *const MatchesArray, swath_offset: usize, index: usize, swath_length: usize) Value {
        var result = Value{
            .data = .{ .uint64_value = 0 },
            .flags = @bitCast(@as(u16, 0xffff)),
        };

        const max_bytes = @min(swath_length - index, @as(usize, 8));

        var flags_bits: u16 = 0xffff;
        if (max_bytes < 8) flags_bits &= ~flags64Mask();
        if (max_bytes < 4) flags_bits &= ~flags32Mask();
        if (max_bytes < 2) flags_bits &= ~flags16Mask();
        if (max_bytes < 1) flags_bits = 0;

        var i: usize = 0;
        while (i < max_bytes) : (i += 1) {
            result.data.bytes[i] = self.entryAtConst(swath_offset, index + i).old_value;
        }

        flags_bits &= self.entryAtConst(swath_offset, index).match_info_bits;
        result.flags = @bitCast(flags_bits);
        return result;
    }

    fn swathAt(self: *MatchesArray, offset: usize) *align(1) SwathHeader {
        return std.mem.bytesAsValue(SwathHeader, self.storage[offset .. offset + swath_header_size]);
    }

    fn swathAtConst(self: *const MatchesArray, offset: usize) *align(1) const SwathHeader {
        return std.mem.bytesAsValue(SwathHeader, self.storage[offset .. offset + swath_header_size]);
    }

    fn entryAt(self: *MatchesArray, swath_offset: usize, index: usize) *align(1) OldValueAndMatchInfo {
        const start = self.entryByteOffset(swath_offset, index);
        return std.mem.bytesAsValue(OldValueAndMatchInfo, self.storage[start .. start + entry_size]);
    }

    fn entryAtConst(self: *const MatchesArray, swath_offset: usize, index: usize) *align(1) const OldValueAndMatchInfo {
        const start = self.entryByteOffset(swath_offset, index);
        return std.mem.bytesAsValue(OldValueAndMatchInfo, self.storage[start .. start + entry_size]);
    }

    fn writeSentinel(self: *MatchesArray, offset: usize) void {
        self.swathAt(offset).* = .{};
    }

    fn entryByteOffset(self: *const MatchesArray, swath_offset: usize, index: usize) usize {
        _ = self;
        return swath_offset + swath_header_size + index * entry_size;
    }

    fn localAddressBeyondLastElement(self: *const MatchesArray, swath_offset: usize) usize {
        const swath = self.swathAtConst(swath_offset);
        return self.localAddressBeyondLastElementWithLength(swath_offset, swath.number_of_bytes);
    }

    fn localAddressBeyondLastElementWithLength(self: *const MatchesArray, swath_offset: usize, length: usize) usize {
        _ = self;
        return swath_offset + swath_header_size + length * entry_size;
    }

    fn remoteAddressOfNthElement(self: *const MatchesArray, swath_offset: usize, index: usize) usize {
        const swath = self.swathAtConst(swath_offset);
        return swath.first_byte_in_child + index;
    }

    fn remoteAddressOfLastElement(self: *const MatchesArray, swath_offset: usize) usize {
        const swath = self.swathAtConst(swath_offset);
        return swath.first_byte_in_child + (swath.number_of_bytes - 1);
    }
};

inline fn flags16Mask() u16 {
    return (MatchFlags{
        .u16b = true,
        .s16b = true,
    }).bits();
}

inline fn flags32Mask() u16 {
    return (MatchFlags{
        .u32b = true,
        .s32b = true,
        .f32b = true,
    }).bits();
}

inline fn flags64Mask() u16 {
    return (MatchFlags{
        .u64b = true,
        .s64b = true,
        .f64b = true,
    }).bits();
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "append: keeps contiguous and near-gap bytes in one swath" {
    var matches = try MatchesArray.init(std.testing.allocator, 256);
    defer matches.deinit();

    try matches.append(0x1000, 0xaa, .{ .u8b = true });
    try matches.append(0x1001, 0xbb, .{ .u8b = true });
    try matches.append(0x1003, 0xcc, .{ .u8b = true });

    try std.testing.expectEqual(@as(usize, 3), matches.matchCount());
    try std.testing.expectEqual(@as(usize, 4), matches.swathAtConst(0).number_of_bytes);
    try std.testing.expectEqual(@as(usize, 0x1000), matches.swathAtConst(0).first_byte_in_child);
    try std.testing.expectEqual(@as(u8, 0xaa), matches.entryAtConst(0, 0).old_value);
    try std.testing.expectEqual(@as(u8, 0xbb), matches.entryAtConst(0, 1).old_value);
    try std.testing.expectEqual(@as(u16, 0), matches.entryAtConst(0, 2).match_info_bits);
    try std.testing.expectEqual(@as(u8, 0), matches.entryAtConst(0, 2).old_value);
    try std.testing.expectEqual(@as(u8, 0xcc), matches.entryAtConst(0, 3).old_value);
    try std.testing.expectEqual(@as(usize, 0), matches.swathAtConst(matches.localAddressBeyondLastElement(0)).first_byte_in_child);
}

test "append: starts a new swath when padding cost matches header cost" {
    var matches = try MatchesArray.init(std.testing.allocator, 256);
    defer matches.deinit();

    try matches.append(0x2000, 0x11, .{ .u8b = true });
    try matches.append(0x2005, 0x22, .{ .u8b = true });

    const first_swath = matches.swathAtConst(0);
    try std.testing.expectEqual(@as(usize, 0x2000), first_swath.first_byte_in_child);
    try std.testing.expectEqual(@as(usize, 1), first_swath.number_of_bytes);

    const second_swath_offset = matches.localAddressBeyondLastElement(0);
    const second_swath = matches.swathAtConst(second_swath_offset);
    try std.testing.expectEqual(@as(usize, 0x2005), second_swath.first_byte_in_child);
    try std.testing.expectEqual(@as(usize, 1), second_swath.number_of_bytes);
    try std.testing.expectEqual(@as(usize, 2), matches.matchCount());
    try std.testing.expectEqual(@as(usize, 0), matches.swathAtConst(matches.localAddressBeyondLastElement(second_swath_offset)).first_byte_in_child);
}

test "nthMatch: skips padded entries" {
    var matches = try MatchesArray.init(std.testing.allocator, 256);
    defer matches.deinit();

    try matches.append(0x3000, 0x10, .{ .u8b = true });
    try matches.append(0x3002, 0x20, .{ .u8b = true });

    const first = matches.nthMatch(0).?;
    const second = matches.nthMatch(1).?;

    try std.testing.expectEqual(@as(usize, 0x3000), first.remoteAddress(&matches));
    try std.testing.expectEqual(@as(usize, 0x3002), second.remoteAddress(&matches));
    try std.testing.expectEqual(@as(u16, 0), matches.entryAtConst(0, 1).match_info_bits);
    try std.testing.expect(matches.nthMatch(2) == null);
    try std.testing.expectEqual(@as(usize, 0), matches.findMatchIndexByAddress(0x3000).?);
    try std.testing.expectEqual(@as(?usize, 1), matches.findMatchIndexByAddress(0x3002));
    try std.testing.expectEqual(@as(?usize, null), matches.findMatchIndexByAddress(0x3001));
}

test "deleteInAddressRange: compacts in place and preserves remaining matches" {
    var matches = try MatchesArray.init(std.testing.allocator, 512);
    defer matches.deinit();

    try matches.append(0x4000, 0x01, .{ .u8b = true });
    try matches.append(0x4001, 0x02, .{ .u8b = true });
    try matches.append(0x4005, 0x03, .{ .u8b = true });
    try matches.append(0x4006, 0x04, .{ .u8b = true });
    try matches.finalize();

    try matches.deleteInAddressRange(0x4001, 0x4006);

    try std.testing.expectEqual(@as(usize, 2), matches.matchCount());
    const first = matches.nthMatch(0).?;
    const second = matches.nthMatch(1).?;
    try std.testing.expectEqual(@as(usize, 0x4000), first.remoteAddress(&matches));
    try std.testing.expectEqual(@as(usize, 0x4006), second.remoteAddress(&matches));
    try std.testing.expect(matches.nthMatch(2) == null);
    try std.testing.expectEqual(@as(u8, 0x01), first.value(&matches).data.uint8_value);
    try std.testing.expectEqual(@as(u8, 0x04), second.value(&matches).data.uint8_value);
    try std.testing.expectEqual(@as(?usize, null), matches.findMatchIndexByAddress(0x4001));
    try std.testing.expectEqual(@as(?usize, null), matches.findMatchIndexByAddress(0x4005));
}

test "removeMatch: preserves dense match sets after deleting one match" {
    var matches = try MatchesArray.init(std.testing.allocator, 64 * 1024);
    defer matches.deinit();

    var address: usize = 0x5000;
    var i: usize = 0;
    while (i < 1024) : (i += 1) {
        try matches.append(address, @intCast(i & 0xff), .{ .u8b = true });
        address += 4;
    }
    try matches.finalize();

    const location = matches.nthMatch(400).?;
    matches.removeMatch(location);

    try std.testing.expectEqual(@as(usize, 1023), matches.matchCount());
    try std.testing.expectEqual(@as(usize, 0x5000), matches.nthMatch(0).?.remoteAddress(&matches));
    try std.testing.expectEqual(@as(usize, 0x5000 + 4 * 399), matches.nthMatch(399).?.remoteAddress(&matches));
    try std.testing.expectEqual(@as(usize, 0x5000 + 4 * 401), matches.nthMatch(400).?.remoteAddress(&matches));
    try std.testing.expectEqual(@as(usize, 0x5000 + 4 * 1023), matches.nthMatch(1022).?.remoteAddress(&matches));
    try std.testing.expect(matches.nthMatch(1023) == null);
    try std.testing.expectEqual(@as(?usize, null), matches.findMatchIndexByAddress(0x5000 + 4 * 400));
}

test "dataToValue: truncates width flags by remaining bytes" {
    var matches = try MatchesArray.init(std.testing.allocator, 256);
    defer matches.deinit();

    try matches.append(0x5000, 0x78, .{ .u32b = true, .s32b = true, .u16b = true, .s16b = true, .u8b = true, .s8b = true });
    try matches.append(0x5001, 0x56, .{});
    try matches.append(0x5002, 0x34, .{});

    const value = matches.dataToValue(0, 0);
    try std.testing.expectEqual(@as(u16, (MatchFlags{ .u8b = true, .s8b = true, .u16b = true, .s16b = true }).bits()), value.flags.bits());
    try std.testing.expectEqual(@as(u8, 0x78), value.data.bytes[0]);
    try std.testing.expectEqual(@as(u8, 0x56), value.data.bytes[1]);
    try std.testing.expectEqual(@as(u8, 0x34), value.data.bytes[2]);
}

test "dataToValue: reconstructs full 64-bit value from match plus trailing bytes" {
    var matches = try MatchesArray.init(std.testing.allocator, 256);
    defer matches.deinit();

    try matches.append(0x7000, 0x10, .{ .u64b = true });
    try matches.append(0x7001, 0x6f, .{});
    try matches.append(0x7002, 0x2b, .{});
    try matches.append(0x7003, 0x9e, .{});
    try matches.append(0x7004, 0xc4, .{});
    try matches.append(0x7005, 0xd3, .{});
    try matches.append(0x7006, 0x17, .{});
    try matches.append(0x7007, 0x5a, .{});

    const value = matches.dataToValue(0, 0);
    try std.testing.expectEqual(@as(u16, (MatchFlags{ .u64b = true }).bits()), value.flags.bits());
    try std.testing.expectEqual(@as(u64, 0x5A17D3C49E2B6F10), value.data.uint64_value);
}

test "dataToBytes: returns raw stored bytes" {
    var matches = try MatchesArray.init(std.testing.allocator, 256);
    defer matches.deinit();

    try matches.append(0x6000, 'A', .{ .u8b = true });
    try matches.append(0x6001, 0x07, .{ .u8b = true });
    try matches.append(0x6002, 'Z', .{ .u8b = true });

    var raw_bytes: [3]u8 = undefined;

    try std.testing.expectEqualSlices(u8, &[_]u8{ 'A', 0x07, 'Z' }, matches.dataToBytes(0, 0, 3, &raw_bytes));
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x07, 'Z' }, matches.dataToBytes(0, 1, 3, &raw_bytes));
}
