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
    match_info_bits: u16 align(1) = 0,

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
            if (self.swath_offset >= self.matches.sentinelOffset()) return null;
            const swath = self.matches.swathAtConst(self.swath_offset);

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
    swath_number_of_bytes: usize,
    address: usize,
    old_value: u8,
    raw_match_info_bits: u16,

    pub fn isMatch(self: StoredByte) bool {
        return self.raw_match_info_bits != 0;
    }

    pub fn value(self: StoredByte, matches: *const MatchesArray) Value {
        return matches.dataToValueAux(self.swath_offset, self.index, self.swath_number_of_bytes, self.raw_match_info_bits);
    }
};

pub const StoredByteIterator = struct {
    matches: *const MatchesArray,
    swath_offset: usize = 0,
    index: usize = 0,
    end_offset: usize,
    swath: SwathHeader,
    entry_offset: usize,
    entry_chunk_index: usize = 0,
    entry_chunk_end: usize = 0,

    pub fn next(self: *StoredByteIterator) ?StoredByte {
        while (true) {
            if (self.swath_offset >= self.end_offset) return null;

            if (self.index < self.swath.number_of_bytes) {
                const entry = entry: {
                    const entry_end = self.entry_offset + MatchesArray.entry_size;
                    if (entry_end > self.entry_chunk_end) {
                        self.entry_chunk_index = self.matches.chunkIndexForOffset(self.entry_offset);
                        const chunk = self.matches.chunks.items[self.entry_chunk_index];
                        self.entry_chunk_end = chunk.base + chunk.data.len;
                    }
                    if (entry_end <= self.entry_chunk_end) {
                        const chunk = self.matches.chunks.items[self.entry_chunk_index];
                        const local_offset = self.entry_offset - chunk.base;
                        break :entry std.mem.bytesToValue(OldValueAndMatchInfo, chunk.data[local_offset .. local_offset + MatchesArray.entry_size]);
                    }
                    break :entry self.matches.entryAtConst(self.swath_offset, self.index);
                };
                const item = StoredByte{
                    .swath_offset = self.swath_offset,
                    .index = self.index,
                    .swath_number_of_bytes = self.swath.number_of_bytes,
                    .address = self.swath.first_byte_in_child + self.index,
                    .old_value = entry.old_value,
                    .raw_match_info_bits = entry.match_info_bits,
                };
                self.index += 1;
                self.entry_offset += MatchesArray.entry_size;
                return item;
            }

            self.swath_offset = localAddressBeyondLastElementWithLength(self.swath_offset, self.swath.number_of_bytes);
            self.index = 0;
            self.entry_offset = entryByteOffset(self.swath_offset, 0);
            if (self.swath_offset >= self.end_offset) return null;
            self.swath = if (self.end_offset == self.matches.sentinelOffset())
                self.matches.swathAtConst(self.swath_offset)
            else
                self.matches.swathFromStorage(self.swath_offset);
        }
    }
};

pub const MatchesArray = struct {
    const Chunk = struct {
        base: usize,
        data: []align(@alignOf(SwathHeader)) u8,
    };

    allocator: Allocator,
    chunks: std.ArrayList(Chunk),
    capacity_len: usize,
    used_len: usize,
    max_needed_bytes: usize,
    tail_swath_offset: usize,
    tail_swath: SwathHeader,
    tail_dirty: bool,
    match_count: usize,

    const swath_header_size = @sizeOf(SwathHeader);
    const entry_size = @sizeOf(OldValueAndMatchInfo);
    const new_swath_cost = swath_header_size + entry_size;
    const max_chunk_size = 16 * 1024 * 1024;

    pub fn init(allocator: Allocator, max_needed_bytes: usize) StorageError!MatchesArray {
        var matches = MatchesArray{
            .allocator = allocator,
            .chunks = .empty,
            .capacity_len = 0,
            .used_len = swath_header_size,
            .max_needed_bytes = max_needed_bytes,
            .tail_swath_offset = 0,
            .tail_swath = .{},
            .tail_dirty = false,
            .match_count = 0,
        };
        errdefer matches.deinit();

        try matches.addChunk(swath_header_size);
        matches.writeSwath(0, .{});
        return matches;
    }

    pub fn deinit(self: *MatchesArray) void {
        for (self.chunks.items) |chunk| {
            self.allocator.free(chunk.data);
        }
        self.chunks.deinit(self.allocator);
        self.* = undefined;
    }

    pub fn append(self: *MatchesArray, remote_address: usize, old_value: u8, match_info: MatchFlags) StorageError!void {
        try self.appendInternal(remote_address, old_value, match_info, true);
    }

    pub fn finalize(self: *MatchesArray) StorageError!void {
        self.syncTail();
        try self.trimStorage();
    }

    pub fn matchCount(self: *const MatchesArray) usize {
        return self.match_count;
    }

    pub fn iterator(self: *const MatchesArray) MatchIterator {
        return .{ .matches = self };
    }

    pub fn storedByteIterator(self: *const MatchesArray) StoredByteIterator {
        return .{
            .matches = self,
            .end_offset = self.sentinelOffset(),
            .swath = self.swathAtConst(0),
            .entry_offset = swath_header_size,
        };
    }

    pub fn storedByteCount(self: *const MatchesArray) usize {
        var count: usize = 0;
        var swath_offset: usize = 0;
        while (swath_offset < self.sentinelOffset()) {
            const swath = self.swathAtConst(swath_offset);
            count += swath.number_of_bytes;
            swath_offset = localAddressBeyondLastElementWithLength(swath_offset, swath.number_of_bytes);
        }
        return count;
    }

    pub fn resetForStorageLoad(
        self: *MatchesArray,
        used_len: usize,
        max_needed_bytes: usize,
        tail_swath_offset: usize,
        match_count: usize,
    ) StorageError!void {
        self.max_needed_bytes = max_needed_bytes;
        try self.ensureCapacity(used_len, true);
        self.used_len = used_len;
        self.tail_swath_offset = tail_swath_offset;
        self.tail_swath = .{};
        self.tail_dirty = false;
        self.match_count = match_count;
    }

    pub fn finishStorageLoad(self: *MatchesArray) void {
        self.tail_swath = self.swathFromStorage(self.tail_swath_offset);
        self.tail_dirty = false;
    }

    pub fn nthMatch(self: *const MatchesArray, n: usize) ?MatchLocation {
        var seen: usize = 0;
        var swath_offset: usize = 0;

        while (true) {
            if (swath_offset >= self.sentinelOffset()) return null;
            const swath = self.swathAtConst(swath_offset);

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
        self.syncTail();

        const read_end_offset = self.sentinelOffset();
        var read_swath_offset: usize = 0;
        var read_swath = self.swathFromStorage(0);

        self.beginInPlaceRewrite();

        while (read_swath_offset < read_end_offset) {
            var index: usize = 0;
            while (index < read_swath.number_of_bytes) : (index += 1) {
                const address = read_swath.first_byte_in_child + index;
                if (address >= start_address and address < end_address) continue;

                const entry = self.entryAtConst(read_swath_offset, index);
                try self.appendInternal(address, entry.old_value, entry.matchInfo(), false);
            }

            read_swath_offset = localAddressBeyondLastElementWithLength(read_swath_offset, read_swath.number_of_bytes);
            read_swath = self.swathFromStorage(read_swath_offset);
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
        return self.dataToValueAux(swath_offset, index, swath.number_of_bytes, self.entryAtConst(swath_offset, index).match_info_bits);
    }

    pub fn rawMatchInfoBits(self: *const MatchesArray, swath_offset: usize, index: usize) u16 {
        return self.entryAtConst(swath_offset, index).match_info_bits;
    }

    pub fn removeMatch(self: *MatchesArray, location: MatchLocation) void {
        const swath = self.swathAtConst(location.swath_offset);

        var end_index = location.index + 1;
        while (end_index < swath.number_of_bytes) : (end_index += 1) {
            if (self.entryAtConst(location.swath_offset, end_index).isMatch()) break;
        }

        var index = location.index;
        while (index < end_index) : (index += 1) {
            self.writeValue(OldValueAndMatchInfo, entryByteOffset(location.swath_offset, index), .{});
        }

        std.debug.assert(self.match_count > 0);
        self.match_count -= 1;
    }

    pub fn beginInPlaceRewrite(self: *MatchesArray) void {
        self.syncTail();
        self.tail_swath_offset = 0;
        self.tail_swath = .{};
        self.match_count = 0;
        self.used_len = swath_header_size;
        self.writeSwath(0, .{});
    }

    pub fn appendInPlaceRewrite(self: *MatchesArray, remote_address: usize, old_value: u8, match_info: MatchFlags) StorageError!void {
        try self.appendInternal(remote_address, old_value, match_info, false);
    }

    fn appendInternal(self: *MatchesArray, remote_address: usize, old_value: u8, match_info: MatchFlags, allow_growth: bool) StorageError!void {
        var swath_offset = self.tail_swath_offset;
        var swath = self.tail_swath;

        if (swath.number_of_bytes == 0) {
            std.debug.assert(swath.first_byte_in_child == 0);
            try self.ensureCapacity(swath_offset + swath_header_size + entry_size + swath_header_size, allow_growth);
            swath.first_byte_in_child = remote_address;
        } else if (remote_address == swath.first_byte_in_child + swath.number_of_bytes) {
            const required = localAddressBeyondLastElementWithLength(swath_offset, swath.number_of_bytes + 1) + swath_header_size;
            if (required > self.capacity_len) try self.ensureCapacity(required, allow_growth);
        } else {
            const last_address = swath.first_byte_in_child + (swath.number_of_bytes - 1);
            std.debug.assert(remote_address > last_address);

            const local_index_excess = remote_address - last_address;
            const local_address_excess = local_index_excess * entry_size;

            if (local_address_excess >= new_swath_cost) {
                if (self.tail_dirty) {
                    self.writeSwath(self.tail_swath_offset, self.tail_swath);
                    self.tail_dirty = false;
                }
                swath_offset = localAddressBeyondLastElementWithLength(swath_offset, swath.number_of_bytes);
                try self.ensureCapacity(swath_offset + swath_header_size + entry_size + swath_header_size, allow_growth);
                self.tail_swath_offset = swath_offset;
                swath = .{
                    .first_byte_in_child = remote_address,
                    .number_of_bytes = 0,
                };
            } else {
                try self.ensureCapacity(localAddressBeyondLastElementWithLength(swath_offset, swath.number_of_bytes) + local_address_excess + swath_header_size, allow_growth);

                if (local_index_excess > 1) {
                    const gap_start = entryByteOffset(swath_offset, swath.number_of_bytes);
                    const gap_len = (local_index_excess - 1) * entry_size;
                    self.zeroBytes(gap_start, gap_len);
                    swath.number_of_bytes += local_index_excess - 1;
                }
            }
        }

        var entry = OldValueAndMatchInfo{};
        entry.old_value = old_value;
        entry.setMatchInfo(match_info);
        self.writeValue(OldValueAndMatchInfo, entryByteOffset(swath_offset, swath.number_of_bytes), entry);
        swath.number_of_bytes += 1;

        if (match_info.hasAny()) {
            self.match_count += 1;
        }

        const sentinel_offset = localAddressBeyondLastElementWithLength(swath_offset, swath.number_of_bytes);
        self.used_len = sentinel_offset + swath_header_size;
        self.tail_swath_offset = swath_offset;
        self.tail_swath = swath;
        self.tail_dirty = true;
    }

    fn ensureCapacity(self: *MatchesArray, required: usize, allow_growth: bool) StorageError!void {
        if (required <= self.capacity_len) return;
        if (!allow_growth) return StorageError.ExceedsMaximumSize;

        while (required > self.capacity_len) {
            if (self.max_needed_bytes != 0 and self.capacity_len >= self.max_needed_bytes) {
                return StorageError.ExceedsMaximumSize;
            }

            var chunk_size = @min(@max(self.capacity_len, swath_header_size), max_chunk_size);
            if (self.max_needed_bytes != 0) {
                chunk_size = @min(chunk_size, self.max_needed_bytes - self.capacity_len);
            }
            if (chunk_size == 0) return StorageError.ExceedsMaximumSize;

            try self.addChunk(chunk_size);
        }
    }

    fn dataToValueAux(self: *const MatchesArray, swath_offset: usize, index: usize, swath_length: usize, match_info_bits: u16) Value {
        var result = Value{
            .data = .{ .uint64_value = 0 },
            .flags = .{},
        };

        const max_bytes: usize = @min(swath_length - index, 8);

        var flags_bits: u16 = 0xffff;
        if (max_bytes < 8) flags_bits &= ~flags64Mask();
        if (max_bytes < 4) flags_bits &= ~flags32Mask();
        if (max_bytes < 2) flags_bits &= ~flags16Mask();
        if (max_bytes < 1) flags_bits = 0;

        const start_offset = entryByteOffset(swath_offset, index);
        const total_bytes = max_bytes * entry_size;
        if (self.chunkIndexForRange(start_offset, total_bytes)) |chunk_index| {
            const chunk = self.chunks.items[chunk_index];
            const local_offset = start_offset - chunk.base;
            const entries = chunk.data[local_offset .. local_offset + total_bytes];
            var i: usize = 0;
            while (i < max_bytes) : (i += 1) {
                result.data.bytes[i] = entries[i * entry_size];
            }
        } else {
            var i: usize = 0;
            while (i < max_bytes) : (i += 1) {
                result.data.bytes[i] = self.entryAtConst(swath_offset, index + i).old_value;
            }
        }

        flags_bits &= match_info_bits;
        result.flags = @bitCast(flags_bits);
        return result;
    }

    fn swathAtConst(self: *const MatchesArray, offset: usize) SwathHeader {
        if (offset >= self.sentinelOffset()) return .{};
        if (offset == self.tail_swath_offset) return self.tail_swath;
        return self.swathFromStorage(offset);
    }

    fn swathFromStorage(self: *const MatchesArray, offset: usize) SwathHeader {
        return self.readValue(SwathHeader, offset);
    }

    fn writeSwath(self: *MatchesArray, offset: usize, swath: SwathHeader) void {
        self.writeValue(SwathHeader, offset, swath);
    }

    fn entryAtConst(self: *const MatchesArray, swath_offset: usize, index: usize) OldValueAndMatchInfo {
        const start = entryByteOffset(swath_offset, index);
        return self.readValue(OldValueAndMatchInfo, start);
    }

    fn syncTail(self: *MatchesArray) void {
        if (!self.tail_dirty) return;
        self.writeSwath(self.tail_swath_offset, self.tail_swath);
        self.writeSwath(self.sentinelOffset(), .{});
        self.tail_dirty = false;
    }

    fn addChunk(self: *MatchesArray, size: usize) StorageError!void {
        const data = self.allocator.alignedAlloc(u8, std.mem.Alignment.of(SwathHeader), size) catch return StorageError.OutOfMemory;
        errdefer self.allocator.free(data);

        self.chunks.append(self.allocator, .{
            .base = self.capacity_len,
            .data = data,
        }) catch return StorageError.OutOfMemory;
        self.capacity_len += size;
    }

    fn trimStorage(self: *MatchesArray) StorageError!void {
        while (self.chunks.items.len > 1) {
            const last_index = self.chunks.items.len - 1;
            const last = self.chunks.items[last_index];
            if (self.used_len > last.base) break;

            self.allocator.free(last.data);
            _ = self.chunks.pop();
            self.capacity_len = last.base;
        }

        const last_index = self.chunks.items.len - 1;
        var last = &self.chunks.items[last_index];
        const used_in_last = self.used_len - last.base;
        if (used_in_last == last.data.len) return;

        if (self.allocator.remap(last.data, used_in_last)) |new_data| {
            last.data = new_data;
            self.capacity_len = self.used_len;
            return;
        }

        const new_data = self.allocator.alignedAlloc(u8, std.mem.Alignment.of(SwathHeader), used_in_last) catch return StorageError.OutOfMemory;
        @memcpy(new_data, last.data[0..used_in_last]);
        self.allocator.free(last.data);
        last.data = new_data;
        self.capacity_len = self.used_len;
    }

    fn readValue(self: *const MatchesArray, comptime T: type, offset: usize) T {
        if (self.chunkIndexForRange(offset, @sizeOf(T))) |chunk_index| {
            const chunk = self.chunks.items[chunk_index];
            const local_offset = offset - chunk.base;
            return std.mem.bytesToValue(T, chunk.data[local_offset .. local_offset + @sizeOf(T)]);
        }

        var bytes: [@sizeOf(T)]u8 = undefined;
        self.readBytes(offset, &bytes);
        return std.mem.bytesToValue(T, &bytes);
    }

    fn writeValue(self: *MatchesArray, comptime T: type, offset: usize, value: T) void {
        if (self.chunkIndexForRange(offset, @sizeOf(T))) |chunk_index| {
            const chunk = &self.chunks.items[chunk_index];
            const local_offset = offset - chunk.base;
            std.mem.bytesAsValue(T, chunk.data[local_offset .. local_offset + @sizeOf(T)]).* = value;
            return;
        }

        var local = value;
        self.writeBytes(offset, std.mem.asBytes(&local));
    }

    fn readBytes(self: *const MatchesArray, offset: usize, dest: []u8) void {
        var current_offset = offset;
        var written: usize = 0;
        while (written < dest.len) {
            const chunk = self.chunks.items[self.chunkIndexForOffset(current_offset)];
            const local_offset = current_offset - chunk.base;
            const len = @min(dest.len - written, chunk.data.len - local_offset);
            @memcpy(dest[written .. written + len], chunk.data[local_offset .. local_offset + len]);
            current_offset += len;
            written += len;
        }
    }

    fn writeBytes(self: *MatchesArray, offset: usize, bytes: []const u8) void {
        var current_offset = offset;
        var read: usize = 0;
        while (read < bytes.len) {
            const chunk = &self.chunks.items[self.chunkIndexForOffset(current_offset)];
            const local_offset = current_offset - chunk.base;
            const len = @min(bytes.len - read, chunk.data.len - local_offset);
            @memcpy(chunk.data[local_offset .. local_offset + len], bytes[read .. read + len]);
            current_offset += len;
            read += len;
        }
    }

    fn zeroBytes(self: *MatchesArray, offset: usize, len: usize) void {
        var current_offset = offset;
        var zeroed: usize = 0;
        while (zeroed < len) {
            const chunk = &self.chunks.items[self.chunkIndexForOffset(current_offset)];
            const local_offset = current_offset - chunk.base;
            const part_len = @min(len - zeroed, chunk.data.len - local_offset);
            @memset(chunk.data[local_offset .. local_offset + part_len], 0);
            current_offset += part_len;
            zeroed += part_len;
        }
    }

    fn chunkIndexForOffset(self: *const MatchesArray, offset: usize) usize {
        std.debug.assert(offset < self.capacity_len);

        const first = self.chunks.items[0];
        if (offset < first.data.len) return 0;

        const last_index = self.chunks.items.len - 1;
        const last = self.chunks.items[last_index];
        if (offset >= last.base) return last_index;

        var low: usize = 0;
        var high: usize = self.chunks.items.len;
        while (low < high) {
            const mid = low + (high - low) / 2;
            const chunk = self.chunks.items[mid];
            if (offset < chunk.base) {
                high = mid;
            } else if (offset >= chunk.base + chunk.data.len) {
                low = mid + 1;
            } else {
                return mid;
            }
        }

        unreachable;
    }

    fn chunkIndexForRange(self: *const MatchesArray, offset: usize, len: usize) ?usize {
        const chunk_index = self.chunkIndexForOffset(offset);
        const chunk = self.chunks.items[chunk_index];
        if (offset + len <= chunk.base + chunk.data.len) return chunk_index;
        return null;
    }

    fn localAddressBeyondLastElement(self: *const MatchesArray, swath_offset: usize) usize {
        const swath = self.swathAtConst(swath_offset);
        return localAddressBeyondLastElementWithLength(swath_offset, swath.number_of_bytes);
    }

    fn sentinelOffset(self: *const MatchesArray) usize {
        return self.used_len - swath_header_size;
    }

    fn remoteAddressOfNthElement(self: *const MatchesArray, swath_offset: usize, index: usize) usize {
        const swath = self.swathAtConst(swath_offset);
        return swath.first_byte_in_child + index;
    }
};

inline fn entryByteOffset(swath_offset: usize, index: usize) usize {
    return swath_offset + MatchesArray.swath_header_size + index * MatchesArray.entry_size;
}

inline fn localAddressBeyondLastElementWithLength(swath_offset: usize, length: usize) usize {
    return swath_offset + MatchesArray.swath_header_size + length * MatchesArray.entry_size;
}

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
    try std.testing.expectEqual(3, @sizeOf(OldValueAndMatchInfo));

    var matches = try MatchesArray.init(std.testing.allocator, 256);
    defer matches.deinit();

    try matches.append(0x1000, 0xaa, .{ .u8b = true });
    try matches.append(0x1001, 0xbb, .{ .u8b = true });
    try matches.append(0x1003, 0xcc, .{ .u8b = true });

    try std.testing.expectEqual(3, matches.matchCount());
    try std.testing.expectEqual(4, matches.storedByteCount());
    try std.testing.expectEqual(4, matches.swathAtConst(0).number_of_bytes);
    try std.testing.expectEqual(0x1000, matches.swathAtConst(0).first_byte_in_child);
    try std.testing.expectEqual(0xaa, matches.entryAtConst(0, 0).old_value);
    try std.testing.expectEqual(0xbb, matches.entryAtConst(0, 1).old_value);
    try std.testing.expectEqual(0, matches.entryAtConst(0, 2).match_info_bits);
    try std.testing.expectEqual(0, matches.entryAtConst(0, 2).old_value);
    try std.testing.expectEqual(0xcc, matches.entryAtConst(0, 3).old_value);
    try std.testing.expectEqual(0, matches.swathAtConst(matches.localAddressBeyondLastElement(0)).first_byte_in_child);
}

test "append: starts a new swath when gap padding reaches header cost" {
    var matches = try MatchesArray.init(std.testing.allocator, 256);
    defer matches.deinit();

    try matches.append(0x2000, 0x11, .{ .u8b = true });
    try matches.append(0x2007, 0x22, .{ .u8b = true });

    const first_swath = matches.swathAtConst(0);
    try std.testing.expectEqual(0x2000, first_swath.first_byte_in_child);
    try std.testing.expectEqual(1, first_swath.number_of_bytes);

    const second_swath_offset = matches.localAddressBeyondLastElement(0);
    const second_swath = matches.swathAtConst(second_swath_offset);
    try std.testing.expectEqual(0x2007, second_swath.first_byte_in_child);
    try std.testing.expectEqual(1, second_swath.number_of_bytes);
    try std.testing.expectEqual(2, matches.matchCount());
    try std.testing.expectEqual(0, matches.swathAtConst(matches.localAddressBeyondLastElement(second_swath_offset)).first_byte_in_child);
}

test "nthMatch: skips padded entries" {
    var matches = try MatchesArray.init(std.testing.allocator, 256);
    defer matches.deinit();

    try matches.append(0x3000, 0x10, .{ .u8b = true });
    try matches.append(0x3002, 0x20, .{ .u8b = true });

    const first = matches.nthMatch(0).?;
    const second = matches.nthMatch(1).?;

    try std.testing.expectEqual(0x3000, first.remoteAddress(&matches));
    try std.testing.expectEqual(0x3002, second.remoteAddress(&matches));
    try std.testing.expectEqual(0, matches.entryAtConst(0, 1).match_info_bits);
    try std.testing.expect(matches.nthMatch(2) == null);
    try std.testing.expectEqual(0, matches.findMatchIndexByAddress(0x3000).?);
    try std.testing.expectEqual(1, matches.findMatchIndexByAddress(0x3002));
    try std.testing.expectEqual(null, matches.findMatchIndexByAddress(0x3001));
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

    try std.testing.expectEqual(2, matches.matchCount());
    const first = matches.nthMatch(0).?;
    const second = matches.nthMatch(1).?;
    try std.testing.expectEqual(0x4000, first.remoteAddress(&matches));
    try std.testing.expectEqual(0x4006, second.remoteAddress(&matches));
    try std.testing.expect(matches.nthMatch(2) == null);
    try std.testing.expectEqual(0x01, first.value(&matches).data.uint8_value);
    try std.testing.expectEqual(0x04, second.value(&matches).data.uint8_value);
    try std.testing.expectEqual(null, matches.findMatchIndexByAddress(0x4001));
    try std.testing.expectEqual(null, matches.findMatchIndexByAddress(0x4005));
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

    try std.testing.expectEqual(1023, matches.matchCount());
    try std.testing.expectEqual(0x5000, matches.nthMatch(0).?.remoteAddress(&matches));
    try std.testing.expectEqual(0x5000 + 4 * 399, matches.nthMatch(399).?.remoteAddress(&matches));
    try std.testing.expectEqual(0x5000 + 4 * 401, matches.nthMatch(400).?.remoteAddress(&matches));
    try std.testing.expectEqual(0x5000 + 4 * 1023, matches.nthMatch(1022).?.remoteAddress(&matches));
    try std.testing.expect(matches.nthMatch(1023) == null);
    try std.testing.expectEqual(null, matches.findMatchIndexByAddress(0x5000 + 4 * 400));
}

test "dataToValue: truncates width flags by remaining bytes" {
    var matches = try MatchesArray.init(std.testing.allocator, 256);
    defer matches.deinit();

    try matches.append(0x5000, 0x78, .{ .u32b = true, .s32b = true, .u16b = true, .s16b = true, .u8b = true, .s8b = true });
    try matches.append(0x5001, 0x56, .{});
    try matches.append(0x5002, 0x34, .{});

    const value = matches.dataToValue(0, 0);
    try std.testing.expectEqual((MatchFlags{ .u8b = true, .s8b = true, .u16b = true, .s16b = true }).bits(), value.flags.bits());
    try std.testing.expectEqual(0x78, value.data.bytes[0]);
    try std.testing.expectEqual(0x56, value.data.bytes[1]);
    try std.testing.expectEqual(0x34, value.data.bytes[2]);
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
    try std.testing.expectEqual((MatchFlags{ .u64b = true }).bits(), value.flags.bits());
    try std.testing.expectEqual(0x5A17D3C49E2B6F10, value.data.uint64_value);
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
