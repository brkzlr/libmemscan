//! Dense compressed match storage.

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

const max_chunk_size: usize = 16 * 1024 * 1024;
const max_segment_payload: usize = 2 * 1024 * 1024;
const max_gap_padding_bytes: usize = 24;
const exception_entry_size: usize = 6; // u32 candidate index + u16 raw bits
const max_indexed_raw_bits: usize = 255;

pub const DenseLayout = enum(u8) {
    shared_raw_bits = 0,
    inline_raw_bits = 1,
    dual_raw_bits = 2,
    indexed_raw_bits = 3,
};

/// Encoded header for a contiguous range of stored bytes.
/// Payload follows immediately after the header in storage:
///   shared_raw_bits layout:
///     old_values[number_of_bytes] u8
///     match_bitmap[ceil(candidate_count / 8)] u8       (bit set => candidate is a match)
///     exceptions[exception_count] { u32 candidate_idx, u16 raw_bits } (sorted by candidate_idx)
///   dual_raw_bits layout:
///     old_values[number_of_bytes] u8
///     match_bitmap_a[ceil(candidate_count / 8)] u8     (bit set => shared_raw_bits)
///     match_bitmap_b[ceil(candidate_count / 8)] u8     (bit set => exception_count as u16)
///   indexed_raw_bits layout:
///     old_values[number_of_bytes] u8
///     raw_bits_table[exception_count] u16
///     raw_bits_index[ceil(candidate_count * bits_per_index / 8)] bit-packed
///       (0 => no match, otherwise table index + 1; bits_per_index inferred from exception_count)
///   inline_raw_bits layout:
///     old_values[number_of_bytes] u8
///     raw_bits_inline[candidate_count] u16             (0 => no match)
pub const SwathHeader = extern struct {
    first_byte_in_child: usize = 0,
    number_of_bytes: usize = 0,
    match_count: usize = 0,
    exception_count: u32 = 0,
    shared_raw_bits: u16 = 0,
    layout: DenseLayout = .shared_raw_bits,
};

pub const MatchLocation = struct {
    swath_offset: usize,
    index: usize,
    address: usize,
    raw_match_info_bits: u16,

    pub fn value(self: MatchLocation, matches: *const MatchesArray) Value {
        var result = Value{};
        const max_bytes = matches.readStoredBytes(self.swath_offset, self.index, result.data.bytes[0..]).len;

        var flags_bits: u16 = 0xffff;
        if (max_bytes < 8) flags_bits &= ~flags64_mask;
        if (max_bytes < 4) flags_bits &= ~flags32_mask;
        if (max_bytes < 2) flags_bits &= ~flags16_mask;
        if (max_bytes < 1) flags_bits = 0;

        flags_bits &= self.raw_match_info_bits;
        result.flags = @bitCast(flags_bits);
        return result;
    }
};

pub const MatchIterator = struct {
    matches: *const MatchesArray,
    swath_offset: usize = 0,
    header: SwathHeader = .{},
    header_loaded: bool = false,
    first_candidate: usize = 0,
    candidate_count: usize = 0,
    full_shared_raw_bits: u16 = 0,
    candidate_index: usize = 0,

    pub fn next(self: *MatchIterator) ?MatchLocation {
        while (true) {
            if (self.swath_offset >= self.matches.used_len) return null;

            if (!self.header_loaded) {
                self.header = self.matches.readSwathHeader(self.swath_offset);
                self.header_loaded = true;
                if (self.header.match_count == 0) {
                    self.swath_offset += self.matches.swathByteSize(self.header);
                    self.header_loaded = false;
                    continue;
                }
                self.first_candidate = alignForwardStride(self.header.first_byte_in_child, self.matches.stride);
                self.candidate_count = candidateCount(self.header.first_byte_in_child, self.header.number_of_bytes, self.matches.stride);
                self.full_shared_raw_bits = if (self.header.layout == .shared_raw_bits and self.header.exception_count == 0 and self.header.match_count == self.candidate_count)
                    self.header.shared_raw_bits
                else
                    0;
                self.candidate_index = 0;
            }

            while (self.candidate_index < self.candidate_count) {
                const raw_bits = if (self.full_shared_raw_bits != 0)
                    self.full_shared_raw_bits
                else
                    self.matches.rawBitsAtCandidate(self.swath_offset, self.header, self.candidate_index);
                if (raw_bits != 0) {
                    const addr = self.first_candidate + self.candidate_index * self.matches.stride;
                    const byte_index = addr - self.header.first_byte_in_child;
                    self.candidate_index += 1;
                    return .{
                        .swath_offset = self.swath_offset,
                        .index = byte_index,
                        .address = addr,
                        .raw_match_info_bits = raw_bits,
                    };
                }
                self.candidate_index += 1;
            }

            self.swath_offset += self.matches.swathByteSize(self.header);
            self.header_loaded = false;
        }
    }
};

pub const SegmentView = struct {
    swath_offset: usize,
    end_offset: usize,
    header: SwathHeader,
    first_candidate: usize,
    candidate_count: usize,
};

pub const SegmentIterator = struct {
    matches: *const MatchesArray,
    swath_offset: usize = 0,

    pub fn next(self: *SegmentIterator) ?SegmentView {
        if (self.swath_offset >= self.matches.used_len) return null;

        const swath_offset = self.swath_offset;
        const header = self.matches.readSwathHeader(swath_offset);
        const next_offset = swath_offset + self.matches.swathByteSize(header);
        self.swath_offset = next_offset;

        return .{
            .swath_offset = swath_offset,
            .end_offset = next_offset,
            .header = header,
            .first_candidate = alignForwardStride(header.first_byte_in_child, self.matches.stride),
            .candidate_count = candidateCount(header.first_byte_in_child, header.number_of_bytes, self.matches.stride),
        };
    }
};

pub const StoredByte = struct {
    address: usize,
    old_value: u8,
    raw_match_info_bits: u16,
};

pub const StoredByteIterator = struct {
    matches: *const MatchesArray,
    swath_offset: usize = 0,
    header: SwathHeader = .{},
    header_loaded: bool = false,
    index: usize = 0,

    pub fn next(self: *StoredByteIterator) ?StoredByte {
        while (true) {
            if (self.swath_offset >= self.matches.used_len) return null;

            if (!self.header_loaded) {
                self.header = self.matches.readSwathHeader(self.swath_offset);
                self.header_loaded = true;
                self.index = 0;
            }

            if (self.index < self.header.number_of_bytes) {
                const address = self.header.first_byte_in_child + self.index;
                const raw_bits = blk: {
                    if (address % self.matches.stride != 0) break :blk 0;
                    const first_cand = alignForwardStride(self.header.first_byte_in_child, self.matches.stride);
                    if (address < first_cand) break :blk 0;
                    break :blk self.matches.rawBitsAtCandidate(self.swath_offset, self.header, (address - first_cand) / self.matches.stride);
                };
                const item = StoredByte{
                    .address = address,
                    .old_value = self.matches.readU8(self.swath_offset + @sizeOf(SwathHeader) + self.index),
                    .raw_match_info_bits = raw_bits,
                };
                self.index += 1;
                return item;
            }

            self.swath_offset += self.matches.swathByteSize(self.header);
            self.header_loaded = false;
        }
    }
};

const SegmentBuilder = struct {
    base_address: usize = 0,
    has_data: bool = false,
    match_count: usize = 0,
    old_values: std.ArrayList(u8) = .empty,
    candidate_raw_bits: std.ArrayList(u16) = .empty,
    bitmap_scratch: std.ArrayList(u8) = .empty,

    fn deinit(self: *SegmentBuilder, allocator: Allocator) void {
        self.old_values.deinit(allocator);
        self.candidate_raw_bits.deinit(allocator);
        self.bitmap_scratch.deinit(allocator);
    }

    fn reset(self: *SegmentBuilder) void {
        self.base_address = 0;
        self.has_data = false;
        self.match_count = 0;
        self.old_values.clearRetainingCapacity();
        self.candidate_raw_bits.clearRetainingCapacity();
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
    stride: u16,
    match_count: usize,
    builder: SegmentBuilder,

    pub fn init(allocator: Allocator, max_needed_bytes: usize, stride: u16) StorageError!MatchesArray {
        std.debug.assert(stride != 0);
        return .{
            .allocator = allocator,
            .chunks = .empty,
            .capacity_len = 0,
            .used_len = 0,
            .max_needed_bytes = max_needed_bytes,
            .stride = stride,
            .match_count = 0,
            .builder = .{},
        };
    }

    pub fn deinit(self: *MatchesArray) void {
        for (self.chunks.items) |chunk| {
            self.allocator.free(chunk.data);
        }
        self.chunks.deinit(self.allocator);
        self.builder.deinit(self.allocator);
        self.* = undefined;
    }

    pub fn append(self: *MatchesArray, remote_address: usize, old_value: u8, match_info: MatchFlags) StorageError!void {
        try self.appendRaw(remote_address, old_value, match_info.bits());
    }

    pub fn appendRaw(self: *MatchesArray, remote_address: usize, old_value: u8, raw_bits: u16) StorageError!void {
        try self.prepareAppend(remote_address);

        self.builder.old_values.append(self.allocator, old_value) catch return StorageError.OutOfMemory;

        if (raw_bits != 0 and remote_address % self.stride == 0) {
            const first_cand = alignForwardStride(self.builder.base_address, self.stride);
            std.debug.assert(remote_address >= first_cand);
            const cand_index = (remote_address - first_cand) / self.stride;
            if (self.builder.candidate_raw_bits.items.len < cand_index) {
                self.builder.candidate_raw_bits.appendNTimes(self.allocator, 0, cand_index - self.builder.candidate_raw_bits.items.len) catch return StorageError.OutOfMemory;
            }
            std.debug.assert(self.builder.candidate_raw_bits.items.len == cand_index);
            self.builder.candidate_raw_bits.append(self.allocator, raw_bits) catch return StorageError.OutOfMemory;
            self.builder.match_count += 1;
        }

        if (self.builder.old_values.items.len >= max_segment_payload) {
            try self.flushBuilder();
        }
    }

    pub fn appendRun(self: *MatchesArray, remote_address: usize, old_values: []const u8, raw_bits: u16, match_candidate_count: usize) StorageError!void {
        if (old_values.len == 0) return;
        std.debug.assert(raw_bits != 0 or match_candidate_count == 0);

        if (!self.builder.has_data and raw_bits != 0 and match_candidate_count != 0) {
            return self.appendSharedRun(remote_address, old_values, raw_bits, match_candidate_count);
        }

        var consumed: usize = 0;
        var candidates_seen: usize = 0;
        while (consumed < old_values.len) {
            const address = remote_address + consumed;
            try self.prepareAppend(address);

            const len = @min(old_values.len - consumed, max_segment_payload - self.builder.old_values.items.len);
            self.builder.old_values.appendSlice(self.allocator, old_values[consumed .. consumed + len]) catch return StorageError.OutOfMemory;

            if (candidates_seen < match_candidate_count) {
                const cand_count = candidateCount(address, len, self.stride);
                const matched = @min(cand_count, match_candidate_count - candidates_seen);
                if (matched > 0) {
                    const first_builder_cand = alignForwardStride(self.builder.base_address, self.stride);
                    const first_run_cand = alignForwardStride(address, self.stride);
                    const cand_index = (first_run_cand - first_builder_cand) / self.stride;
                    const missing = cand_index -| self.builder.candidate_raw_bits.items.len;
                    self.builder.candidate_raw_bits.appendNTimes(self.allocator, 0, missing) catch return StorageError.OutOfMemory;
                    std.debug.assert(self.builder.candidate_raw_bits.items.len == cand_index);
                    self.builder.candidate_raw_bits.appendNTimes(self.allocator, raw_bits, matched) catch return StorageError.OutOfMemory;
                    self.builder.match_count += matched;
                }
                candidates_seen += cand_count;
            }

            consumed += len;
            if (self.builder.old_values.items.len >= max_segment_payload) {
                try self.flushBuilder();
            }
        }
    }

    pub fn appendRescanBatch(self: *MatchesArray, remote_address: usize, old_values: []const u8, raw_bits_per_candidate: []const u16) StorageError!void {
        if (old_values.len == 0) return;
        std.debug.assert(raw_bits_per_candidate.len <= candidateCount(remote_address, old_values.len, self.stride));

        var consumed_bytes: usize = 0;
        var consumed_candidates: usize = 0;
        while (consumed_bytes < old_values.len) {
            const address = remote_address + consumed_bytes;
            try self.prepareAppend(address);

            const len = @min(old_values.len - consumed_bytes, max_segment_payload - self.builder.old_values.items.len);
            self.builder.old_values.appendSlice(self.allocator, old_values[consumed_bytes .. consumed_bytes + len]) catch return StorageError.OutOfMemory;

            const cand_count = candidateCount(address, len, self.stride);
            const available = if (consumed_candidates < raw_bits_per_candidate.len) raw_bits_per_candidate.len - consumed_candidates else 0;
            const emit_count = @min(cand_count, available);
            if (emit_count > 0) {
                const first_builder_cand = alignForwardStride(self.builder.base_address, self.stride);
                const first_batch_cand = alignForwardStride(address, self.stride);
                const cand_index = (first_batch_cand - first_builder_cand) / self.stride;
                const missing = cand_index -| self.builder.candidate_raw_bits.items.len;
                self.builder.candidate_raw_bits.appendNTimes(self.allocator, 0, missing) catch return StorageError.OutOfMemory;
                std.debug.assert(self.builder.candidate_raw_bits.items.len == cand_index);

                const raw_bits = raw_bits_per_candidate[consumed_candidates .. consumed_candidates + emit_count];
                self.builder.candidate_raw_bits.appendSlice(self.allocator, raw_bits) catch return StorageError.OutOfMemory;
                for (raw_bits) |bits| {
                    if (bits != 0) self.builder.match_count += 1;
                }
            }

            consumed_bytes += len;
            consumed_candidates += cand_count;
            if (self.builder.old_values.items.len >= max_segment_payload) {
                try self.flushBuilder();
            }
        }
    }

    pub fn finalize(self: *MatchesArray) StorageError!void {
        try self.flushBuilder();
        try self.trimStorage();
        self.builder.deinit(self.allocator);
        self.builder = .{};
    }

    pub fn matchCount(self: *const MatchesArray) usize {
        return self.match_count;
    }

    pub fn iterator(self: *const MatchesArray) MatchIterator {
        return .{ .matches = self };
    }

    pub fn iteratorFrom(self: *const MatchesArray, swath_offset: usize) MatchIterator {
        return .{ .matches = self, .swath_offset = swath_offset };
    }

    pub fn segmentIterator(self: *const MatchesArray) SegmentIterator {
        return .{ .matches = self };
    }

    pub fn storedByteIterator(self: *const MatchesArray) StoredByteIterator {
        return .{ .matches = self };
    }

    pub fn storedByteCount(self: *const MatchesArray) usize {
        var count: usize = 0;
        var offset: usize = 0;
        while (offset < self.used_len) {
            const header = self.readSwathHeader(offset);
            count += header.number_of_bytes;
            offset += self.swathByteSize(header);
        }
        return count;
    }

    /// Drop whole storage chunks that end before "offset".
    /// Only use when no future read will touch earlier offsets as the logical offsets stay stable.
    pub fn releaseStorageBefore(self: *MatchesArray, offset: usize) void {
        while (self.chunks.items.len > 0 and self.chunks.items[0].base + self.chunks.items[0].data.len <= offset) {
            const chunk = self.chunks.items[0];
            self.allocator.free(chunk.data);
            std.mem.copyForwards(Chunk, self.chunks.items[0 .. self.chunks.items.len - 1], self.chunks.items[1..]);
            _ = self.chunks.pop();
        }
    }

    pub fn nthMatch(self: *const MatchesArray, n: usize) ?MatchLocation {
        var seen: usize = 0;
        var iter = self.iterator();
        while (iter.next()) |loc| : (seen += 1) {
            if (seen == n) return loc;
        }
        return null;
    }

    pub fn findMatchIndexByAddress(self: *const MatchesArray, address: usize) ?usize {
        var iter = self.iterator();
        var index: usize = 0;
        while (iter.next()) |loc| : (index += 1) {
            if (loc.address == address) return index;
        }
        return null;
    }

    pub fn deleteInAddressRange(self: *MatchesArray, start_address: usize, end_address: usize) StorageError!void {
        var new_matches = try MatchesArray.init(self.allocator, self.max_needed_bytes, self.stride);
        errdefer new_matches.deinit();

        var iter = self.storedByteIterator();
        while (iter.next()) |stored| {
            if (stored.address >= start_address and stored.address < end_address) continue;
            try new_matches.appendRaw(stored.address, stored.old_value, stored.raw_match_info_bits);
        }
        try new_matches.finalize();

        var old = self.*;
        self.* = new_matches;
        old.deinit();
    }

    pub fn dataToBytes(self: *const MatchesArray, swath_offset: usize, index: usize, byte_length: usize, buf: []u8) []const u8 {
        return self.readStoredBytes(swath_offset, index, buf[0..@min(byte_length, buf.len)]);
    }

    /// Safe during forward iteration when removing only the match just returned by that iterator.
    /// Clearing future matches can invalidate iterator caches.
    pub fn removeMatch(self: *MatchesArray, location: MatchLocation) void {
        const header = self.readSwathHeader(location.swath_offset);
        const addr = header.first_byte_in_child + location.index;
        if (addr % self.stride != 0) return;
        const first_cand = alignForwardStride(header.first_byte_in_child, self.stride);
        if (addr < first_cand) return;
        const cand_index = (addr - first_cand) / self.stride;

        const payload_offset = location.swath_offset + @sizeOf(SwathHeader) + header.number_of_bytes;
        switch (header.layout) {
            .shared_raw_bits => {
                const byte_offset = payload_offset + cand_index / 8;
                const bit_idx: u3 = @truncate(cand_index);
                const one: u8 = 1;
                const mask = one << bit_idx;
                const chunk = &self.chunks.items[self.chunkIndexForOffset(byte_offset)];
                const local = byte_offset - chunk.base;
                if ((chunk.data[local] & mask) == 0) return;
                chunk.data[local] = chunk.data[local] & ~mask;
            },
            .inline_raw_bits => {
                const slot_offset = payload_offset + 2 * cand_index;
                if (self.readU16(slot_offset) == 0) return;
                self.writeBytes(slot_offset, &[_]u8{ 0, 0 });
            },
            .dual_raw_bits => {
                const bitmap_size = (candidateCount(header.first_byte_in_child, header.number_of_bytes, self.stride) + 7) / 8;
                const byte_offset = payload_offset + cand_index / 8;
                const bit_idx: u3 = @truncate(cand_index);
                const one: u8 = 1;
                const mask = one << bit_idx;
                const first = self.readU8(byte_offset);
                if ((first & mask) != 0) {
                    self.writeBytes(byte_offset, &[_]u8{first & ~mask});
                } else {
                    const second_offset = byte_offset + bitmap_size;
                    const second = self.readU8(second_offset);
                    if ((second & mask) == 0) return;
                    self.writeBytes(second_offset, &[_]u8{second & ~mask});
                }
            },
            .indexed_raw_bits => {
                const index_offset = payload_offset + header.exception_count * 2;
                const bit_width = indexedBitsPerCandidate(header.exception_count);
                const bit_offset = cand_index * bit_width;
                const byte_offset = index_offset + bit_offset / 8;
                const shift: u4 = @intCast(bit_offset & 7);
                const raw_index = self.readPackedIndex(index_offset, cand_index, bit_width);
                if (raw_index == 0) return;

                const width_shift: u4 = @intCast(bit_width);
                const one: u16 = 1;
                const clear_mask: u16 = ~(((one << width_shift) - 1) << shift);
                const first_mask: u8 = @truncate(clear_mask);
                const first = self.readU8(byte_offset) & first_mask;
                self.writeBytes(byte_offset, &[_]u8{first});
                const shift_usize: usize = shift;
                if (shift_usize + bit_width > 8) {
                    const second_mask: u8 = @truncate(clear_mask >> 8);
                    const second = self.readU8(byte_offset + 1) & second_mask;
                    self.writeBytes(byte_offset + 1, &[_]u8{second});
                }
            },
        }

        var new_match_count = header.match_count - 1;
        self.writeBytes(location.swath_offset + @offsetOf(SwathHeader, "match_count"), std.mem.asBytes(&new_match_count));
        self.match_count -= 1;
    }

    /// Used by undo restore: discard everything and resize storage to hold "used_len" bytes.
    pub fn resetForStorageLoad(self: *MatchesArray, used_len: usize, max_needed_bytes: usize, match_count: usize) StorageError!void {
        self.max_needed_bytes = max_needed_bytes;
        try self.ensureCapacity(used_len);
        self.used_len = used_len;
        self.match_count = match_count;
        self.builder.reset();
    }

    pub fn validate(self: *const MatchesArray) StorageError!void {
        var offset: usize = 0;
        var total_match_count: usize = 0;
        while (offset < self.used_len) {
            if (offset + @sizeOf(SwathHeader) > self.used_len) return StorageError.ExceedsMaximumSize;
            const header = self.readSwathHeader(offset);
            const cand_count = candidateCount(header.first_byte_in_child, header.number_of_bytes, self.stride);
            const payload_offset = offset + @sizeOf(SwathHeader) + header.number_of_bytes;

            var counted: usize = 0;
            switch (header.layout) {
                .shared_raw_bits => {
                    for (0..cand_count) |i| {
                        const bit_idx: u3 = @truncate(i);
                        const one: u8 = 1;
                        const mask = one << bit_idx;
                        const bitmap_byte = self.readU8(payload_offset + i / 8);
                        if ((bitmap_byte & mask) != 0) counted += 1;
                    }
                },
                .inline_raw_bits => {
                    for (0..cand_count) |i| {
                        if (self.readU16(payload_offset + 2 * i) != 0) counted += 1;
                    }
                },
                .dual_raw_bits => {
                    const bitmap_size = (cand_count + 7) / 8;
                    for (0..cand_count) |i| {
                        const bit_idx: u3 = @truncate(i);
                        const one: u8 = 1;
                        const mask = one << bit_idx;
                        if ((self.readU8(payload_offset + i / 8) & mask) != 0) counted += 1;
                        if ((self.readU8(payload_offset + bitmap_size + i / 8) & mask) != 0) counted += 1;
                    }
                },
                .indexed_raw_bits => {
                    if (header.exception_count == 0 or header.exception_count > max_indexed_raw_bits) return StorageError.ExceedsMaximumSize;
                    for (0..header.exception_count) |i| {
                        const bits = self.readU16(payload_offset + 2 * i);
                        if (bits == 0) return StorageError.ExceedsMaximumSize;
                        for (0..i) |j| {
                            if (bits == self.readU16(payload_offset + 2 * j)) return StorageError.ExceedsMaximumSize;
                        }
                    }

                    const index_offset = payload_offset + header.exception_count * 2;
                    const bit_width = indexedBitsPerCandidate(header.exception_count);
                    for (0..cand_count) |i| {
                        const raw_index = self.readPackedIndex(index_offset, i, bit_width);
                        if (raw_index == 0) continue;
                        if (raw_index > header.exception_count) return StorageError.ExceedsMaximumSize;
                        counted += 1;
                    }
                },
            }
            if (counted != header.match_count) return StorageError.ExceedsMaximumSize;
            total_match_count += header.match_count;
            offset += self.swathByteSize(header);
        }
        if (offset != self.used_len) return StorageError.ExceedsMaximumSize;
        if (total_match_count != self.match_count) return StorageError.ExceedsMaximumSize;
    }

    // -----------------------------------------------------------------------
    // Internals
    // -----------------------------------------------------------------------

    fn prepareAppend(self: *MatchesArray, remote_address: usize) StorageError!void {
        if (!self.builder.has_data) {
            self.builder.base_address = remote_address;
            self.builder.has_data = true;
            return;
        }

        const last_addr = self.builder.base_address + self.builder.old_values.items.len - 1;
        std.debug.assert(remote_address > last_addr);
        const gap_bytes = remote_address - last_addr - 1;
        if (gap_bytes >= max_gap_padding_bytes) {
            try self.flushBuilder();
            self.builder.base_address = remote_address;
            self.builder.has_data = true;
        } else if (gap_bytes > 0) {
            self.builder.old_values.appendNTimes(self.allocator, 0, gap_bytes) catch return StorageError.OutOfMemory;
            if (self.builder.old_values.items.len >= max_segment_payload) {
                try self.flushBuilder();
                self.builder.base_address = remote_address;
                self.builder.has_data = true;
            }
        }
    }

    fn readStoredBytes(self: *const MatchesArray, swath_offset: usize, index: usize, dest: []u8) []const u8 {
        var current_offset = swath_offset;
        var current_index = index;
        var written: usize = 0;

        while (written < dest.len and current_offset < self.used_len) {
            const header = self.readSwathHeader(current_offset);
            if (current_index >= header.number_of_bytes) break;

            const available = @min(header.number_of_bytes - current_index, dest.len - written);
            self.readBytes(current_offset + @sizeOf(SwathHeader) + current_index, dest[written .. written + available]);
            written += available;
            if (written == dest.len) break;

            const next_offset = current_offset + self.swathByteSize(header);
            if (next_offset >= self.used_len) break;
            const next_header = self.readSwathHeader(next_offset);
            if (next_header.first_byte_in_child != header.first_byte_in_child + header.number_of_bytes) break;

            current_offset = next_offset;
            current_index = 0;
        }

        return dest[0..written];
    }

    fn flushBuilder(self: *MatchesArray) StorageError!void {
        if (!self.builder.has_data) return;

        const number_of_bytes = self.builder.old_values.items.len;
        const cand_count = candidateCount(self.builder.base_address, number_of_bytes, self.stride);

        const missing = cand_count -| self.builder.candidate_raw_bits.items.len;
        self.builder.candidate_raw_bits.appendNTimes(self.allocator, 0, missing) catch return StorageError.OutOfMemory;

        const candidates = self.builder.candidate_raw_bits.items[0..cand_count];
        const mode = pickSharedRawBits(candidates);
        const bitmap_size = (cand_count + 7) / 8;
        const shared_payload = number_of_bytes + bitmap_size + exception_entry_size * mode.exception_count;
        const inline_payload = number_of_bytes + 2 * cand_count;
        var layout: DenseLayout = .shared_raw_bits;
        var payload_size = shared_payload;
        var dual_first: u16 = 0;
        var dual_second: u16 = 0;
        var raw_values: [max_indexed_raw_bits]u16 = undefined;
        var raw_index_by_bits: [std.math.maxInt(u16) + 1]u8 = undefined;
        var raw_count: usize = 0;
        var raw_overflow = false;
        if (mode.exception_count > 0) {
            var dual_possible = true;
            for (candidates) |bits| {
                if (bits == 0) continue;
                if (dual_first == 0) {
                    dual_first = bits;
                } else if (bits != dual_first and dual_second == 0) {
                    dual_second = bits;
                } else if (bits != dual_first and bits != dual_second) {
                    dual_possible = false;
                    break;
                }
            }
            if (dual_possible and dual_second != 0) {
                const dual_payload = number_of_bytes + 2 * bitmap_size;
                if (dual_payload < payload_size) {
                    layout = .dual_raw_bits;
                    payload_size = dual_payload;
                }
            } else if (!dual_possible) {
                @memset(raw_index_by_bits[0..], 0);
                for (candidates) |bits| {
                    if (bits == 0 or raw_index_by_bits[bits] != 0) continue;
                    if (raw_count == max_indexed_raw_bits) {
                        raw_overflow = true;
                        break;
                    }
                    raw_values[raw_count] = bits;
                    raw_index_by_bits[bits] = @intCast(raw_count + 1);
                    raw_count += 1;
                }
                if (!raw_overflow and raw_count != 0) {
                    const indexed_payload = number_of_bytes + raw_count * 2 + packedIndexByteSize(cand_count, raw_count);
                    if (indexed_payload < payload_size) {
                        layout = .indexed_raw_bits;
                        payload_size = indexed_payload;
                    }
                }
            }
        }
        if (inline_payload < payload_size) {
            layout = .inline_raw_bits;
            payload_size = inline_payload;
        }
        const encoded_size = std.mem.alignForward(usize, @sizeOf(SwathHeader) + payload_size, @alignOf(SwathHeader));

        try self.ensureCapacity(self.used_len + encoded_size);

        const swath_offset = self.used_len;
        const header = SwathHeader{
            .first_byte_in_child = self.builder.base_address,
            .number_of_bytes = number_of_bytes,
            .match_count = self.builder.match_count,
            .exception_count = switch (layout) {
                .shared_raw_bits => mode.exception_count,
                .dual_raw_bits => dual_second,
                .indexed_raw_bits => @intCast(raw_count),
                .inline_raw_bits => 0,
            },
            .shared_raw_bits = switch (layout) {
                .shared_raw_bits => mode.shared,
                .dual_raw_bits => dual_first,
                .indexed_raw_bits => 0,
                .inline_raw_bits => 0,
            },
            .layout = layout,
        };
        self.writeBytes(swath_offset, std.mem.asBytes(&header));
        self.writeBytes(swath_offset + @sizeOf(SwathHeader), self.builder.old_values.items);

        const payload_offset = swath_offset + @sizeOf(SwathHeader) + number_of_bytes;
        switch (layout) {
            .inline_raw_bits => self.writeBytes(payload_offset, std.mem.sliceAsBytes(candidates)),
            .shared_raw_bits => {
                const bitmap = &self.builder.bitmap_scratch;
                bitmap.resize(self.allocator, bitmap_size) catch return StorageError.OutOfMemory;
                // Fast-fill for fully-dense MATCHANY-style segments: every
                // candidate matches the shared value, so every bit is set.
                if (mode.total_nonzero == cand_count) {
                    @memset(bitmap.items, 0xFF);
                    const trailing = cand_count & 7;
                    if (trailing != 0) {
                        const one: u8 = 1;
                        const trailing_mask = (one << @intCast(trailing)) - 1;
                        bitmap.items[bitmap_size - 1] = trailing_mask;
                    }
                } else {
                    @memset(bitmap.items, 0);
                    for (candidates, 0..) |bits, idx| {
                        if (bits == 0) continue;
                        const bit_idx: u3 = @truncate(idx);
                        const one: u8 = 1;
                        const mask = one << bit_idx;
                        bitmap.items[idx / 8] |= mask;
                    }
                }
                self.writeBytes(payload_offset, bitmap.items);

                if (mode.exception_count > 0) {
                    var exc_offset = payload_offset + bitmap_size;
                    for (candidates, 0..) |bits, idx| {
                        if (bits == 0 or bits == mode.shared) continue;
                        var entry: [exception_entry_size]u8 = undefined;
                        std.mem.writeInt(u32, entry[0..4], @intCast(idx), .native);
                        std.mem.writeInt(u16, entry[4..6], bits, .native);
                        self.writeBytes(exc_offset, &entry);
                        exc_offset += exception_entry_size;
                    }
                }
            },
            .dual_raw_bits => {
                const bitmap = &self.builder.bitmap_scratch;
                bitmap.resize(self.allocator, 2 * bitmap_size) catch return StorageError.OutOfMemory;
                @memset(bitmap.items, 0);
                for (candidates, 0..) |bits, idx| {
                    if (bits == 0) continue;
                    const bit_idx: u3 = @truncate(idx);
                    const one: u8 = 1;
                    const mask = one << bit_idx;
                    if (bits == dual_first) {
                        bitmap.items[idx / 8] |= mask;
                    } else {
                        bitmap.items[bitmap_size + idx / 8] |= mask;
                    }
                }
                self.writeBytes(payload_offset, bitmap.items);
            },
            .indexed_raw_bits => {
                var table_offset = payload_offset;
                for (raw_values[0..raw_count]) |bits| {
                    var raw_bits = bits;
                    self.writeBytes(table_offset, std.mem.asBytes(&raw_bits));
                    table_offset += 2;
                }

                const indexes = &self.builder.bitmap_scratch;
                const bit_width = indexedBitsPerCandidate(raw_count);
                indexes.resize(self.allocator, packedIndexByteSize(cand_count, raw_count)) catch return StorageError.OutOfMemory;
                @memset(indexes.items, 0);
                for (candidates, 0..) |bits, idx| {
                    if (bits == 0) continue;
                    writePackedIndex(indexes.items, idx, bit_width, raw_index_by_bits[bits]);
                }
                self.writeBytes(table_offset, indexes.items);
            },
        }

        self.used_len += encoded_size;
        self.match_count += self.builder.match_count;
        self.builder.reset();
    }

    fn appendSharedRun(self: *MatchesArray, remote_address: usize, old_values: []const u8, raw_bits: u16, match_candidate_count: usize) StorageError!void {
        var consumed: usize = 0;
        var remaining_matches = match_candidate_count;
        while (consumed < old_values.len) {
            const address = remote_address + consumed;
            const len = @min(old_values.len - consumed, max_segment_payload);
            const cand_count = candidateCount(address, len, self.stride);
            const matched = @min(cand_count, remaining_matches);
            try self.writeSharedRunSegment(address, old_values[consumed .. consumed + len], raw_bits, matched);
            remaining_matches -= matched;
            consumed += len;
        }
    }

    fn writeSharedRunSegment(self: *MatchesArray, remote_address: usize, old_values: []const u8, raw_bits: u16, match_count: usize) StorageError!void {
        const cand_count = candidateCount(remote_address, old_values.len, self.stride);
        const bitmap_size = (cand_count + 7) / 8;
        const encoded_size = std.mem.alignForward(usize, @sizeOf(SwathHeader) + old_values.len + bitmap_size, @alignOf(SwathHeader));

        try self.ensureCapacity(self.used_len + encoded_size);

        const swath_offset = self.used_len;
        const header = SwathHeader{
            .first_byte_in_child = remote_address,
            .number_of_bytes = old_values.len,
            .match_count = match_count,
            .exception_count = 0,
            .shared_raw_bits = if (match_count == 0) 0 else raw_bits,
            .layout = .shared_raw_bits,
        };
        self.writeBytes(swath_offset, std.mem.asBytes(&header));
        self.writeBytes(swath_offset + @sizeOf(SwathHeader), old_values);

        const bitmap = &self.builder.bitmap_scratch;
        bitmap.resize(self.allocator, bitmap_size) catch return StorageError.OutOfMemory;
        @memset(bitmap.items, 0);
        if (match_count != 0) {
            const full_bytes = match_count / 8;
            @memset(bitmap.items[0..full_bytes], 0xFF);
            const trailing = match_count & 7;
            if (trailing != 0) {
                const one: u8 = 1;
                const trailing_mask = (one << @intCast(trailing)) - 1;
                bitmap.items[full_bytes] = trailing_mask;
            }
        }
        self.writeBytes(swath_offset + @sizeOf(SwathHeader) + old_values.len, bitmap.items);

        self.used_len += encoded_size;
        self.match_count += match_count;
    }

    fn readSwathHeader(self: *const MatchesArray, offset: usize) SwathHeader {
        return self.readValue(SwathHeader, offset);
    }

    fn swathByteSize(self: *const MatchesArray, header: SwathHeader) usize {
        const cand_count = candidateCount(header.first_byte_in_child, header.number_of_bytes, self.stride);
        const trailing = switch (header.layout) {
            .shared_raw_bits => ((cand_count + 7) / 8) + exception_entry_size * header.exception_count,
            .inline_raw_bits => 2 * cand_count,
            .dual_raw_bits => 2 * ((cand_count + 7) / 8),
            .indexed_raw_bits => header.exception_count * 2 + packedIndexByteSize(cand_count, header.exception_count),
        };
        return std.mem.alignForward(usize, @sizeOf(SwathHeader) + header.number_of_bytes + trailing, @alignOf(SwathHeader));
    }

    fn rawBitsAtCandidate(self: *const MatchesArray, swath_offset: usize, header: SwathHeader, cand_index: usize) u16 {
        const payload_offset = swath_offset + @sizeOf(SwathHeader) + header.number_of_bytes;
        switch (header.layout) {
            .shared_raw_bits => {
                const cand_count = candidateCount(header.first_byte_in_child, header.number_of_bytes, self.stride);
                if (header.exception_count == 0 and header.match_count == cand_count) return header.shared_raw_bits;

                const byte_idx = cand_index / 8;
                const bit_idx: u3 = @truncate(cand_index);
                const one: u8 = 1;
                const mask = one << bit_idx;
                const bitmap_byte = self.readU8(payload_offset + byte_idx);
                if ((bitmap_byte & mask) == 0) return 0;
                if (header.exception_count == 0) return header.shared_raw_bits;
                const bitmap_size = (cand_count + 7) / 8;
                const exc_offset = payload_offset + bitmap_size;
                for (0..header.exception_count) |e| {
                    const idx = self.readValue(u32, exc_offset + exception_entry_size * e);
                    if (idx == cand_index) return self.readValue(u16, exc_offset + exception_entry_size * e + 4);
                    if (idx > cand_index) break;
                }
                return header.shared_raw_bits;
            },
            .inline_raw_bits => {
                return self.readU16(payload_offset + 2 * cand_index);
            },
            .dual_raw_bits => {
                const bitmap_size = (candidateCount(header.first_byte_in_child, header.number_of_bytes, self.stride) + 7) / 8;
                const byte_idx = cand_index / 8;
                const bit_idx: u3 = @truncate(cand_index);
                const one: u8 = 1;
                const mask = one << bit_idx;
                if ((self.readU8(payload_offset + byte_idx) & mask) != 0) return header.shared_raw_bits;
                if ((self.readU8(payload_offset + bitmap_size + byte_idx) & mask) != 0) return @truncate(header.exception_count);
                return 0;
            },
            .indexed_raw_bits => {
                const index_offset = payload_offset + header.exception_count * 2;
                const raw_index: usize = self.readPackedIndex(index_offset, cand_index, indexedBitsPerCandidate(header.exception_count));
                if (raw_index == 0) return 0;
                return self.readU16(payload_offset + 2 * (raw_index - 1));
            },
        }
    }

    fn ensureCapacity(self: *MatchesArray, required: usize) StorageError!void {
        if (required <= self.capacity_len) return;
        while (required > self.capacity_len) {
            if (self.max_needed_bytes != 0 and self.capacity_len >= self.max_needed_bytes) {
                return StorageError.ExceedsMaximumSize;
            }
            var chunk_size = @max(self.capacity_len, @sizeOf(SwathHeader));
            chunk_size = @min(chunk_size, max_chunk_size);
            if (self.max_needed_bytes != 0) {
                chunk_size = @min(chunk_size, self.max_needed_bytes - self.capacity_len);
            }
            if (chunk_size == 0) return StorageError.ExceedsMaximumSize;
            try self.addChunk(chunk_size);
        }
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
        while (self.chunks.items.len > 0) {
            const last_index = self.chunks.items.len - 1;
            const last = self.chunks.items[last_index];
            if (self.used_len > last.base) break;
            self.allocator.free(last.data);
            _ = self.chunks.pop();
            self.capacity_len = last.base;
        }
        if (self.chunks.items.len == 0) return;

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
        const chunk = self.chunks.items[self.chunkIndexForOffset(offset)];
        const local_offset = offset - chunk.base;
        if (local_offset + @sizeOf(T) <= chunk.data.len) {
            return std.mem.bytesToValue(T, chunk.data[local_offset .. local_offset + @sizeOf(T)]);
        }

        var bytes: [@sizeOf(T)]u8 = undefined;
        self.readBytes(offset, &bytes);
        return std.mem.bytesToValue(T, &bytes);
    }

    fn readU8(self: *const MatchesArray, offset: usize) u8 {
        // Doesn't use readValue as 1 byte cannot cross a chunk boundary
        // so skipping those checks helps with performance as this function is hot
        const chunk = self.chunks.items[self.chunkIndexForOffset(offset)];
        return chunk.data[offset - chunk.base];
    }

    fn readU16(self: *const MatchesArray, offset: usize) u16 {
        return self.readValue(u16, offset);
    }

    fn readPackedIndex(self: *const MatchesArray, offset: usize, cand_index: usize, bit_width: usize) u8 {
        const bit_offset = cand_index * bit_width;
        const byte_offset = offset + bit_offset / 8;
        const shift: u4 = @intCast(bit_offset & 7);
        var value: u16 = self.readU8(byte_offset);
        value >>= shift;
        const shift_usize: usize = shift;
        if (shift_usize + bit_width > 8) {
            const next_byte: u16 = self.readU8(byte_offset + 1);
            value |= next_byte << @intCast(8 - shift_usize);
        }
        const width_shift: u4 = @intCast(bit_width);
        const one: u16 = 1;
        const mask = (one << width_shift) - 1;
        return @intCast(value & mask);
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

    fn chunkIndexForOffset(self: *const MatchesArray, offset: usize) usize {
        std.debug.assert(offset < self.capacity_len);

        const first = self.chunks.items[0];
        if (offset >= first.base and offset < first.base + first.data.len) return 0;

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
};

fn candidateCount(first_byte: usize, number_of_bytes: usize, stride: u16) usize {
    if (number_of_bytes == 0) return 0;
    const first = alignForwardStride(first_byte, stride);
    const end = first_byte + number_of_bytes;
    if (first >= end) return 0;
    return (end - first + stride - 1) / stride;
}

fn indexedBitsPerCandidate(raw_count: anytype) usize {
    std.debug.assert(raw_count != 0);
    var bits: usize = 1;
    while (true) {
        const one: usize = 1;
        const capacity = one << @intCast(bits);
        if (capacity > raw_count) break;
        bits += 1;
    }
    return bits;
}

fn packedIndexByteSize(cand_count: usize, raw_count: anytype) usize {
    return (cand_count * indexedBitsPerCandidate(raw_count) + 7) / 8;
}

fn writePackedIndex(indexes: []u8, cand_index: usize, bit_width: usize, raw_index: u8) void {
    const bit_offset = cand_index * bit_width;
    const byte_index = bit_offset / 8;
    const shift: u4 = @intCast(bit_offset & 7);
    const raw_value: u16 = raw_index;
    const value = raw_value << shift;
    indexes[byte_index] |= @truncate(value);
    const shift_usize: usize = shift;
    if (shift_usize + bit_width > 8) indexes[byte_index + 1] |= @truncate(value >> 8);
}

fn alignForwardStride(addr: usize, stride: u16) usize {
    if (stride <= 1) return addr;
    const rem = addr % stride;
    return if (rem == 0) addr else addr + (stride - rem);
}

fn pickSharedRawBits(candidates: []const u16) struct { shared: u16, exception_count: u32, total_nonzero: u32 } {
    var slots: [16]struct { value: u16, count: u32 } = undefined;
    var slot_count: usize = 0;
    var top_value: u16 = 0;
    var top_count: u32 = 0;
    var total_nonzero: u32 = 0;
    var majority_value: u16 = 0;
    var majority_balance: u32 = 0;

    outer: for (candidates) |c| {
        if (c == 0) continue;
        total_nonzero += 1;
        if (majority_balance == 0) {
            majority_value = c;
            majority_balance = 1;
        } else if (majority_value == c) {
            majority_balance += 1;
        } else {
            majority_balance -= 1;
        }

        for (slots[0..slot_count]) |*s| {
            if (s.value == c) {
                s.count += 1;
                if (s.count > top_count) {
                    top_count = s.count;
                    top_value = c;
                }
                continue :outer;
            }
        }
        if (slot_count < slots.len) {
            slots[slot_count] = .{ .value = c, .count = 1 };
            slot_count += 1;
            if (top_count == 0) {
                top_value = c;
                top_count = 1;
            }
        }
    }

    var shared = top_value;
    var shared_count: u32 = top_count;
    if (majority_value != 0 and majority_value != top_value) {
        var majority_count: u32 = 0;
        for (candidates) |c| {
            if (c == majority_value) majority_count += 1;
        }
        if (majority_count > shared_count) {
            shared = majority_value;
            shared_count = majority_count;
        }
    }

    return .{ .shared = shared, .exception_count = total_nonzero - shared_count, .total_nonzero = total_nonzero };
}

const flags16_mask: u16 = (MatchFlags{ .u16b = true, .s16b = true }).bits();
const flags32_mask: u16 = (MatchFlags{ .u32b = true, .s32b = true, .f32b = true }).bits();
const flags64_mask: u16 = (MatchFlags{ .u64b = true, .s64b = true, .f64b = true }).bits();

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

fn validateAndExpect(matches: *const MatchesArray, expected_count: usize) !void {
    try matches.validate();
    try std.testing.expectEqual(expected_count, matches.matchCount());
}

test "SwathHeader: layout is 32 bytes" {
    try std.testing.expectEqual(32, @sizeOf(SwathHeader));
}

test "append: keeps contiguous and near-gap bytes in one swath" {
    var matches = try MatchesArray.init(std.testing.allocator, 256, 1);
    defer matches.deinit();

    try matches.append(0x1000, 0xaa, .{ .u8b = true });
    try matches.append(0x1001, 0xbb, .{ .u8b = true });
    try matches.append(0x1003, 0xcc, .{ .u8b = true });
    try matches.finalize();

    try validateAndExpect(&matches, 3);
    try std.testing.expectEqual(4, matches.storedByteCount());
    const header = matches.readSwathHeader(0);
    try std.testing.expectEqual(0x1000, header.first_byte_in_child);
    try std.testing.expectEqual(4, header.number_of_bytes);
}

test "append: starts a new swath when gap exceeds padding threshold" {
    var matches = try MatchesArray.init(std.testing.allocator, 256, 1);
    defer matches.deinit();

    try matches.append(0x2000, 0x11, .{ .u8b = true });
    try matches.append(0x2030, 0x22, .{ .u8b = true });
    try matches.finalize();

    try validateAndExpect(&matches, 2);

    const first = matches.readSwathHeader(0);
    try std.testing.expectEqual(0x2000, first.first_byte_in_child);
    try std.testing.expectEqual(1, first.number_of_bytes);

    const second_offset = matches.swathByteSize(first);
    const second = matches.readSwathHeader(second_offset);
    try std.testing.expectEqual(0x2030, second.first_byte_in_child);
    try std.testing.expectEqual(1, second.number_of_bytes);
}

test "nthMatch and findMatchIndexByAddress: skip padding bytes" {
    var matches = try MatchesArray.init(std.testing.allocator, 256, 1);
    defer matches.deinit();

    try matches.append(0x3000, 0x10, .{ .u8b = true });
    try matches.append(0x3002, 0x20, .{ .u8b = true });
    try matches.finalize();

    try validateAndExpect(&matches, 2);
    try std.testing.expectEqual(0x3000, matches.nthMatch(0).?.address);
    try std.testing.expectEqual(0x3002, matches.nthMatch(1).?.address);
    try std.testing.expect(matches.nthMatch(2) == null);
    try std.testing.expectEqual(0, matches.findMatchIndexByAddress(0x3000).?);
    try std.testing.expectEqual(1, matches.findMatchIndexByAddress(0x3002).?);
    try std.testing.expectEqual(null, matches.findMatchIndexByAddress(0x3001));
}

test "deleteInAddressRange: compacts and preserves remaining matches" {
    var matches = try MatchesArray.init(std.testing.allocator, 512, 1);
    defer matches.deinit();

    try matches.append(0x4000, 0x01, .{ .u8b = true });
    try matches.append(0x4001, 0x02, .{ .u8b = true });
    try matches.append(0x4005, 0x03, .{ .u8b = true });
    try matches.append(0x4006, 0x04, .{ .u8b = true });
    try matches.finalize();

    try matches.deleteInAddressRange(0x4001, 0x4006);

    try validateAndExpect(&matches, 2);
    try std.testing.expectEqual(0x4000, matches.nthMatch(0).?.address);
    try std.testing.expectEqual(0x4006, matches.nthMatch(1).?.address);
    try std.testing.expectEqual(0x01, matches.nthMatch(0).?.value(&matches).data.uint8_value);
    try std.testing.expectEqual(0x04, matches.nthMatch(1).?.value(&matches).data.uint8_value);
}

test "deleteInAddressRange: creates non-stride-aligned base from mid-stride cut" {
    var matches = try MatchesArray.init(std.testing.allocator, 256, 4);
    defer matches.deinit();

    try matches.append(0x1000, 0xaa, MatchFlags.i32b);
    try matches.append(0x1001, 0xbb, .{});
    try matches.append(0x1002, 0xcc, .{});
    try matches.append(0x1003, 0xdd, .{});
    try matches.append(0x1004, 0xee, MatchFlags.i32b);
    try matches.append(0x1005, 0xff, .{});
    try matches.append(0x1006, 0x11, .{});
    try matches.append(0x1007, 0x22, .{});
    try matches.finalize();

    try matches.deleteInAddressRange(0x1000, 0x1003);

    try validateAndExpect(&matches, 1);
    const header = matches.readSwathHeader(0);
    try std.testing.expectEqual(0x1003, header.first_byte_in_child);
    try std.testing.expectEqual(0x1004, matches.nthMatch(0).?.address);
}

test "removeMatch: clears bitmap bit and preserves trailing old values" {
    var matches = try MatchesArray.init(std.testing.allocator, 64 * 1024, 4);
    defer matches.deinit();

    try matches.append(0x5000, 0x11, MatchFlags.i32b);
    try matches.append(0x5001, 0x22, .{});
    try matches.append(0x5002, 0x33, .{});
    try matches.append(0x5003, 0x44, .{});
    try matches.append(0x5004, 0x55, MatchFlags.i32b);
    try matches.append(0x5005, 0x66, .{});
    try matches.append(0x5006, 0x77, .{});
    try matches.append(0x5007, 0x88, .{});
    try matches.finalize();

    try validateAndExpect(&matches, 2);
    const removed = matches.nthMatch(0).?;
    matches.removeMatch(removed);

    try validateAndExpect(&matches, 1);
    try std.testing.expectEqual(0x5004, matches.nthMatch(0).?.address);

    // Trailing bytes of the removed match must still be readable.
    const expected = [_]u8{ 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88 };
    var iter = matches.storedByteIterator();
    for (expected, 0..) |value, i| {
        const stored = iter.next() orelse return error.MissingStoredByte;
        try std.testing.expectEqual(0x5000 + i, stored.address);
        try std.testing.expectEqual(value, stored.old_value);
    }
    try std.testing.expectEqual(null, iter.next());
}

test "MatchLocation.value: truncates width flags by remaining bytes" {
    var matches = try MatchesArray.init(std.testing.allocator, 256, 1);
    defer matches.deinit();

    try matches.append(0x5000, 0x78, .{ .u32b = true, .s32b = true, .u16b = true, .s16b = true, .u8b = true, .s8b = true });
    try matches.append(0x5001, 0x56, .{});
    try matches.append(0x5002, 0x34, .{});
    try matches.finalize();

    const value = matches.nthMatch(0).?.value(&matches);
    try std.testing.expectEqual((MatchFlags{ .u8b = true, .s8b = true, .u16b = true, .s16b = true }).bits(), value.flags.bits());
    try std.testing.expectEqual(0x78, value.data.bytes[0]);
    try std.testing.expectEqual(0x56, value.data.bytes[1]);
    try std.testing.expectEqual(0x34, value.data.bytes[2]);
}

test "MatchLocation.value: reconstructs full 64-bit value from match plus trailing bytes" {
    var matches = try MatchesArray.init(std.testing.allocator, 256, 1);
    defer matches.deinit();

    try matches.append(0x7000, 0x10, .{ .u64b = true });
    try matches.append(0x7001, 0x6f, .{});
    try matches.append(0x7002, 0x2b, .{});
    try matches.append(0x7003, 0x9e, .{});
    try matches.append(0x7004, 0xc4, .{});
    try matches.append(0x7005, 0xd3, .{});
    try matches.append(0x7006, 0x17, .{});
    try matches.append(0x7007, 0x5a, .{});
    try matches.finalize();

    const value = matches.nthMatch(0).?.value(&matches);
    try std.testing.expectEqual((MatchFlags{ .u64b = true }).bits(), value.flags.bits());
    try std.testing.expectEqual(0x5A17D3C49E2B6F10, value.data.uint64_value);
}

test "dataToBytes: returns raw stored bytes" {
    var matches = try MatchesArray.init(std.testing.allocator, 256, 1);
    defer matches.deinit();

    try matches.append(0x6000, 'A', .{ .u8b = true });
    try matches.append(0x6001, 0x07, .{ .u8b = true });
    try matches.append(0x6002, 'Z', .{ .u8b = true });
    try matches.finalize();

    var raw_bytes: [3]u8 = undefined;
    try std.testing.expectEqualSlices(u8, &[_]u8{ 'A', 0x07, 'Z' }, matches.dataToBytes(0, 0, 3, &raw_bytes));
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x07, 'Z' }, matches.dataToBytes(0, 1, 3, &raw_bytes));
}

test "MatchLocation.value: reconstructs u32 across dense segment boundary" {
    var matches = try MatchesArray.init(std.testing.allocator, max_segment_payload * 2, 1);
    defer matches.deinit();

    const base: usize = 0x100000;
    const prefix = try std.testing.allocator.alloc(u8, max_segment_payload - 2);
    defer std.testing.allocator.free(prefix);
    @memset(prefix, 0);

    try matches.appendRun(base, prefix, 0, 0);
    try matches.appendRun(base + max_segment_payload - 2, &[_]u8{ 0x78, 0x56, 0x34, 0x12 }, MatchFlags.i32b.bits(), 1);
    try matches.finalize();

    try validateAndExpect(&matches, 1);
    const value = matches.nthMatch(0).?.value(&matches);
    try std.testing.expectEqual(MatchFlags.i32b.bits(), value.flags.bits());
    try std.testing.expectEqual(0x12345678, value.data.uint32_value);
}

test "MatchLocation.value: reconstructs u64 across dense align-4 segment boundary" {
    var matches = try MatchesArray.init(std.testing.allocator, max_segment_payload * 2, 4);
    defer matches.deinit();

    const base: usize = 0x200000;
    const prefix = try std.testing.allocator.alloc(u8, max_segment_payload - 4);
    defer std.testing.allocator.free(prefix);
    @memset(prefix, 0);

    try matches.appendRun(base, prefix, 0, 0);
    try matches.appendRun(base + max_segment_payload - 4, &[_]u8{ 0x10, 0x6f, 0x2b, 0x9e, 0xc4, 0xd3, 0x17, 0x5a }, (MatchFlags{ .u64b = true }).bits(), 1);
    try matches.finalize();

    try validateAndExpect(&matches, 1);
    const value = matches.nthMatch(0).?.value(&matches);
    try std.testing.expectEqual((MatchFlags{ .u64b = true }).bits(), value.flags.bits());
    try std.testing.expectEqual(0x5A17D3C49E2B6F10, value.data.uint64_value);
}

test "dense INTEGER32 align 4 MATCHANY size approaches 1.03 B/byte" {
    var matches = try MatchesArray.init(std.testing.allocator, 16 * 1024 * 1024, 4);
    defer matches.deinit();

    const total_addresses: usize = 4096;
    const addr: usize = 0x10000;
    for (0..total_addresses / 4) |i| {
        const start = addr + i * 4;
        try matches.append(start, @truncate(i), MatchFlags.i32b);
        try matches.append(start + 1, 0, .{});
        try matches.append(start + 2, 0, .{});
        try matches.append(start + 3, 0, .{});
    }
    try matches.finalize();

    try matches.validate();
    try std.testing.expectEqual(total_addresses / 4, matches.matchCount());

    // Expected: header(32) + old_values(N) + bitmap(N/32) + 0 exceptions, padded to align(8).
    const expected_unpadded = @sizeOf(SwathHeader) + total_addresses + (total_addresses / 4 + 7) / 8;
    const expected = std.mem.alignForward(usize, expected_unpadded, @alignOf(SwathHeader));
    try std.testing.expectEqual(expected, matches.used_len);
}

test "appendRun: uniform run writes shared segment without candidate raw_bits buffer" {
    var matches = try MatchesArray.init(std.testing.allocator, 16 * 1024 * 1024, 4);
    defer matches.deinit();

    var old_values: [4096]u8 = undefined;
    @memset(&old_values, 0);

    try matches.appendRun(0x18000, &old_values, MatchFlags.i32b.bits(), old_values.len / 4);

    try std.testing.expectEqual(0, matches.builder.candidate_raw_bits.items.len);
    try std.testing.expect(!matches.builder.has_data);
    try std.testing.expect(matches.used_len != 0);

    try matches.finalize();
    try validateAndExpect(&matches, old_values.len / 4);

    const header = matches.readSwathHeader(0);
    try std.testing.expectEqual(DenseLayout.shared_raw_bits, header.layout);
    try std.testing.expectEqual(MatchFlags.i32b.bits(), header.shared_raw_bits);
    try std.testing.expectEqual(old_values.len / 4, header.match_count);
    try std.testing.expectEqual(0, header.exception_count);

    const expected_unpadded = @sizeOf(SwathHeader) + old_values.len + (old_values.len / 4 + 7) / 8;
    const expected = std.mem.alignForward(usize, expected_unpadded, @alignOf(SwathHeader));
    try std.testing.expectEqual(expected, matches.used_len);
}

test "dense ANYINTEGER with heterogeneous raw_bits picks inline layout when smaller" {
    var matches = try MatchesArray.init(std.testing.allocator, 1024, 4);
    defer matches.deinit();

    // Build a tiny segment with more distinct raw_bits values than the multi-bitmap cap.
    const addr: usize = 0x20000;
    for (0..16) |i| {
        const raw_bits: u16 = @intCast(i + 1);
        const base = addr + i * 4;
        try matches.appendRaw(base, @truncate(i), raw_bits);
        try matches.append(base + 1, 0, .{});
        try matches.append(base + 2, 0, .{});
        try matches.append(base + 3, 0, .{});
    }
    try matches.finalize();

    try matches.validate();
    const header = matches.readSwathHeader(0);
    try std.testing.expectEqual(DenseLayout.inline_raw_bits, header.layout);
    try std.testing.expectEqual(16, header.match_count);
}

test "dense wide raw_bits set picks packed indexed layout" {
    var matches = try MatchesArray.init(std.testing.allocator, 4096, 1);
    defer matches.deinit();

    const addr: usize = 0x23000;
    for (0..512) |i| {
        const raw_bits: u16 = @intCast(i % 51 + 1);
        try matches.appendRaw(addr + i, @truncate(i), raw_bits);
    }
    try matches.finalize();

    try matches.validate();
    const header = matches.readSwathHeader(0);
    try std.testing.expectEqual(DenseLayout.indexed_raw_bits, header.layout);
    try std.testing.expectEqual(51, header.exception_count);
    try std.testing.expectEqual(512, header.match_count);
    try std.testing.expectEqual(1, matches.nthMatch(0).?.raw_match_info_bits);
    try std.testing.expectEqual(51, matches.nthMatch(50).?.raw_match_info_bits);
    try std.testing.expectEqual(1, matches.nthMatch(51).?.raw_match_info_bits);

    const expected_unpadded = @sizeOf(SwathHeader) + 512 + 51 * 2 + (512 * 6 + 7) / 8;
    const expected = std.mem.alignForward(usize, expected_unpadded, @alignOf(SwathHeader));
    try std.testing.expectEqual(expected, matches.used_len);
}

test "appendRescanBatch: stores mixed candidate raw bits" {
    var matches = try MatchesArray.init(std.testing.allocator, 4096, 1);
    defer matches.deinit();

    var old_values: [512]u8 = undefined;
    var raw_bits: [512]u16 = undefined;
    for (&old_values, &raw_bits, 0..) |*old_value, *bits, i| {
        old_value.* = @truncate(i);
        bits.* = if (i % 5 == 0) 0 else @intCast(i % 51 + 1);
    }

    try matches.appendRescanBatch(0x23400, &old_values, &raw_bits);
    try matches.finalize();

    try validateAndExpect(&matches, 409);
    const header = matches.readSwathHeader(0);
    try std.testing.expectEqual(DenseLayout.indexed_raw_bits, header.layout);
    try std.testing.expectEqual(51, header.exception_count);
    try std.testing.expectEqual(2, matches.nthMatch(0).?.raw_match_info_bits);
    try std.testing.expectEqual(3, matches.nthMatch(1).?.raw_match_info_bits);
    try std.testing.expectEqual(0x23400 + 1, matches.nthMatch(0).?.address);
}

test "removeMatch: clears packed indexed slot" {
    var matches = try MatchesArray.init(std.testing.allocator, 4096, 1);
    defer matches.deinit();

    const addr: usize = 0x23800;
    for (0..512) |i| {
        const raw_bits: u16 = @intCast(i % 51 + 1);
        try matches.appendRaw(addr + i, @truncate(i), raw_bits);
    }
    try matches.finalize();

    try validateAndExpect(&matches, 512);
    try std.testing.expectEqual(DenseLayout.indexed_raw_bits, matches.readSwathHeader(0).layout);

    matches.removeMatch(matches.nthMatch(50).?);

    try validateAndExpect(&matches, 511);
    try std.testing.expectEqual(null, matches.findMatchIndexByAddress(addr + 50));
    try std.testing.expectEqual(50, matches.nthMatch(49).?.raw_match_info_bits);
    try std.testing.expectEqual(1, matches.nthMatch(50).?.raw_match_info_bits);
}

test "dense two-value raw_bits picks dual bitmap layout" {
    var matches = try MatchesArray.init(std.testing.allocator, 1024, 4);
    defer matches.deinit();

    const addr: usize = 0x24000;
    for (0..16) |i| {
        const flags: MatchFlags = if (i % 2 == 0) .{ .u32b = true } else .{ .s32b = true };
        const base = addr + i * 4;
        try matches.append(base, @truncate(i), flags);
        try matches.append(base + 1, 0, .{});
        try matches.append(base + 2, 0, .{});
        try matches.append(base + 3, 0, .{});
    }
    try matches.finalize();

    try matches.validate();
    const header = matches.readSwathHeader(0);
    try std.testing.expectEqual(DenseLayout.dual_raw_bits, header.layout);
    try std.testing.expectEqual(16, header.match_count);
    try std.testing.expectEqual((MatchFlags{ .u32b = true }).bits(), header.shared_raw_bits);
    const second_raw_bits: u16 = @truncate(header.exception_count);
    try std.testing.expectEqual((MatchFlags{ .s32b = true }).bits(), second_raw_bits);

    const expected_unpadded = @sizeOf(SwathHeader) + 64 + 2 * ((16 + 7) / 8);
    const expected = std.mem.alignForward(usize, expected_unpadded, @alignOf(SwathHeader));
    try std.testing.expectEqual(expected, matches.used_len);
}

test "dense shared raw_bits layout wins for a small exception set" {
    var matches = try MatchesArray.init(std.testing.allocator, 1024, 1);
    defer matches.deinit();

    const addr: usize = 0x28000;
    for (0..64) |i| {
        const raw_bits: u16 = if (i < 4) @intCast(i + 2) else 1;
        try matches.appendRaw(addr + i, @truncate(i), raw_bits);
    }
    try matches.finalize();

    try validateAndExpect(&matches, 64);
    const header = matches.readSwathHeader(0);
    try std.testing.expectEqual(DenseLayout.shared_raw_bits, header.layout);
    try std.testing.expectEqual(1, header.shared_raw_bits);
    try std.testing.expectEqual(4, header.exception_count);

    const expected_unpadded = @sizeOf(SwathHeader) + 64 + 8 + 4 * exception_entry_size;
    const expected = std.mem.alignForward(usize, expected_unpadded, @alignOf(SwathHeader));
    try std.testing.expectEqual(expected, matches.used_len);
}

test "overlap: u32 matches at alignment 1 with shared trailing bytes" {
    var matches = try MatchesArray.init(std.testing.allocator, 256, 1);
    defer matches.deinit();

    // Two overlapping u32 match starts at 0x1000 and 0x1001 share trailing bytes.
    try matches.append(0x1000, 0x11, MatchFlags.i32b);
    try matches.append(0x1001, 0x22, MatchFlags.i32b);
    try matches.append(0x1002, 0x33, .{});
    try matches.append(0x1003, 0x44, .{});
    try matches.append(0x1004, 0x55, .{});
    try matches.finalize();

    try validateAndExpect(&matches, 2);
    try std.testing.expectEqual(0x1000, matches.nthMatch(0).?.address);
    try std.testing.expectEqual(0x1001, matches.nthMatch(1).?.address);
    try std.testing.expectEqual(MatchFlags.i32b.bits(), matches.nthMatch(0).?.raw_match_info_bits);
    try std.testing.expectEqual(MatchFlags.i32b.bits(), matches.nthMatch(1).?.raw_match_info_bits);
}

test "overlap: u32 matches at alignment 2 with shared trailing bytes" {
    var matches = try MatchesArray.init(std.testing.allocator, 256, 2);
    defer matches.deinit();

    try matches.append(0x2000, 0x11, MatchFlags.i32b);
    try matches.append(0x2001, 0x22, .{});
    try matches.append(0x2002, 0x33, MatchFlags.i32b);
    try matches.append(0x2003, 0x44, .{});
    try matches.append(0x2004, 0x55, .{});
    try matches.append(0x2005, 0x66, .{});
    try matches.finalize();

    try validateAndExpect(&matches, 2);
    try std.testing.expectEqual(0x2000, matches.nthMatch(0).?.address);
    try std.testing.expectEqual(0x2002, matches.nthMatch(1).?.address);
    try std.testing.expectEqual(null, matches.findMatchIndexByAddress(0x2001));
    try std.testing.expectEqual(null, matches.findMatchIndexByAddress(0x2003));
}

test "dense INTEGER8 MATCHANY size approaches 1.125 B/byte" {
    var matches = try MatchesArray.init(std.testing.allocator, 16 * 1024 * 1024, 1);
    defer matches.deinit();

    const total_bytes: usize = 4096;
    const addr: usize = 0x40000;
    for (0..total_bytes) |i| {
        try matches.append(addr + i, @truncate(i), MatchFlags.i8b);
    }
    try matches.finalize();

    try matches.validate();
    try std.testing.expectEqual(total_bytes, matches.matchCount());

    // Expected: header + N old_values + ceil(N/8) bitmap + 0 exceptions, padded to align(8).
    const expected_unpadded = @sizeOf(SwathHeader) + total_bytes + (total_bytes + 7) / 8;
    const expected = std.mem.alignForward(usize, expected_unpadded, @alignOf(SwathHeader));
    try std.testing.expectEqual(expected, matches.used_len);
}

test "dense BYTEARRAY uniform-length matches choose shared layout" {
    var matches = try MatchesArray.init(std.testing.allocator, 1024, 3);
    defer matches.deinit();

    // Base divisible by stride so every match start lands on a candidate slot.
    const addr: usize = 0x30000;
    for (0..4) |i| {
        const base = addr + i * 3;
        try matches.appendRaw(base, 0xaa, 3);
        try matches.appendRaw(base + 1, 0xbb, 0);
        try matches.appendRaw(base + 2, 0xcc, 0);
    }
    try matches.finalize();

    try matches.validate();
    const header = matches.readSwathHeader(0);
    try std.testing.expectEqual(DenseLayout.shared_raw_bits, header.layout);
    try std.testing.expectEqual(4, header.match_count);
    try std.testing.expectEqual(3, header.shared_raw_bits);
    try std.testing.expectEqual(0, header.exception_count);
}

test "append: sparse stride-4 survivors split by gap threshold" {
    var matches = try MatchesArray.init(std.testing.allocator, 1024 * 1024, 4);
    defer matches.deinit();

    const start: usize = 0x60000;
    for (0..100) |i| {
        const base = start + i * 4;
        try matches.append(base, @truncate(i), MatchFlags.i32b);
        try matches.append(base + 1, 0, .{});
        try matches.append(base + 2, 0, .{});
        try matches.append(base + 3, 0, .{});
    }
    try matches.finalize();
    try validateAndExpect(&matches, 100);

    try std.testing.expectEqual(400, matches.readSwathHeader(0).number_of_bytes);

    var pruned = try MatchesArray.init(std.testing.allocator, 1024 * 1024, 4);
    defer pruned.deinit();

    for ([_]usize{ 0, 50, 99 }) |idx| {
        const base = start + idx * 4;
        try pruned.append(base, @truncate(idx), MatchFlags.i32b);
        try pruned.append(base + 1, 0, .{});
        try pruned.append(base + 2, 0, .{});
        try pruned.append(base + 3, 0, .{});
    }
    try pruned.finalize();
    try validateAndExpect(&pruned, 3);

    // Gaps between survivors (50*4 = 200 bytes) >> 24, so each becomes its own segment.
    var seg_count: usize = 0;
    var offset: usize = 0;
    while (offset < pruned.used_len) {
        seg_count += 1;
        offset += pruned.swathByteSize(pruned.readSwathHeader(offset));
    }
    try std.testing.expectEqual(3, seg_count);
}

test "validate: detects inconsistent match count" {
    var matches = try MatchesArray.init(std.testing.allocator, 256, 1);
    defer matches.deinit();

    try matches.append(0x9000, 0x42, .{ .u8b = true });
    try matches.finalize();

    try matches.validate();

    // Corrupt the header's match_count to trigger validation failure.
    var bad_match_count: usize = 99;
    matches.writeBytes(@offsetOf(SwathHeader, "match_count"), std.mem.asBytes(&bad_match_count));
    try std.testing.expectError(StorageError.ExceedsMaximumSize, matches.validate());
}

test "releaseStorageBefore: released chunks are not double-freed" {
    var matches = try MatchesArray.init(std.testing.allocator, 256, 1);
    defer matches.deinit();

    try matches.append(0x1000, 0xaa, .{ .u8b = true });
    try matches.finalize();

    matches.releaseStorageBefore(matches.used_len);
    try std.testing.expectEqual(0, matches.chunks.items.len);
}
