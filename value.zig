//! Core numeric value and user-input parsing helpers.

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

const Allocator = std.mem.Allocator;

const whitespace = " \t\n\r\x0b\x0c";

pub const ParseError = error{
    InvalidByteArray,
    InvalidInteger,
    InvalidFloat,
    InvalidNumber,
    OutOfMemory,
};

/// Flags that represent the potential type of a match
pub const MatchFlags = packed struct(u16) {
    u8b: bool = false,
    s8b: bool = false,
    u16b: bool = false,
    s16b: bool = false,
    u32b: bool = false,
    s32b: bool = false,
    u64b: bool = false,
    s64b: bool = false,
    f32b: bool = false,
    f64b: bool = false,
    _reserved: u6 = 0,

    pub const i8b: MatchFlags = .{ .u8b = true, .s8b = true };
    pub const i16b: MatchFlags = .{ .u16b = true, .s16b = true };
    pub const i32b: MatchFlags = .{ .u32b = true, .s32b = true };
    pub const i64b: MatchFlags = .{ .u64b = true, .s64b = true };
    pub const integer: MatchFlags = .{
        .u8b = true,
        .s8b = true,
        .u16b = true,
        .s16b = true,
        .u32b = true,
        .s32b = true,
        .u64b = true,
        .s64b = true,
    };
    pub const float: MatchFlags = .{ .f32b = true, .f64b = true };
    pub const all: MatchFlags = .{
        .u8b = true,
        .s8b = true,
        .u16b = true,
        .s16b = true,
        .u32b = true,
        .s32b = true,
        .u64b = true,
        .s64b = true,
        .f32b = true,
        .f64b = true,
    };

    pub fn bits(self: MatchFlags) u16 {
        return @bitCast(self);
    }
};

pub const ValueData = extern union {
    int8_value: i8,
    uint8_value: u8,
    int16_value: i16,
    uint16_value: u16,
    int32_value: i32,
    uint32_value: u32,
    int64_value: i64,
    uint64_value: u64,
    float32_value: f32,
    float64_value: f64,
    bytes: [@sizeOf(u64)]u8,
    chars: [@sizeOf(u64)]u8,
};

/// Describes matched values
pub const Value = extern struct {
    data: ValueData = .{ .uint64_value = 0 },
    flags: MatchFlags = .{},
};

pub const Wildcard = enum(u8) {
    FIXED = 0xFF,
    WILDCARD = 0x00,
};

/// Describes values provided by users
pub const UserValue = struct {
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
    bytearray_value: ?[]const u8 = null,
    wildcard_value: ?[]const Wildcard = null,
    string_value: ?[]const u8 = null,
    flags: MatchFlags = .{},

    pub fn deinit(self: *UserValue, allocator: Allocator) void {
        if (self.bytearray_value) |bytes| allocator.free(bytes);
        if (self.wildcard_value) |wildcards| allocator.free(wildcards);
        self.bytearray_value = null;
        self.wildcard_value = null;
    }

    pub fn parseByteArray(allocator: Allocator, tokens: []const []const u8) ParseError!UserValue {
        var result = UserValue{};
        errdefer result.deinit(allocator);

        const bytes = allocator.alloc(u8, tokens.len) catch return ParseError.OutOfMemory;
        errdefer allocator.free(bytes);

        const wildcards = allocator.alloc(Wildcard, tokens.len) catch return ParseError.OutOfMemory;
        errdefer allocator.free(wildcards);

        for (tokens, 0..) |token, index| {
            if (token.len != 2) {
                return ParseError.InvalidByteArray;
            }

            if (std.mem.eql(u8, token, "??")) {
                bytes[index] = 0;
                wildcards[index] = .WILDCARD;
            } else {
                bytes[index] = std.fmt.parseUnsigned(u8, token, 16) catch return ParseError.InvalidByteArray;
                wildcards[index] = .FIXED;
            }
        }

        result.bytearray_value = bytes;
        result.wildcard_value = wildcards;
        return result;
    }

    pub fn parseByteArrayText(allocator: Allocator, text: []const u8) ParseError!UserValue {
        var token_count: usize = 0;
        var counter = std.mem.tokenizeAny(u8, text, whitespace);
        while (counter.next() != null) {
            token_count += 1;
        }
        if (token_count == 0) return ParseError.InvalidByteArray;

        const tokens = allocator.alloc([]const u8, token_count) catch return ParseError.OutOfMemory;
        defer allocator.free(tokens);

        var it = std.mem.tokenizeAny(u8, text, whitespace);
        var index: usize = 0;
        while (it.next()) |token| : (index += 1) {
            tokens[index] = token;
        }

        return parseByteArray(allocator, tokens);
    }

    pub fn parseNumber(text: []const u8) ParseError!UserValue {
        if (UserValue.parseInt(text)) |result| {
            var number = result;
            number.flags.f32b = true;
            number.flags.f64b = true;
            if (number.flags.s64b) {
                number.float32_value = @floatFromInt(number.int64_value);
                number.float64_value = @floatFromInt(number.int64_value);
            } else {
                number.float32_value = @floatFromInt(number.uint64_value);
                number.float64_value = @floatFromInt(number.uint64_value);
            }
            return number;
        } else |int_err| switch (int_err) {
            ParseError.InvalidInteger => return UserValue.parseFloatAndBackfillInts(text) catch ParseError.InvalidNumber,
            ParseError.OutOfMemory => unreachable,
            else => return ParseError.InvalidNumber,
        }
    }

    pub fn parseInt(text: []const u8) ParseError!UserValue {
        const trimmed = std.mem.trimStart(u8, text, whitespace);
        var result = UserValue{};

        const signed_value = std.fmt.parseInt(i64, trimmed, 0) catch null;
        const unsigned_value = if (trimmed.len > 0 and trimmed[0] != '-')
            std.fmt.parseInt(u64, trimmed, 0) catch null
        else
            null;

        if (signed_value == null and unsigned_value == null) {
            return ParseError.InvalidInteger;
        }

        if (unsigned_value) |value| {
            if (value <= std.math.maxInt(u8)) {
                result.flags.u8b = true;
                result.uint8_value = @intCast(value);
            }
            if (value <= std.math.maxInt(u16)) {
                result.flags.u16b = true;
                result.uint16_value = @intCast(value);
            }
            if (value <= std.math.maxInt(u32)) {
                result.flags.u32b = true;
                result.uint32_value = @intCast(value);
            }
            result.flags.u64b = true;
            result.uint64_value = value;
        }

        if (signed_value) |value| {
            if (value >= std.math.minInt(i8) and value <= std.math.maxInt(i8)) {
                result.flags.s8b = true;
                result.int8_value = @intCast(value);
            }
            if (value >= std.math.minInt(i16) and value <= std.math.maxInt(i16)) {
                result.flags.s16b = true;
                result.int16_value = @intCast(value);
            }
            if (value >= std.math.minInt(i32) and value <= std.math.maxInt(i32)) {
                result.flags.s32b = true;
                result.int32_value = @intCast(value);
            }
            result.flags.s64b = true;
            result.int64_value = value;
        }

        return result;
    }

    pub fn parseFloat(text: []const u8) ParseError!UserValue {
        const trimmed = std.mem.trimStart(u8, text, whitespace);
        const number = std.fmt.parseFloat(f64, trimmed) catch return ParseError.InvalidFloat;

        return .{
            .float32_value = @floatCast(number),
            .float64_value = number,
            .flags = MatchFlags.float,
        };
    }

    fn parseFloatAndBackfillInts(text: []const u8) ParseError!UserValue {
        var result = try UserValue.parseFloat(text);
        const number = result.float64_value;

        if (number >= 0 and number <= std.math.maxInt(u8)) {
            result.flags.u8b = true;
            result.uint8_value = @intFromFloat(number);
        }
        if (number >= std.math.minInt(i8) and number <= std.math.maxInt(i8)) {
            result.flags.s8b = true;
            result.int8_value = @intFromFloat(number);
        }
        if (number >= 0 and number <= std.math.maxInt(u16)) {
            result.flags.u16b = true;
            result.uint16_value = @intFromFloat(number);
        }
        if (number >= std.math.minInt(i16) and number <= std.math.maxInt(i16)) {
            result.flags.s16b = true;
            result.int16_value = @intFromFloat(number);
        }
        if (number >= 0 and number <= std.math.maxInt(u32)) {
            result.flags.u32b = true;
            result.uint32_value = @intFromFloat(number);
        }
        if (number >= std.math.minInt(i32) and number <= std.math.maxInt(i32)) {
            result.flags.s32b = true;
            result.int32_value = @intFromFloat(number);
        }
        if (number >= 0 and number < @as(f64, @floatFromInt(std.math.maxInt(u64)))) {
            result.flags.u64b = true;
            result.uint64_value = @intFromFloat(number);
        }
        if (number >= std.math.minInt(i64) and number < @as(f64, @floatFromInt(std.math.maxInt(i64)))) {
            result.flags.s64b = true;
            result.int64_value = @intFromFloat(number);
        }

        return result;
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "parseInt: preserves matching signed and unsigned ranges" {
    const value = try UserValue.parseInt("255");
    try std.testing.expectEqual((MatchFlags{ .u8b = true, .u16b = true, .u32b = true, .u64b = true, .s16b = true, .s32b = true, .s64b = true }).bits(), value.flags.bits());
    try std.testing.expect(!value.flags.s8b);
    try std.testing.expectEqual(255, value.uint8_value);
    try std.testing.expectEqual(255, value.uint16_value);
    try std.testing.expectEqual(255, value.uint32_value);
    try std.testing.expectEqual(255, value.uint64_value);
    try std.testing.expectEqual(255, value.int16_value);
    try std.testing.expectEqual(255, value.int32_value);
    try std.testing.expectEqual(255, value.int64_value);
}

test "parseInt: does not enable float flags" {
    const value = try UserValue.parseInt("42");
    try std.testing.expect(!value.flags.f32b);
    try std.testing.expect(!value.flags.f64b);
}

test "parseNumber: from integer also enables float flags" {
    const value = try UserValue.parseNumber("42");
    try std.testing.expectEqual(MatchFlags.all.bits(), value.flags.bits());
    try std.testing.expectEqual(42, value.uint8_value);
    try std.testing.expectEqual(42, value.int8_value);
    try std.testing.expectEqual(42, value.float32_value);
    try std.testing.expectEqual(42, value.float64_value);
}

test "parseNumber: from float backfills integer candidates" {
    const value = try UserValue.parseNumber("12.75");
    try std.testing.expectEqual(MatchFlags.all.bits(), value.flags.bits());
    try std.testing.expectEqual(12, value.uint8_value);
    try std.testing.expectEqual(12, value.int8_value);
    try std.testing.expectEqual(12.75, value.float32_value);
    try std.testing.expectEqual(12.75, value.float64_value);
}

test "parseByteArray: allocates bytes and wildcards" {
    const allocator = std.testing.allocator;
    const tokens = [_][]const u8{ "4F", "??", "A0" };
    var value = try UserValue.parseByteArray(allocator, &tokens);
    defer value.deinit(allocator);

    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x4F, 0x00, 0xA0 }, value.bytearray_value.?);
    try std.testing.expectEqual(Wildcard.FIXED, value.wildcard_value.?[0]);
    try std.testing.expectEqual(Wildcard.WILDCARD, value.wildcard_value.?[1]);
    try std.testing.expectEqual(Wildcard.FIXED, value.wildcard_value.?[2]);
}

test "parseByteArrayText: tokenizes whitespace-delimited input" {
    const allocator = std.testing.allocator;
    var value = try UserValue.parseByteArrayText(allocator, "4F ?? A0");
    defer value.deinit(allocator);

    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x4F, 0x00, 0xA0 }, value.bytearray_value.?);
    try std.testing.expectEqualSlices(Wildcard, &[_]Wildcard{ .FIXED, .WILDCARD, .FIXED }, value.wildcard_value.?);
}
