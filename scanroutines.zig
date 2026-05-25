//! Scan type definitions and matching kernels.

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
const UserValue = value_mod.UserValue;

pub const ScanDataType = enum {
    ANYNUMBER, // ANYINTEGER or ANYFLOAT
    ANYINTEGER, // Integer of any width
    ANYFLOAT, // Float of any width
    INTEGER8,
    INTEGER16,
    INTEGER32,
    INTEGER64,
    FLOAT32,
    FLOAT64,
    BYTEARRAY,
    STRING,
};

pub const ScanMatchType = enum {
    MATCHANY, // For snapshot
    MATCHEQUALTO,
    MATCHNOTEQUALTO,
    MATCHGREATERTHAN,
    MATCHLESSTHAN,
    MATCHRANGE,
    MATCHUPDATE,
    MATCHNOTCHANGED,
    MATCHCHANGED,
    MATCHINCREASED,
    MATCHDECREASED,
    MATCHINCREASEDBY,
    MATCHDECREASEDBY,
};

/// Validates a (data_type, match_type, user_values) combination prior to scanning.
/// Scanner code rejects invalid combinations with "ScannerError.UnsupportedScanCombination"
/// before dispatching to a specialized scanner-side path or a pre-selected kernel.
pub fn validateCombo(data_type: ScanDataType, match_type: ScanMatchType, user_values: []const UserValue) bool {
    // STRING/BYTEARRAY only support MATCHANY, MATCHEQUALTO, and MATCHUPDATE.
    // Numeric delta/compare match types have no meaning for variable-length data.
    switch (data_type) {
        .BYTEARRAY, .STRING => switch (match_type) {
            .MATCHANY, .MATCHEQUALTO, .MATCHUPDATE => {},
            else => return false,
        },
        else => {},
    }

    switch (match_type) {
        .MATCHEQUALTO,
        .MATCHNOTEQUALTO,
        .MATCHGREATERTHAN,
        .MATCHLESSTHAN,
        .MATCHINCREASEDBY,
        .MATCHDECREASEDBY,
        => if (user_values.len < 1) return false,
        .MATCHRANGE => if (user_values.len < 2) return false,
        else => return true,
    }

    const primary_bits = possibleMatchBits(data_type, user_values[0]);
    if (match_type == .MATCHRANGE) {
        return primary_bits & possibleMatchBits(data_type, user_values[1]) != 0;
    }
    return primary_bits != 0;
}

fn possibleMatchBits(data_type: ScanDataType, user_value: UserValue) u16 {
    return switch (data_type) {
        .ANYNUMBER => user_value.flags.bits() & MatchFlags.all.bits(),
        .ANYINTEGER => user_value.flags.bits() & MatchFlags.integer.bits(),
        .ANYFLOAT => user_value.flags.bits() & MatchFlags.float.bits(),
        .INTEGER8 => user_value.flags.bits() & MatchFlags.i8b.bits(),
        .INTEGER16 => user_value.flags.bits() & MatchFlags.i16b.bits(),
        .INTEGER32 => user_value.flags.bits() & MatchFlags.i32b.bits(),
        .INTEGER64 => user_value.flags.bits() & MatchFlags.i64b.bits(),
        .FLOAT32 => user_value.flags.bits() & (MatchFlags{ .f32b = true }).bits(),
        .FLOAT64 => user_value.flags.bits() & (MatchFlags{ .f64b = true }).bits(),
        // Variable-length match metadata stores length in "raw_bits: u16",
        // so reject patterns/strings that would overflow at match time and
        // require BYTEARRAY pattern/wildcard slices to be the same length.
        .BYTEARRAY => blk: {
            const pattern = user_value.bytearray_value orelse break :blk 0;
            const wildcards = user_value.wildcard_value orelse break :blk 0;
            break :blk if (pattern.len == wildcards.len and pattern.len <= std.math.maxInt(u16)) 1 else 0;
        },
        .STRING => blk: {
            const text = user_value.string_value orelse break :blk 0;
            break :blk if (text.len <= std.math.maxInt(u16)) 1 else 0;
        },
    };
}

pub const InitialNumericKernel = *const fn (memory: []const u8, user_values: []const UserValue) u16;

pub fn pickInitialNumericKernel(data_type: ScanDataType, match_type: ScanMatchType, reverse_endianness: bool) ?InitialNumericKernel {
    return switch (match_type) {
        .MATCHANY => switch (data_type) {
            .INTEGER8 => initialFixedAnyKernel(MatchFlags.i8b.bits(), 1),
            .INTEGER16 => initialFixedAnyKernel(MatchFlags.i16b.bits(), 2),
            .INTEGER32 => initialFixedAnyKernel(MatchFlags.i32b.bits(), 4),
            .INTEGER64 => initialFixedAnyKernel(MatchFlags.i64b.bits(), 8),
            .FLOAT32 => initialFixedAnyKernel((MatchFlags{ .f32b = true }).bits(), 4),
            .FLOAT64 => initialFixedAnyKernel((MatchFlags{ .f64b = true }).bits(), 8),
            .ANYINTEGER => initialAnyWidthKernel(true, false),
            .ANYFLOAT => initialAnyWidthKernel(false, true),
            .ANYNUMBER => initialAnyWidthKernel(true, true),
            .BYTEARRAY, .STRING => null,
        },
        .MATCHEQUALTO,
        .MATCHNOTEQUALTO,
        .MATCHGREATERTHAN,
        .MATCHLESSTHAN,
        .MATCHRANGE,
        => switch (data_type) {
            .INTEGER8, .INTEGER16, .INTEGER32, .INTEGER64, .FLOAT32, .FLOAT64, .ANYINTEGER, .ANYFLOAT, .ANYNUMBER => pickFixedCompareKernel(data_type, match_type, reverse_endianness),
            .BYTEARRAY, .STRING => null,
        },
        else => null,
    };
}

fn initialFixedAnyKernel(comptime raw_bits: u16, comptime width: usize) InitialNumericKernel {
    return struct {
        fn kernel(memory: []const u8, _: []const UserValue) u16 {
            return if (memory.len >= width) raw_bits else 0;
        }
    }.kernel;
}

fn initialAnyWidthKernel(comptime include_integer: bool, comptime include_float: bool) InitialNumericKernel {
    return struct {
        fn kernel(memory: []const u8, _: []const UserValue) u16 {
            var bits: u16 = 0;
            if (include_integer) bits |= anyIntegerInitialBits(memory.len);
            if (include_float) bits |= anyFloatInitialBits(memory.len);
            return bits;
        }
    }.kernel;
}

pub fn anyIntegerInitialBits(len: usize) u16 {
    var bits: u16 = 0;
    if (len >= 1) bits |= MatchFlags.i8b.bits();
    if (len >= 2) bits |= MatchFlags.i16b.bits();
    if (len >= 4) bits |= MatchFlags.i32b.bits();
    if (len >= 8) bits |= MatchFlags.i64b.bits();
    return bits;
}

pub fn anyFloatInitialBits(len: usize) u16 {
    var bits: u16 = 0;
    if (len >= 4) bits |= (MatchFlags{ .f32b = true }).bits();
    if (len >= 8) bits |= (MatchFlags{ .f64b = true }).bits();
    return bits;
}

/// Pre-selected fixed-width delta kernel: specialized per (data_type, match_type, reverse_endianness).
/// Same shape as the compare kernel, caller picks once via "pickFixedDeltaKernel" and runs it per
/// candidate with no runtime dispatch in the hot loop.
pub const FixedDeltaKernel = *const fn (current: []const u8, old: []const u8, old_raw_bits: u16, user_values: []const UserValue) u16;

pub fn pickFixedDeltaKernel(data_type: ScanDataType, match_type: ScanMatchType, reverse_endianness: bool) FixedDeltaKernel {
    return switch (data_type) {
        .INTEGER8 => pickIntegerDeltaKernel(i8, u8, .s8b, .u8b, "int8_value", "uint8_value", match_type, reverse_endianness),
        .INTEGER16 => pickIntegerDeltaKernel(i16, u16, .s16b, .u16b, "int16_value", "uint16_value", match_type, reverse_endianness),
        .INTEGER32 => pickIntegerDeltaKernel(i32, u32, .s32b, .u32b, "int32_value", "uint32_value", match_type, reverse_endianness),
        .INTEGER64 => pickIntegerDeltaKernel(i64, u64, .s64b, .u64b, "int64_value", "uint64_value", match_type, reverse_endianness),
        .FLOAT32 => pickFloatDeltaKernel(f32, u32, .f32b, "float32_value", match_type, reverse_endianness),
        .FLOAT64 => pickFloatDeltaKernel(f64, u64, .f64b, "float64_value", match_type, reverse_endianness),
        .ANYINTEGER => pickAnyIntegerDeltaKernel(match_type, reverse_endianness),
        .ANYFLOAT => pickAnyFloatDeltaKernel(match_type, reverse_endianness),
        .ANYNUMBER => pickAnyNumberDeltaKernel(match_type, reverse_endianness),
        else => &noopDeltaKernel,
    };
}

fn noopDeltaKernel(current: []const u8, old: []const u8, old_raw_bits: u16, user_values: []const UserValue) u16 {
    _ = current;
    _ = old;
    _ = old_raw_bits;
    _ = user_values;
    return 0;
}

fn pickIntegerDeltaKernel(
    comptime S: type,
    comptime U: type,
    comptime sf: std.meta.FieldEnum(MatchFlags),
    comptime uf: std.meta.FieldEnum(MatchFlags),
    comptime signed_user_field: []const u8,
    comptime unsigned_user_field: []const u8,
    match_type: ScanMatchType,
    reverse_endianness: bool,
) FixedDeltaKernel {
    return switch (match_type) {
        inline .MATCHINCREASED, .MATCHDECREASED, .MATCHINCREASEDBY, .MATCHDECREASEDBY => |mt| switch (reverse_endianness) {
            inline true, false => |re| &struct {
                fn kernel(current: []const u8, old: []const u8, old_raw_bits: u16, user_values: []const UserValue) u16 {
                    return fixedIntegerDeltaFlags(S, U, sf, uf, signed_user_field, unsigned_user_field, mt, current, old, old_raw_bits, user_values, re).bits();
                }
            }.kernel,
        },
        else => &noopDeltaKernel,
    };
}

fn pickFloatDeltaKernel(
    comptime F: type,
    comptime Bits: type,
    comptime ff: std.meta.FieldEnum(MatchFlags),
    comptime float_user_field: []const u8,
    match_type: ScanMatchType,
    reverse_endianness: bool,
) FixedDeltaKernel {
    return switch (match_type) {
        inline .MATCHINCREASED, .MATCHDECREASED, .MATCHINCREASEDBY, .MATCHDECREASEDBY => |mt| switch (reverse_endianness) {
            inline true, false => |re| &struct {
                fn kernel(current: []const u8, old: []const u8, old_raw_bits: u16, user_values: []const UserValue) u16 {
                    return fixedFloatDeltaFlags(F, Bits, ff, float_user_field, mt, current, old, old_raw_bits, user_values, re).bits();
                }
            }.kernel,
        },
        else => &noopDeltaKernel,
    };
}

fn pickAnyIntegerDeltaKernel(match_type: ScanMatchType, reverse_endianness: bool) FixedDeltaKernel {
    return switch (match_type) {
        inline .MATCHINCREASED, .MATCHDECREASED, .MATCHINCREASEDBY, .MATCHDECREASEDBY => |mt| switch (reverse_endianness) {
            inline true, false => |re| &struct {
                fn kernel(current: []const u8, old: []const u8, old_raw_bits: u16, user_values: []const UserValue) u16 {
                    return anyIntegerDeltaFlags(mt, current, old, old_raw_bits, user_values, re).bits();
                }
            }.kernel,
        },
        else => &noopDeltaKernel,
    };
}

fn pickAnyFloatDeltaKernel(match_type: ScanMatchType, reverse_endianness: bool) FixedDeltaKernel {
    return switch (match_type) {
        inline .MATCHINCREASED, .MATCHDECREASED, .MATCHINCREASEDBY, .MATCHDECREASEDBY => |mt| switch (reverse_endianness) {
            inline true, false => |re| &struct {
                fn kernel(current: []const u8, old: []const u8, old_raw_bits: u16, user_values: []const UserValue) u16 {
                    return anyFloatDeltaFlags(mt, current, old, old_raw_bits, user_values, re).bits();
                }
            }.kernel,
        },
        else => &noopDeltaKernel,
    };
}

fn pickAnyNumberDeltaKernel(match_type: ScanMatchType, reverse_endianness: bool) FixedDeltaKernel {
    return switch (match_type) {
        inline .MATCHINCREASED, .MATCHDECREASED, .MATCHINCREASEDBY, .MATCHDECREASEDBY => |mt| switch (reverse_endianness) {
            inline true, false => |re| &struct {
                fn kernel(current: []const u8, old: []const u8, old_raw_bits: u16, user_values: []const UserValue) u16 {
                    return anyIntegerDeltaFlags(mt, current, old, old_raw_bits, user_values, re).bits() |
                        anyFloatDeltaFlags(mt, current, old, old_raw_bits, user_values, re).bits();
                }
            }.kernel,
        },
        else => &noopDeltaKernel,
    };
}

fn anyIntegerDeltaFlags(
    comptime match_type: ScanMatchType,
    current: []const u8,
    old: []const u8,
    old_raw_bits: u16,
    user_values: []const UserValue,
    comptime reverse_endianness: bool,
) MatchFlags {
    var bits: u16 = 0;
    if (current.len >= 1 and old.len >= 1) bits |= fixedIntegerDeltaFlags(i8, u8, .s8b, .u8b, "int8_value", "uint8_value", match_type, current[0..1], old[0..1], old_raw_bits, user_values, reverse_endianness).bits();
    if (current.len >= 2 and old.len >= 2) bits |= fixedIntegerDeltaFlags(i16, u16, .s16b, .u16b, "int16_value", "uint16_value", match_type, current[0..2], old[0..2], old_raw_bits, user_values, reverse_endianness).bits();
    if (current.len >= 4 and old.len >= 4) bits |= fixedIntegerDeltaFlags(i32, u32, .s32b, .u32b, "int32_value", "uint32_value", match_type, current[0..4], old[0..4], old_raw_bits, user_values, reverse_endianness).bits();
    if (current.len >= 8 and old.len >= 8) bits |= fixedIntegerDeltaFlags(i64, u64, .s64b, .u64b, "int64_value", "uint64_value", match_type, current[0..8], old[0..8], old_raw_bits, user_values, reverse_endianness).bits();
    return @bitCast(bits);
}

fn anyFloatDeltaFlags(
    comptime match_type: ScanMatchType,
    current: []const u8,
    old: []const u8,
    old_raw_bits: u16,
    user_values: []const UserValue,
    comptime reverse_endianness: bool,
) MatchFlags {
    var bits: u16 = 0;
    if (current.len >= 4 and old.len >= 4) bits |= fixedFloatDeltaFlags(f32, u32, .f32b, "float32_value", match_type, current[0..4], old[0..4], old_raw_bits, user_values, reverse_endianness).bits();
    if (current.len >= 8 and old.len >= 8) bits |= fixedFloatDeltaFlags(f64, u64, .f64b, "float64_value", match_type, current[0..8], old[0..8], old_raw_bits, user_values, reverse_endianness).bits();
    return @bitCast(bits);
}

/// Pre-selected fixed-width compare kernel: specialized per (data_type, match_type, reverse_endianness).
/// Callers in the rescan hot loops pick the kernel once via "pickFixedCompareKernel" and call it per
/// candidate without re-dispatching.
pub const FixedCompareKernel = *const fn (current: []const u8, user_values: []const UserValue) u16;

pub fn pickFixedCompareKernel(data_type: ScanDataType, match_type: ScanMatchType, reverse_endianness: bool) FixedCompareKernel {
    return switch (data_type) {
        .INTEGER8 => pickIntegerCompareKernel(i8, u8, .s8b, .u8b, match_type, reverse_endianness),
        .INTEGER16 => pickIntegerCompareKernel(i16, u16, .s16b, .u16b, match_type, reverse_endianness),
        .INTEGER32 => pickIntegerCompareKernel(i32, u32, .s32b, .u32b, match_type, reverse_endianness),
        .INTEGER64 => pickIntegerCompareKernel(i64, u64, .s64b, .u64b, match_type, reverse_endianness),
        .FLOAT32 => pickFloatCompareKernel(f32, u32, .f32b, "float32_value", match_type, reverse_endianness),
        .FLOAT64 => pickFloatCompareKernel(f64, u64, .f64b, "float64_value", match_type, reverse_endianness),
        .ANYINTEGER => pickAnyIntegerCompareKernel(match_type, reverse_endianness),
        .ANYFLOAT => pickAnyFloatCompareKernel(match_type, reverse_endianness),
        .ANYNUMBER => pickAnyNumberCompareKernel(match_type, reverse_endianness),
        else => &noopCompareKernel,
    };
}

fn noopCompareKernel(current: []const u8, user_values: []const UserValue) u16 {
    _ = current;
    _ = user_values;
    return 0;
}

fn pickIntegerCompareKernel(
    comptime S: type,
    comptime U: type,
    comptime sf: std.meta.FieldEnum(MatchFlags),
    comptime uf: std.meta.FieldEnum(MatchFlags),
    match_type: ScanMatchType,
    reverse_endianness: bool,
) FixedCompareKernel {
    return switch (match_type) {
        inline .MATCHEQUALTO, .MATCHNOTEQUALTO, .MATCHGREATERTHAN, .MATCHLESSTHAN, .MATCHRANGE => |mt| switch (reverse_endianness) {
            inline true, false => |re| &struct {
                fn kernel(current: []const u8, user_values: []const UserValue) u16 {
                    return fixedIntegerCompareFlags(S, U, sf, uf, mt, current, user_values, re).bits();
                }
            }.kernel,
        },
        else => &noopCompareKernel,
    };
}

fn pickFloatCompareKernel(
    comptime F: type,
    comptime Bits: type,
    comptime ff: std.meta.FieldEnum(MatchFlags),
    comptime float_user_field: []const u8,
    match_type: ScanMatchType,
    reverse_endianness: bool,
) FixedCompareKernel {
    return switch (match_type) {
        inline .MATCHEQUALTO, .MATCHNOTEQUALTO, .MATCHGREATERTHAN, .MATCHLESSTHAN, .MATCHRANGE => |mt| switch (reverse_endianness) {
            inline true, false => |re| &struct {
                fn kernel(current: []const u8, user_values: []const UserValue) u16 {
                    return fixedFloatCompareFlags(F, Bits, ff, float_user_field, mt, current, user_values, re).bits();
                }
            }.kernel,
        },
        else => &noopCompareKernel,
    };
}

fn pickAnyIntegerCompareKernel(match_type: ScanMatchType, reverse_endianness: bool) FixedCompareKernel {
    return switch (match_type) {
        inline .MATCHEQUALTO, .MATCHNOTEQUALTO, .MATCHGREATERTHAN, .MATCHLESSTHAN, .MATCHRANGE => |mt| switch (reverse_endianness) {
            inline true, false => |re| &struct {
                fn kernel(current: []const u8, user_values: []const UserValue) u16 {
                    return anyIntegerCompareFlags(mt, current, user_values, re).bits();
                }
            }.kernel,
        },
        else => &noopCompareKernel,
    };
}

fn pickAnyFloatCompareKernel(match_type: ScanMatchType, reverse_endianness: bool) FixedCompareKernel {
    return switch (match_type) {
        inline .MATCHEQUALTO, .MATCHNOTEQUALTO, .MATCHGREATERTHAN, .MATCHLESSTHAN, .MATCHRANGE => |mt| switch (reverse_endianness) {
            inline true, false => |re| &struct {
                fn kernel(current: []const u8, user_values: []const UserValue) u16 {
                    return anyFloatCompareFlags(mt, current, user_values, re).bits();
                }
            }.kernel,
        },
        else => &noopCompareKernel,
    };
}

fn pickAnyNumberCompareKernel(match_type: ScanMatchType, reverse_endianness: bool) FixedCompareKernel {
    return switch (match_type) {
        inline .MATCHEQUALTO, .MATCHNOTEQUALTO, .MATCHGREATERTHAN, .MATCHLESSTHAN, .MATCHRANGE => |mt| switch (reverse_endianness) {
            inline true, false => |re| &struct {
                fn kernel(current: []const u8, user_values: []const UserValue) u16 {
                    return anyIntegerCompareFlags(mt, current, user_values, re).bits() |
                        anyFloatCompareFlags(mt, current, user_values, re).bits();
                }
            }.kernel,
        },
        else => &noopCompareKernel,
    };
}

fn anyIntegerCompareFlags(
    comptime match_type: ScanMatchType,
    current: []const u8,
    user_values: []const UserValue,
    comptime reverse_endianness: bool,
) MatchFlags {
    var bits: u16 = 0;
    if (current.len >= 1) bits |= fixedIntegerCompareFlags(i8, u8, .s8b, .u8b, match_type, current[0..1], user_values, reverse_endianness).bits();
    if (current.len >= 2) bits |= fixedIntegerCompareFlags(i16, u16, .s16b, .u16b, match_type, current[0..2], user_values, reverse_endianness).bits();
    if (current.len >= 4) bits |= fixedIntegerCompareFlags(i32, u32, .s32b, .u32b, match_type, current[0..4], user_values, reverse_endianness).bits();
    if (current.len >= 8) bits |= fixedIntegerCompareFlags(i64, u64, .s64b, .u64b, match_type, current[0..8], user_values, reverse_endianness).bits();
    return @bitCast(bits);
}

fn anyFloatCompareFlags(
    comptime match_type: ScanMatchType,
    current: []const u8,
    user_values: []const UserValue,
    comptime reverse_endianness: bool,
) MatchFlags {
    var bits: u16 = 0;
    if (current.len >= 4) bits |= fixedFloatCompareFlags(f32, u32, .f32b, "float32_value", match_type, current[0..4], user_values, reverse_endianness).bits();
    if (current.len >= 8) bits |= fixedFloatCompareFlags(f64, u64, .f64b, "float64_value", match_type, current[0..8], user_values, reverse_endianness).bits();
    return @bitCast(bits);
}

fn fixedIntegerCompareFlags(
    comptime S: type,
    comptime U: type,
    comptime signed_flag: std.meta.FieldEnum(MatchFlags),
    comptime unsigned_flag: std.meta.FieldEnum(MatchFlags),
    comptime match_type: ScanMatchType,
    current: []const u8,
    user_values: []const UserValue,
    comptime reverse_endianness: bool,
) MatchFlags {
    if (current.len < @sizeOf(U)) return .{};
    var current_unsigned = std.mem.readInt(U, current[0..@sizeOf(U)], .native);
    if (reverse_endianness and @sizeOf(U) > 1) current_unsigned = @byteSwap(current_unsigned);
    const current_signed: S = @bitCast(current_unsigned);

    var matched_flags = MatchFlags{};
    applyCompareFlag(S, signed_flag, fieldNameForFlag(signed_flag), match_type, current_signed, user_values, &matched_flags);
    applyCompareFlag(U, unsigned_flag, fieldNameForFlag(unsigned_flag), match_type, current_unsigned, user_values, &matched_flags);
    return matched_flags;
}

fn fixedFloatCompareFlags(
    comptime F: type,
    comptime Bits: type,
    comptime float_flag: std.meta.FieldEnum(MatchFlags),
    comptime float_user_field: []const u8,
    comptime match_type: ScanMatchType,
    current: []const u8,
    user_values: []const UserValue,
    comptime reverse_endianness: bool,
) MatchFlags {
    if (current.len < @sizeOf(Bits)) return .{};
    var bits = std.mem.readInt(Bits, current[0..@sizeOf(Bits)], .native);
    if (reverse_endianness) bits = @byteSwap(bits);
    const current_value: F = @bitCast(bits);

    var matched_flags = MatchFlags{};
    applyCompareFlag(F, float_flag, float_user_field, match_type, current_value, user_values, &matched_flags);
    return matched_flags;
}

inline fn applyCompareFlag(
    comptime T: type,
    comptime flag: std.meta.FieldEnum(MatchFlags),
    comptime user_field: []const u8,
    comptime match_type: ScanMatchType,
    current_value: T,
    user_values: []const UserValue,
    matched_flags: *MatchFlags,
) void {
    const flag_name = @tagName(flag);
    if (user_values.len == 0 or !@field(user_values[0].flags, flag_name)) return;

    const lower = @field(user_values[0], user_field);
    const matched = switch (match_type) {
        .MATCHEQUALTO => current_value == lower,
        .MATCHNOTEQUALTO => current_value != lower,
        .MATCHGREATERTHAN => current_value > lower,
        .MATCHLESSTHAN => current_value < lower,
        .MATCHRANGE => user_values.len >= 2 and @field(user_values[1].flags, flag_name) and current_value >= lower and current_value <= @field(user_values[1], user_field),
        else => false,
    };
    if (matched) @field(matched_flags, flag_name) = true;
}

fn fixedIntegerDeltaFlags(
    comptime S: type,
    comptime U: type,
    comptime signed_flag: std.meta.FieldEnum(MatchFlags),
    comptime unsigned_flag: std.meta.FieldEnum(MatchFlags),
    comptime signed_user_field: []const u8,
    comptime unsigned_user_field: []const u8,
    comptime match_type: ScanMatchType,
    current: []const u8,
    old: []const u8,
    old_raw_bits: u16,
    user_values: []const UserValue,
    comptime reverse_endianness: bool,
) MatchFlags {
    if (current.len < @sizeOf(U) or old.len < @sizeOf(U)) return .{};
    var current_unsigned = std.mem.readInt(U, current[0..@sizeOf(U)], .native);
    var old_unsigned = std.mem.readInt(U, old[0..@sizeOf(U)], .native);
    if (reverse_endianness and @sizeOf(U) > 1) {
        current_unsigned = @byteSwap(current_unsigned);
        old_unsigned = @byteSwap(old_unsigned);
    }
    const current_signed: S = @bitCast(current_unsigned);
    const old_signed: S = @bitCast(old_unsigned);
    const old_flags: MatchFlags = @bitCast(old_raw_bits);

    var matched_flags = MatchFlags{};
    applyDeltaFlag(S, signed_flag, signed_user_field, match_type, current_signed, old_signed, old_flags, user_values, &matched_flags);
    applyDeltaFlag(U, unsigned_flag, unsigned_user_field, match_type, current_unsigned, old_unsigned, old_flags, user_values, &matched_flags);

    return matched_flags;
}

fn fixedFloatDeltaFlags(
    comptime F: type,
    comptime Bits: type,
    comptime float_flag: std.meta.FieldEnum(MatchFlags),
    comptime float_user_field: []const u8,
    comptime match_type: ScanMatchType,
    current: []const u8,
    old: []const u8,
    old_raw_bits: u16,
    user_values: []const UserValue,
    comptime reverse_endianness: bool,
) MatchFlags {
    if (current.len < @sizeOf(Bits) or old.len < @sizeOf(Bits)) return .{};
    var current_bits = std.mem.readInt(Bits, current[0..@sizeOf(Bits)], .native);
    var old_bits = std.mem.readInt(Bits, old[0..@sizeOf(Bits)], .native);
    if (reverse_endianness) {
        current_bits = @byteSwap(current_bits);
        old_bits = @byteSwap(old_bits);
    }
    const current_value: F = @bitCast(current_bits);
    const old_value: F = @bitCast(old_bits);
    const old_flags: MatchFlags = @bitCast(old_raw_bits);

    var matched_flags = MatchFlags{};
    const flag_name = @tagName(float_flag);
    if (@field(old_flags, flag_name)) {
        const matched = switch (match_type) {
            .MATCHINCREASED => current_value > old_value,
            .MATCHDECREASED => current_value < old_value,
            .MATCHINCREASEDBY => if (user_values.len == 0 or !@field(user_values[0].flags, flag_name))
                false
            else blk: {
                const expected = old_value + @field(user_values[0], float_user_field);
                break :blk expected > old_value and current_value == expected;
            },
            .MATCHDECREASEDBY => if (user_values.len == 0 or !@field(user_values[0].flags, flag_name))
                false
            else blk: {
                const expected = old_value - @field(user_values[0], float_user_field);
                break :blk expected < old_value and current_value == expected;
            },
            else => false,
        };
        if (matched) @field(matched_flags, flag_name) = true;
    }

    return matched_flags;
}

inline fn applyDeltaFlag(
    comptime T: type,
    comptime flag: std.meta.FieldEnum(MatchFlags),
    comptime user_field: []const u8,
    comptime match_type: ScanMatchType,
    current_value: T,
    old_value: T,
    old_flags: MatchFlags,
    user_values: []const UserValue,
    matched_flags: *MatchFlags,
) void {
    const flag_name = @tagName(flag);
    if (!@field(old_flags, flag_name)) return;

    const matched = switch (match_type) {
        .MATCHINCREASED => current_value > old_value,
        .MATCHDECREASED => current_value < old_value,
        .MATCHINCREASEDBY => if (user_values.len == 0 or !@field(user_values[0].flags, flag_name))
            false
        else blk: {
            const expected = std.math.add(T, old_value, @field(user_values[0], user_field)) catch break :blk false;
            break :blk expected > old_value and current_value == expected;
        },
        .MATCHDECREASEDBY => if (user_values.len == 0 or !@field(user_values[0].flags, flag_name))
            false
        else blk: {
            const expected = std.math.sub(T, old_value, @field(user_values[0], user_field)) catch break :blk false;
            break :blk expected < old_value and current_value == expected;
        },
        else => false,
    };
    if (matched) @field(matched_flags, flag_name) = true;
}

fn fieldNameForFlag(comptime flag: std.meta.FieldEnum(MatchFlags)) []const u8 {
    return switch (flag) {
        .s8b => "int8_value",
        .u8b => "uint8_value",
        .s16b => "int16_value",
        .u16b => "uint16_value",
        .s32b => "int32_value",
        .u32b => "uint32_value",
        .s64b => "int64_value",
        .u64b => "uint64_value",
        else => @compileError("invalid integer flag"),
    };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "validateCombo: rejects float-only value for integer scans" {
    const user = try UserValue.parseFloat("1.5");
    try std.testing.expect(!validateCombo(.INTEGER32, .MATCHEQUALTO, &.{user}));
}

test "validateCombo: rejects unsupported match types for STRING/BYTEARRAY" {
    // STRING/BYTEARRAY only support MATCHANY, MATCHEQUALTO, and MATCHUPDATE.
    // Numeric delta/compare match types have no meaning for variable-length data.
    try std.testing.expect(!validateCombo(.STRING, .MATCHCHANGED, &.{}));
    try std.testing.expect(!validateCombo(.STRING, .MATCHNOTCHANGED, &.{}));
    try std.testing.expect(!validateCombo(.STRING, .MATCHINCREASED, &.{}));
    try std.testing.expect(!validateCombo(.BYTEARRAY, .MATCHDECREASED, &.{}));
    try std.testing.expect(!validateCombo(.BYTEARRAY, .MATCHGREATERTHAN, &.{}));

    // Supported combos remain accepted.
    try std.testing.expect(validateCombo(.STRING, .MATCHANY, &.{}));
    try std.testing.expect(validateCombo(.BYTEARRAY, .MATCHANY, &.{}));
    try std.testing.expect(validateCombo(.STRING, .MATCHUPDATE, &.{}));
}

test "validateCombo: range requires a common bound flag" {
    const signed_lower = UserValue{
        .int32_value = -10,
        .flags = .{ .s32b = true },
    };
    const unsigned_upper = UserValue{
        .uint32_value = 10,
        .flags = .{ .u32b = true },
    };
    try std.testing.expect(!validateCombo(.INTEGER32, .MATCHRANGE, &.{ signed_lower, unsigned_upper }));

    const signed_upper = UserValue{
        .int32_value = 10,
        .flags = .{ .s32b = true },
    };
    try std.testing.expect(validateCombo(.INTEGER32, .MATCHRANGE, &.{ signed_lower, signed_upper }));
}

test "pickInitialNumericKernel: ANYNUMBER MATCHANY reports every fitting width" {
    const kernel = pickInitialNumericKernel(.ANYNUMBER, .MATCHANY, false).?;
    const full_bytes: [8]u8 = @splat(0);
    const full = kernel(&full_bytes, &.{});
    try std.testing.expectEqual(MatchFlags.all.bits(), full);

    const four_bytes: [4]u8 = @splat(0);
    const four = kernel(&four_bytes, &.{});
    try std.testing.expectEqual((MatchFlags{ .u8b = true, .s8b = true, .u16b = true, .s16b = true, .u32b = true, .s32b = true, .f32b = true }).bits(), four);

    const one_byte = [_]u8{0};
    const one = kernel(&one_byte, &.{});
    try std.testing.expectEqual(MatchFlags.i8b.bits(), one);
}

test "pickFixedCompareKernel: integer exact preserves signed and unsigned flags independently" {
    var bytes: [4]u8 = undefined;
    std.mem.writeInt(u32, &bytes, 5, .native);
    const both = try UserValue.parseNumber("5");
    try std.testing.expectEqual(MatchFlags.i32b.bits(), pickFixedCompareKernel(.INTEGER32, .MATCHEQUALTO, false)(&bytes, &.{both}));

    std.mem.writeInt(u32, &bytes, std.math.maxInt(u32), .native);
    const signed_only = try UserValue.parseNumber("-1");
    try std.testing.expectEqual((MatchFlags{ .s32b = true }).bits(), pickFixedCompareKernel(.INTEGER32, .MATCHEQUALTO, false)(&bytes, &.{signed_only}));

    const unsigned_only = try UserValue.parseNumber("4294967295");
    try std.testing.expectEqual((MatchFlags{ .u32b = true }).bits(), pickFixedCompareKernel(.INTEGER32, .MATCHEQUALTO, false)(&bytes, &.{unsigned_only}));
}

test "pickFixedCompareKernel: integer range preserves signed and unsigned flags independently" {
    var bytes: [4]u8 = undefined;
    std.mem.writeInt(u32, &bytes, 5, .native);

    const lower_both = try UserValue.parseNumber("0");
    const upper_both = try UserValue.parseNumber("10");
    try std.testing.expectEqual(MatchFlags.i32b.bits(), pickFixedCompareKernel(.INTEGER32, .MATCHRANGE, false)(&bytes, &.{ lower_both, upper_both }));

    const lower_signed = try UserValue.parseNumber("-10");
    const upper_signed = try UserValue.parseNumber("10");
    try std.testing.expectEqual((MatchFlags{ .s32b = true }).bits(), pickFixedCompareKernel(.INTEGER32, .MATCHRANGE, false)(&bytes, &.{ lower_signed, upper_signed }));
}

test "pickFixedCompareKernel: range ignores flags missing from upper bound" {
    var bytes: [4]u8 = undefined;
    std.mem.writeInt(u32, &bytes, 5, .native);

    const lower = UserValue{
        .uint32_value = 0,
        .flags = .{ .u32b = true },
    };
    const upper = UserValue{
        .uint32_value = 10,
        .flags = .{},
    };
    try std.testing.expectEqual(0, pickFixedCompareKernel(.INTEGER32, .MATCHRANGE, false)(&bytes, &.{ lower, upper }));
}

test "reverseEndianness: pickFixedCompareKernel honors target endian" {
    const user = try UserValue.parseNumber("0x1234");
    const original: u16 = 0x1234;
    const swapped = @byteSwap(original);
    const memory = std.mem.asBytes(&swapped);

    try std.testing.expectEqual(0, pickFixedCompareKernel(.INTEGER16, .MATCHEQUALTO, false)(memory, &.{user}));
    try std.testing.expectEqual(MatchFlags.i16b.bits(), pickFixedCompareKernel(.INTEGER16, .MATCHEQUALTO, true)(memory, &.{user}));
}

test "pickFixedCompareKernel: ANYINTEGER aggregates every fitting sub-width flag" {
    // Value 5 fits in all four signed and unsigned integer widths, so every flag
    // up to the input length should survive.
    var bytes: [8]u8 = .{ 0, 0, 0, 0, 0, 0, 0, 0 };
    std.mem.writeInt(u64, &bytes, 5, .native);
    const user = try UserValue.parseNumber("5");

    const kernel = pickFixedCompareKernel(.ANYINTEGER, .MATCHEQUALTO, false);
    const expect_all = (MatchFlags{
        .s8b = true,
        .u8b = true,
        .s16b = true,
        .u16b = true,
        .s32b = true,
        .u32b = true,
        .s64b = true,
        .u64b = true,
    }).bits();
    try std.testing.expectEqual(expect_all, kernel(&bytes, &.{user}));

    // Same bytes but only 4 bytes visible: the 64-bit flags must drop out.
    const expect_to_32 = (MatchFlags{
        .s8b = true,
        .u8b = true,
        .s16b = true,
        .u16b = true,
        .s32b = true,
        .u32b = true,
    }).bits();
    try std.testing.expectEqual(expect_to_32, kernel(bytes[0..4], &.{user}));

    // 2 bytes visible: only 8 and 16-bit interpretations.
    const expect_to_16 = (MatchFlags{ .s8b = true, .u8b = true, .s16b = true, .u16b = true }).bits();
    try std.testing.expectEqual(expect_to_16, kernel(bytes[0..2], &.{user}));

    // 1 byte: only 8-bit signed/unsigned.
    const expect_to_8 = (MatchFlags{ .s8b = true, .u8b = true }).bits();
    try std.testing.expectEqual(expect_to_8, kernel(bytes[0..1], &.{user}));
}

test "pickFixedCompareKernel: ANYINTEGER GT splits signed and unsigned independently per width" {
    // 0x800000F0 as i32 = large negative, as u32 = huge positive.
    var bytes: [4]u8 = undefined;
    std.mem.writeInt(u32, &bytes, 0x800000F0, .native);
    const user_zero = try UserValue.parseNumber("0");

    const kernel = pickFixedCompareKernel(.ANYINTEGER, .MATCHGREATERTHAN, false);
    const result = kernel(&bytes, &.{user_zero});

    const flags: MatchFlags = @bitCast(result);
    // i32 interpretation: -2147483408 > 0 -> false; u32: 2.1B > 0 -> true.
    try std.testing.expect(!flags.s32b);
    try std.testing.expect(flags.u32b);
    // The low byte is 0xF0; as i8 (= -16) it is NOT > 0, as u8 (= 240) it IS > 0.
    try std.testing.expect(!flags.s8b);
    try std.testing.expect(flags.u8b);
}

test "pickFixedCompareKernel: ANYFLOAT honors both widths and NaN drops" {
    // Encode 0.5 as f32 in the low 4 bytes, NaN as f64 in the high 8 bytes.
    var memory: [8]u8 = undefined;
    const half: f32 = 0.5;
    std.mem.writeInt(u32, memory[0..4], @bitCast(half), .native);

    // The 4-byte input should match f32 = 0.5.
    const user_half = try UserValue.parseNumber("0.5");
    const kernel = pickFixedCompareKernel(.ANYFLOAT, .MATCHEQUALTO, false);
    const r4 = kernel(memory[0..4], &.{user_half});
    try std.testing.expectEqual((MatchFlags{ .f32b = true }).bits(), r4);

    // Build a memory image whose f64 interpretation is NaN; equality must drop f64b.
    const nan_bits: u64 = 0x7ff8000000000000;
    std.mem.writeInt(u64, &memory, nan_bits, .native);
    const user_one = try UserValue.parseNumber("1.0");
    const r8 = kernel(&memory, &.{user_one});
    const flags8: MatchFlags = @bitCast(r8);
    try std.testing.expect(!flags8.f64b);
}

test "pickFixedCompareKernel: ANYNUMBER unions integer and float survivors" {
    // 0x3F800000 is f32 = 1.0 AND a valid u32/s32 = 1065353216.
    var bytes: [4]u8 = undefined;
    std.mem.writeInt(u32, &bytes, 0x3F800000, .native);

    const user_one_float = try UserValue.parseNumber("1.0");
    const kernel_eq = pickFixedCompareKernel(.ANYNUMBER, .MATCHEQUALTO, false);
    const r_eq = kernel_eq(&bytes, &.{user_one_float});
    const eq_flags: MatchFlags = @bitCast(r_eq);
    // f32 interpretation matches 1.0; integer interpretations match 1065353216 (not 1.0 -> drop).
    try std.testing.expect(eq_flags.f32b);
    try std.testing.expect(!eq_flags.s32b);
    try std.testing.expect(!eq_flags.u32b);
}

test "reverseEndianness: pickFixedDeltaKernel honors target endian for unsigned ordering" {
    // Build bytes that represent 1 -> 256 under the reverse-of-native endian by
    // writing the byte-swapped values as native.
    // Reading those bytes back under native yields the swapped pair (256 -> 1),
    // so the verdict flips between endian interpretations on any host.
    var old_bytes: [2]u8 = undefined;
    var cur_bytes: [2]u8 = undefined;
    const old_target: u16 = 1;
    const cur_target: u16 = 256;
    std.mem.writeInt(u16, &old_bytes, @byteSwap(old_target), .native);
    std.mem.writeInt(u16, &cur_bytes, @byteSwap(cur_target), .native);
    const old_raw = (MatchFlags{ .u16b = true, .s16b = true }).bits();

    // reverse_endianness=true: target sees 1 -> 256, so INCREASED matches.
    const reverse_inc: MatchFlags = @bitCast(pickFixedDeltaKernel(.INTEGER16, .MATCHINCREASED, true)(&cur_bytes, &old_bytes, old_raw, &.{}));
    try std.testing.expect(reverse_inc.u16b);
    const reverse_dec: MatchFlags = @bitCast(pickFixedDeltaKernel(.INTEGER16, .MATCHDECREASED, true)(&cur_bytes, &old_bytes, old_raw, &.{}));
    try std.testing.expect(!reverse_dec.u16b);

    // reverse_endianness=false: native sees 256 -> 1, so DECREASED matches.
    const native_dec: MatchFlags = @bitCast(pickFixedDeltaKernel(.INTEGER16, .MATCHDECREASED, false)(&cur_bytes, &old_bytes, old_raw, &.{}));
    try std.testing.expect(native_dec.u16b);
    const native_inc: MatchFlags = @bitCast(pickFixedDeltaKernel(.INTEGER16, .MATCHINCREASED, false)(&cur_bytes, &old_bytes, old_raw, &.{}));
    try std.testing.expect(!native_inc.u16b);
}

test "reverseEndianness: pickFixedDeltaKernel honors target endian for float ordering" {
    // Build bytes that represent 1.0 -> 2.0 under the reverse-of-native endian.
    // Native reading produces byte-swapped subnormal bit patterns where 1.0's
    // swap is numerically larger than 2.0's swap (mantissa bits dominate),
    // flipping the verdict.
    var old_bytes: [4]u8 = undefined;
    var cur_bytes: [4]u8 = undefined;
    const old_target: f32 = 1.0;
    const cur_target: f32 = 2.0;
    const old_bits: u32 = @bitCast(old_target);
    const cur_bits: u32 = @bitCast(cur_target);
    std.mem.writeInt(u32, &old_bytes, @byteSwap(old_bits), .native);
    std.mem.writeInt(u32, &cur_bytes, @byteSwap(cur_bits), .native);
    const old_raw = (MatchFlags{ .f32b = true }).bits();

    // reverse_endianness=true: 1.0 -> 2.0, INCREASED matches.
    const reverse_inc: MatchFlags = @bitCast(pickFixedDeltaKernel(.FLOAT32, .MATCHINCREASED, true)(&cur_bytes, &old_bytes, old_raw, &.{}));
    try std.testing.expect(reverse_inc.f32b);

    // reverse_endianness=false: byte-swapped subnormals, old > cur, INCREASED doesn't match.
    const native_inc: MatchFlags = @bitCast(pickFixedDeltaKernel(.FLOAT32, .MATCHINCREASED, false)(&cur_bytes, &old_bytes, old_raw, &.{}));
    try std.testing.expect(!native_inc.f32b);
}

test "pickFixedDeltaKernel: float delta-by requires actual movement" {
    const delta = try UserValue.parseNumber("1");
    const old_raw = (MatchFlags{ .f32b = true }).bits();

    const unchanged: f32 = 16777216.0;
    const unchanged_bits = std.mem.asBytes(&unchanged);
    const miss: MatchFlags = @bitCast(pickFixedDeltaKernel(.FLOAT32, .MATCHINCREASEDBY, false)(unchanged_bits, unchanged_bits, old_raw, &.{delta}));
    try std.testing.expect(!miss.f32b);

    const old_value: f32 = 1.0;
    const current_value: f32 = 2.0;
    const hit: MatchFlags = @bitCast(pickFixedDeltaKernel(.FLOAT32, .MATCHINCREASEDBY, false)(std.mem.asBytes(&current_value), std.mem.asBytes(&old_value), old_raw, &.{delta}));
    try std.testing.expect(hit.f32b);
}

test "pickFixedDeltaKernel: integer delta-by checks overflow and actual movement" {
    const old_raw = (MatchFlags{ .u32b = true }).bits();
    var old_bytes: [4]u8 = undefined;
    var current_bytes: [4]u8 = undefined;
    std.mem.writeInt(u32, &old_bytes, std.math.maxInt(u32), .native);
    std.mem.writeInt(u32, &current_bytes, 0, .native);
    const plus_one = UserValue{
        .uint32_value = 1,
        .flags = .{ .u32b = true },
    };
    try std.testing.expectEqual(0, pickFixedDeltaKernel(.INTEGER32, .MATCHINCREASEDBY, false)(&current_bytes, &old_bytes, old_raw, &.{plus_one}));

    const signed_raw = (MatchFlags{ .s32b = true }).bits();
    const old_value: i32 = 10;
    const current_value: i32 = 5;
    std.mem.writeInt(u32, &old_bytes, @bitCast(old_value), .native);
    std.mem.writeInt(u32, &current_bytes, @bitCast(current_value), .native);
    const negative_delta = UserValue{
        .int32_value = -5,
        .flags = .{ .s32b = true },
    };
    try std.testing.expectEqual(0, pickFixedDeltaKernel(.INTEGER32, .MATCHINCREASEDBY, false)(&current_bytes, &old_bytes, signed_raw, &.{negative_delta}));

    const positive_delta = UserValue{
        .int32_value = 5,
        .flags = .{ .s32b = true },
    };
    try std.testing.expectEqual(signed_raw, pickFixedDeltaKernel(.INTEGER32, .MATCHDECREASEDBY, false)(&current_bytes, &old_bytes, signed_raw, &.{positive_delta}));
}

test "reverseEndianness: pickFixedDeltaKernel honors target endian for INCREASEDBY" {
    // Build bytes that represent 10 -> 15 under the reverse-of-native endian.
    var old_bytes: [4]u8 = undefined;
    var cur_bytes: [4]u8 = undefined;
    const old_target: u32 = 10;
    const cur_target: u32 = 15;
    std.mem.writeInt(u32, &old_bytes, @byteSwap(old_target), .native);
    std.mem.writeInt(u32, &cur_bytes, @byteSwap(cur_target), .native);

    const delta = try UserValue.parseNumber("5");
    const old_raw = (MatchFlags{ .u32b = true, .s32b = true }).bits();

    // reverse_endianness=true: target sees (10, 15), 15 == 10 + 5, u32b matches.
    const reverse_hit: MatchFlags = @bitCast(pickFixedDeltaKernel(.INTEGER32, .MATCHINCREASEDBY, true)(&cur_bytes, &old_bytes, old_raw, &.{delta}));
    try std.testing.expect(reverse_hit.u32b);

    // reverse_endianness=false: byte-swapped values, cur != old + 5, no match.
    const native_miss: MatchFlags = @bitCast(pickFixedDeltaKernel(.INTEGER32, .MATCHINCREASEDBY, false)(&cur_bytes, &old_bytes, old_raw, &.{delta}));
    try std.testing.expect(!native_miss.u32b);
}
