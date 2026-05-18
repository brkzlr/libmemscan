//! Scan routine selection and matching logic.

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

pub const SaveInfo = union(enum) {
    NONE,
    NUMERIC: MatchFlags,
    VARIABLE_LENGTH: u16,

    pub fn raw(self: SaveInfo) u16 {
        return switch (self) {
            .NONE => 0,
            .NUMERIC => |flags| flags.bits(),
            .VARIABLE_LENGTH => |len| len,
        };
    }
};

pub const ScanResult = struct {
    matched_len: usize = 0,
    save: SaveInfo = .NONE,

    pub fn noMatch() ScanResult {
        return .{};
    }
};

pub const ScanRoutine = *const fn (memory: []const u8, old_value: ?*const Value, user_values: []const UserValue) ScanResult;

pub fn chooseRoutine(data_type: ScanDataType, match_type: ScanMatchType, user_values: []const UserValue, reverse_endianness: bool) ?ScanRoutine {
    if (requiresUserValues(match_type)) {
        switch (match_type) {
            .MATCHRANGE => {
                if (user_values.len < 2) return null;
            },
            else => {
                if (user_values.len < 1) return null;
            },
        }

        if (!canPossiblyMatch(data_type, user_values)) return null;
    }

    return switch (data_type) {
        .INTEGER8 => switch (match_type) {
            .MATCHANY => integerRoutine(i8, u8, .s8b, .u8b, .MATCHANY, false),
            .MATCHUPDATE => integerRoutine(i8, u8, .s8b, .u8b, .MATCHUPDATE, false),
            .MATCHEQUALTO => integerRoutine(i8, u8, .s8b, .u8b, .MATCHEQUALTO, false),
            .MATCHNOTEQUALTO => integerRoutine(i8, u8, .s8b, .u8b, .MATCHNOTEQUALTO, false),
            .MATCHGREATERTHAN => integerRoutine(i8, u8, .s8b, .u8b, .MATCHGREATERTHAN, false),
            .MATCHLESSTHAN => integerRoutine(i8, u8, .s8b, .u8b, .MATCHLESSTHAN, false),
            .MATCHRANGE => integerRoutine(i8, u8, .s8b, .u8b, .MATCHRANGE, false),
            .MATCHNOTCHANGED => integerRoutine(i8, u8, .s8b, .u8b, .MATCHNOTCHANGED, false),
            .MATCHCHANGED => integerRoutine(i8, u8, .s8b, .u8b, .MATCHCHANGED, false),
            .MATCHINCREASED => integerRoutine(i8, u8, .s8b, .u8b, .MATCHINCREASED, false),
            .MATCHDECREASED => integerRoutine(i8, u8, .s8b, .u8b, .MATCHDECREASED, false),
            .MATCHINCREASEDBY => integerRoutine(i8, u8, .s8b, .u8b, .MATCHINCREASEDBY, false),
            .MATCHDECREASEDBY => integerRoutine(i8, u8, .s8b, .u8b, .MATCHDECREASEDBY, false),
        },
        .INTEGER16 => integerChooser(i16, u16, .s16b, .u16b, match_type, reverse_endianness),
        .INTEGER32 => integerChooser(i32, u32, .s32b, .u32b, match_type, reverse_endianness),
        .INTEGER64 => integerChooser(i64, u64, .s64b, .u64b, match_type, reverse_endianness),
        .FLOAT32 => floatChooser(f32, u32, .f32b, match_type, reverse_endianness),
        .FLOAT64 => floatChooser(f64, u64, .f64b, match_type, reverse_endianness),
        .ANYINTEGER => anyIntegerChooser(match_type, reverse_endianness),
        .ANYFLOAT => anyFloatChooser(match_type, reverse_endianness),
        .ANYNUMBER => anyNumberChooser(match_type, reverse_endianness),
        .BYTEARRAY => bytearrayChooser(match_type),
        .STRING => stringChooser(match_type),
    };
}

fn requiresUserValues(match_type: ScanMatchType) bool {
    return switch (match_type) {
        .MATCHEQUALTO,
        .MATCHNOTEQUALTO,
        .MATCHGREATERTHAN,
        .MATCHLESSTHAN,
        .MATCHRANGE,
        .MATCHINCREASEDBY,
        .MATCHDECREASEDBY,
        => true,
        else => false,
    };
}

fn canPossiblyMatch(data_type: ScanDataType, user_values: []const UserValue) bool {
    return switch (data_type) {
        .ANYNUMBER => user_values[0].flags.bits() & MatchFlags.all.bits() != 0,
        .ANYINTEGER => user_values[0].flags.bits() & MatchFlags.integer.bits() != 0,
        .ANYFLOAT => user_values[0].flags.bits() & MatchFlags.float.bits() != 0,
        .INTEGER8 => user_values[0].flags.s8b or user_values[0].flags.u8b,
        .INTEGER16 => user_values[0].flags.s16b or user_values[0].flags.u16b,
        .INTEGER32 => user_values[0].flags.s32b or user_values[0].flags.u32b,
        .INTEGER64 => user_values[0].flags.s64b or user_values[0].flags.u64b,
        .FLOAT32 => user_values[0].flags.f32b,
        .FLOAT64 => user_values[0].flags.f64b,
        .BYTEARRAY => user_values[0].bytearray_value != null and user_values[0].wildcard_value != null,
        .STRING => user_values[0].string_value != null,
    };
}

fn integerChooser(
    comptime S: type,
    comptime U: type,
    comptime signed_flag: std.meta.FieldEnum(MatchFlags),
    comptime unsigned_flag: std.meta.FieldEnum(MatchFlags),
    match_type: ScanMatchType,
    reverse_endianness: bool,
) ?ScanRoutine {
    return switch (match_type) {
        .MATCHANY => integerRoutine(S, U, signed_flag, unsigned_flag, .MATCHANY, false),
        .MATCHUPDATE => integerRoutine(S, U, signed_flag, unsigned_flag, .MATCHUPDATE, false),
        .MATCHEQUALTO => if (reverse_endianness)
            integerRoutine(S, U, signed_flag, unsigned_flag, .MATCHEQUALTO, true)
        else
            integerRoutine(S, U, signed_flag, unsigned_flag, .MATCHEQUALTO, false),
        .MATCHNOTEQUALTO => if (reverse_endianness)
            integerRoutine(S, U, signed_flag, unsigned_flag, .MATCHNOTEQUALTO, true)
        else
            integerRoutine(S, U, signed_flag, unsigned_flag, .MATCHNOTEQUALTO, false),
        .MATCHGREATERTHAN => if (reverse_endianness)
            integerRoutine(S, U, signed_flag, unsigned_flag, .MATCHGREATERTHAN, true)
        else
            integerRoutine(S, U, signed_flag, unsigned_flag, .MATCHGREATERTHAN, false),
        .MATCHLESSTHAN => if (reverse_endianness)
            integerRoutine(S, U, signed_flag, unsigned_flag, .MATCHLESSTHAN, true)
        else
            integerRoutine(S, U, signed_flag, unsigned_flag, .MATCHLESSTHAN, false),
        .MATCHRANGE => if (reverse_endianness)
            integerRoutine(S, U, signed_flag, unsigned_flag, .MATCHRANGE, true)
        else
            integerRoutine(S, U, signed_flag, unsigned_flag, .MATCHRANGE, false),
        .MATCHNOTCHANGED => integerRoutine(S, U, signed_flag, unsigned_flag, .MATCHNOTCHANGED, false),
        .MATCHCHANGED => integerRoutine(S, U, signed_flag, unsigned_flag, .MATCHCHANGED, false),
        .MATCHINCREASED => integerRoutine(S, U, signed_flag, unsigned_flag, .MATCHINCREASED, false),
        .MATCHDECREASED => integerRoutine(S, U, signed_flag, unsigned_flag, .MATCHDECREASED, false),
        .MATCHINCREASEDBY => integerRoutine(S, U, signed_flag, unsigned_flag, .MATCHINCREASEDBY, false),
        .MATCHDECREASEDBY => integerRoutine(S, U, signed_flag, unsigned_flag, .MATCHDECREASEDBY, false),
    };
}

fn floatChooser(
    comptime F: type,
    comptime Bits: type,
    comptime float_flag: std.meta.FieldEnum(MatchFlags),
    match_type: ScanMatchType,
    reverse_endianness: bool,
) ?ScanRoutine {
    return switch (match_type) {
        .MATCHANY => floatRoutine(F, Bits, float_flag, .MATCHANY, false),
        .MATCHUPDATE => floatRoutine(F, Bits, float_flag, .MATCHUPDATE, false),
        .MATCHEQUALTO => if (reverse_endianness)
            floatRoutine(F, Bits, float_flag, .MATCHEQUALTO, true)
        else
            floatRoutine(F, Bits, float_flag, .MATCHEQUALTO, false),
        .MATCHNOTEQUALTO => if (reverse_endianness)
            floatRoutine(F, Bits, float_flag, .MATCHNOTEQUALTO, true)
        else
            floatRoutine(F, Bits, float_flag, .MATCHNOTEQUALTO, false),
        .MATCHGREATERTHAN => if (reverse_endianness)
            floatRoutine(F, Bits, float_flag, .MATCHGREATERTHAN, true)
        else
            floatRoutine(F, Bits, float_flag, .MATCHGREATERTHAN, false),
        .MATCHLESSTHAN => if (reverse_endianness)
            floatRoutine(F, Bits, float_flag, .MATCHLESSTHAN, true)
        else
            floatRoutine(F, Bits, float_flag, .MATCHLESSTHAN, false),
        .MATCHRANGE => if (reverse_endianness)
            floatRoutine(F, Bits, float_flag, .MATCHRANGE, true)
        else
            floatRoutine(F, Bits, float_flag, .MATCHRANGE, false),
        .MATCHNOTCHANGED => floatRoutine(F, Bits, float_flag, .MATCHNOTCHANGED, false),
        .MATCHCHANGED => floatRoutine(F, Bits, float_flag, .MATCHCHANGED, false),
        .MATCHINCREASED => floatRoutine(F, Bits, float_flag, .MATCHINCREASED, false),
        .MATCHDECREASED => floatRoutine(F, Bits, float_flag, .MATCHDECREASED, false),
        .MATCHINCREASEDBY => floatRoutine(F, Bits, float_flag, .MATCHINCREASEDBY, false),
        .MATCHDECREASEDBY => floatRoutine(F, Bits, float_flag, .MATCHDECREASEDBY, false),
    };
}

fn anyIntegerChooser(match_type: ScanMatchType, reverse_endianness: bool) ScanRoutine {
    return switch (match_type) {
        .MATCHANY => anyIntegerRoutine(.MATCHANY, false),
        .MATCHUPDATE => anyIntegerRoutine(.MATCHUPDATE, false),
        .MATCHEQUALTO => if (reverse_endianness) anyIntegerRoutine(.MATCHEQUALTO, true) else anyIntegerRoutine(.MATCHEQUALTO, false),
        .MATCHNOTEQUALTO => if (reverse_endianness) anyIntegerRoutine(.MATCHNOTEQUALTO, true) else anyIntegerRoutine(.MATCHNOTEQUALTO, false),
        .MATCHGREATERTHAN => if (reverse_endianness) anyIntegerRoutine(.MATCHGREATERTHAN, true) else anyIntegerRoutine(.MATCHGREATERTHAN, false),
        .MATCHLESSTHAN => if (reverse_endianness) anyIntegerRoutine(.MATCHLESSTHAN, true) else anyIntegerRoutine(.MATCHLESSTHAN, false),
        .MATCHRANGE => if (reverse_endianness) anyIntegerRoutine(.MATCHRANGE, true) else anyIntegerRoutine(.MATCHRANGE, false),
        .MATCHNOTCHANGED => anyIntegerRoutine(.MATCHNOTCHANGED, false),
        .MATCHCHANGED => anyIntegerRoutine(.MATCHCHANGED, false),
        .MATCHINCREASED => anyIntegerRoutine(.MATCHINCREASED, false),
        .MATCHDECREASED => anyIntegerRoutine(.MATCHDECREASED, false),
        .MATCHINCREASEDBY => anyIntegerRoutine(.MATCHINCREASEDBY, false),
        .MATCHDECREASEDBY => anyIntegerRoutine(.MATCHDECREASEDBY, false),
    };
}

fn anyFloatChooser(match_type: ScanMatchType, reverse_endianness: bool) ScanRoutine {
    return switch (match_type) {
        .MATCHANY => anyFloatRoutine(.MATCHANY, false),
        .MATCHUPDATE => anyFloatRoutine(.MATCHUPDATE, false),
        .MATCHEQUALTO => if (reverse_endianness) anyFloatRoutine(.MATCHEQUALTO, true) else anyFloatRoutine(.MATCHEQUALTO, false),
        .MATCHNOTEQUALTO => if (reverse_endianness) anyFloatRoutine(.MATCHNOTEQUALTO, true) else anyFloatRoutine(.MATCHNOTEQUALTO, false),
        .MATCHGREATERTHAN => if (reverse_endianness) anyFloatRoutine(.MATCHGREATERTHAN, true) else anyFloatRoutine(.MATCHGREATERTHAN, false),
        .MATCHLESSTHAN => if (reverse_endianness) anyFloatRoutine(.MATCHLESSTHAN, true) else anyFloatRoutine(.MATCHLESSTHAN, false),
        .MATCHRANGE => if (reverse_endianness) anyFloatRoutine(.MATCHRANGE, true) else anyFloatRoutine(.MATCHRANGE, false),
        .MATCHNOTCHANGED => anyFloatRoutine(.MATCHNOTCHANGED, false),
        .MATCHCHANGED => anyFloatRoutine(.MATCHCHANGED, false),
        .MATCHINCREASED => anyFloatRoutine(.MATCHINCREASED, false),
        .MATCHDECREASED => anyFloatRoutine(.MATCHDECREASED, false),
        .MATCHINCREASEDBY => anyFloatRoutine(.MATCHINCREASEDBY, false),
        .MATCHDECREASEDBY => anyFloatRoutine(.MATCHDECREASEDBY, false),
    };
}

fn anyNumberChooser(match_type: ScanMatchType, reverse_endianness: bool) ScanRoutine {
    return switch (match_type) {
        .MATCHANY => anyNumberRoutine(.MATCHANY, false),
        .MATCHUPDATE => anyNumberRoutine(.MATCHUPDATE, false),
        .MATCHEQUALTO => if (reverse_endianness) anyNumberRoutine(.MATCHEQUALTO, true) else anyNumberRoutine(.MATCHEQUALTO, false),
        .MATCHNOTEQUALTO => if (reverse_endianness) anyNumberRoutine(.MATCHNOTEQUALTO, true) else anyNumberRoutine(.MATCHNOTEQUALTO, false),
        .MATCHGREATERTHAN => if (reverse_endianness) anyNumberRoutine(.MATCHGREATERTHAN, true) else anyNumberRoutine(.MATCHGREATERTHAN, false),
        .MATCHLESSTHAN => if (reverse_endianness) anyNumberRoutine(.MATCHLESSTHAN, true) else anyNumberRoutine(.MATCHLESSTHAN, false),
        .MATCHRANGE => if (reverse_endianness) anyNumberRoutine(.MATCHRANGE, true) else anyNumberRoutine(.MATCHRANGE, false),
        .MATCHNOTCHANGED => anyNumberRoutine(.MATCHNOTCHANGED, false),
        .MATCHCHANGED => anyNumberRoutine(.MATCHCHANGED, false),
        .MATCHINCREASED => anyNumberRoutine(.MATCHINCREASED, false),
        .MATCHDECREASED => anyNumberRoutine(.MATCHDECREASED, false),
        .MATCHINCREASEDBY => anyNumberRoutine(.MATCHINCREASEDBY, false),
        .MATCHDECREASEDBY => anyNumberRoutine(.MATCHDECREASEDBY, false),
    };
}

fn bytearrayChooser(match_type: ScanMatchType) ?ScanRoutine {
    return switch (match_type) {
        .MATCHANY => variableLengthAnyRoutine,
        .MATCHUPDATE => variableLengthUpdateRoutine,
        .MATCHEQUALTO => bytearrayEqualRoutine,
        else => null,
    };
}

fn stringChooser(match_type: ScanMatchType) ?ScanRoutine {
    return switch (match_type) {
        .MATCHANY => variableLengthAnyRoutine,
        .MATCHUPDATE => variableLengthUpdateRoutine,
        .MATCHEQUALTO => stringEqualRoutine,
        else => null,
    };
}

fn integerRoutine(
    comptime S: type,
    comptime U: type,
    comptime signed_flag: std.meta.FieldEnum(MatchFlags),
    comptime unsigned_flag: std.meta.FieldEnum(MatchFlags),
    comptime match_type: ScanMatchType,
    comptime reverse_endianness: bool,
) ScanRoutine {
    return struct {
        fn run(memory: []const u8, old_value: ?*const Value, user_values: []const UserValue) ScanResult {
            const width = @sizeOf(U);
            if (memory.len < width) return .noMatch();

            const current_unsigned = readUnsigned(U, memory, reverse_endianness);
            const current_signed: S = @bitCast(current_unsigned);

            var matched_flags = MatchFlags{};
            var matched = false;

            switch (match_type) {
                .MATCHANY => {
                    @field(matched_flags, @tagName(signed_flag)) = true;
                    @field(matched_flags, @tagName(unsigned_flag)) = true;
                    matched = true;
                },
                .MATCHUPDATE => {
                    if (old_value) |old| {
                        if (@field(old.flags, @tagName(signed_flag))) {
                            @field(matched_flags, @tagName(signed_flag)) = true;
                            matched = true;
                        }
                        if (@field(old.flags, @tagName(unsigned_flag))) {
                            @field(matched_flags, @tagName(unsigned_flag)) = true;
                            matched = true;
                        }
                    }
                },
                .MATCHEQUALTO,
                .MATCHNOTEQUALTO,
                .MATCHGREATERTHAN,
                .MATCHLESSTHAN,
                .MATCHRANGE,
                .MATCHINCREASEDBY,
                .MATCHDECREASEDBY,
                => {
                    if (user_values.len == 0) return .noMatch();
                    const user = user_values[0];

                    if (@field(user.flags, @tagName(signed_flag))) {
                        const lhs = current_signed;
                        const rhs = @field(user, fieldNameForFlag(signed_flag));
                        if (match_type == .MATCHRANGE) {
                            if (user_values.len < 2) return .noMatch();
                            const upper = @field(user_values[1], fieldNameForFlag(signed_flag));
                            if (lhs >= rhs and lhs <= upper) {
                                @field(matched_flags, @tagName(signed_flag)) = true;
                                matched = true;
                            }
                        } else if (match_type == .MATCHINCREASEDBY or match_type == .MATCHDECREASEDBY) {
                            if (old_value) |old| {
                                if (@field(old.flags, @tagName(signed_flag))) {
                                    const old_v = @field(old.data, dataFieldNameForFlag(signed_flag));
                                    const expected = if (match_type == .MATCHINCREASEDBY) old_v + rhs else old_v - rhs;
                                    if (lhs == expected) {
                                        @field(matched_flags, @tagName(signed_flag)) = true;
                                        matched = true;
                                    }
                                }
                            }
                        } else {
                            if (compare(match_type, lhs, rhs)) {
                                @field(matched_flags, @tagName(signed_flag)) = true;
                                matched = true;
                            }
                        }
                    }

                    if (@field(user.flags, @tagName(unsigned_flag))) {
                        const lhs = current_unsigned;
                        const rhs = @field(user, fieldNameForFlag(unsigned_flag));
                        if (match_type == .MATCHRANGE) {
                            if (user_values.len < 2) return .noMatch();
                            const upper = @field(user_values[1], fieldNameForFlag(unsigned_flag));
                            if (lhs >= rhs and lhs <= upper) {
                                @field(matched_flags, @tagName(unsigned_flag)) = true;
                                matched = true;
                            }
                        } else if (match_type == .MATCHINCREASEDBY or match_type == .MATCHDECREASEDBY) {
                            if (old_value) |old| {
                                if (@field(old.flags, @tagName(unsigned_flag))) {
                                    const old_v = @field(old.data, dataFieldNameForFlag(unsigned_flag));
                                    const expected = if (match_type == .MATCHINCREASEDBY) old_v + rhs else old_v - rhs;
                                    if (lhs == expected) {
                                        @field(matched_flags, @tagName(unsigned_flag)) = true;
                                        matched = true;
                                    }
                                }
                            }
                        } else {
                            if (compare(match_type, lhs, rhs)) {
                                @field(matched_flags, @tagName(unsigned_flag)) = true;
                                matched = true;
                            }
                        }
                    }
                },
                .MATCHNOTCHANGED,
                .MATCHCHANGED,
                .MATCHINCREASED,
                .MATCHDECREASED,
                => {
                    if (old_value) |old| {
                        if (@field(old.flags, @tagName(signed_flag))) {
                            const rhs = @field(old.data, dataFieldNameForFlag(signed_flag));
                            if (compareOld(match_type, current_signed, rhs)) {
                                @field(matched_flags, @tagName(signed_flag)) = true;
                                matched = true;
                            }
                        }
                        if (@field(old.flags, @tagName(unsigned_flag))) {
                            const rhs = @field(old.data, dataFieldNameForFlag(unsigned_flag));
                            if (compareOld(match_type, current_unsigned, rhs)) {
                                @field(matched_flags, @tagName(unsigned_flag)) = true;
                                matched = true;
                            }
                        }
                    }
                },
            }

            if (!matched) return .noMatch();
            return .{
                .matched_len = width,
                .save = .{ .NUMERIC = matched_flags },
            };
        }
    }.run;
}

fn floatRoutine(
    comptime F: type,
    comptime Bits: type,
    comptime float_flag: std.meta.FieldEnum(MatchFlags),
    comptime match_type: ScanMatchType,
    comptime reverse_endianness: bool,
) ScanRoutine {
    return struct {
        fn run(memory: []const u8, old_value: ?*const Value, user_values: []const UserValue) ScanResult {
            const width = @sizeOf(F);
            if (memory.len < width) return .noMatch();

            const bits = readUnsigned(Bits, memory, reverse_endianness);
            const current: F = @bitCast(bits);

            var matched_flags = MatchFlags{};
            var matched = false;

            switch (match_type) {
                .MATCHANY => {
                    @field(matched_flags, @tagName(float_flag)) = true;
                    matched = true;
                },
                .MATCHUPDATE => {
                    if (old_value) |old| {
                        if (@field(old.flags, @tagName(float_flag))) {
                            @field(matched_flags, @tagName(float_flag)) = true;
                            matched = true;
                        }
                    }
                },
                .MATCHEQUALTO,
                .MATCHNOTEQUALTO,
                .MATCHGREATERTHAN,
                .MATCHLESSTHAN,
                .MATCHRANGE,
                .MATCHINCREASEDBY,
                .MATCHDECREASEDBY,
                => {
                    if (user_values.len == 0) return .noMatch();
                    const user = user_values[0];
                    if (!@field(user.flags, @tagName(float_flag))) return .noMatch();

                    if (match_type == .MATCHRANGE) {
                        if (user_values.len < 2) return .noMatch();
                        const lower = @field(user_values[0], fieldNameForFloatFlag(float_flag));
                        const upper = @field(user_values[1], fieldNameForFloatFlag(float_flag));
                        if (current >= lower and current <= upper) {
                            @field(matched_flags, @tagName(float_flag)) = true;
                            matched = true;
                        }
                    } else if (match_type == .MATCHINCREASEDBY or match_type == .MATCHDECREASEDBY) {
                        if (old_value) |old| {
                            if (@field(old.flags, @tagName(float_flag))) {
                                const old_v = @field(old.data, dataFieldNameForFloatFlag(float_flag));
                                const delta = @field(user, fieldNameForFloatFlag(float_flag));
                                const expected = if (match_type == .MATCHINCREASEDBY) old_v + delta else old_v - delta;
                                if (current == expected) {
                                    @field(matched_flags, @tagName(float_flag)) = true;
                                    matched = true;
                                }
                            }
                        }
                    } else {
                        const rhs = @field(user, fieldNameForFloatFlag(float_flag));
                        if (compare(match_type, current, rhs)) {
                            @field(matched_flags, @tagName(float_flag)) = true;
                            matched = true;
                        }
                    }
                },
                .MATCHNOTCHANGED,
                .MATCHCHANGED,
                .MATCHINCREASED,
                .MATCHDECREASED,
                => {
                    if (old_value) |old| {
                        if (@field(old.flags, @tagName(float_flag))) {
                            const rhs = @field(old.data, dataFieldNameForFloatFlag(float_flag));
                            if (compareOld(match_type, current, rhs)) {
                                @field(matched_flags, @tagName(float_flag)) = true;
                                matched = true;
                            }
                        }
                    }
                },
            }

            if (!matched) return .noMatch();
            return .{
                .matched_len = width,
                .save = .{ .NUMERIC = matched_flags },
            };
        }
    }.run;
}

fn anyIntegerRoutine(comptime match_type: ScanMatchType, comptime reverse_endianness: bool) ScanRoutine {
    return struct {
        fn run(memory: []const u8, old_value: ?*const Value, user_values: []const UserValue) ScanResult {
            return combineNumericResults(&.{
                integerRoutine(i8, u8, .s8b, .u8b, match_type, false),
                integerRoutine(i16, u16, .s16b, .u16b, match_type, reverse_endianness),
                integerRoutine(i32, u32, .s32b, .u32b, match_type, reverse_endianness),
                integerRoutine(i64, u64, .s64b, .u64b, match_type, reverse_endianness),
            }, memory, old_value, user_values);
        }
    }.run;
}

fn anyFloatRoutine(comptime match_type: ScanMatchType, comptime reverse_endianness: bool) ScanRoutine {
    return struct {
        fn run(memory: []const u8, old_value: ?*const Value, user_values: []const UserValue) ScanResult {
            return combineNumericResults(&.{
                floatRoutine(f32, u32, .f32b, match_type, reverse_endianness),
                floatRoutine(f64, u64, .f64b, match_type, reverse_endianness),
            }, memory, old_value, user_values);
        }
    }.run;
}

fn anyNumberRoutine(comptime match_type: ScanMatchType, comptime reverse_endianness: bool) ScanRoutine {
    return struct {
        fn run(memory: []const u8, old_value: ?*const Value, user_values: []const UserValue) ScanResult {
            return combineNumericResults(&.{
                anyIntegerRoutine(match_type, reverse_endianness),
                anyFloatRoutine(match_type, reverse_endianness),
            }, memory, old_value, user_values);
        }
    }.run;
}

fn combineNumericResults(
    routines: []const ScanRoutine,
    memory: []const u8,
    old_value: ?*const Value,
    user_values: []const UserValue,
) ScanResult {
    var matched_len: usize = 0;
    var flags = MatchFlags{};
    var matched = false;

    for (routines) |routine| {
        const result = routine(memory, old_value, user_values);
        switch (result.save) {
            .NUMERIC => |numeric_flags| {
                if (numeric_flags.hasAny()) {
                    matched = true;
                    matched_len = @max(matched_len, result.matched_len);
                    flags = orFlags(flags, numeric_flags);
                }
            },
            else => {},
        }
    }

    if (!matched) return .noMatch();
    return .{
        .matched_len = matched_len,
        .save = .{ .NUMERIC = flags },
    };
}

fn bytearrayEqualRoutine(memory: []const u8, _: ?*const Value, user_values: []const UserValue) ScanResult {
    const bytes = user_values[0].bytearray_value orelse return .noMatch();
    const wildcards = user_values[0].wildcard_value orelse return .noMatch();
    if (bytes.len != wildcards.len or memory.len < bytes.len) return .noMatch();

    for (bytes, wildcards, 0..) |byte, wildcard, i| {
        if (byte != (memory[i] & @intFromEnum(wildcard))) return .noMatch();
    }

    return .{ .matched_len = bytes.len, .save = .{ .VARIABLE_LENGTH = @intCast(bytes.len) } };
}

fn stringEqualRoutine(memory: []const u8, _: ?*const Value, user_values: []const UserValue) ScanResult {
    const text = user_values[0].string_value orelse return .noMatch();
    if (memory.len < text.len) return .noMatch();
    if (!std.mem.eql(u8, memory[0..text.len], text)) return .noMatch();

    return .{ .matched_len = text.len, .save = .{ .VARIABLE_LENGTH = @intCast(text.len) } };
}

fn variableLengthAnyRoutine(memory: []const u8, _: ?*const Value, _: []const UserValue) ScanResult {
    const len = @min(memory.len, std.math.maxInt(u16));
    if (len == 0) return .noMatch();

    return .{
        .matched_len = len,
        .save = .{ .VARIABLE_LENGTH = len },
    };
}

fn variableLengthUpdateRoutine(memory: []const u8, old_value: ?*const Value, _: []const UserValue) ScanResult {
    const previous = old_value orelse return .noMatch();
    const len = @min(memory.len, previous.flags.bits());
    if (len == 0) return .noMatch();

    return .{
        .matched_len = len,
        .save = .{ .VARIABLE_LENGTH = len },
    };
}

fn compare(comptime match_type: ScanMatchType, lhs: anytype, rhs: @TypeOf(lhs)) bool {
    return switch (match_type) {
        .MATCHEQUALTO => lhs == rhs,
        .MATCHNOTEQUALTO => lhs != rhs,
        .MATCHGREATERTHAN => lhs > rhs,
        .MATCHLESSTHAN => lhs < rhs,
        else => false,
    };
}

fn compareOld(comptime match_type: ScanMatchType, lhs: anytype, rhs: @TypeOf(lhs)) bool {
    return switch (match_type) {
        .MATCHNOTCHANGED => lhs == rhs,
        .MATCHCHANGED => lhs != rhs,
        .MATCHINCREASED => lhs > rhs,
        .MATCHDECREASED => lhs < rhs,
        else => false,
    };
}

fn readUnsigned(comptime U: type, memory: []const u8, comptime reverse_endianness: bool) U {
    var buf: [@sizeOf(U)]u8 = undefined;
    @memcpy(buf[0..], memory[0..@sizeOf(U)]);
    var value = std.mem.bytesToValue(U, &buf);
    if (reverse_endianness and @sizeOf(U) > 1) {
        value = @byteSwap(value);
    }
    return value;
}

fn orFlags(lhs: MatchFlags, rhs: MatchFlags) MatchFlags {
    return @bitCast(lhs.bits() | rhs.bits());
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

fn dataFieldNameForFlag(comptime flag: std.meta.FieldEnum(MatchFlags)) []const u8 {
    return fieldNameForFlag(flag);
}

fn fieldNameForFloatFlag(comptime flag: std.meta.FieldEnum(MatchFlags)) []const u8 {
    return switch (flag) {
        .f32b => "float32_value",
        .f64b => "float64_value",
        else => @compileError("invalid float flag"),
    };
}

fn dataFieldNameForFloatFlag(comptime flag: std.meta.FieldEnum(MatchFlags)) []const u8 {
    return fieldNameForFloatFlag(flag);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "chooseRoutine: rejects float-only value for integer scans" {
    const user = try UserValue.parseFloat("1.5");
    try std.testing.expect(chooseRoutine(.INTEGER32, .MATCHEQUALTO, &.{user}, false) == null);
}

test "MATCHEQUALTO-INTEGER32: matches both signed and unsigned flags when possible" {
    const user = try UserValue.parseNumber("42");
    const routine = chooseRoutine(.INTEGER32, .MATCHEQUALTO, &.{user}, false).?;
    const memory: u32 = 42;
    const result = routine(std.mem.asBytes(&memory), null, &.{user});

    try std.testing.expectEqual(4, result.matched_len);
    try std.testing.expectEqual((MatchFlags{ .u32b = true, .s32b = true }).bits(), result.save.raw());
}

test "reverseEndianness: integer equalto swaps compared bytes" {
    const user = try UserValue.parseNumber("0x1234");
    const original: u16 = 0x1234;
    const swapped = @byteSwap(original);
    const memory = std.mem.asBytes(&swapped);

    const native_routine = chooseRoutine(.INTEGER16, .MATCHEQUALTO, &.{user}, false).?;
    const native_result = native_routine(memory, null, &.{user});
    try std.testing.expectEqual(0, native_result.matched_len);
    try std.testing.expectEqual(0, native_result.save.raw());

    const reverse_routine = chooseRoutine(.INTEGER16, .MATCHEQUALTO, &.{user}, true).?;
    const result = reverse_routine(memory, null, &.{user});

    try std.testing.expectEqual(2, result.matched_len);
    try std.testing.expectEqual((MatchFlags{ .u16b = true, .s16b = true }).bits(), result.save.raw());
}

test "MATCHCHANGED: compares against old value" {
    var old_value = Value{
        .data = .{ .uint32_value = 10 },
        .flags = .{ .u32b = true },
    };
    const routine = chooseRoutine(.INTEGER32, .MATCHCHANGED, &.{}, false).?;

    const unchanged: u32 = 10;
    const unchanged_result = routine(std.mem.asBytes(&unchanged), &old_value, &.{});
    try std.testing.expectEqual(0, unchanged_result.matched_len);
    try std.testing.expectEqual(0, unchanged_result.save.raw());

    const changed: u32 = 11;
    const result = routine(std.mem.asBytes(&changed), &old_value, &.{});

    try std.testing.expectEqual(4, result.matched_len);
    try std.testing.expectEqual((MatchFlags{ .u32b = true }).bits(), result.save.raw());
}

test "MATCHRANGE-FLOAT: matches inside inclusive bounds" {
    const lower = try UserValue.parseFloat("1.25");
    const upper = try UserValue.parseFloat("2.5");
    const routine = chooseRoutine(.FLOAT32, .MATCHRANGE, &.{ lower, upper }, false).?;

    const memory: f32 = 2.0;
    const result = routine(std.mem.asBytes(&memory), null, &.{ lower, upper });

    try std.testing.expectEqual(4, result.matched_len);
    try std.testing.expectEqual((MatchFlags{ .f32b = true }).bits(), result.save.raw());
}

test "ANYNUMBER: aggregates integer and float matches" {
    const user = try UserValue.parseNumber("0.5");
    const routine = chooseRoutine(.ANYNUMBER, .MATCHEQUALTO, &.{user}, false).?;

    var memory = [_]u8{ 0, 0, 0, 0, 0xff, 0xff, 0xff, 0xff };
    const float32_value: f32 = 0.5;
    const float32_bits: u32 = @bitCast(float32_value);
    std.mem.writeInt(u32, memory[0..4], float32_bits, .little);
    const result = routine(&memory, null, &.{user});

    try std.testing.expectEqual(4, result.matched_len);
    try std.testing.expectEqual((MatchFlags{ .u8b = true, .s8b = true, .u16b = true, .s16b = true, .f32b = true }).bits(), result.save.raw());
}

test "BYTEARRAY: honors wildcards" {
    var user = UserValue{};
    user.bytearray_value = &[_]u8{ 0xaa, 0x00, 0xcc };
    user.wildcard_value = &[_]value_mod.Wildcard{ .FIXED, .WILDCARD, .FIXED };

    const routine = chooseRoutine(.BYTEARRAY, .MATCHEQUALTO, &.{user}, false).?;
    const memory = [_]u8{ 0xaa, 0x77, 0xcc };
    const result = routine(&memory, null, &.{user});

    try std.testing.expectEqual(3, result.matched_len);
    try std.testing.expectEqual(3, result.save.raw());

    const fixed_mismatch = [_]u8{ 0xaa, 0x77, 0xcd };
    const mismatch_result = routine(&fixed_mismatch, null, &.{user});
    try std.testing.expectEqual(0, mismatch_result.matched_len);
    try std.testing.expectEqual(0, mismatch_result.save.raw());
}

test "MATCHEQUALTO-STRING: matches exact bytes" {
    const user = UserValue{ .string_value = "PINCE" };
    const routine = chooseRoutine(.STRING, .MATCHEQUALTO, &.{user}, false).?;
    const result = routine("PINCE rocks", null, &.{user});

    try std.testing.expectEqual(5, result.matched_len);
    try std.testing.expectEqual(5, result.save.raw());

    const mismatch_result = routine("PENCE rocks", null, &.{user});
    try std.testing.expectEqual(0, mismatch_result.matched_len);
    try std.testing.expectEqual(0, mismatch_result.save.raw());
}

test "BYTEARRAY: records variable length snapshot size" {
    const routine = chooseRoutine(.BYTEARRAY, .MATCHANY, &.{}, false).?;
    const memory = [_]u8{ 0xaa, 0xbb, 0xcc, 0xdd };
    const result = routine(&memory, null, &.{});

    try std.testing.expectEqual(4, result.matched_len);
    try std.testing.expectEqual(4, result.save.raw());
}

test "MATCHUPDATE-STRING: preserves previous variable length" {
    var old_value = Value{
        .data = .{ .uint64_value = 0 },
        .flags = @bitCast(@as(u16, 5)),
    };
    const routine = chooseRoutine(.STRING, .MATCHUPDATE, &.{}, false).?;
    const result = routine("HELLO, world", &old_value, &.{});

    try std.testing.expectEqual(5, result.matched_len);
    try std.testing.expectEqual(5, result.save.raw());
}
