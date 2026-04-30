//! Platform abstraction layer for process memory access.

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
const builtin = @import("builtin");

pub const ScanLevel = enum {
    /// Every readable region, including read-only mappings.
    ALL,
    /// Every readable AND writable region.
    ALL_RW,
    /// Heap, stack, and executable (mapped binary) regions only.
    HEAP_STACK_EXE,
    /// heap_stack_exe plus anonymous (BSS-like) regions.
    HEAP_STACK_EXE_BSS,
};

pub const RegionKind = enum {
    MISC,
    CODE,
    EXE,
    HEAP,
    STACK,
};

/// Permission flags for a memory region.
pub const RegionFlags = packed struct(u8) {
    read: bool,
    write: bool,
    exec: bool,
    shared: bool,
    private: bool,
    _pad: u3 = 0,
};

/// A single mappable memory region from the target process.
/// Owns its `filename` slice, caller must free via the same allocator
/// that was passed to `readRegions`.
pub const Region = struct {
    /// Start address inside the target process address space.
    start: usize,
    size: usize,
    kind: RegionKind,
    flags: RegionFlags,
    /// Load address of the ELF/Mach-O executable this region belongs to.
    load_addr: usize,
    /// Unique sequential ID assigned during enumeration.
    id: u32,
    /// Path of the backing file, empty string if anonymous.
    filename: []const u8,

    pub fn deinit(self: *Region, allocator: std.mem.Allocator) void {
        allocator.free(self.filename);
    }
};

pub const ProcessError = error{
    AttachFailed,
    ReadFailed,
    WriteFailed,
    RegionEnumFailed,
};

const PlatformBackend = switch (builtin.os.tag) {
    .linux => LinuxBackend,
    .macos => MacOSBackend,
    else => @compileError("Unsupported platform: " ++ @tagName(builtin.os.tag)),
};

pub const ProcessHandle = struct {
    io: std.Io,
    pid: std.posix.pid_t,
    backend: PlatformBackend,

    /// Open a handle to `pid`. Must be paired with `deinit()`.
    pub fn attach(io: std.Io, pid: std.posix.pid_t) ProcessError!ProcessHandle {
        return .{
            .io = io,
            .pid = pid,
            .backend = try PlatformBackend.attach(io, pid),
        };
    }

    pub fn deinit(self: *ProcessHandle) void {
        self.backend.deinit(self.io);
    }

    /// Read `buf.len` bytes from `addr` in the target process into `buf`.
    /// Returns the number of bytes actually read (may be less at region edges).
    pub fn read(self: *ProcessHandle, addr: usize, buf: []u8) ProcessError!usize {
        return self.backend.read(self.io, addr, buf);
    }

    /// Write `data` to `addr` in the target process.
    pub fn write(self: *ProcessHandle, addr: usize, data: []const u8) ProcessError!void {
        return self.backend.write(self.io, addr, data);
    }

    /// Enumerate all memory regions of the process, filtered by `level`.
    /// Caller owns the returned slice and must call `deinit()` on each Region.
    pub fn readRegions(self: *ProcessHandle, allocator: std.mem.Allocator, level: ScanLevel) ProcessError![]Region {
        return self.backend.readRegions(self.io, self.pid, allocator, level);
    }
};

/// Returns true if this region should be included at the given scan level.
fn isUsefulRegion(region_kind: RegionKind, flags: RegionFlags, filename: []const u8, exe_name: []const u8, level: ScanLevel) bool {
    if (level != .ALL and !flags.write) {
        return false;
    }

    return switch (level) {
        .ALL, .ALL_RW => true,

        .HEAP_STACK_EXE_BSS => {
            // anonymous regions (BSS-like) are included
            if (filename.len == 0) {
                return true;
            }
            return isRegionHeapStackOrExe(region_kind, filename, exe_name);
        },

        .HEAP_STACK_EXE => isRegionHeapStackOrExe(region_kind, filename, exe_name),
    };
}

inline fn isRegionHeapStackOrExe(region_kind: RegionKind, filename: []const u8, exe_name: []const u8) bool {
    return region_kind == .HEAP or
        region_kind == .STACK or
        region_kind == .EXE or
        std.mem.eql(u8, filename, exe_name);
}

// ---------------------------------------------------------------------------
// Linux
// ---------------------------------------------------------------------------

/// Parsed fields from a single /proc/pid/maps line.
const MapsLine = struct {
    start: usize,
    end: usize,
    flags: RegionFlags,
    pathname: []const u8, // is a slice into the original line buffer
};

/// Parse one line from /proc/pid/maps.
/// Returns null if the line is malformed or has fewer than 5 fields.
///
/// Format: start-end perms offset dev inode [pathname]
/// Example: 7f1234000000-7f1234001000 r-xp 00000000 08:01 12345 /lib/libc.so.6
fn parseMapsLine(line: []const u8) ?MapsLine {
    var it = std.mem.tokenizeScalar(u8, line, ' ');

    // field 1: "start-end"
    const addr_field = it.next() orelse return null;
    const dash = std.mem.indexOfScalar(u8, addr_field, '-') orelse return null;
    const start = std.fmt.parseUnsigned(usize, addr_field[0..dash], 16) catch return null;
    const end = std.fmt.parseUnsigned(usize, addr_field[dash + 1 ..], 16) catch return null;

    // field 2: "rwxp" permissions
    const perms = it.next() orelse return null;
    if (perms.len < 4) return null;
    const flags = RegionFlags{
        .read = perms[0] == 'r',
        .write = perms[1] == 'w',
        .exec = perms[2] == 'x',
        .shared = perms[3] == 's',
        .private = perms[3] == 'p',
    };

    // fields 3-5: offset, dev, inode (skip)
    _ = it.next(); // offset
    _ = it.next(); // dev
    _ = it.next(); // inode

    // field 6 (optional): pathname
    // remainder of the line after the inode field, trimmed
    const pathname = std.mem.trim(u8, it.rest(), " \t");

    return .{
        .start = start,
        .end = end,
        .flags = flags,
        .pathname = pathname,
    };
}

const LinuxBackend = struct {
    /// File descriptor for /proc/<pid>/mem — opened once on attach.
    mem_fd: std.Io.File,

    fn attach(io: std.Io, pid: std.posix.pid_t) ProcessError!LinuxBackend {
        var path_buf: [64]u8 = undefined;
        const path = std.fmt.bufPrint(&path_buf, "/proc/{d}/mem", .{pid}) catch return ProcessError.AttachFailed;

        const file = std.Io.Dir.openFileAbsolute(io, path, .{ .mode = .read_write }) catch return ProcessError.AttachFailed;

        return .{ .mem_fd = file };
    }

    fn deinit(self: *LinuxBackend, io: std.Io) void {
        self.mem_fd.close(io);
    }

    fn read(self: *LinuxBackend, io: std.Io, addr: usize, buf: []u8) ProcessError!usize {
        var nread: usize = 0;

        while (nread < buf.len) {
            const ret = self.mem_fd.readPositional(io, &.{buf[nread..]}, @intCast(addr + nread)) catch {
                return if (nread == 0) ProcessError.ReadFailed else nread;
            };

            if (ret == 0) break;
            nread += ret;
        }

        return nread;
    }

    fn write(self: *LinuxBackend, io: std.Io, addr: usize, data: []const u8) ProcessError!void {
        var offset: usize = 0;
        while (offset < data.len) {
            const n = self.mem_fd.writePositional(io, &.{data[offset..]}, @intCast(addr + offset)) catch return ProcessError.WriteFailed;
            if (n == 0) return ProcessError.WriteFailed;
            offset += n;
        }
    }

    fn readRegions(_: *LinuxBackend, io: std.Io, pid: std.posix.pid_t, allocator: std.mem.Allocator, level: ScanLevel) ProcessError![]Region {
        var path_buf: [64]u8 = undefined;
        const maps_path = std.fmt.bufPrint(&path_buf, "/proc/{d}/maps", .{pid}) catch return ProcessError.RegionEnumFailed;

        const maps_file = std.Io.Dir.openFileAbsolute(io, maps_path, .{}) catch return ProcessError.RegionEnumFailed;
        defer maps_file.close(io);

        // resolve the executable path via /proc/<pid>/exe
        var exe_path_buf: [64]u8 = undefined;
        const exe_link_path = std.fmt.bufPrint(&exe_path_buf, "/proc/{d}/exe", .{pid}) catch return ProcessError.RegionEnumFailed;

        var exe_name_buf: [std.Io.Dir.max_path_bytes]u8 = undefined;
        const exe_name_len = std.Io.Dir.readLinkAbsolute(io, exe_link_path, &exe_name_buf) catch 0;
        const exe_name = exe_name_buf[0..exe_name_len];

        // Read the entire maps file up front, then split by newline.
        // The maps file is small, a few KB at most.
        var reader_buf: [4096]u8 = undefined;
        // /proc/<pid>/maps is a procfs text stream; use the streaming reader
        // rather than positional reads to avoid procfs-specific read quirks.
        var reader = maps_file.readerStreaming(io, &reader_buf);
        const maps_content = reader.interface.allocRemaining(allocator, .limited(4 * 1024 * 1024)) catch return ProcessError.RegionEnumFailed;
        defer allocator.free(maps_content);

        var regions: std.ArrayList(Region) = .empty;
        errdefer {
            for (regions.items) |*r| {
                r.deinit(allocator);
            }
            regions.deinit(allocator);
        }

        // ELF tracking
        var code_regions: u32 = 0;
        var exe_regions: u32 = 0;
        var prev_end: usize = 0;
        var load_addr: usize = 0;
        var exe_load: usize = 0;
        var is_exe: bool = false;
        var bin_name_buf: [std.Io.Dir.max_path_bytes]u8 = undefined;
        var bin_name: []const u8 = "";
        var region_id: u32 = 0;

        var lines = std.mem.splitScalar(u8, maps_content, '\n');
        while (lines.next()) |line| {
            if (line.len == 0) {
                continue;
            }

            const parsed = parseMapsLine(line) orelse continue;

            if (code_regions > 0) {
                const same_file = parsed.pathname.len > 0 and std.mem.eql(u8, parsed.pathname, bin_name);
                const consecutive = parsed.pathname.len == 0 and parsed.start == prev_end;

                if (parsed.flags.exec or (!same_file and !consecutive) or code_regions >= 4) {
                    code_regions = 0;
                    is_exe = false;
                    if (exe_regions > 1) {
                        exe_regions = 0;
                    }
                } else {
                    code_regions += 1;
                    if (is_exe) {
                        exe_regions += 1;
                    }
                }
            }

            if (code_regions == 0) {
                if (parsed.flags.exec and parsed.pathname.len > 0) {
                    code_regions = 1;
                    if (std.mem.eql(u8, parsed.pathname, exe_name)) {
                        exe_regions = 1;
                        exe_load = parsed.start;
                        is_exe = true;
                    }
                    @memcpy(bin_name_buf[0..parsed.pathname.len], parsed.pathname);
                    bin_name = bin_name_buf[0..parsed.pathname.len];
                } else if (exe_regions == 1 and parsed.pathname.len > 0 and std.mem.eql(u8, parsed.pathname, exe_name)) {
                    exe_regions += 1;
                    code_regions = exe_regions;
                    load_addr = exe_load;
                    is_exe = true;
                    @memcpy(bin_name_buf[0..parsed.pathname.len], parsed.pathname);
                    bin_name = bin_name_buf[0..parsed.pathname.len];
                }

                if (exe_regions < 2) load_addr = parsed.start;
            }

            prev_end = parsed.end;

            if (!parsed.flags.read or parsed.end <= parsed.start) {
                continue;
            }

            const region_kind: RegionKind = blk: {
                if (is_exe) break :blk .EXE;
                if (code_regions > 0) break :blk .CODE;
                if (std.mem.eql(u8, parsed.pathname, "[heap]")) break :blk .HEAP;
                if (std.mem.eql(u8, parsed.pathname, "[stack]")) break :blk .STACK;
                break :blk .MISC;
            };

            if (!isUsefulRegion(region_kind, parsed.flags, parsed.pathname, exe_name, level))
                continue;

            const filename_copy = allocator.dupe(u8, parsed.pathname) catch return ProcessError.RegionEnumFailed;

            regions.append(allocator, .{
                .start = parsed.start,
                .size = parsed.end - parsed.start,
                .kind = region_kind,
                .flags = parsed.flags,
                .load_addr = load_addr,
                .id = region_id,
                .filename = filename_copy,
            }) catch return ProcessError.RegionEnumFailed;

            region_id += 1;
        }

        return regions.toOwnedSlice(allocator) catch return ProcessError.RegionEnumFailed;
    }
};

const MacOSBackend = struct {
    // Might need to change this to mach_port_t probably
    task: u32,

    fn attach(_: std.Io, _: std.posix.pid_t) ProcessError!MacOSBackend {
        // Maybe use task_for_pid?
        @panic("TODO: implement attach for macOS backend");
    }

    fn deinit(_: *MacOSBackend, _: std.Io) void {
        // Maybe mach_port_deallocate?
        @panic("TODO: implement deinit for macOS backend");
    }

    fn read(_: *MacOSBackend, _: std.Io, _: usize, _: []u8) ProcessError!usize {
        // Use mach_vm_read_overwrite
        @panic("TODO: implement read for macOS backend");
    }

    fn write(_: *MacOSBackend, _: std.Io, _: usize, _: []const u8) ProcessError!void {
        // Use mach_vm_write
        @panic("TODO: implement write for macOS backend");
    }

    fn readRegions(_: *MacOSBackend, _: std.Io, _: std.posix.pid_t, _: std.mem.Allocator, _: ScanLevel) ProcessError![]Region {
        // Use mach_vm_region
        @panic("TODO: implement readRegions for macOS backend");
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "parseMapsLine: normal executable region" {
    const line = "7f1234560000-7f1234561000 r-xp 00000000 08:01 99999 /usr/lib/libc.so.6";
    const result = parseMapsLine(line).?;
    try std.testing.expectEqual(@as(usize, 0x7f1234560000), result.start);
    try std.testing.expectEqual(@as(usize, 0x7f1234561000), result.end);
    try std.testing.expect(result.flags.read);
    try std.testing.expect(!result.flags.write);
    try std.testing.expect(result.flags.exec);
    try std.testing.expect(result.flags.private);
    try std.testing.expectEqualStrings("/usr/lib/libc.so.6", result.pathname);
}

test "parseMapsLine: anonymous rw region (heap-like)" {
    const line = "55a000000000-55a000010000 rw-p 00000000 00:00 0 ";
    const result = parseMapsLine(line).?;
    try std.testing.expect(result.flags.read);
    try std.testing.expect(result.flags.write);
    try std.testing.expect(!result.flags.exec);
    try std.testing.expectEqualStrings("", result.pathname);
}

test "parseMapsLine: [heap] region" {
    const line = "55b000000000-55b000100000 rw-p 00000000 00:00 0            [heap]";
    const result = parseMapsLine(line).?;
    try std.testing.expectEqualStrings("[heap]", result.pathname);
}

test "parseMapsLine: malformed line returns null" {
    try std.testing.expectEqual(@as(?MapsLine, null), parseMapsLine("not a maps line"));
}

test "isUsefulRegion: heap is included in heap_stack_exe" {
    try std.testing.expect(isUsefulRegion(
        .HEAP,
        .{ .read = true, .write = true, .exec = false, .shared = false, .private = true },
        "[heap]",
        "/bin/myapp",
        .HEAP_STACK_EXE,
    ));
}

test "isUsefulRegion: read-only code region excluded from all_rw" {
    try std.testing.expect(!isUsefulRegion(
        .CODE,
        .{ .read = true, .write = false, .exec = true, .shared = false, .private = true },
        "/lib/libfoo.so",
        "/bin/myapp",
        .ALL_RW,
    ));
}

test "isUsefulRegion: anonymous writable region is included in heap_stack_exe_bss" {
    try std.testing.expect(isUsefulRegion(
        .MISC,
        .{ .read = true, .write = true, .exec = false, .shared = false, .private = true },
        "",
        "/bin/myapp",
        .HEAP_STACK_EXE_BSS,
    ));
}

test "isUsefulRegion: anonymous writable region is excluded from heap_stack_exe" {
    try std.testing.expect(!isUsefulRegion(
        .MISC,
        .{ .read = true, .write = true, .exec = false, .shared = false, .private = true },
        "",
        "/bin/myapp",
        .HEAP_STACK_EXE,
    ));
}

test "isUsefulRegion: shared library code is excluded from heap_stack_exe" {
    try std.testing.expect(!isUsefulRegion(
        .CODE,
        .{ .read = true, .write = true, .exec = true, .shared = true, .private = false },
        "/lib/libfoo.so",
        "/bin/myapp",
        .HEAP_STACK_EXE,
    ));
}

test "isUsefulRegion: writable executable mapping of main binary is included in heap_stack_exe" {
    try std.testing.expect(isUsefulRegion(
        .EXE,
        .{ .read = true, .write = true, .exec = true, .shared = false, .private = true },
        "/bin/myapp",
        "/bin/myapp",
        .HEAP_STACK_EXE,
    ));
}

test "isUsefulRegion: read-only exe region excluded from heap_stack_exe_bss" {
    try std.testing.expect(!isUsefulRegion(
        .EXE,
        .{ .read = true, .write = false, .exec = true, .shared = false, .private = true },
        "/bin/myapp",
        "/bin/myapp",
        .HEAP_STACK_EXE_BSS,
    ));
}

test "isUsefulRegion: read-only exe region excluded from heap_stack_exe" {
    try std.testing.expect(!isUsefulRegion(
        .EXE,
        .{ .read = true, .write = false, .exec = true, .shared = false, .private = true },
        "/bin/myapp",
        "/bin/myapp",
        .HEAP_STACK_EXE,
    ));
}
