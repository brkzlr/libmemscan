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
    offset: usize,
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

    // fields 3-5: offset, dev, inode
    const offset = std.fmt.parseUnsigned(usize, it.next() orelse return null, 16) catch return null;
    _ = it.next() orelse return null; // dev
    _ = it.next() orelse return null; // inode

    // field 6 (optional): pathname
    // remainder of the line after the inode field, trimmed
    const pathname = std.mem.trim(u8, it.rest(), " \t");

    return .{
        .start = start,
        .end = end,
        .offset = offset,
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
        var bin_name: []const u8 = "";
        var region_id: u32 = 0;

        var lines = std.mem.splitScalar(u8, maps_content, '\n');
        while (lines.next()) |line| {
            if (line.len == 0) {
                continue;
            }

            const parsed = parseMapsLine(line) orelse continue;
            // File offsets let all mapped slices of the same ELF image share one load address.
            var region_load_addr = if (parsed.pathname.len > 0 and parsed.offset <= parsed.start)
                parsed.start - parsed.offset
            else
                parsed.start;

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
                    region_load_addr = load_addr;
                    if (is_exe) {
                        exe_regions += 1;
                    }
                }
            }

            if (code_regions == 0) {
                if (parsed.flags.exec and parsed.pathname.len > 0) {
                    code_regions = 1;
                    load_addr = region_load_addr;
                    if (std.mem.eql(u8, parsed.pathname, exe_name)) {
                        exe_regions = 1;
                        exe_load = load_addr;
                        is_exe = true;
                    }
                    bin_name = parsed.pathname;
                } else if (exe_regions == 1 and parsed.pathname.len > 0 and std.mem.eql(u8, parsed.pathname, exe_name)) {
                    exe_regions += 1;
                    code_regions = exe_regions;
                    load_addr = exe_load;
                    region_load_addr = load_addr;
                    is_exe = true;
                    bin_name = parsed.pathname;
                }

                if (exe_regions < 2) load_addr = region_load_addr;
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
                .load_addr = region_load_addr,
                .id = region_id,
                .filename = filename_copy,
            }) catch return ProcessError.RegionEnumFailed;

            region_id += 1;
        }

        // Earlier non-executable mappings of an ELF image can be seen before
        // the executable slice that identifies the module.
        for (regions.items) |*region| {
            if (region.kind != .MISC or region.filename.len == 0) continue;

            for (regions.items) |candidate| {
                if (candidate.kind != .EXE and candidate.kind != .CODE) continue;
                if (candidate.load_addr != region.load_addr) continue;
                if (!std.mem.eql(u8, candidate.filename, region.filename)) continue;

                region.kind = candidate.kind;
                break;
            }
        }

        return regions.toOwnedSlice(allocator) catch return ProcessError.RegionEnumFailed;
    }
};

// ---------------------------------------------------------------------------
// MacOS
// ---------------------------------------------------------------------------

const darwin = std.posix.system;

extern "c" fn proc_pidpath(pid: c_int, buffer: [*]u8, buffersize: u32) c_int;
extern "c" fn proc_regionfilename(pid: c_int, address: u64, buffer: [*]u8, buffersize: u32) c_int;

const MacOSBackend = struct {
    target_task: darwin.mach_port_t,

    fn attach(_: std.Io, pid: std.posix.pid_t) ProcessError!MacOSBackend {
        var target_task: darwin.mach_port_t = undefined;
        const kern_result = darwin.task_for_pid(darwin.mach_task_self(), pid, &target_task);

        if (kern_result != 0) return ProcessError.AttachFailed;

        return .{ .target_task = target_task };
    }

    fn deinit(self: *MacOSBackend, _: std.Io) void {
        _ = darwin.mach_port_deallocate(darwin.mach_task_self(), self.target_task);
    }

    fn read(self: *MacOSBackend, _: std.Io, addr: usize, buf: []u8) ProcessError!usize {
        // We want to gate mach_vm_read size due to the allocations it does.
        const max_chunk: usize = 64 * 1024;
        var nread: usize = 0;

        while (nread < buf.len) {
            const remaining = buf.len - nread;
            const read_size = @min(remaining, max_chunk);

            // mach_vm_read allocates memory in our own process space and then copies bytes from the target_task
            // addr to the allocated data buffer.
            // data_addr represents the address where our newly allocated memory containing the data resides.
            // data_count represents the size of copied bytes.
            var data_addr: darwin.vm_offset_t = 0;
            var data_count: darwin.mach_msg_type_number_t = 0;
            const kern_result = darwin.mach_vm_read(self.target_task, addr + nread, read_size, &data_addr, &data_count);

            if (kern_result != 0) return if (nread == 0) ProcessError.ReadFailed else nread;
            if (data_count == 0) break;

            const read_count = @min(read_size, data_count);

            const src: [*]const u8 = @ptrFromInt(data_addr);
            @memcpy(buf[nread .. nread + read_count], src[0..read_count]);

            // We have to deallocate mach_vm_read allocations once we've copied the data to our internal buffer.
            _ = darwin.vm_deallocate(darwin.mach_task_self(), data_addr, data_count);

            nread += read_count;
            if (read_count < read_size) break;
        }

        return nread;
    }

    fn write(self: *MacOSBackend, _: std.Io, addr: usize, data: []const u8) ProcessError!void {
        if (data.len == 0) return;

        // Might need mach_vm_protect to change region protections to write to un-writtable regions.
        // Usually we'd ignore those but programs (like PINCE) can scan non-writtable regions.
        // TODO: Decide if libmemscan should forcibly write to write-disabled regions.
        const kern_result = darwin.mach_vm_write(self.target_task, addr, @intFromPtr(data.ptr), @intCast(data.len));
        if (kern_result != 0) return ProcessError.WriteFailed;
    }

    fn readRegions(self: *MacOSBackend, io: std.Io, pid: std.posix.pid_t, allocator: std.mem.Allocator, level: ScanLevel) ProcessError![]Region {
        var regions: std.ArrayList(Region) = .empty;
        errdefer {
            for (regions.items) |*r| r.deinit(allocator);
            regions.deinit(allocator);
        }

        // Tracking Mach-O images
        const ImageLoad = struct {
            filename: []const u8,
            load_addr: usize,
            dev: i32,
            ino: std.c.ino_t,
            has_identity: bool,
        };

        const SM_COW: u8 = 1;
        const SM_PRIVATE: u8 = 2;
        const SM_SHARED: u8 = 4;
        const SM_TRUESHARED: u8 = 5;
        const SM_PRIVATE_ALIASED: u8 = 6;
        const SM_SHARED_ALIASED: u8 = 7;
        const KERN_INVALID_ADDRESS: darwin.kern_return_t = 1;

        const VM_MEMORY_MALLOC_FIRST: u32 = 1;
        const VM_MEMORY_MALLOC_LAST: u32 = 9;
        const VM_MEMORY_MALLOC_NANO: u32 = 11;
        const VM_MEMORY_MALLOC_PROB_GUARD: u32 = 13;
        const VM_MEMORY_STACK: u32 = 30;

        var image_loads: std.ArrayList(ImageLoad) = .empty;
        defer {
            for (image_loads.items) |load| allocator.free(load.filename);
            image_loads.deinit(allocator);
        }

        // Grab executable name for specified PID.
        var exe_name_buf: [std.Io.Dir.max_path_bytes]u8 = undefined;
        var exe_name: []const u8 = "";
        var exe_stat: std.c.Stat = undefined;
        var exe_has_identity = false;
        const exe_name_raw_len = proc_pidpath(@intCast(pid), &exe_name_buf, @intCast(exe_name_buf.len));
        if (exe_name_raw_len > 0) {
            const exe_name_len = @min(@as(usize, @intCast(exe_name_raw_len)), exe_name_buf.len);
            const exe_name_path = exe_name_buf[0..exe_name_len];
            exe_name = exe_name_path[0 .. std.mem.indexOfScalar(u8, exe_name_path, 0) orelse exe_name_path.len];
            if (exe_name.len < exe_name_buf.len) {
                exe_name_buf[exe_name.len] = 0;
                exe_has_identity = std.c.fstatat(std.c.AT.FDCWD, @ptrCast(exe_name_buf[0..].ptr), &exe_stat, 0) == 0;
            }
        }

        // Note that address is an in/out variable. When calling mach_vm_region*, we supply it an address of where to begin searching
        // where upon return, it's populated with the address of a found region.
        var address: darwin.mach_vm_address_t = 0;
        var depth: darwin.natural_t = 0;
        var region_id: u32 = 0;
        var filename_buf: [std.Io.Dir.max_path_bytes]u8 = undefined;

        while (true) {
            var region_size: darwin.mach_vm_size_t = 0;
            var info: darwin.vm_region_submap_info_64 = undefined;
            var info_count: darwin.mach_msg_type_number_t = darwin.VM.REGION.SUBMAP_INFO_COUNT_64;

            const kern_result = darwin.mach_vm_region_recurse(self.target_task, &address, &region_size, &depth, @ptrCast(&info), &info_count);
            if (kern_result == KERN_INVALID_ADDRESS) break;
            if (kern_result != 0) return ProcessError.RegionEnumFailed;
            if (region_size == 0) break;

            if (info.is_submap != 0) {
                depth += 1;
                continue;
            }

            const next_address = std.math.add(darwin.mach_vm_address_t, address, region_size) catch break;
            defer address = next_address;

            const region_flags = RegionFlags{
                .read = info.protection.READ,
                .write = info.protection.WRITE,
                .exec = info.protection.EXEC,
                .shared = info.share_mode == SM_SHARED or
                    info.share_mode == SM_TRUESHARED or
                    info.share_mode == SM_SHARED_ALIASED,
                .private = info.share_mode == SM_PRIVATE or
                    info.share_mode == SM_PRIVATE_ALIASED or
                    info.share_mode == SM_COW,
            };

            if (!region_flags.read) continue;

            // Grab the filename that backs up this region
            // If empty (""), might be anonymous region which is the equivalent of Linux BSS.
            var filename: []const u8 = "";
            const filename_raw_len = proc_regionfilename(@intCast(pid), @intCast(address), &filename_buf, @intCast(filename_buf.len));
            if (filename_raw_len > 0) {
                const filename_len = @min(@as(usize, @intCast(filename_raw_len)), filename_buf.len);
                const filename_path = filename_buf[0..filename_len];
                filename = filename_path[0 .. std.mem.indexOfScalar(u8, filename_path, 0) orelse filename_path.len];
            }

            // If region has a filename, let's grab the fstat so we can also compare using dev and ino
            // instead of just comparing path strings.
            var filename_stat: std.c.Stat = undefined;
            const filename_has_identity = filename.len > 0 and filename.len < filename_buf.len and blk: {
                filename_buf[filename.len] = 0;
                break :blk std.c.fstatat(std.c.AT.FDCWD, @ptrCast(filename_buf[0..].ptr), &filename_stat, 0) == 0;
            };

            // Main executable region if same device and inode as the filename of the PID.
            // Fallback to filename path equality checking.
            const main_executable_region = filename.len > 0 and
                ((exe_has_identity and filename_has_identity and exe_stat.dev == filename_stat.dev and exe_stat.ino == filename_stat.ino) or
                    (exe_name.len > 0 and std.mem.eql(u8, filename, exe_name)));

            var load_addr = address; // Initialize load address with the region start address as fallback.
            if (filename.len > 0 and (region_flags.exec or main_executable_region)) {
                var found_load_addr = false;

                // Do we already have a cached image load addr for this filename?
                // Same method as .EXE checking, use dev and ino before falling back to str equality.
                for (image_loads.items) |load| {
                    const same_image = if (load.has_identity and filename_has_identity)
                        load.dev == filename_stat.dev and load.ino == filename_stat.ino
                    else
                        std.mem.eql(u8, load.filename, filename);

                    if (same_image) {
                        load_addr = load.load_addr;
                        found_load_addr = true;
                        break;
                    }
                }

                // We didn't have a cached load addr, so we'll have to manually check and cache if found
                if (!found_load_addr and region_flags.exec and region_size >= @sizeOf(u32)) {
                    // If this is an executable region, read the first 4 bytes of this region and check for Mach-O magic.
                    var magic_buf: [@sizeOf(u32)]u8 = undefined;
                    if ((self.read(io, address, magic_buf[0..]) catch 0) == magic_buf.len) {
                        const magic = std.mem.readInt(u32, &magic_buf, .little);

                        // If we indeed classified this file as Mach-O using the magic at the start of region, cache this image load for other regions' checks.
                        if (magic == std.macho.MH_MAGIC or magic == std.macho.MH_MAGIC_64) {
                            load_addr = address;

                            const image_filename = allocator.dupe(u8, filename) catch return ProcessError.RegionEnumFailed;
                            image_loads.append(allocator, .{
                                .filename = image_filename,
                                .load_addr = address,
                                .dev = if (filename_has_identity) filename_stat.dev else 0,
                                .ino = if (filename_has_identity) filename_stat.ino else 0,
                                .has_identity = filename_has_identity,
                            }) catch {
                                allocator.free(image_filename);
                                return ProcessError.RegionEnumFailed;
                            };
                        }
                    }
                }
            }

            const kind: RegionKind = blk: {
                if (info.user_tag == VM_MEMORY_STACK) break :blk .STACK;
                if (main_executable_region) break :blk .EXE;
                if (region_flags.exec) break :blk .CODE;
                if (filename.len == 0 and ((info.user_tag >= VM_MEMORY_MALLOC_FIRST and info.user_tag <= VM_MEMORY_MALLOC_LAST) or
                    (info.user_tag >= VM_MEMORY_MALLOC_NANO and info.user_tag <= VM_MEMORY_MALLOC_PROB_GUARD)))
                {
                    break :blk .HEAP;
                }

                break :blk .MISC;
            };

            // We do two calls to isUsefulRegion because main_executable_region can be based on dev+ino checks
            // instead of the filename == exe_name checks like Linux is doing, so we have to double check with
            // a explicit filename == filename in case the first one returns a false positive.
            if (!isUsefulRegion(kind, region_flags, filename, exe_name, level) and
                !(main_executable_region and isUsefulRegion(kind, region_flags, filename, filename, level)))
            {
                continue;
            }

            const filename_copy = allocator.dupe(u8, filename) catch return ProcessError.RegionEnumFailed;
            regions.append(allocator, .{
                .start = address,
                .size = region_size,
                .kind = kind,
                .flags = region_flags,
                .load_addr = load_addr,
                .id = region_id,
                .filename = filename_copy,
            }) catch {
                allocator.free(filename_copy);
                return ProcessError.RegionEnumFailed;
            };

            region_id += 1;
        }

        return regions.toOwnedSlice(allocator) catch return ProcessError.RegionEnumFailed;
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "[Linux] parseMapsLine: normal executable region" {
    const line = "7f1234560000-7f1234561000 r-xp 00003000 08:01 99999 /usr/lib/libc.so.6";
    const result = parseMapsLine(line).?;
    try std.testing.expectEqual(@as(usize, 0x7f1234560000), result.start);
    try std.testing.expectEqual(@as(usize, 0x7f1234561000), result.end);
    try std.testing.expectEqual(@as(usize, 0x3000), result.offset);
    try std.testing.expect(result.flags.read);
    try std.testing.expect(!result.flags.write);
    try std.testing.expect(result.flags.exec);
    try std.testing.expect(result.flags.private);
    try std.testing.expectEqualStrings("/usr/lib/libc.so.6", result.pathname);
}

test "[Linux] parseMapsLine: anonymous rw region (heap-like)" {
    const line = "55a000000000-55a000010000 rw-p 00000000 00:00 0 ";
    const result = parseMapsLine(line).?;
    try std.testing.expect(result.flags.read);
    try std.testing.expect(result.flags.write);
    try std.testing.expect(!result.flags.exec);
    try std.testing.expectEqualStrings("", result.pathname);
}

test "[Linux] parseMapsLine: [heap] region" {
    const line = "55b000000000-55b000100000 rw-p 00000000 00:00 0            [heap]";
    const result = parseMapsLine(line).?;
    try std.testing.expectEqualStrings("[heap]", result.pathname);
}

test "[Linux] parseMapsLine: malformed line returns null" {
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
