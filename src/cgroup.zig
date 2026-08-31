const std = @import("std");
const sys = @import("linux.zig");

pub const cgroup_root = "/sys/fs/cgroup";

pub const Cgroup = struct {
    allocator: std.mem.Allocator,
    path: [:0]const u8,

    pub fn create(allocator: std.mem.Allocator, name: []const u8) !Cgroup {
        sys.writeFile(cgroup_root ++ "/cgroup.subtree_control", "+cpu +memory") catch |err| {
            std.log.warn(
                "enabling cpu/memory controllers on root cgroup failed (maybe already enabled): {s}",
                .{@errorName(err)},
            );
        };

        const path = try std.fmt.allocPrintSentinel(
            allocator,
            "{s}/{s}",
            .{cgroup_root, name},
            0,
        );
        errdefer allocator.free(path);
        try sys.makeDir(path.ptr, 0o755);

        return Cgroup{ .allocator = allocator, .path = path };
    }

    pub fn setMemoryMax(self: Cgroup, bytes: u64) !void {
        try self.writeControlFile("memory.max", "{d}", .{bytes});
    }

    pub fn setCpuMax(self: Cgroup, quota_us: u64, period_us: u64) !void {
        try self.writeControlFile("cpu.max", "{d} {d}", .{ quota_us, period_us });
    }

    pub fn addProcess(self: Cgroup, pid: i32) !void {
        try self.writeControlFile("cgroup.procs", "{d}", .{pid});
    }

    fn writeControlFile(
        self: Cgroup,
        file_name: []const u8,
        comptime fmt: []const u8,
        args: anytype,
    ) !void {
        const file_path = try std.fmt.allocPrintSentinel(
            self.allocator,
            "{s}/{s}",
            .{ self.path, file_name },
            0,
        );
        defer self.allocator.free(file_path);

        const value = try std.fmt.allocPrint(self.allocator, fmt, args);
        defer self.allocator.free(value);

        try sys.writeFile(file_path.ptr, value);
    }

    pub fn destroy(self: Cgroup) void {
        sys.removeDir(self.path.ptr) catch |err| {
            std.log.warn("removing cgroup {s} failed: {s}", .{ self.path, @errorName(err) });
        };
        self.allocator.free(self.path);
    }
};