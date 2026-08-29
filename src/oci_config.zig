const std = @import("std");
const sys = @import("linux.zig");

pub const Process = struct {
    args: [][]const u8,
    env: [][]const u8 = &.{},
    cwd: []const u8 = "/",
};

pub const Root = struct {
    path: []const u8,
};

pub const Memory = struct {
    limit : ?u64 = null,
};

pub const Cpu = struct {
    quota: ?u64 = null,
    period: ?u64 = null,
};

pub const Resources = struct {
    memory: Memory = .{},
    cpu: Cpu = .{},
};

pub const LinuxConfig = struct {
    resources: Resources = .{},
};

pub const Config = struct {
    ociVersion: []const u8 = "1.0.2",
    hostname: []const u8 = "zigcon",
    process: Process,
    root: Root,
    linux: LinuxConfig = .{},
};

pub fn loadFromBundle(allocator: std.mem.Allocator, bundle_dir: []const u8) !Config {
    const config_path = try std.fmt.allocPrintSentinel(allocator, "{s}/config.json", .{bundle_dir}, 0);
    var buf: [64 * 1024]u8 = undefined;
    const json_text = try sys.readFile(config_path.ptr, &buf);

    return try std.json.parseFromSliceLeaky(
        Config,
        allocator,
        json_text,
        .{
            .ignore_unknown_fields = true,
            .allocate = .alloc_always,
        },
    );
}

pub fn resolveRootfsPath(allocator: std.mem.Allocator, bundle_dir: []const u8, config: Config) ![:0]const u8 {
    return try std.fmt.allocPrintSentinel(allocator, "{s}/{s}", .{ bundle_dir, config.root.path }, 0);
}

