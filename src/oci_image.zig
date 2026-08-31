const std = @import("std");
const oci_registry = @import("oci_registry.zig");
const oci_config = @import("oci_config.zig");

pub fn extractLayer(
    io: std.Io,
    dir: std.Io.Dir,
    layer: oci_registry.Descriptor,
    blob: []const u8
) !void {
    if (std.mem.indexOf(u8, layer.mediaType, "gzip") == null) {
        return error.UnsupportedLayerMediaType;
    }

    var reader: std.Io.Reader = .fixed(blob);
    var decompress_buffer: [std.compress.flate.max_window_len]u8 = undefined;
    var decompress: std.compress.flate.Decompress = .init(&reader, .gzip, &decompress_buffer);

    try std.tar.extract(io, dir, &decompress.reader, .{});
}

const ImageConfigDetail = struct {
    Env: [][]const u8 = &.{},
    Entrypoint: ?[][]const u8 = null,
    Cmd: ?[][]const u8 = null,
    WorkingDir: []const u8 = "",
};

const ImageConfig = struct {
    config: ImageConfigDetail = .{},
};

fn resolveProcessArgs(
    allocator: std.mem.Allocator,
    image_config: ImageConfigDetail,
) ![][]const u8 {
    const entrypoint = image_config.Entrypoint orelse &.{};
    const cmd = image_config.Cmd orelse &.{};
    if (entrypoint.len == 0 and cmd.len == 0) {
        return allocator.dupe([]const u8, &.{"/bin/sh"});
    }

    const args = try allocator.alloc([]const u8, entrypoint.len + cmd.len);
    @memcpy(args[0..entrypoint.len], entrypoint);
    @memcpy(args[entrypoint.len..], cmd);
    return args;
}

pub fn writeBundleConfig(
    allocator: std.mem.Allocator,
    io: std.Io,
    bundle_dir: []const u8,
    config_blob: []const u8,
) !void {
    const image_config = try std.json.parseFromSliceLeaky(
        ImageConfig,
        allocator,
        config_blob,
        .{ .ignore_unknown_fields = true },
    );

    const runtime_config = oci_config.Config {
        .process = .{
            .args = try resolveProcessArgs(allocator, image_config.config),
            .env = image_config.config.Env,
            .cwd = if (image_config.config.WorkingDir.len == 0) "/" else image_config.config.WorkingDir,
        },
        .root = .{ .path = "rootfs" },
    };

    const config_path = try std.fmt.allocPrint(allocator, "{s}/config.json", .{bundle_dir});
    const file = try std.Io.Dir.cwd().createFile(io, config_path, .{});
    defer file.close(io);

    var buffer: [8192]u8 = undefined;
    var writer = file.writer(io, &buffer);
    try std.json.Stringify.value(runtime_config, .{ .whitespace = .indent_2 }, &writer.interface);
    try writer.interface.flush();
}