const std = @import("std");

pub const STATE_ROOT = "/run/zigcon";

pub const Status = enum { created, running, stopped };

pub const State = struct {
    id: []const u8,
    pid: i32,
    bundle: []const u8,
    status: Status,
};

pub fn stateDir(allocator: std.mem.Allocator, id: []const u8) ![]const u8 {
    return std.fmt.allocPrint(allocator, "{s}/{s}", .{ STATE_ROOT, id });
}

pub fn execFifoPath(allocator: std.mem.Allocator, id: []const u8) ![:0]const u8 {
    return std.fmt.allocPrintSentinel(
        allocator,
        "{s}/{s}/exec.fifo",
        .{ STATE_ROOT, id },
        0
    );
}

pub fn save(allocator: std.mem.Allocator, io: std.Io, state: State) !void {
    const dir_path = try stateDir(allocator, state.id);
    const dir = try std.Io.Dir.cwd().createDirPathOpen(io, dir_path, .{});
    defer dir.close(io);

    const file = try dir.createFile(io, "state.json", .{});
    defer file.close(io);

    var buffer: [4096]u8 = undefined;
    var writer = file.writer(io, &buffer);
    try std.json.Stringify.value(state, .{ .whitespace = .indent_2 }, &writer.interface);
    try writer.interface.flush();
}

pub fn load(allocator: std.mem.Allocator, io: std.Io, id: []const u8) !State {
    const dir_path = try stateDir(allocator, id);
    const dir = try std.Io.Dir.cwd().openDir(io, dir_path, .{});
    defer dir.close(io);

    const file = try dir.openFile(io, "state.json", .{});
    defer file.close(io);

    var buffer: [4096]u8 = undefined;
    var reader = file.reader(io, &buffer);
    const json_text = try reader.interface.allocRemaining(allocator, .unlimited);

    return try std.json.parseFromSliceLeaky(State, allocator, json_text, .{
        .ignore_unknown_fields = true,
        .allocate = .alloc_always,
    });
}