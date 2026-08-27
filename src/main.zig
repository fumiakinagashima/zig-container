const std = @import("std");

pub fn main(init: std.process.Init) !void {
    const allocator = init.arena.allocator();
    const args = try init.minimal.args.toSlice(allocator);
    
    if (args.len < 2) {
        std.debug.print("usage: {s} <command>\n", .{args[0]});
        return;
    }

    std.debug.print("command: {s}\n", .{args[1]});
}