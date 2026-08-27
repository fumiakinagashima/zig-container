const std = @import("std");
const sys = @import("linux.zig");

pub fn main(init: std.process.Init) !void {
    const allocator = init.arena.allocator();
    const args = try init.minimal.args.toSlice(allocator);
    
    if (args.len < 2) {
        std.debug.print("usage: {s} <command>\n", .{args[0]});
        return;
    }

    std.debug.print("command: {s}\n", .{args[1]});

    const uts = try sys.getUname();
    std.debug.print("current hostname: {s}\n",.{std.mem.sliceTo(&uts.nodename, 0)});

    sys.setHostname("zig-container-test") catch |err| {
        std.debug.print(
            "setHostname failed as expected (no privilege / no UTS namespace yet): {s}\n",
            .{@errorName(err)}
        );
    };
}