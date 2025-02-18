const std = @import("std");
const ChildProcess = std.process.Child;

const LogStream = struct { eventMessage: []const u8, subsystem: []const u8, processID: c_int, timestamp: []const u8, machTimestamp: u64 };

const AppEvent = struct { timeString: []const u8, type: []const u8, delta: u64 };

const stdout = std.io.getStdOut().writer();
const stderr = std.io.getStdErr().writer();

pub fn emitEvent(event: AppEvent) !void {
    try stdout.print("{s},{s}\n", .{ event.timeString, event.type });
}

pub fn main() !void {
    var allocatorBacking = std.heap.GeneralPurposeAllocator(.{}){};
    const allocator = allocatorBacking.allocator();

    const filter = "sender == 'com.cyberark.CyberArkEPMEndpointSecurityExtension' AND ((eventMessage == 'Requested administrative privileges') OR (eventMessage BEGINSWITH 'Did ' AND eventMessage ENDSWITH \"to '_cyberarkepm_sudoers' group\"))";

    var proc = ChildProcess.init(&[_][]const u8{ "/usr/bin/log", "stream", "--style", "ndjson", "--info", "--predicate", filter }, allocator);
    proc.stdout_behavior = ChildProcess.StdIo.Pipe;
    proc.stderr_behavior = ChildProcess.StdIo.Ignore;
    try proc.spawn();

    // The max I've seen is around 5400 bytes
    var buffer: [8192]u8 = undefined;

    const reader = proc.stdout.?.reader();

    // Skip the first line: "Filtering the log data using ..."
    _ = try reader.readUntilDelimiter(&buffer, '\n');

    try stderr.print("Observing events...\n", .{});

    while (true) {
        const bytesRead = (try reader.readUntilDelimiter(&buffer, '\n')).len;
        const parsed = try std.json.parseFromSlice(LogStream, allocator, buffer[0..bytesRead], .{ .ignore_unknown_fields = true });
        defer parsed.deinit();

        var evtObject = AppEvent{ .timeString = parsed.value.timestamp, .type = undefined, .delta = 0 };
        // TODO: handle delta, later on...

        // e.g.
        if (std.mem.startsWith(u8, parsed.value.eventMessage, "Requested")) {
            evtObject.type = "request";
        } else if (std.mem.startsWith(u8, parsed.value.eventMessage, "Did add")) {
            evtObject.type = "grant";
        } else if (std.mem.startsWith(u8, parsed.value.eventMessage, "Did remove")) {
            evtObject.type = "revoke";
        } else {
            continue;
        }

        try emitEvent(evtObject);
    }
}
