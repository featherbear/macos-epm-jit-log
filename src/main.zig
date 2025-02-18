const std = @import("std");
const ChildProcess = std.process.Child;

const LogStream = struct { eventMessage: []const u8, subsystem: []const u8, processID: c_int, timestamp: []const u8 };

const AppEvent = struct { timeString: []const u8, type: []const u8, hasDelta: bool, delta: i64 };

const stdout = std.io.getStdOut().writer();
const stderr = std.io.getStdErr().writer();

pub fn emitEvent(event: AppEvent) !void {
    if (event.hasDelta) {
        try stdout.print("{s},{s},{d}\n", .{ event.timeString, event.type, event.delta });
    } else {
        try stdout.print("{s},{s}\n", .{ event.timeString, event.type });
    }
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

    var reqStartTimeMs: i64 = 0;

    while (true) {
        const bytesRead = (try reader.readUntilDelimiter(&buffer, '\n')).len;
        const parsed = try std.json.parseFromSlice(LogStream, allocator, buffer[0..bytesRead], .{ .ignore_unknown_fields = true });
        defer parsed.deinit();

        var evtObject = AppEvent{ .timeString = parsed.value.timestamp, .type = undefined, .hasDelta = false, .delta = 0 };

        if (std.mem.startsWith(u8, parsed.value.eventMessage, "Requested")) {
            evtObject.type = "request";

            // There is another outstanding request, calculate the delta between requests
            if (reqStartTimeMs > 0) {
                evtObject.hasDelta = true;
                evtObject.delta = std.time.milliTimestamp() - reqStartTimeMs;
            }
            reqStartTimeMs = std.time.milliTimestamp();
        } else if (std.mem.startsWith(u8, parsed.value.eventMessage, "Did add")) {
            evtObject.type = "grant";

            if (reqStartTimeMs > 0) {
                evtObject.hasDelta = true;
                evtObject.delta = std.time.milliTimestamp() - reqStartTimeMs;
            }
            reqStartTimeMs = 0;
        } else if (std.mem.startsWith(u8, parsed.value.eventMessage, "Did remove")) {
            evtObject.type = "revoke";
        } else {
            try stderr.print("Unexpected message at {s}: {s}...\n", .{ parsed.value.timestamp, parsed.value.eventMessage });
            continue;
        }

        try emitEvent(evtObject);
    }
}
