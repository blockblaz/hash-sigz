const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const lib = b.addStaticLibrary(.{
        .name = "hash-sigz",
        .root_source_file = b.path("src/main.zig") ,
        .target = target,
        .optimize = optimize,
    });
    b.installArtifact(lib);

    const bench = b.addExecutable(.{
        .name = "bench",
        .root_source_file = b.path("bench/bench_sha3.zig"),
        .target = target,
        .optimize = .ReleaseFast,
    });
    b.installArtifact(bench);

    const run_bench = b.addRunArtifact(bench);

    const bench_step = b.step("bench", "Run benchmarks");
    bench_step.dependOn(&run_bench.step);
}
