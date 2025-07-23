const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // Build the Rust static library using cargo
    const cargo_cmd = if (optimize == .ReleaseFast or optimize == .ReleaseSmall) 
        b.addSystemCommand(&.{ "cargo", "build", "--release", "--manifest-path", "rust/Cargo.toml" })
    else 
        b.addSystemCommand(&.{ "cargo", "build", "--manifest-path", "rust/Cargo.toml" });

    // Create the Zig module
    const hashsig_module = b.addModule("hash-sigzz", .{
        .root_source_file = b.path("src/lib.zig"),
        .target = target,
        .optimize = optimize,
    });

    // Create a test executable
    const test_exe = b.addExecutable(.{
        .name = "hash-sigzz-test",
        .root_source_file = b.path("src/test.zig"),
        .target = target,
        .optimize = optimize,
    });

    test_exe.root_module.addImport("hash-sigzz", hashsig_module);
    
    // Add the Rust static library directly
    const rust_lib_path = if (optimize == .ReleaseFast or optimize == .ReleaseSmall)
        "rust/target/release/libhashsig_host.a"
    else
        "rust/target/debug/libhashsig_host.a";
    
    test_exe.addObjectFile(b.path(rust_lib_path));
    test_exe.linkLibC();
    test_exe.linkSystemLibrary("unwind");
    
    // Ensure cargo builds before we link (zeam pattern)
    test_exe.step.dependOn(&cargo_cmd.step);

    // Install the test executable
    const install_test = b.addInstallArtifact(test_exe, .{});
    b.getInstallStep().dependOn(&install_test.step);

    // Run step
    const run_cmd = b.addRunArtifact(test_exe);
    if (b.args) |args| {
        run_cmd.addArgs(args);
    }

    const run_step = b.step("run", "Run the test");
    run_step.dependOn(&run_cmd.step);

    // Test step
    const unit_tests = b.addTest(.{
        .root_source_file = b.path("src/test.zig"),
        .target = target,
        .optimize = optimize,
    });
    
    unit_tests.root_module.addImport("hash-sigzz", hashsig_module);

    unit_tests.addObjectFile(b.path(rust_lib_path));
    unit_tests.linkLibC();
    unit_tests.linkSystemLibrary("unwind");
    unit_tests.step.dependOn(&cargo_cmd.step);

    const run_unit_tests = b.addRunArtifact(unit_tests);
    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_unit_tests.step);
}