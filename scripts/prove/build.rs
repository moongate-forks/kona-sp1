// use std::process::Command;

// use sp1_build::{build_program_with_args, BuildArgs};

/// Build a native program.
// fn build_native_program(program: &str) {
//     let status = Command::new("cargo")
//         .args(["build", "--workspace", "--bin", program, "--profile", "release-client-lto"])
//         .status()
//         .expect("Failed to execute cargo build command");

//     if !status.success() {
//         panic!("Failed to build {}", program);
//     }

//     println!("cargo:warning={} built with release-client-lto profile", program);
// }

// /// Build a program for the zkVM.
// fn build_zkvm_program(program: &str) {
//     build_program_with_args(
//         &format!("../../programs/{}", program),
//         BuildArgs {
//             elf_name: format!("{}-elf", program),
//             // docker: true,
//             ..Default::default()
//         },
//     );
// }
use std::process::Command;

/// Build the native host runner to a separate target directory to avoid build lockups.
fn build_native_host_runner() {
    let metadata =
        cargo_metadata::MetadataCommand::new().exec().expect("Failed to get cargo metadata");
    let target_dir = metadata.target_directory.join("native_host_runner");

    let status = Command::new("cargo")
        .args([
            "build",
            "--workspace",
            "--bin",
            "native_host_runner",
            "--release",
            "--target-dir",
            target_dir.as_ref(),
        ])
        .status()
        .expect("Failed to execute cargo build command");
    if !status.success() {
        panic!("Failed to build native_host_runner");
    }

    println!("cargo:warning=native_host_runner built with release profile",);
}

fn main() {
    // let programs = vec!["range"];
    // for program in programs {
    // build_native_program(program);
    // build_zkvm_program(program);
    // }

    // build_zkvm_program("aggregation");

    // This runs the build script every time as the timestamp ont he build script updates.
    println!("cargo:rerun-if-changed=build.rs");
    build_native_host_runner(); 
}
