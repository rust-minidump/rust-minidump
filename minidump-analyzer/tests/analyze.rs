use minidump_writer::minidump_writer::MinidumpWriter;
use std::fs::File;
use std::io::{Read, Write};
use std::process::{Child, Command};
use tempfile::tempdir;

fn start_child() -> Child {
    Command::new("cargo")
        .arg("test")
        .arg("client::basic_entry")
        .spawn()
        .expect("failed to execute child")
}

#[test]
fn analyze_basic_minidump() {
    let dir = tempdir().expect("failed to create temporary directory");
    let minidump_file = dir.path().join("mini.dump");
    let extra_file = dir.path().join("mini.extra");

    // Create minidump from test.
    {
        let mut child = start_child();
        let pid = child.id() as i32;

        let mut writer = MinidumpWriter::new(pid, pid);
        writer
            .dump(&mut File::create(&minidump_file).expect("failed to create minidump file"))
            .expect("failed to write minidump");
        child.kill().expect("child already terminated?");
    }

    // Create empty extra file
    {
        let mut extra = File::create(&extra_file).expect("failed to create extra json file");
        write!(&mut extra, "{{}}").expect("failed to write to extra json file");
    }

    // Run minidump-analyzer
    {
        let output = Command::new(env!("CARGO_BIN_EXE_minidump-analyzer"))
            .env("RUST_BACKTRACE", "1")
            .arg(&minidump_file)
            .output()
            .expect("failed to run minidump-analyzer");
        assert!(
            output.status.success(),
            "stderr:\n{}",
            std::str::from_utf8(&output.stderr).unwrap()
        );
    }

    // Check the output JSON
    // The stack trace will actually be in cargo. It forks and execs the test program; there is no
    // clean way to make it just exec one or to directly address the binary (without creating a new
    // crate).
    {
        let mut extra_content = String::new();
        File::open(extra_file)
            .expect("failed to open extra json file")
            .read_to_string(&mut extra_content)
            .expect("failed to read extra json file");

        let extra = json::parse(&extra_content).expect("failed to parse extra json");
        let stack_traces = &extra["StackTraces"];
        assert!(stack_traces.is_object());
        let threads = &stack_traces["threads"];
        assert!(threads.is_array() && threads.len() == 1);
        assert!(threads[0].is_object());
        let frames = &threads[0]["frames"];
        assert!(frames.is_array() && frames.len() > 0);
    }
}
