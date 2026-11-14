//! The relay with a reader that closed its output streams. `--help` and
//! `--version` print to standard output, and the log layer writes the log
//! lines there: none of it may end the process with a panic (exit code 101)
//! when the reader is gone.

use std::io::{Read, Write};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

/// The write end of a pipe whose read end is already closed.
fn pipe_without_reader() -> Stdio {
    let (reader, writer) = std::io::pipe().expect("pipe");
    drop(reader);
    writer.into()
}

/// A fresh, empty working directory.
fn empty_dir() -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "augenmass-relay-closed-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).expect("create dir");
    dir
}

/// The relay with an empty environment except `envs`. `closed_out` and
/// `closed_err` say which streams have no reader; the others are piped.
fn relay(args: &[&str], envs: &[(&str, String)], closed_out: bool, closed_err: bool) -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_augenmass-relay"));
    cmd.env_clear().current_dir(empty_dir()).args(args);
    for (key, value) in envs {
        cmd.env(key, value);
    }
    cmd.stdin(Stdio::null());
    cmd.stdout(if closed_out {
        pipe_without_reader()
    } else {
        Stdio::piped()
    });
    cmd.stderr(if closed_err {
        pipe_without_reader()
    } else {
        Stdio::piped()
    });
    cmd
}

#[test]
fn help_and_version_survive_a_closed_stdout() {
    for (arg, start) in [
        ("--help", "Hosted wallet-only relay"),
        ("--version", "augenmass-relay "),
    ] {
        let open = relay(&[arg], &[], false, false).output().expect("run");
        assert_eq!(open.status.code(), Some(0));
        let stdout = String::from_utf8(open.stdout).expect("utf8");
        assert!(stdout.starts_with(start), "{stdout}");

        for closed_err in [false, true] {
            let out = relay(&[arg], &[], true, closed_err).output().expect("run");
            let stderr = String::from_utf8(out.stderr).expect("utf8");
            assert_eq!(out.status.code(), Some(0), "{arg}: {stderr}");
            assert!(!stderr.contains("panicked"), "{arg}: {stderr}");
            assert!(stderr.is_empty(), "{arg}: {stderr}");
        }
    }
}

/// The status line of `GET /healthz` on a local port, or `None` while
/// nothing answers there.
fn health_status_line(port: u16) -> Option<String> {
    let mut stream = std::net::TcpStream::connect(("127.0.0.1", port)).ok()?;
    stream.set_read_timeout(Some(Duration::from_secs(5))).ok()?;
    write!(
        stream,
        "GET /healthz HTTP/1.1\r\nhost: 127.0.0.1\r\nconnection: close\r\n\r\n"
    )
    .ok()?;
    let mut response = String::new();
    let _ = stream.read_to_string(&mut response);
    response.lines().next().map(str::to_string)
}

/// Stops the relay when the test ends, also when it fails.
struct Running(Child);

impl Drop for Running {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// The relay binds loopback on a free port and stays up with its streams
/// closed. Its log layer reported a failed write of a log line with a print
/// macro of its own, which panicked once standard error was closed too.
#[test]
fn the_relay_starts_and_runs_with_closed_streams() {
    for (closed_out, closed_err) in [(false, false), (true, false), (true, true)] {
        let port = std::net::TcpListener::bind("127.0.0.1:0")
            .expect("bind")
            .local_addr()
            .expect("addr")
            .port();
        let envs = [
            ("AUGENMASS_RELAY_HOST", "127.0.0.1".to_string()),
            ("AUGENMASS_RELAY_PORT", port.to_string()),
        ];
        let mut running = Running(
            relay(&[], &envs, closed_out, closed_err)
                .spawn()
                .expect("spawn relay"),
        );
        let mut healthy = false;
        for _ in 0..300 {
            if running.0.try_wait().expect("try_wait").is_some() {
                break;
            }
            if health_status_line(port).is_some_and(|line| line.contains(" 200")) {
                healthy = true;
                break;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        let still_runs = running.0.try_wait().expect("try_wait").is_none();
        let _ = running.0.kill();
        let _ = running.0.wait();
        let mut stdout = String::new();
        if let Some(mut pipe) = running.0.stdout.take() {
            let _ = pipe.read_to_string(&mut stdout);
        }
        let mut stderr = String::new();
        if let Some(mut pipe) = running.0.stderr.take() {
            let _ = pipe.read_to_string(&mut stderr);
        }
        let case = format!("stdout closed: {closed_out}, stderr closed: {closed_err}");
        assert!(healthy, "{case}: /healthz did not answer\n{stderr}");
        assert!(still_runs, "{case}: the relay exited\n{stderr}");
        assert!(!stderr.contains("panicked"), "{case}: {stderr}");
        assert!(!stderr.contains("[tracing-subscriber]"), "{case}: {stderr}");
        if !closed_out {
            // The log line is written: the other runs reach that write.
            assert!(stdout.contains("augenmass relay listening"), "{stdout}");
        }
    }
}
