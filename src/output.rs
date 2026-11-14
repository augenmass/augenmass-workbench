//! Output format handling. Every read-only command can emit either a
//! human-readable text rendering or a machine-readable JSON document, selected
//! by the global `--json` flag. JSON output is what makes the toolkit usable
//! from agents, scripts, and CI.
//!
//! This module is also the only place of the crate that writes to standard
//! output and standard error ([`out`], [`outln`], [`diag`], [`LogWriter`]),
//! so that a reader that closes a stream early never ends a command with a
//! panic: the exit code of a verdict survives a closed pipe.

use std::io::{self, Write};
use std::sync::atomic::{AtomicBool, Ordering};

use anyhow::{Context, Result};
use serde_json::Value;

/// Set once a write to standard output found the reader gone.
static STDOUT_CLOSED: AtomicBool = AtomicBool::new(false);
/// Set once a write to standard error found the reader gone.
static STDERR_CLOSED: AtomicBool = AtomicBool::new(false);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputFormat {
    Text,
    Json,
}

impl OutputFormat {
    pub fn from_json_flag(json: bool) -> Self {
        if json {
            Self::Json
        } else {
            Self::Text
        }
    }

    pub fn is_json(self) -> bool {
        matches!(self, Self::Json)
    }
}

/// Print a result as either pretty JSON or the supplied text rendering.
/// The text is printed verbatim (callers include their own trailing newline
/// where needed); JSON is always newline-terminated. A reader that closed
/// standard output is not an error (see [`out`]).
pub fn emit(format: OutputFormat, json: &Value, text: &str) -> Result<()> {
    match format {
        OutputFormat::Json => outln(&serde_json::to_string_pretty(json)?),
        OutputFormat::Text => out(text),
    }
}

/// Write `text` to standard output. A reader that closed the pipe is not an
/// error: the stream is remembered as closed, nothing more is written to it,
/// and the call returns Ok, so the command goes on and exits with the code
/// it computes. Every other error that the standard library's handle
/// reports, from the write or from the flush, is returned (a full disk, for
/// example). The standard library itself reports a write to a descriptor
/// that is not open for writing as done, so that case looks like a closed
/// reader here: nothing is written and nothing is reported.
///
/// This module is the only place of the crate that writes to standard output
/// and standard error. The print macros panic on a failed write, which would
/// replace the exit code of a verdict by 101; clippy denies them in this
/// crate (`print_stdout`, `print_stderr` in `lib.rs` and `main.rs`).
pub fn out(text: &str) -> Result<()> {
    write_guarded(&mut io::stdout().lock(), &STDOUT_CLOSED, text.as_bytes())
        .context("write standard output")
}

/// [`out`] with a line break after `text`.
pub fn outln(text: &str) -> Result<()> {
    let mut line = String::with_capacity(text.len() + 1);
    line.push_str(text);
    line.push('\n');
    out(&line)
}

/// Write one line to standard error. Standard error carries notes, never a
/// result, so a failed write is never fatal: a closed reader is remembered
/// and every other error is dropped.
pub fn diag(text: &str) {
    let mut line = String::with_capacity(text.len() + 1);
    line.push_str(text);
    line.push('\n');
    let _ = write_guarded(&mut io::stderr().lock(), &STDERR_CLOSED, line.as_bytes());
}

/// [`diag`] with the arguments of `format!`; without arguments, an empty
/// line. The replacement of `eprintln!` in this crate.
macro_rules! diagln {
    () => {
        $crate::output::diag("")
    };
    ($($arg:tt)*) => {
        $crate::output::diag(&format!($($arg)*))
    };
}
pub(crate) use diagln;

/// True once a write to standard output found the reader gone. False for a
/// standard output that is not open for writing: the standard library
/// reports such a write as done.
pub fn stdout_closed() -> bool {
    STDOUT_CLOSED.load(Ordering::Relaxed)
}

/// The writer for the log layer of `serve`. A log line goes to standard
/// output through the same rule and the same closed flag as [`out`], and a
/// failed write is never an error for the caller: a log line is a note.
#[derive(Debug, Clone, Copy, Default)]
pub struct LogWriter;

impl Write for LogWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        log_write(&mut io::stdout().lock(), &STDOUT_CLOSED, buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// The rule of [`LogWriter`] on any writer: every byte counts as written,
/// whatever the write returned.
fn log_write(w: &mut impl Write, closed: &AtomicBool, buf: &[u8]) -> io::Result<usize> {
    let _ = write_guarded(w, closed, buf);
    Ok(buf.len())
}

/// The rule itself, on any writer, so that it can be tested without a pipe.
/// Nothing is written once `closed` is set. Else the bytes are written and
/// the writer is flushed; the result of each of the two calls is examined.
/// The error kind `BrokenPipe` (the reader of a pipe or socket is gone) from
/// either call sets `closed` and counts as success. Every other error from
/// either call is returned, so a flush that fails after every byte was
/// accepted is an error and not a success.
fn write_guarded(w: &mut impl Write, closed: &AtomicBool, bytes: &[u8]) -> io::Result<()> {
    if closed.load(Ordering::Relaxed) {
        return Ok(());
    }
    let written = match w.write_all(bytes) {
        Ok(()) => w.flush(),
        Err(error) => Err(error),
    };
    match written {
        Err(error) if error.kind() == io::ErrorKind::BrokenPipe => {
            closed.store(true, Ordering::Relaxed);
            Ok(())
        }
        other => other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A writer that fails `write` with a chosen error kind.
    struct FailingWrite(io::ErrorKind, usize);

    impl Write for FailingWrite {
        fn write(&mut self, _buf: &[u8]) -> io::Result<usize> {
            self.1 += 1;
            Err(io::Error::from(self.0))
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    /// A writer that accepts every byte and fails `flush` with a chosen
    /// error kind.
    struct FailingFlush(io::ErrorKind, Vec<u8>);

    impl Write for FailingFlush {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.1.extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Err(io::Error::from(self.0))
        }
    }

    /// A reader that goes away after `budget` bytes: the writer accepts that
    /// many bytes and then returns `BrokenPipe`.
    struct Budget {
        budget: usize,
        received: Vec<u8>,
        calls_after_close: usize,
    }

    impl Budget {
        fn new(budget: usize) -> Self {
            Self {
                budget,
                received: Vec::new(),
                calls_after_close: 0,
            }
        }
    }

    impl Write for Budget {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            let left = self.budget - self.received.len();
            if left == 0 {
                self.calls_after_close += 1;
                return Err(io::Error::from(io::ErrorKind::BrokenPipe));
            }
            let n = left.min(buf.len());
            self.received.extend_from_slice(&buf[..n]);
            Ok(n)
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn a_closed_reader_is_success_and_nothing_more_is_written() {
        let closed = AtomicBool::new(false);
        let mut w = FailingWrite(io::ErrorKind::BrokenPipe, 0);
        assert!(write_guarded(&mut w, &closed, b"first\n").is_ok());
        assert!(closed.load(Ordering::Relaxed));
        assert_eq!(w.1, 1);
        // The second call does not reach the writer.
        assert!(write_guarded(&mut w, &closed, b"second\n").is_ok());
        assert_eq!(w.1, 1);
    }

    #[test]
    fn every_other_write_error_is_returned() {
        for kind in [io::ErrorKind::StorageFull, io::ErrorKind::Other] {
            let closed = AtomicBool::new(false);
            let mut w = FailingWrite(kind, 0);
            let error = write_guarded(&mut w, &closed, b"text\n").expect_err("returned");
            assert_eq!(error.kind(), kind);
            assert!(!closed.load(Ordering::Relaxed), "{kind:?}");
        }
    }

    /// A guard that drops the result of `flush` would pass this as success.
    #[test]
    fn a_flush_that_fails_after_every_byte_was_accepted_is_an_error() {
        let closed = AtomicBool::new(false);
        let mut w = FailingFlush(io::ErrorKind::StorageFull, Vec::new());
        let error = write_guarded(&mut w, &closed, b"text\n").expect_err("returned");
        assert_eq!(error.kind(), io::ErrorKind::StorageFull);
        assert_eq!(w.1, b"text\n");
        assert!(!closed.load(Ordering::Relaxed));
    }

    #[test]
    fn a_closed_reader_found_by_the_flush_is_success() {
        let closed = AtomicBool::new(false);
        let mut w = FailingFlush(io::ErrorKind::BrokenPipe, Vec::new());
        assert!(write_guarded(&mut w, &closed, b"text\n").is_ok());
        assert!(closed.load(Ordering::Relaxed));
    }

    /// The reader goes away inside the first line, at the first byte of the
    /// last line, and one byte before the end.
    #[test]
    fn a_reader_that_closes_inside_the_text_gets_exactly_its_budget() {
        let text = b"first line\nsecond line\nlast line\n";
        let last_line = text.len() - b"last line\n".len();
        for budget in [4, last_line, text.len() - 1] {
            let closed = AtomicBool::new(false);
            let mut w = Budget::new(budget);
            assert!(write_guarded(&mut w, &closed, text).is_ok(), "{budget}");
            assert!(closed.load(Ordering::Relaxed), "{budget}");
            assert_eq!(w.received, &text[..budget], "{budget}");
            assert_eq!(w.calls_after_close, 1, "{budget}");
            // A later call writes nothing.
            assert!(write_guarded(&mut w, &closed, b"more\n").is_ok());
            assert_eq!(w.received, &text[..budget], "{budget}");
            assert_eq!(w.calls_after_close, 1, "{budget}");
        }
    }

    /// The shape of `register`: the report, then one line.
    #[test]
    fn the_second_of_two_writes_finds_the_reader_gone() {
        let report = b"report\n";
        let closed = AtomicBool::new(false);
        let mut w = Budget::new(report.len());
        assert!(write_guarded(&mut w, &closed, report).is_ok());
        assert!(!closed.load(Ordering::Relaxed));
        assert!(write_guarded(&mut w, &closed, b"one line\n").is_ok());
        assert!(closed.load(Ordering::Relaxed));
        assert_eq!(w.received, report);
    }

    #[test]
    fn a_log_line_never_fails_its_caller() {
        let line = b"log line\n";
        let closed = AtomicBool::new(false);
        let mut gone = FailingWrite(io::ErrorKind::BrokenPipe, 0);
        assert_eq!(log_write(&mut gone, &closed, line).expect("ok"), line.len());
        assert!(closed.load(Ordering::Relaxed));
        // Nothing more is written once the reader is gone.
        assert_eq!(log_write(&mut gone, &closed, line).expect("ok"), line.len());
        assert_eq!(gone.1, 1);

        let closed = AtomicBool::new(false);
        let mut full = FailingWrite(io::ErrorKind::StorageFull, 0);
        assert_eq!(log_write(&mut full, &closed, line).expect("ok"), line.len());
        assert!(!closed.load(Ordering::Relaxed));

        let mut flush_fails = FailingFlush(io::ErrorKind::StorageFull, Vec::new());
        assert_eq!(
            log_write(&mut flush_fails, &closed, line).expect("ok"),
            line.len()
        );
    }
}
