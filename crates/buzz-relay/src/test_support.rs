/// Resolve the database URL shared by PostgreSQL-backed relay tests.
///
/// `BUZZ_TEST_DATABASE_URL` is the only accepted source. Falling back to
/// `DATABASE_URL` (or any other var, or a hardcoded default) is the exact
/// mechanism that let a test drop the live `public` schema on 2026-09-29 —
/// do not reintroduce it.
pub fn database_url() -> String {
    let url = std::env::var("BUZZ_TEST_DATABASE_URL").unwrap_or_else(|_| {
        panic!(
            "BUZZ_TEST_DATABASE_URL is not set. PostgreSQL-backed tests refuse to fall \
             back to DATABASE_URL or any hardcoded default — that fallback is what dropped \
             the live schema on 2026-09-29. Set BUZZ_TEST_DATABASE_URL to a disposable \
             database, e.g. postgres://buzz:buzz_dev@localhost:5432/buzz_test"
        )
    });
    assert_test_database_url(&url);
    url
}

/// Refuse a URL unless it points at a database this codebase treats as
/// disposable: a name ending in `_test`, or one of nextest's per-test
/// isolated `buzz_nt_*` databases (see `scripts/postgres-test-wrapper.sh`).
pub fn assert_test_database_url(url: &str) {
    let db_name = url.rsplit('/').next().unwrap_or_default();
    let db_name = db_name.split(['?', '#']).next().unwrap_or(db_name);
    assert!(
        db_name.ends_with("_test") || db_name.starts_with("buzz_nt_"),
        "refusing to run a PostgreSQL-backed test against database `{db_name}`: it must be \
         disposable (name ending in `_test`, or a nextest-isolated `buzz_nt_*` database) — \
         this is the guard that was missing when a test dropped the live schema on 2026-09-29"
    );
}

/// Pure string-logic tests — no Postgres, no env vars, no I/O of any kind.
/// Safe to run at any time, including under the 2026-09-29 test-run freeze.
#[cfg(test)]
mod guard_tests {
    use super::*;

    #[test]
    fn accepts_disposable_database_names() {
        assert_test_database_url("postgres://buzz:buzz_dev@localhost:5432/buzz_test");
        assert_test_database_url(
            "postgres://buzz:pw@localhost:5432/buzz_nt_deadbeefcafebabe1234?sslmode=disable",
        );
    }

    #[test]
    #[should_panic(expected = "refusing to run")]
    fn rejects_the_live_database_name() {
        assert_test_database_url("postgres://buzz:buzz_dev@localhost:15432/buzz");
    }
}

#[cfg(test)]
const CHILD_TEST_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);
#[cfg(test)]
const MAX_CAPTURE_BYTES: u64 = 1024 * 1024;

#[cfg(test)]
struct CapturedStream {
    retained: Vec<u8>,
    total_bytes: u64,
}

#[cfg(test)]
fn capture_stream(mut stream: impl std::io::Read) -> CapturedStream {
    let mut retained = Vec::new();
    let mut total_bytes = 0_u64;
    let mut chunk = [0_u8; 8192];
    loop {
        let read = stream.read(&mut chunk).expect("read child output pipe");
        if read == 0 {
            break;
        }
        total_bytes = total_bytes.saturating_add(u64::try_from(read).expect("read size fits u64"));
        let remaining = usize::try_from(MAX_CAPTURE_BYTES)
            .expect("capture ceiling fits usize")
            .saturating_sub(retained.len());
        retained.extend_from_slice(&chunk[..read.min(remaining)]);
    }
    CapturedStream {
        retained,
        total_bytes,
    }
}

#[cfg(test)]
fn join_capture(capture: std::thread::JoinHandle<CapturedStream>, stream: &str) -> Vec<u8> {
    let capture = capture.join().expect("child capture thread must not panic");
    assert!(
        capture.total_bytes <= MAX_CAPTURE_BYTES,
        "child {stream} exceeded {MAX_CAPTURE_BYTES} bytes: {}",
        capture.total_bytes,
    );
    capture.retained
}

/// Run exactly one unit test in an isolated, deadline-bounded child process.
#[cfg(test)]
pub(crate) fn run_exact_test_child(test_name: &str, child_env: &str) {
    use std::{
        process::{Command, Stdio},
        thread,
        time::{Duration, Instant},
    };

    let mut child = Command::new(std::env::current_exe().expect("test executable"))
        .arg("--exact")
        .arg(test_name)
        .arg("--nocapture")
        .env(child_env, "1")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn isolated test child");
    let stdout = child.stdout.take().expect("child stdout pipe");
    let stderr = child.stderr.take().expect("child stderr pipe");
    let stdout = thread::spawn(move || capture_stream(stdout));
    let stderr = thread::spawn(move || capture_stream(stderr));

    let deadline = Instant::now() + CHILD_TEST_TIMEOUT;
    let (status, timed_out) = loop {
        if let Some(status) = child.try_wait().expect("poll isolated test child") {
            break (status, false);
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let status = child.wait().expect("reap timed-out test child");
            break (status, true);
        }
        thread::sleep(Duration::from_millis(10));
    };

    let stdout = join_capture(stdout, "stdout");
    let stderr = join_capture(stderr, "stderr");
    let output = format!(
        "{}{}",
        String::from_utf8_lossy(&stdout),
        String::from_utf8_lossy(&stderr)
    );

    assert!(
        !timed_out,
        "isolated test child exceeded {CHILD_TEST_TIMEOUT:?}:\n{output}"
    );
    assert!(status.success(), "isolated test child failed:\n{output}");
    assert!(
        output.contains("running 1 test") && output.contains(test_name),
        "exact selector did not run the intended test {test_name}:\n{output}"
    );
}
