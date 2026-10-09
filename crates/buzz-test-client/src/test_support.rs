//! Database-URL guard for the e2e/regression binaries under `tests/`.
//!
//! `BUZZ_TEST_DATABASE_URL` is the only accepted source. Falling back to
//! `DATABASE_URL` (or any other var, or a hardcoded default) is the exact
//! mechanism that let a test drop the live `public` schema on 2026-09-29 —
//! do not reintroduce it.

/// Resolve the database URL for Postgres-backed e2e/regression tests.
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
