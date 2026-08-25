//! Per-channel resume state, persisted across process restarts.
//!
//! `BgState` tracks `last_seen` and `seen_ids` in memory, which covers a
//! reconnect inside a live session but not a restart: a fresh process starts
//! with empty maps and subscribes from "now", so anything published while it
//! was down is never delivered.
//!
//! Persisting only the timestamp would fix that and introduce a worse bug.
//! Replay is inclusive and Nostr timestamps are second-granularity, so
//! resuming from `last_seen` re-delivers the events at that second — and with
//! `seen_ids` empty on restart, nothing would stop the agent acting on the
//! same mention twice. Storing `last_seen + 1` instead trades that for
//! silently skipping a different event published in the same second.
//!
//! So this stores both: the watermark *and* a bounded list of recently
//! processed event IDs, which the caller feeds back into the existing
//! two-generation dedup at startup. Replay then costs a few redundant events
//! that get deduped, rather than repeated work.
//!
//! Every failure mode degrades to today's behaviour (subscribe from "now")
//! rather than preventing startup: a missing file is a first run, and a
//! corrupt one is not worth crashing an agent over.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Recent event IDs retained per channel.
///
/// Only needs to cover the events sharing the watermark second, so this is
/// generous. `TwoGenDedup` holds thousands once running; this is just the seed
/// that closes the restart gap.
const RECENT_IDS_PER_CHANNEL: usize = 64;

/// Resume state for one channel.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ChannelWatermark {
    /// Newest `created_at` processed for this channel.
    pub last_seen: u64,
    /// Most-recently-processed event IDs, newest last. Seeds dedup on restart.
    #[serde(default)]
    pub recent_ids: Vec<String>,
}

/// Per-channel resume state for one agent.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct WatermarkStore {
    #[serde(default)]
    channels: HashMap<Uuid, ChannelWatermark>,
}

impl WatermarkStore {
    /// Read the store, falling back to empty on any failure.
    ///
    /// A missing file is the first run. A corrupt one is logged and discarded:
    /// the cost is one session of missed catch-up, which is exactly the
    /// behaviour before this existed — cheaper than refusing to start.
    ///
    /// Both fallbacks are *logged*, deliberately. Degrading quietly is what
    /// makes this safe to ship, but it is also what would hide a caller
    /// passing a bad path: the store would read empty forever, the watermark
    /// would never resume, and the agent would double-fire on every restart —
    /// the exact bug this module exists to prevent, with no symptom. So
    /// "genuinely first run" must be distinguishable from "reading the wrong
    /// place" in the logs.
    pub(crate) fn load(path: &Path) -> Self {
        if let Some(problem) = suspect_path(path) {
            tracing::warn!(
                "watermark path {} {problem} — if this is wrong, resume state \
                 will silently never load",
                path.display()
            );
        }

        let raw = match std::fs::read_to_string(path) {
            Ok(raw) => raw,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                tracing::info!(
                    "no watermark file at {} — first run, starting from now",
                    path.display()
                );
                return Self::default();
            }
            Err(e) => {
                tracing::warn!("could not read watermark file {}: {e}", path.display());
                return Self::default();
            }
        };

        match serde_json::from_str(&raw) {
            Ok(store) => store,
            Err(e) => {
                tracing::warn!(
                    "watermark file {} is unreadable ({e}) — starting from now",
                    path.display()
                );
                Self::default()
            }
        }
    }

    /// Write the store atomically.
    ///
    /// Serialises first, then writes a sibling temp file and renames over the
    /// target, so an interrupted write leaves the previous good file rather
    /// than a truncated one. `rename` is atomic within a directory on both
    /// Unix and Windows.
    pub(crate) fn save(&self, path: &Path) -> std::io::Result<()> {
        let encoded = serde_json::to_vec_pretty(self)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)?;
            }
        }

        let tmp = temp_path(path);
        std::fs::write(&tmp, &encoded)?;
        match std::fs::rename(&tmp, path) {
            Ok(()) => Ok(()),
            Err(e) => {
                // Don't leave the temp file behind if the swap failed.
                let _ = std::fs::remove_file(&tmp);
                Err(e)
            }
        }
    }

    /// Record a processed event. `last_seen` only moves forward, so
    /// out-of-order delivery can't rewind the resume point.
    pub(crate) fn record(&mut self, channel_id: Uuid, created_at: u64, event_id: &str) {
        let entry = self.channels.entry(channel_id).or_default();
        entry.last_seen = entry.last_seen.max(created_at);

        if entry.recent_ids.iter().any(|id| id == event_id) {
            return;
        }
        entry.recent_ids.push(event_id.to_string());
        if entry.recent_ids.len() > RECENT_IDS_PER_CHANNEL {
            let excess = entry.recent_ids.len() - RECENT_IDS_PER_CHANNEL;
            entry.recent_ids.drain(..excess);
        }
    }

    /// Resume timestamp for a channel, or `None` to keep today's behaviour.
    pub(crate) fn since(&self, channel_id: &Uuid) -> Option<u64> {
        self.channels
            .get(channel_id)
            .map(|entry| entry.last_seen)
            .filter(|ts| *ts > 0)
    }

    /// Every retained event ID, for seeding dedup before the first subscribe.
    pub(crate) fn all_recent_ids(&self) -> Vec<String> {
        self.channels
            .values()
            .flat_map(|entry| entry.recent_ids.iter().cloned())
            .collect()
    }

    /// Drop state for a channel that is no longer subscribed.
    pub(crate) fn forget(&mut self, channel_id: &Uuid) {
        self.channels.remove(channel_id);
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.channels.is_empty()
    }
}

/// Describe why a watermark path looks like a construction bug, if it does.
///
/// This crate has a live example of the failure mode: its own test suite
/// writes files literally named `C:UsersbradlAppData…json` into the crate
/// directory — a Windows path whose separators were lost, leaving a *relative*
/// path that happens to contain a drive prefix. Because `load` treats an
/// absent file as a harmless first run, a path mangled that way would never
/// surface as an error; it would just quietly never resume.
///
/// Returns `None` when the path looks fine. Advisory only — the caller warns
/// and continues rather than refusing to start.
fn suspect_path(path: &Path) -> Option<&'static str> {
    // A flattened Windows path (`C:Users…json`) is drive-relative, not
    // absolute, so the check below already catches it — no separate
    // separator-sniffing needed.
    if !path.is_absolute() {
        return Some("is relative, so it resolves against the process working directory");
    }

    match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() && !parent.is_dir() => {
            Some("has a parent directory that does not exist")
        }
        _ => None,
    }
}

/// Sibling temp path used for the atomic swap.
fn temp_path(path: &Path) -> PathBuf {
    let mut name = path.file_name().unwrap_or_default().to_os_string();
    name.push(".tmp");
    path.with_file_name(name)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(label: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("buzz-acp-watermark-{label}"));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("create scratch dir");
        dir.join("watermarks.json")
    }

    #[test]
    fn round_trips_through_disk() {
        let path = scratch("round-trip");
        let channel = Uuid::new_v4();

        let mut store = WatermarkStore::default();
        store.record(channel, 1_000, "aaaa");
        store.record(channel, 1_005, "bbbb");
        store.save(&path).expect("save");

        let loaded = WatermarkStore::load(&path);
        assert_eq!(loaded.since(&channel), Some(1_005));
        assert_eq!(loaded.all_recent_ids(), vec!["aaaa", "bbbb"]);
    }

    /// The property the whole module exists for: an event processed before a
    /// restart is still known afterwards, so replaying from the watermark
    /// cannot make the agent act on it twice.
    #[test]
    fn a_processed_event_survives_restart_so_replay_cannot_double_fire() {
        let path = scratch("no-double-fire");
        let channel = Uuid::new_v4();
        let already_handled = "deadbeef";

        let mut before = WatermarkStore::default();
        before.record(channel, 2_000, already_handled);
        before.save(&path).expect("save");

        // Fresh process: resumes from the watermark, and the replayed event is
        // still recognised.
        let after = WatermarkStore::load(&path);
        assert_eq!(
            after.since(&channel),
            Some(2_000),
            "must resume from the last processed event, not from now"
        );
        assert!(
            after
                .all_recent_ids()
                .iter()
                .any(|id| id == already_handled),
            "the event that would be replayed must seed dedup"
        );
    }

    #[test]
    fn missing_file_is_a_first_run_not_an_error() {
        let path = scratch("missing").with_file_name("does-not-exist.json");
        let store = WatermarkStore::load(&path);
        assert!(store.is_empty());
        assert_eq!(store.since(&Uuid::new_v4()), None);
    }

    #[test]
    fn corrupt_file_degrades_to_starting_from_now() {
        let path = scratch("corrupt");
        std::fs::write(&path, b"{ not json at all").expect("write junk");

        let store = WatermarkStore::load(&path);
        assert!(
            store.is_empty(),
            "a corrupt file must not stop the agent starting"
        );
    }

    #[test]
    fn last_seen_never_moves_backwards() {
        let channel = Uuid::new_v4();
        let mut store = WatermarkStore::default();

        store.record(channel, 5_000, "newer");
        store.record(channel, 4_000, "older-arriving-late");

        assert_eq!(store.since(&channel), Some(5_000));
    }

    #[test]
    fn recent_ids_are_bounded_and_keep_the_newest() {
        let channel = Uuid::new_v4();
        let mut store = WatermarkStore::default();

        for i in 0..(RECENT_IDS_PER_CHANNEL + 10) {
            store.record(channel, 1_000 + i as u64, &format!("event-{i}"));
        }

        let ids = store.all_recent_ids();
        assert_eq!(ids.len(), RECENT_IDS_PER_CHANNEL);
        assert!(ids
            .iter()
            .any(|id| id == &format!("event-{}", RECENT_IDS_PER_CHANNEL + 9)));
        assert!(
            !ids.iter().any(|id| id == "event-0"),
            "oldest entries are evicted first"
        );
    }

    #[test]
    fn recording_the_same_event_twice_does_not_duplicate_it() {
        let channel = Uuid::new_v4();
        let mut store = WatermarkStore::default();

        store.record(channel, 1_000, "same");
        store.record(channel, 1_000, "same");

        assert_eq!(store.all_recent_ids(), vec!["same"]);
    }

    #[test]
    fn zero_watermark_is_treated_as_no_resume_point() {
        let channel = Uuid::new_v4();
        let mut store = WatermarkStore::default();
        store.record(channel, 0, "unstamped");

        assert_eq!(
            store.since(&channel),
            None,
            "a zero timestamp must not be handed back as a replay floor"
        );
    }

    /// The failure this crate actually produces: a Windows path flattened into
    /// a filename. It is *relative*, so it would silently resolve somewhere
    /// unexpected and the store would read empty forever.
    #[test]
    fn flattened_windows_path_is_flagged() {
        let mangled = PathBuf::from("C:UsersbradlAppDataLocalTempwatermarks.json");
        assert!(
            suspect_path(&mangled).is_some(),
            "a path with its separators stripped must be flagged"
        );
    }

    #[test]
    fn relative_path_is_flagged() {
        assert!(suspect_path(&PathBuf::from("watermarks.json")).is_some());
        assert!(suspect_path(&PathBuf::from("./state/watermarks.json")).is_some());
    }

    #[test]
    fn a_real_absolute_path_is_not_flagged() {
        let good = scratch("not-suspect");
        assert_eq!(
            suspect_path(&good),
            None,
            "an absolute path with an existing parent is fine"
        );
    }

    #[test]
    fn absolute_path_with_missing_parent_is_flagged() {
        let orphan = scratch("orphan")
            .with_file_name("no-such-dir")
            .join("watermarks.json");
        assert!(suspect_path(&orphan).is_some());
    }

    #[test]
    fn forget_drops_channel_state() {
        let channel = Uuid::new_v4();
        let mut store = WatermarkStore::default();
        store.record(channel, 1_000, "x");
        store.forget(&channel);

        assert!(store.is_empty());
        assert_eq!(store.since(&channel), None);
    }

    #[test]
    fn save_replaces_previous_contents_atomically() {
        let path = scratch("atomic");
        let channel = Uuid::new_v4();

        let mut first = WatermarkStore::default();
        first.record(channel, 1_000, "first");
        first.save(&path).expect("first save");

        let mut second = WatermarkStore::default();
        second.record(channel, 9_000, "second");
        second.save(&path).expect("second save");

        let loaded = WatermarkStore::load(&path);
        assert_eq!(loaded.since(&channel), Some(9_000));
        assert_eq!(loaded.all_recent_ids(), vec!["second"]);
        assert!(
            !temp_path(&path).exists(),
            "the temp file must not be left behind"
        );
    }
}
