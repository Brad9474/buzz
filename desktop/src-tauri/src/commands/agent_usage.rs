//! Per-agent token and cost rollup for the Desktop usage panel.
//!
//! Reads NIP-AM kind 44200 turn metrics from the relay, decrypts them with the
//! identity Desktop already holds, and aggregates per agent.
//!
//! # Why this lives in Rust
//!
//! The metrics are NIP-44 encrypted to their owner, so producing this view
//! requires the private key. Doing the decryption here keeps the key inside the
//! Tauri process — the webview only ever receives finished numbers, never key
//! material and never ciphertext it would need a key to read.
//!
//! The filter's `#p` is built from the caller's own pubkey, so the panel is
//! structurally incapable of showing another identity's spend. That is the same
//! guarantee the `buzz usage` CLI gives, enforced the same way.
//!
//! The accounting itself is [`buzz_core_pkg::usage_rollup`], shared with the
//! CLI so the two surfaces cannot disagree about what a turn cost.

use serde::Serialize;
use tauri::State;

use buzz_core_pkg::kind::KIND_AGENT_TURN_METRIC;
use buzz_core_pkg::usage_rollup::{entries_from_events, rollup, AgentRollup};

use crate::{app_state::AppState, relay::query_relay};

/// Relay page size for the metric query. Metrics accumulate one event per turn,
/// so a busy fleet outgrows a single page quickly.
const USAGE_PAGE_SIZE: usize = 500;

/// One agent's row in the usage panel.
///
/// `u64` token counts are serialized as JSON numbers; at plausible fleet
/// volumes they stay far below the 2^53 point where JavaScript loses integer
/// precision, so no string encoding is needed.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentUsageRow {
    pub agent_pubkey: String,
    /// Profile display name when one is published, else `None` — the frontend
    /// falls back to a short pubkey rather than showing a blank row.
    pub agent_name: Option<String>,
    pub turns: u64,
    pub sessions: u64,
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub cache_read_tokens: u64,
    pub cache_write_tokens: u64,
    pub cost_usd: f64,
    /// Turns that could not be decrypted. Non-zero means the totals are a
    /// floor, and the panel says so rather than presenting them as complete.
    pub undecryptable_turns: u64,
}

/// The panel's full payload.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentUsageReport {
    pub rows: Vec<AgentUsageRow>,
    /// Unix seconds when this was read. The panel reads live on open, so this
    /// is "just now" — surfaced so a stale window is visibly stale.
    pub generated_at: u64,
}

/// Fetch every page of a historical relay filter.
///
/// Mirrors `channels::query_relay_all`: the relay's composite
/// `(until, before_id)` cursor is used rather than a timestamp alone, because
/// more than one page of metrics can share the same second on a busy fleet.
async fn query_all(state: &AppState, mut filter: serde_json::Value) -> Result<Vec<nostr::Event>, String> {
    filter["limit"] = serde_json::json!(USAGE_PAGE_SIZE);
    let mut all = Vec::new();

    loop {
        let page = query_relay(state, &[filter.clone()]).await?;
        let done = page.len() < USAGE_PAGE_SIZE;

        if !done {
            let last = page
                .last()
                .expect("a full relay page always has a last event");
            filter["until"] = serde_json::json!(last.created_at.as_secs());
            filter["before_id"] = serde_json::json!(last.id.to_hex());
        }

        all.extend(page);
        if done {
            return Ok(all);
        }
    }
}

/// Resolve display names for the agents in `rollups`.
///
/// Best-effort: a failed profile lookup degrades to `None` and the panel shows
/// a short pubkey. The numbers are the point; the labels are a convenience, and
/// losing them must not cost the whole view.
async fn fetch_agent_names(
    state: &AppState,
    rollups: &[AgentRollup],
) -> std::collections::HashMap<String, String> {
    let mut names = std::collections::HashMap::new();
    if rollups.is_empty() {
        return names;
    }
    let authors: Vec<&str> = rollups.iter().map(|r| r.agent_pubkey.as_str()).collect();
    let filter = serde_json::json!({
        "kinds": [0],
        "authors": authors,
        "limit": authors.len(),
    });
    let Ok(events) = query_relay(state, &[filter]).await else {
        return names;
    };
    for event in events {
        let Ok(profile) = serde_json::from_str::<serde_json::Value>(&event.content) else {
            continue;
        };
        let name = profile
            .get("display_name")
            .and_then(|v| v.as_str())
            .or_else(|| profile.get("name").and_then(|v| v.as_str()))
            .unwrap_or("")
            .trim()
            .to_string();
        if !name.is_empty() {
            names.insert(event.pubkey.to_hex(), name);
        }
    }
    names
}

/// Build the per-agent usage report for the current identity.
#[tauri::command]
pub async fn agent_usage_rollup(state: State<'_, AppState>) -> Result<AgentUsageReport, String> {
    let keys = state.signing_keys()?;
    let my_pubkey = keys.public_key().to_hex();

    // `#p` is this identity's own pubkey and nothing else. The relay gates
    // kind 44200 on the reader matching this tag, so a query built any other
    // way would be rejected — and building it from our own key means the panel
    // cannot be pointed at somebody else's spend.
    let filter = serde_json::json!({
        "kinds": [KIND_AGENT_TURN_METRIC],
        "#p": [my_pubkey],
    });

    let events = query_all(&state, filter).await?;
    let entries = entries_from_events(&keys, &events);
    let rollups = rollup(&entries);
    let names = fetch_agent_names(&state, &rollups).await;

    let rows = rollups
        .into_iter()
        .map(|r| AgentUsageRow {
            agent_name: names.get(&r.agent_pubkey).cloned(),
            agent_pubkey: r.agent_pubkey,
            turns: r.turns,
            sessions: r.sessions,
            input_tokens: r.input_tokens,
            output_tokens: r.output_tokens,
            cache_read_tokens: r.cache_read_tokens,
            cache_write_tokens: r.cache_write_tokens,
            cost_usd: r.cost_usd,
            undecryptable_turns: r.undecryptable_turns,
        })
        .collect();

    Ok(AgentUsageReport {
        rows,
        generated_at: nostr::Timestamp::now().as_secs(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The webview consumes these keys by name. A rename here silently blanks
    /// a column in the panel rather than failing anywhere visible, so the wire
    /// shape is pinned.
    #[test]
    fn rows_serialize_with_the_camel_case_keys_the_panel_reads() {
        let row = AgentUsageRow {
            agent_pubkey: "abc".into(),
            agent_name: Some("Forge".into()),
            turns: 3,
            sessions: 1,
            input_tokens: 100,
            output_tokens: 20,
            cache_read_tokens: 40,
            cache_write_tokens: 5,
            cost_usd: 1.25,
            undecryptable_turns: 0,
        };
        let json = serde_json::to_value(&row).expect("serialize");
        for key in [
            "agentPubkey",
            "agentName",
            "turns",
            "sessions",
            "inputTokens",
            "outputTokens",
            "cacheReadTokens",
            "cacheWriteTokens",
            "costUsd",
            "undecryptableTurns",
        ] {
            assert!(json.get(key).is_some(), "missing `{key}` in {json}");
        }
        assert!(
            json.get("totalTokens").is_none(),
            "NIP-AM forbids a derived total; it must not appear on the wire"
        );
    }

    #[test]
    fn a_report_with_no_rows_still_serializes_cleanly() {
        let report = AgentUsageReport {
            rows: Vec::new(),
            generated_at: 1_754_000_000,
        };
        let json = serde_json::to_value(&report).expect("serialize");
        assert_eq!(json["rows"].as_array().map(Vec::len), Some(0));
        assert_eq!(json["generatedAt"].as_u64(), Some(1_754_000_000));
    }

    /// An agent with no published profile must still be identifiable in the
    /// panel, so `agentName` is nullable rather than defaulted to an empty
    /// string that would render as a blank cell.
    #[test]
    fn a_missing_display_name_serializes_as_null() {
        let row = AgentUsageRow {
            agent_pubkey: "abc".into(),
            agent_name: None,
            turns: 0,
            sessions: 0,
            input_tokens: 0,
            output_tokens: 0,
            cache_read_tokens: 0,
            cache_write_tokens: 0,
            cost_usd: 0.0,
            undecryptable_turns: 1,
        };
        let json = serde_json::to_value(&row).expect("serialize");
        assert!(json["agentName"].is_null());
    }
}
