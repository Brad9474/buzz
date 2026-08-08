//! Per-agent token and cost rollup from NIP-AM kind 44200 agent turn metrics.
//!
//! # Who can read what
//!
//! Kind 44200 is result-gated (`buzz_core::filter::reader_authorized_for_event`):
//! the reader must equal the event's `#p` tag. This module always sets `#p` to
//! the caller's *own* pubkey, so the command is structurally incapable of
//! surfacing another identity's spend — an agent running it against its own key
//! sees an empty table, not somebody else's numbers. That is the whole reason
//! the digest lives here rather than in a relay-side workflow, which never
//! holds the owner's key.
//!
//! # Why totals come from cumulative counts, not per-turn deltas
//!
//! Each payload carries both a per-turn count and a session-cumulative count.
//! Summing the per-turn figures looks like the obvious move and quietly
//! undercounts: `turn` is `None` whenever `delta_reliable` is false (every
//! goose session's first turn), and a turn whose record was dropped before
//! publishing never contributes one at all. The session-cumulative figure
//! carries those tokens regardless.
//!
//! So the rollup takes the **last** metric of each session — the one with the
//! highest `turnSeq` — reads its cumulative counts, and sums those across
//! sessions. Cumulative is per-session, never per-agent, so summing across
//! sessions is correct and summing across *turns* would multiply-count the
//! whole session on every turn.
//!
//! There is no total-tokens column: NIP-AM forbids a total derived by summing
//! categories, and no provider on either path reports an independent one.

use std::collections::HashMap;

use buzz_core::agent_turn_metric::{
    decrypt_agent_turn_metric, AgentTurnMetricPayload, TokenCounts,
};
use buzz_core::kind::KIND_AGENT_TURN_METRIC;

use crate::client::{normalize_write_response, BuzzClient};
use crate::error::CliError;
use crate::validate::parse_uuid;

/// One kind-44200 event, with its payload decrypted if that succeeded.
///
/// The `agent` tag is plaintext, so an event whose ciphertext we cannot read is
/// still attributable — it is reported as an undecryptable turn for that agent
/// rather than vanishing from the count.
#[derive(Debug, Clone)]
pub struct MetricEntry {
    /// Hex pubkey of the agent that produced the turn.
    pub agent_pubkey: String,
    /// Event `created_at`, used only to break `turnSeq` ties.
    pub created_at: u64,
    /// `None` when the event could not be decrypted or failed validation.
    pub payload: Option<AgentTurnMetricPayload>,
}

/// Rolled-up totals for a single agent.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct AgentRollup {
    pub agent_pubkey: String,
    /// Turns whose payload was read successfully.
    pub turns: u64,
    /// Distinct sessions contributing to these totals.
    pub sessions: u64,
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub cache_read_tokens: u64,
    pub cache_write_tokens: u64,
    pub cost_usd: f64,
    /// Turns attributable to this agent whose payload could not be read.
    /// Their tokens are absent from the totals above; surfaced so an
    /// undercount is visible rather than silent.
    pub undecryptable_turns: u64,
}

/// Fold metric entries into one rollup per agent, ordered by cost descending
/// (ties broken by pubkey so the output is stable).
///
/// Pure over its input so the accounting can be tested without a relay or any
/// key material.
pub fn rollup(entries: &[MetricEntry]) -> Vec<AgentRollup> {
    // agent -> session key -> that session's metrics
    let mut by_agent: HashMap<&str, HashMap<String, Vec<&MetricEntry>>> = HashMap::new();
    let mut undecryptable: HashMap<&str, u64> = HashMap::new();

    for entry in entries {
        match &entry.payload {
            None => {
                *undecryptable.entry(&entry.agent_pubkey).or_default() += 1;
            }
            Some(payload) => {
                // A payload without a session id cannot be grouped with
                // anything, so it becomes its own session. Keying on the turn
                // id keeps two such payloads from colliding and silently
                // discarding one.
                let key = payload.session_id.clone().unwrap_or_else(|| {
                    format!(
                        "\u{0}orphan:{}:{}",
                        payload.turn_id.as_deref().unwrap_or(""),
                        entry.created_at
                    )
                });
                by_agent
                    .entry(&entry.agent_pubkey)
                    .or_default()
                    .entry(key)
                    .or_default()
                    .push(entry);
            }
        }
    }

    let mut rollups: Vec<AgentRollup> = Vec::new();
    let agents: std::collections::BTreeSet<&str> = by_agent
        .keys()
        .copied()
        .chain(undecryptable.keys().copied())
        .collect();

    for agent in agents {
        let mut out = AgentRollup {
            agent_pubkey: agent.to_string(),
            undecryptable_turns: undecryptable.get(agent).copied().unwrap_or(0),
            ..Default::default()
        };

        if let Some(sessions) = by_agent.get(agent) {
            out.sessions = sessions.len() as u64;
            for turns in sessions.values() {
                out.turns += turns.len() as u64;
                accumulate_session(&mut out, turns);
            }
        }
        rollups.push(out);
    }

    rollups.sort_by(|a, b| {
        b.cost_usd
            .partial_cmp(&a.cost_usd)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| a.agent_pubkey.cmp(&b.agent_pubkey))
    });
    rollups
}

/// Add one session's totals to `out`.
///
/// Prefers the cumulative counts on the session's final metric. Falls back to
/// summing per-turn counts only when that metric carries no cumulative block at
/// all — a shape our own publisher never emits, but the field is optional in
/// NIP-AM and silently contributing zero would be worse than an approximation.
fn accumulate_session(out: &mut AgentRollup, turns: &[&MetricEntry]) {
    let last = turns
        .iter()
        .filter_map(|e| e.payload.as_ref().map(|p| (p, e.created_at)))
        .max_by_key(|(p, created_at)| (p.turn_seq.unwrap_or(0), *created_at));

    match last.and_then(|(p, _)| p.cumulative.as_ref()) {
        Some(counts) => add_counts(out, counts),
        None => {
            for entry in turns {
                if let Some(counts) = entry.payload.as_ref().and_then(|p| p.turn.as_ref()) {
                    add_counts(out, counts);
                }
            }
        }
    }
}

fn add_counts(out: &mut AgentRollup, counts: &TokenCounts) {
    out.input_tokens = out
        .input_tokens
        .saturating_add(counts.input_tokens.unwrap_or(0));
    out.output_tokens = out
        .output_tokens
        .saturating_add(counts.output_tokens.unwrap_or(0));
    out.cache_read_tokens = out
        .cache_read_tokens
        .saturating_add(counts.cache_read_tokens.unwrap_or(0));
    out.cache_write_tokens = out
        .cache_write_tokens
        .saturating_add(counts.cache_write_tokens.unwrap_or(0));
    // `validate()` has already rejected negative and non-finite costs, so this
    // cannot poison the total.
    out.cost_usd += counts.cost_usd.unwrap_or(0.0);
}

/// Format an integer with thousands separators.
fn thousands(n: u64) -> String {
    let digits = n.to_string();
    let mut out = String::with_capacity(digits.len() + digits.len() / 3);
    for (i, c) in digits.chars().enumerate() {
        if i > 0 && (digits.len() - i).is_multiple_of(3) {
            out.push(',');
        }
        out.push(c);
    }
    out
}

/// Shorten a hex pubkey for display when no profile name is known.
fn short_pubkey(hex: &str) -> String {
    hex.chars().take(8).collect()
}

/// Make a profile display name safe to drop into a Markdown table cell.
///
/// Display names are attacker-controlled in the weak sense that each agent
/// writes its own profile: a name containing a pipe would split the row into
/// extra columns, and a newline would end the table early and swallow every
/// agent below it. Escape the pipe, flatten the whitespace, and cap the length
/// so one bad profile cannot wreck the whole digest.
fn sanitize_name(name: &str) -> String {
    let flattened: String = name
        .chars()
        .map(|c| if c.is_whitespace() { ' ' } else { c })
        .collect();
    let escaped = flattened.replace('|', "\\|");
    let trimmed = escaped.trim();
    if trimmed.chars().count() > 40 {
        let head: String = trimmed.chars().take(39).collect();
        format!("{head}…")
    } else {
        trimmed.to_string()
    }
}

/// Render the rollup as a Markdown table.
///
/// `names` maps agent pubkey to display name; missing entries fall back to a
/// short hex prefix so an agent without a profile still appears.
pub fn render_markdown(
    rollups: &[AgentRollup],
    names: &HashMap<String, String>,
    generated_at: &str,
) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "**Agent usage — cumulative, as of {generated_at}**\n\n"
    ));

    if rollups.is_empty() {
        out.push_str(
            "No agent turn metrics found. Either no turns have been recorded yet, \
             or turn-usage capture is not live on the fleet.\n",
        );
        return out;
    }

    out.push_str("| Agent | Turns | Input | Output | Cache read | Cache write | Cost (USD) |\n");
    out.push_str("|---|--:|--:|--:|--:|--:|--:|\n");

    let mut total = AgentRollup::default();
    for r in rollups {
        let name = names
            .get(&r.agent_pubkey)
            .map(|n| sanitize_name(n))
            .filter(|n| !n.is_empty())
            .unwrap_or_else(|| short_pubkey(&r.agent_pubkey));
        out.push_str(&format!(
            "| {} | {} | {} | {} | {} | {} | ${:.2} |\n",
            name,
            thousands(r.turns),
            thousands(r.input_tokens),
            thousands(r.output_tokens),
            thousands(r.cache_read_tokens),
            thousands(r.cache_write_tokens),
            r.cost_usd,
        ));
        total.turns += r.turns;
        total.input_tokens += r.input_tokens;
        total.output_tokens += r.output_tokens;
        total.cache_read_tokens += r.cache_read_tokens;
        total.cache_write_tokens += r.cache_write_tokens;
        total.cost_usd += r.cost_usd;
        total.undecryptable_turns += r.undecryptable_turns;
    }

    out.push_str(&format!(
        "| **Total** | **{}** | **{}** | **{}** | **{}** | **{}** | **${:.2}** |\n",
        thousands(total.turns),
        thousands(total.input_tokens),
        thousands(total.output_tokens),
        thousands(total.cache_read_tokens),
        thousands(total.cache_write_tokens),
        total.cost_usd,
    ));

    out.push_str(&format!(
        "\nInput is cache-inclusive: cache-read and cache-write tokens are \
         subsets of it, broken out because they bill at different rates. \
         {} sessions.\n",
        thousands(rollups.iter().map(|r| r.sessions).sum::<u64>()),
    ));

    if total.undecryptable_turns > 0 {
        out.push_str(&format!(
            "\n⚠️ {} turn(s) could not be decrypted and are excluded from the \
             totals above — the figures are a floor, not a complete count.\n",
            thousands(total.undecryptable_turns),
        ));
    }
    out
}

/// Fetch every kind-44200 metric addressed to the caller and decrypt what it can.
async fn fetch_entries(
    client: &BuzzClient,
    since: Option<i64>,
) -> Result<Vec<MetricEntry>, CliError> {
    let my_pk = client.keys().public_key().to_hex();
    let mut filter = serde_json::json!({
        "kinds": [KIND_AGENT_TURN_METRIC],
        "#p": [my_pk],
    });
    if let Some(s) = since {
        filter["since"] = serde_json::json!(s);
    }

    let raw = client.query_all(filter).await?;
    Ok(entries_from_events(client.keys(), &raw))
}

/// Convert raw relay events into [`MetricEntry`] values, decrypting each with
/// `keys`.
///
/// Split from [`fetch_entries`] so the decrypt-and-attribute step can be tested
/// against genuinely encrypted events rather than hand-built structs — the HTTP
/// call is the only part left untested.
fn entries_from_events(keys: &nostr::Keys, raw: &[serde_json::Value]) -> Vec<MetricEntry> {
    let mut entries = Vec::with_capacity(raw.len());
    for value in raw {
        let Ok(event) = serde_json::from_value::<nostr::Event>(value.clone()) else {
            // Not a well-formed event: nothing to attribute it to, so it cannot
            // even be counted as an undecryptable turn.
            continue;
        };
        // The `agent` tag is the publisher's own identity; fall back to the
        // event author, which is the same key in every event we publish.
        let agent_pubkey = crate::client::extract_tag_value(value, "agent");
        let agent_pubkey = if agent_pubkey.is_empty() {
            event.pubkey.to_hex()
        } else {
            agent_pubkey
        };
        let payload = decrypt_agent_turn_metric(keys, &event).ok();
        entries.push(MetricEntry {
            agent_pubkey,
            created_at: event.created_at.as_secs(),
            payload,
        });
    }
    entries
}

/// Resolve display names for the agents present in the rollup.
///
/// Best-effort: a profile lookup failure degrades to hex prefixes rather than
/// failing the whole command, because the numbers are the point and the labels
/// are a convenience.
async fn fetch_agent_names(
    client: &BuzzClient,
    rollups: &[AgentRollup],
) -> HashMap<String, String> {
    let mut names = HashMap::new();
    if rollups.is_empty() {
        return names;
    }
    let authors: Vec<&str> = rollups.iter().map(|r| r.agent_pubkey.as_str()).collect();
    let filter = serde_json::json!({
        "kinds": [0],
        "authors": authors,
        "limit": authors.len(),
    });
    let Ok(resp) = client.query(&filter).await else {
        return names;
    };
    let events: Vec<serde_json::Value> = serde_json::from_str(&resp).unwrap_or_default();
    for ev in events {
        let Some(pk) = ev.get("pubkey").and_then(|v| v.as_str()) else {
            continue;
        };
        let content = ev.get("content").and_then(|v| v.as_str()).unwrap_or("");
        let Ok(profile) = serde_json::from_str::<serde_json::Value>(content) else {
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
            names.insert(pk.to_string(), name);
        }
    }
    names
}

fn now_rfc3339() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

/// Build the rollup and print it — Markdown by default, JSON on `--format json`.
pub async fn cmd_usage_summary(
    client: &BuzzClient,
    since: Option<i64>,
    format: &crate::OutputFormat,
) -> Result<(), CliError> {
    let entries = fetch_entries(client, since).await?;
    let rollups = rollup(&entries);
    let names = fetch_agent_names(client, &rollups).await;

    match format {
        crate::OutputFormat::Json => {
            let rows: Vec<serde_json::Value> = rollups
                .iter()
                .map(|r| {
                    serde_json::json!({
                        "agent_pubkey": r.agent_pubkey,
                        "agent_name": names.get(&r.agent_pubkey),
                        "turns": r.turns,
                        "sessions": r.sessions,
                        "input_tokens": r.input_tokens,
                        "output_tokens": r.output_tokens,
                        "cache_read_tokens": r.cache_read_tokens,
                        "cache_write_tokens": r.cache_write_tokens,
                        "cost_usd": r.cost_usd,
                        "undecryptable_turns": r.undecryptable_turns,
                    })
                })
                .collect();
            println!(
                "{}",
                serde_json::json!({
                    "generated_at": now_rfc3339(),
                    "basis": "cumulative",
                    "agents": rows,
                })
            );
        }
        crate::OutputFormat::Compact => {
            print!("{}", render_markdown(&rollups, &names, &now_rfc3339()));
        }
    }
    Ok(())
}

/// Build the rollup and post it into `channel_id`.
pub async fn cmd_usage_digest(
    client: &BuzzClient,
    channel_id: &str,
    since: Option<i64>,
) -> Result<(), CliError> {
    let channel_uuid = parse_uuid(channel_id)?;
    let entries = fetch_entries(client, since).await?;
    let rollups = rollup(&entries);
    let names = fetch_agent_names(client, &rollups).await;
    let content = render_markdown(&rollups, &names, &now_rfc3339());

    let builder = buzz_sdk::build_message(channel_uuid, &content, None, &[], false, &[])
        .map_err(|e| CliError::Other(format!("build_message failed: {e}")))?;
    let event = client.sign_event(builder)?;
    let resp = client.submit_event(event).await?;
    let mut output: serde_json::Value = serde_json::from_str(&normalize_write_response(&resp))
        .unwrap_or_else(|_| serde_json::json!({ "response": resp }));
    if let Some(object) = output.as_object_mut() {
        object.insert("agents".into(), serde_json::json!(rollups.len()));
    }
    println!("{output}");
    Ok(())
}

pub async fn dispatch(
    cmd: crate::UsageCmd,
    client: &BuzzClient,
    format: &crate::OutputFormat,
) -> Result<(), CliError> {
    use crate::UsageCmd;
    match cmd {
        UsageCmd::Summary { since } => cmd_usage_summary(client, since, format).await,
        UsageCmd::Digest { channel, since } => cmd_usage_digest(client, &channel, since).await,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn counts(input: u64, output: u64, read: u64, write: u64, cost: f64) -> TokenCounts {
        TokenCounts {
            input_tokens: Some(input),
            output_tokens: Some(output),
            total_tokens: None,
            cost_usd: Some(cost),
            cache_read_tokens: Some(read),
            cache_write_tokens: Some(write),
        }
    }

    fn entry(
        agent: &str,
        session: Option<&str>,
        turn_seq: u64,
        turn: Option<TokenCounts>,
        cumulative: Option<TokenCounts>,
    ) -> MetricEntry {
        MetricEntry {
            agent_pubkey: agent.to_string(),
            created_at: 1_000 + turn_seq,
            payload: Some(AgentTurnMetricPayload {
                harness: "claude".to_string(),
                model: None,
                channel_id: None,
                session_id: session.map(str::to_string),
                turn_id: Some(format!("turn-{turn_seq}")),
                turn_seq: Some(turn_seq),
                timestamp: "2026-08-08T00:00:00.000Z".to_string(),
                turn,
                cumulative,
                delta_reliable: true,
                stop_reason: None,
            }),
        }
    }

    /// The core accounting rule: cumulative counts are per-session running
    /// totals, so a session contributes its final metric once — not once per
    /// turn. Getting this wrong inflates every figure by roughly the turn count.
    #[test]
    fn a_session_contributes_its_final_cumulative_once() {
        let entries = vec![
            entry(
                "a",
                Some("s1"),
                1,
                Some(counts(100, 10, 0, 0, 0.01)),
                Some(counts(100, 10, 0, 0, 0.01)),
            ),
            entry(
                "a",
                Some("s1"),
                2,
                Some(counts(200, 20, 0, 0, 0.02)),
                Some(counts(300, 30, 0, 0, 0.03)),
            ),
            entry(
                "a",
                Some("s1"),
                3,
                Some(counts(150, 15, 0, 0, 0.015)),
                Some(counts(450, 45, 0, 0, 0.045)),
            ),
        ];
        let out = rollup(&entries);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].turns, 3);
        assert_eq!(out[0].sessions, 1);
        assert_eq!(
            out[0].input_tokens, 450,
            "final cumulative, not the sum of all three"
        );
        assert_eq!(out[0].output_tokens, 45);
        assert!((out[0].cost_usd - 0.045).abs() < 1e-9);
    }

    /// Out-of-order arrival must not change the answer — the highest turnSeq
    /// wins, not the last one seen.
    #[test]
    fn the_highest_turn_seq_wins_regardless_of_order() {
        let entries = vec![
            entry("a", Some("s1"), 3, None, Some(counts(450, 45, 0, 0, 0.045))),
            entry("a", Some("s1"), 1, None, Some(counts(100, 10, 0, 0, 0.01))),
            entry("a", Some("s1"), 2, None, Some(counts(300, 30, 0, 0, 0.03))),
        ];
        let out = rollup(&entries);
        assert_eq!(out[0].input_tokens, 450);
    }

    #[test]
    fn sessions_sum_but_agents_stay_separate() {
        let entries = vec![
            entry("a", Some("s1"), 1, None, Some(counts(100, 10, 5, 1, 0.01))),
            entry("a", Some("s2"), 1, None, Some(counts(200, 20, 7, 2, 0.02))),
            entry("b", Some("s3"), 1, None, Some(counts(50, 5, 0, 0, 0.005))),
        ];
        let out = rollup(&entries);
        assert_eq!(out.len(), 2);
        let a = out.iter().find(|r| r.agent_pubkey == "a").expect("agent a");
        assert_eq!(a.sessions, 2);
        assert_eq!(a.input_tokens, 300);
        assert_eq!(a.cache_read_tokens, 12);
        assert_eq!(a.cache_write_tokens, 3);
        let b = out.iter().find(|r| r.agent_pubkey == "b").expect("agent b");
        assert_eq!(b.input_tokens, 50);
    }

    /// A goose first turn has `turn: None` but a populated cumulative. Reading
    /// per-turn counts would drop it; reading cumulative keeps it.
    #[test]
    fn a_turn_with_no_per_turn_delta_still_counts() {
        let entries = vec![entry(
            "a",
            Some("s1"),
            1,
            None,
            Some(counts(1_000, 200, 0, 0, 0.05)),
        )];
        let out = rollup(&entries);
        assert_eq!(out[0].input_tokens, 1_000);
        assert!((out[0].cost_usd - 0.05).abs() < 1e-9);
    }

    /// Cumulative is optional in NIP-AM. When it is genuinely absent the
    /// fallback sums per-turn counts rather than contributing nothing.
    #[test]
    fn missing_cumulative_falls_back_to_summing_turns() {
        let entries = vec![
            entry("a", Some("s1"), 1, Some(counts(100, 10, 0, 0, 0.01)), None),
            entry("a", Some("s1"), 2, Some(counts(200, 20, 0, 0, 0.02)), None),
        ];
        let out = rollup(&entries);
        assert_eq!(out[0].input_tokens, 300);
        assert!((out[0].cost_usd - 0.03).abs() < 1e-9);
    }

    /// Two payloads with no session id must not collide into one bucket and
    /// lose a turn.
    #[test]
    fn payloads_without_a_session_id_are_counted_separately() {
        let entries = vec![
            entry("a", None, 1, None, Some(counts(100, 10, 0, 0, 0.01))),
            entry("a", None, 2, None, Some(counts(200, 20, 0, 0, 0.02))),
        ];
        let out = rollup(&entries);
        assert_eq!(out[0].turns, 2);
        assert_eq!(out[0].sessions, 2);
        assert_eq!(out[0].input_tokens, 300);
    }

    /// An unreadable payload is still a turn that happened. It must surface as
    /// an explicit exclusion, not disappear into a total that looks complete.
    #[test]
    fn undecryptable_turns_are_reported_not_swallowed() {
        let entries = vec![
            entry("a", Some("s1"), 1, None, Some(counts(100, 10, 0, 0, 0.01))),
            MetricEntry {
                agent_pubkey: "a".to_string(),
                created_at: 1_002,
                payload: None,
            },
        ];
        let out = rollup(&entries);
        assert_eq!(out[0].turns, 1, "only readable turns feed the totals");
        assert_eq!(out[0].undecryptable_turns, 1);

        let md = render_markdown(&out, &HashMap::new(), "2026-08-08T00:00:00Z");
        assert!(
            md.contains("could not be decrypted"),
            "the exclusion must be visible in the rendered digest:\n{md}"
        );
    }

    /// An agent whose every turn is unreadable must still appear, or it would
    /// look like it had simply been idle.
    #[test]
    fn an_agent_with_only_undecryptable_turns_still_appears() {
        let entries = vec![MetricEntry {
            agent_pubkey: "ghost".to_string(),
            created_at: 1_000,
            payload: None,
        }];
        let out = rollup(&entries);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].agent_pubkey, "ghost");
        assert_eq!(out[0].turns, 0);
        assert_eq!(out[0].undecryptable_turns, 1);
    }

    #[test]
    fn rollups_are_ordered_by_cost_descending() {
        let entries = vec![
            entry(
                "cheap",
                Some("s1"),
                1,
                None,
                Some(counts(10, 1, 0, 0, 0.001)),
            ),
            entry("dear", Some("s2"), 1, None, Some(counts(10, 1, 0, 0, 5.0))),
            entry("mid", Some("s3"), 1, None, Some(counts(10, 1, 0, 0, 1.0))),
        ];
        let out = rollup(&entries);
        let order: Vec<&str> = out.iter().map(|r| r.agent_pubkey.as_str()).collect();
        assert_eq!(order, vec!["dear", "mid", "cheap"]);
    }

    #[test]
    fn empty_input_renders_an_explanation_not_an_empty_table() {
        let md = render_markdown(&[], &HashMap::new(), "2026-08-08T00:00:00Z");
        assert!(md.contains("No agent turn metrics found"));
        assert!(!md.contains("| Agent |"));
    }

    #[test]
    fn the_table_totals_every_column() {
        let entries = vec![
            entry("a", Some("s1"), 1, None, Some(counts(100, 10, 5, 1, 1.5))),
            entry("b", Some("s2"), 1, None, Some(counts(200, 20, 7, 2, 2.25))),
        ];
        let out = rollup(&entries);
        let md = render_markdown(&out, &HashMap::new(), "2026-08-08T00:00:00Z");
        assert!(md.contains("**300**"), "input total missing:\n{md}");
        assert!(md.contains("**30**"), "output total missing:\n{md}");
        assert!(md.contains("**$3.75**"), "cost total missing:\n{md}");
    }

    #[test]
    fn display_names_replace_hex_when_known() {
        let entries = vec![entry(
            "abcdef0123456789",
            Some("s1"),
            1,
            None,
            Some(counts(1, 1, 0, 0, 0.0)),
        )];
        let out = rollup(&entries);

        let bare = render_markdown(&out, &HashMap::new(), "t");
        assert!(
            bare.contains("| abcdef01 |"),
            "hex fallback missing:\n{bare}"
        );

        let mut names = HashMap::new();
        names.insert("abcdef0123456789".to_string(), "Forge".to_string());
        let named = render_markdown(&out, &names, "t");
        assert!(
            named.contains("| Forge |"),
            "display name missing:\n{named}"
        );
    }

    // ── Real crypto: a signed, encrypted event all the way to a rollup ─────

    /// Build a real kind-44200 event: NIP-AM payload, NIP-44 encrypted to
    /// `owner`, signed by `agent`, tagged the way `publish_agent_turn_metric`
    /// tags it.
    fn signed_metric_event(
        agent: &nostr::Keys,
        owner: &nostr::PublicKey,
        session: &str,
        turn_seq: u64,
        cumulative: TokenCounts,
    ) -> serde_json::Value {
        use nostr::{EventBuilder, Kind, Tag};

        let payload = AgentTurnMetricPayload {
            harness: "claude".to_string(),
            model: None,
            channel_id: None,
            session_id: Some(session.to_string()),
            turn_id: Some(format!("turn-{turn_seq}")),
            turn_seq: Some(turn_seq),
            timestamp: "2026-08-08T00:00:00.000Z".to_string(),
            turn: None,
            cumulative: Some(cumulative),
            delta_reliable: true,
            stop_reason: None,
        };
        let ciphertext =
            buzz_core::agent_turn_metric::encrypt_agent_turn_metric(agent, owner, &payload)
                .expect("encrypt");
        let event = EventBuilder::new(Kind::Custom(KIND_AGENT_TURN_METRIC as u16), ciphertext)
            .tags([
                Tag::parse(["p", &owner.to_hex()]).expect("p tag"),
                Tag::parse(["agent", &agent.public_key().to_hex()]).expect("agent tag"),
            ])
            .sign_with_keys(agent)
            .expect("sign");
        serde_json::to_value(event).expect("event to json")
    }

    #[test]
    fn genuinely_encrypted_events_decrypt_and_roll_up() {
        let agent = nostr::Keys::generate();
        let owner = nostr::Keys::generate();

        let raw = vec![
            signed_metric_event(
                &agent,
                &owner.public_key(),
                "s1",
                1,
                counts(100, 10, 40, 5, 0.01),
            ),
            signed_metric_event(
                &agent,
                &owner.public_key(),
                "s1",
                2,
                counts(300, 30, 120, 9, 0.04),
            ),
        ];

        let entries = entries_from_events(&owner, &raw);
        assert_eq!(entries.len(), 2);
        assert!(
            entries.iter().all(|e| e.payload.is_some()),
            "the owner's key must decrypt its own metrics"
        );
        assert_eq!(entries[0].agent_pubkey, agent.public_key().to_hex());

        let out = rollup(&entries);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].turns, 2);
        assert_eq!(out[0].input_tokens, 300, "session cumulative, not 100+300");
        assert_eq!(out[0].cache_read_tokens, 120);
        assert!((out[0].cost_usd - 0.04).abs() < 1e-9);
    }

    /// The gate that makes this command safe to ship in a shared CLI: another
    /// identity's metrics are unreadable even when the events are handed
    /// straight to it, with no relay in the way.
    #[test]
    fn another_identity_cannot_decrypt_the_owners_metrics() {
        let agent = nostr::Keys::generate();
        let owner = nostr::Keys::generate();
        let eavesdropper = nostr::Keys::generate();

        let raw = vec![signed_metric_event(
            &agent,
            &owner.public_key(),
            "s1",
            1,
            counts(100, 10, 0, 0, 0.01),
        )];

        let entries = entries_from_events(&eavesdropper, &raw);
        assert_eq!(entries.len(), 1);
        assert!(
            entries[0].payload.is_none(),
            "a non-owner must never read the plaintext"
        );

        let out = rollup(&entries);
        assert_eq!(out[0].turns, 0, "no readable turns");
        assert_eq!(out[0].undecryptable_turns, 1);
        assert_eq!(out[0].cost_usd, 0.0);
    }

    #[test]
    fn malformed_events_are_skipped_without_panicking() {
        let owner = nostr::Keys::generate();
        let raw = vec![
            serde_json::json!({"not": "an event"}),
            serde_json::json!(null),
        ];
        assert!(entries_from_events(&owner, &raw).is_empty());
    }

    /// A profile name is written by the agent itself. A pipe would add phantom
    /// columns and a newline would truncate the table, hiding every agent below
    /// it — so one careless profile must not be able to break the digest.
    #[test]
    fn hostile_display_names_cannot_break_the_table() {
        let entries = vec![
            entry("a", Some("s1"), 1, None, Some(counts(100, 10, 0, 0, 1.0))),
            entry("b", Some("s2"), 1, None, Some(counts(200, 20, 0, 0, 0.5))),
        ];
        let out = rollup(&entries);

        let mut names = HashMap::new();
        names.insert(
            "a".to_string(),
            "Evil | Agent\n| **Total** | 0 |".to_string(),
        );
        names.insert("b".to_string(), "Benign".to_string());
        let md = render_markdown(&out, &names, "t");

        assert!(!md.contains("Evil | Agent"), "pipe must be escaped:\n{md}");
        assert!(md.contains("Evil \\| Agent"), "escaped name missing:\n{md}");
        assert!(
            md.contains("| Benign |"),
            "the agent below the hostile name must survive:\n{md}"
        );
        // Header, separator, two agents, total — the row count is unchanged.
        assert_eq!(
            md.lines().filter(|l| l.starts_with('|')).count(),
            5,
            "row count changed, so the table shape was altered:\n{md}"
        );
    }

    #[test]
    fn sanitize_name_flattens_trims_and_caps() {
        assert_eq!(sanitize_name("  Forge  "), "Forge");
        assert_eq!(sanitize_name("Forge\nBot"), "Forge Bot");
        assert_eq!(sanitize_name("a|b"), "a\\|b");
        let long = "x".repeat(80);
        let capped = sanitize_name(&long);
        assert_eq!(capped.chars().count(), 40);
        assert!(capped.ends_with('…'));
    }

    /// A profile whose name is only whitespace must fall back to the hex
    /// prefix rather than rendering a blank, unattributable row.
    #[test]
    fn a_blank_display_name_falls_back_to_hex() {
        let entries = vec![entry(
            "abcdef0123456789",
            Some("s1"),
            1,
            None,
            Some(counts(1, 1, 0, 0, 0.0)),
        )];
        let out = rollup(&entries);
        let mut names = HashMap::new();
        names.insert("abcdef0123456789".to_string(), "   ".to_string());
        let md = render_markdown(&out, &names, "t");
        assert!(md.contains("| abcdef01 |"), "hex fallback missing:\n{md}");
    }

    #[test]
    fn thousands_separates_correctly() {
        assert_eq!(thousands(0), "0");
        assert_eq!(thousands(999), "999");
        assert_eq!(thousands(1_000), "1,000");
        assert_eq!(thousands(12_345), "12,345");
        assert_eq!(thousands(1_234_567), "1,234,567");
    }
}
