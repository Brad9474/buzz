//! `buzz usage` — per-agent token and cost rollup, rendered for a terminal or
//! posted into a channel.
//!
//! The accounting itself lives in [`buzz_core::usage_rollup`], shared with Buzz
//! Desktop's usage panel so the two surfaces can never disagree about what a
//! turn cost. What remains here is the CLI's own concerns: fetching, resolving
//! display names, Markdown rendering, and the two subcommands.
//!
//! # Who can read what
//!
//! Kind 44200 is result-gated (`buzz_core::filter::reader_authorized_for_event`):
//! the reader must equal the event's `#p` tag. This module always sets `#p` to
//! the caller's *own* pubkey, so the command is structurally incapable of
//! surfacing another identity's spend — an agent running it against its own key
//! sees an empty table, not somebody else's numbers. That is the whole reason
//! this is a local command rather than a relay-side workflow, which never holds
//! the owner's key.

use std::collections::HashMap;

use buzz_core::kind::KIND_AGENT_TURN_METRIC;
use buzz_core::usage_rollup::{entries_from_events, rollup, AgentRollup};

use crate::client::{normalize_write_response, BuzzClient};
use crate::error::CliError;
use crate::validate::parse_uuid;

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
) -> Result<Vec<buzz_core::usage_rollup::MetricEntry>, CliError> {
    let my_pk = client.keys().public_key().to_hex();
    let mut filter = serde_json::json!({
        "kinds": [KIND_AGENT_TURN_METRIC],
        "#p": [my_pk],
    });
    if let Some(s) = since {
        filter["since"] = serde_json::json!(s);
    }

    let raw = client.query_all(filter).await?;
    // A value that will not parse as an event has no `agent` tag to attribute
    // it to, so it cannot even be reported as an undecryptable turn — dropping
    // it is the only honest option.
    let events: Vec<nostr::Event> = raw
        .into_iter()
        .filter_map(|value| serde_json::from_value(value).ok())
        .collect();
    Ok(entries_from_events(client.keys(), &events))
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
    use buzz_core::agent_turn_metric::{AgentTurnMetricPayload, TokenCounts};
    use buzz_core::usage_rollup::MetricEntry;

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
