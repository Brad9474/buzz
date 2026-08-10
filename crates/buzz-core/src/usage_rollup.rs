//! Per-agent token and cost accounting over NIP-AM kind 44200 turn metrics.
//!
//! Shared by every surface that reports agent spend — the `buzz usage` CLI and
//! Buzz Desktop's usage panel both call [`rollup`]. It lives here rather than
//! in either caller because two independent implementations of this arithmetic
//! would eventually disagree, and the failure mode is two plausible-looking
//! totals with no way to tell which is wrong.
//!
//! # Who can read what
//!
//! Kind 44200 is result-gated ([`crate::filter::reader_authorized_for_event`]):
//! the reader must equal the event's `#p` tag. Callers are expected to build
//! their filter from their *own* pubkey, which makes surfacing another
//! identity's spend structurally impossible rather than merely disallowed.
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

use nostr::{Event, Keys};

use crate::agent_turn_metric::{decrypt_agent_turn_metric, AgentTurnMetricPayload, TokenCounts};

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
    /// Hex pubkey of the agent these totals belong to.
    pub agent_pubkey: String,
    /// Turns whose payload was read successfully.
    pub turns: u64,
    /// Distinct sessions contributing to these totals.
    pub sessions: u64,
    /// Input tokens, inclusive of the cache figures below (NIP-AM's definition).
    pub input_tokens: u64,
    /// Output tokens.
    pub output_tokens: u64,
    /// Cache-read tokens — a subset of `input_tokens`, billed at a lower rate.
    pub cache_read_tokens: u64,
    /// Cache-write tokens — a subset of `input_tokens`.
    pub cache_write_tokens: u64,
    /// Provider-reported cost in USD, summed across sessions.
    pub cost_usd: f64,
    /// Turns attributable to this agent whose payload could not be read.
    /// Their tokens are absent from the totals above; surfaced so an
    /// undercount is visible rather than silent.
    pub undecryptable_turns: u64,
}

/// Read the `agent` tag from a kind-44200 event, falling back to the event
/// author.
///
/// `publish_agent_turn_metric` signs with the agent's own key and tags the same
/// pubkey, so the fallback and the tag agree for everything we publish. The tag
/// is preferred anyway: it survives a future change of signer.
fn agent_pubkey_of(event: &Event) -> String {
    event
        .tags
        .iter()
        .find_map(|tag| {
            let slice = tag.as_slice();
            match slice.first().map(String::as_str) {
                Some("agent") => slice.get(1).filter(|v| !v.is_empty()).cloned(),
                _ => None,
            }
        })
        .unwrap_or_else(|| event.pubkey.to_hex())
}

/// Decrypt a batch of kind-44200 events into [`MetricEntry`] values.
///
/// Events that fail to decrypt keep their attribution and are surfaced as
/// undecryptable turns rather than dropped — see [`AgentRollup`].
pub fn entries_from_events(keys: &Keys, events: &[Event]) -> Vec<MetricEntry> {
    events
        .iter()
        .map(|event| MetricEntry {
            agent_pubkey: agent_pubkey_of(event),
            created_at: event.created_at.as_secs(),
            payload: decrypt_agent_turn_metric(keys, event).ok(),
        })
        .collect()
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

    /// An unreadable payload is still a turn that happened. It must be counted
    /// separately rather than disappearing into a total that looks complete.
    #[test]
    fn undecryptable_turns_are_counted_not_swallowed() {
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

    // ── Real crypto: signed, encrypted events all the way to a rollup ──────

    /// Build a real kind-44200 event: NIP-AM payload, NIP-44 encrypted to
    /// `owner`, signed by `agent`, tagged the way `publish_agent_turn_metric`
    /// tags it.
    fn signed_metric_event(
        agent: &Keys,
        owner: &nostr::PublicKey,
        session: &str,
        turn_seq: u64,
        cumulative: TokenCounts,
    ) -> Event {
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
            crate::agent_turn_metric::encrypt_agent_turn_metric(agent, owner, &payload)
                .expect("encrypt");
        EventBuilder::new(
            Kind::Custom(crate::kind::KIND_AGENT_TURN_METRIC as u16),
            ciphertext,
        )
        .tags([
            Tag::parse(["p", &owner.to_hex()]).expect("p tag"),
            Tag::parse(["agent", &agent.public_key().to_hex()]).expect("agent tag"),
        ])
        .sign_with_keys(agent)
        .expect("sign")
    }

    #[test]
    fn genuinely_encrypted_events_decrypt_and_roll_up() {
        let agent = Keys::generate();
        let owner = Keys::generate();

        let events = vec![
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

        let entries = entries_from_events(&owner, &events);
        assert_eq!(entries.len(), 2);
        assert!(
            entries.iter().all(|e| e.payload.is_some()),
            "the owner's key must decrypt its own metrics"
        );
        assert_eq!(
            entries[0].agent_pubkey,
            agent.public_key().to_hex(),
            "attribution must come from the `agent` tag"
        );

        let out = rollup(&entries);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].turns, 2);
        assert_eq!(out[0].input_tokens, 300, "session cumulative, not 100+300");
        assert_eq!(out[0].cache_read_tokens, 120);
        assert!((out[0].cost_usd - 0.04).abs() < 1e-9);
    }

    /// The gate the whole design rests on: another identity's metrics stay
    /// unreadable even when the events are handed straight over with no relay
    /// in the way.
    #[test]
    fn another_identity_cannot_decrypt_the_owners_metrics() {
        let agent = Keys::generate();
        let owner = Keys::generate();
        let eavesdropper = Keys::generate();

        let events = vec![signed_metric_event(
            &agent,
            &owner.public_key(),
            "s1",
            1,
            counts(100, 10, 0, 0, 0.01),
        )];

        let entries = entries_from_events(&eavesdropper, &events);
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

    /// An event with no `agent` tag still has to land somewhere, or a publisher
    /// change would silently drop turns from the ledger.
    #[test]
    fn an_event_without_an_agent_tag_falls_back_to_the_author() {
        use nostr::{EventBuilder, Kind, Tag};
        let agent = Keys::generate();
        let owner = Keys::generate();
        let payload = AgentTurnMetricPayload {
            harness: "claude".to_string(),
            model: None,
            channel_id: None,
            session_id: Some("s1".to_string()),
            turn_id: Some("turn-1".to_string()),
            turn_seq: Some(1),
            timestamp: "2026-08-08T00:00:00.000Z".to_string(),
            turn: None,
            cumulative: Some(counts(10, 1, 0, 0, 0.001)),
            delta_reliable: true,
            stop_reason: None,
        };
        let ciphertext = crate::agent_turn_metric::encrypt_agent_turn_metric(
            &agent,
            &owner.public_key(),
            &payload,
        )
        .expect("encrypt");
        let event = EventBuilder::new(
            Kind::Custom(crate::kind::KIND_AGENT_TURN_METRIC as u16),
            ciphertext,
        )
        .tags([Tag::parse(["p", &owner.public_key().to_hex()]).expect("p tag")])
        .sign_with_keys(&agent)
        .expect("sign");

        let entries = entries_from_events(&owner, &[event]);
        assert_eq!(entries[0].agent_pubkey, agent.public_key().to_hex());
    }
}
