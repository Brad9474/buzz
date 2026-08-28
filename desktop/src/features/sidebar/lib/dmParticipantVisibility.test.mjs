import assert from "node:assert/strict";
import test from "node:test";

import { resolveVisibleDmParticipants } from "./dmParticipantVisibility.ts";

const ME = "me-pubkey";
const HELM = "helm-pubkey";

function dm({ participantPubkeys, participants, memberCount }) {
  return { memberCount, participantPubkeys, participants };
}

test("returns the peer for a normal 2-person DM", () => {
  const channel = dm({
    memberCount: 2,
    participantPubkeys: [ME, HELM],
    participants: ["Me", "Helm"],
  });
  const visible = resolveVisibleDmParticipants(channel, ME, new Set());
  assert.deepEqual(
    visible.map((p) => p.pubkey),
    [HELM],
  );
});

test("returns self for a genuine self-DM (memberCount matches)", () => {
  const channel = dm({
    memberCount: 1,
    participantPubkeys: [ME],
    participants: ["Me"],
  });
  const visible = resolveVisibleDmParticipants(channel, ME, new Set());
  assert.deepEqual(
    visible.map((p) => p.pubkey),
    [ME],
  );
});

test("returns no rows for an incomplete-cache DM instead of a stand-in self row", () => {
  // memberCount (server-authoritative) says 2, but participantPubkeys only
  // has self cached so far — this is the race, not a real self-DM.
  const channel = dm({
    memberCount: 2,
    participantPubkeys: [ME],
    participants: ["Me"],
  });
  const visible = resolveVisibleDmParticipants(channel, ME, new Set());
  assert.deepEqual(visible, []);
});

test("filters out a 'note to self' fallback label alongside a real peer", () => {
  const channel = dm({
    memberCount: 2,
    participantPubkeys: [ME, HELM],
    participants: ["My Display Name", "Helm"],
  });
  const selfDmLabels = new Set(["my display name"]);
  const visible = resolveVisibleDmParticipants(channel, ME, selfDmLabels);
  assert.deepEqual(
    visible.map((p) => p.pubkey),
    [HELM],
  );
});
