import assert from "node:assert/strict";
import test from "node:test";

import { resolveChannelDisplayLabel } from "./channelLabels.ts";

const ME = "me-pubkey";
const HELM = "helm-pubkey";

function dm({ participantPubkeys, participants, memberCount, name = "" }) {
  return {
    channelType: "dm",
    memberCount,
    name,
    participantPubkeys,
    participants,
  };
}

test("resolves a normal 2-person DM to the peer's name", () => {
  const channel = dm({
    memberCount: 2,
    participantPubkeys: [ME, HELM],
    participants: ["Me", "Helm"],
  });
  assert.equal(resolveChannelDisplayLabel(channel, ME, undefined), "Helm");
});

test("resolves a genuine self-DM (memberCount matches) to 'You'", () => {
  const channel = dm({
    memberCount: 1,
    participantPubkeys: [ME],
    participants: ["Me"],
  });
  assert.equal(resolveChannelDisplayLabel(channel, ME, undefined), "You");
});

test("does not label an incomplete-cache DM as 'You' — falls back to the raw name", () => {
  // memberCount (server-authoritative) says 2 participants, but the cached
  // participantPubkeys only has self so far — the peer hasn't landed yet.
  const channel = dm({
    memberCount: 2,
    name: "dm",
    participantPubkeys: [ME],
    participants: ["Me"],
  });
  assert.equal(resolveChannelDisplayLabel(channel, ME, undefined), "dm");
});

test("leaves a non-generic channel name untouched", () => {
  const channel = dm({
    memberCount: 2,
    name: "Project Falcon",
    participantPubkeys: [ME, HELM],
    participants: ["Me", "Helm"],
  });
  assert.equal(
    resolveChannelDisplayLabel(channel, ME, undefined),
    "Project Falcon",
  );
});

test("ignores non-DM channels entirely", () => {
  const channel = {
    channelType: "stream",
    memberCount: 5,
    name: "general",
    participantPubkeys: [],
    participants: [],
  };
  assert.equal(resolveChannelDisplayLabel(channel, ME, undefined), "general");
});
