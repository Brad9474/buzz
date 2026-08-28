import assert from "node:assert/strict";
import test from "node:test";

import { findExistingDirectMessage } from "./findExistingDirectMessage.ts";

const ME = "me-pubkey";
const HELM = "helm-pubkey";
const SAGE = "sage-pubkey";

function dm(id, participantPubkeys) {
  return { channelType: "dm", id, participantPubkeys };
}

function stream(id, participantPubkeys) {
  return { channelType: "stream", id, participantPubkeys };
}

test("finds the existing 1:1 DM for a single selected recipient", () => {
  const channels = [dm("dm-1", [ME, HELM]), dm("dm-2", [ME, SAGE])];
  const found = findExistingDirectMessage(channels, [HELM], ME);
  assert.equal(found?.id, "dm-1");
});

test("returns null when no DM exists for the requested recipients", () => {
  const channels = [dm("dm-1", [ME, HELM])];
  assert.equal(findExistingDirectMessage(channels, [SAGE], ME), null);
});

test("does not match a group DM as a partial overlap of a 1:1 selection", () => {
  const channels = [dm("dm-group", [ME, HELM, SAGE])];
  assert.equal(findExistingDirectMessage(channels, [HELM], ME), null);
});

test("does not match a 1:1 DM when composing a larger group", () => {
  const channels = [dm("dm-1", [ME, HELM])];
  assert.equal(findExistingDirectMessage(channels, [HELM, SAGE], ME), null);
});

test("matches a group DM regardless of recipient order", () => {
  const channels = [dm("dm-group", [ME, HELM, SAGE])];
  const found = findExistingDirectMessage(channels, [SAGE, HELM], ME);
  assert.equal(found?.id, "dm-group");
});

test("ignores non-DM channels even with a matching participant set", () => {
  const channels = [stream("stream-1", [ME, HELM])];
  assert.equal(findExistingDirectMessage(channels, [HELM], ME), null);
});

test("is case-insensitive on pubkeys", () => {
  const channels = [dm("dm-1", [ME.toUpperCase(), HELM.toUpperCase()])];
  const found = findExistingDirectMessage(channels, [HELM], ME);
  assert.equal(found?.id, "dm-1");
});

test("returns null with no recipients selected", () => {
  const channels = [dm("dm-1", [ME, HELM])];
  assert.equal(findExistingDirectMessage(channels, [], ME), null);
});

test("returns null with an empty channel list", () => {
  assert.equal(findExistingDirectMessage([], [HELM], ME), null);
});
