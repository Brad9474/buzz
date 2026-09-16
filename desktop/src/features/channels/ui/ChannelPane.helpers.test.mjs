import assert from "node:assert/strict";
import test from "node:test";

import {
  getChannelIntroDescription,
  getChannelIntroKind,
  getMainComposerPlaceholder,
  shouldPrioritizeIdleAuxiliary,
  shouldUseFocusIdleDrawer,
} from "./ChannelPane.helpers.ts";

function channel(overrides = {}) {
  return {
    ttlDeadline: null,
    ttlSeconds: null,
    visibility: "open",
    ...overrides,
  };
}

test("focus idle drawers yield to every higher-priority auxiliary surface", () => {
  const idleDrawer = {
    channelManagementOpen: false,
    hasAgentSession: false,
    hasIdleAuxiliaryPanel: true,
    hasIdlePanelCloseHandler: true,
    hasProfilePanel: false,
    hasThreadSurface: false,
    useSplitAuxiliaryPane: true,
  };

  assert.equal(shouldUseFocusIdleDrawer(idleDrawer), true);
  for (const surface of [
    "channelManagementOpen",
    "hasAgentSession",
    "hasProfilePanel",
    "hasThreadSurface",
  ]) {
    assert.equal(
      shouldUseFocusIdleDrawer({ ...idleDrawer, [surface]: true }),
      false,
      `idle drawer must yield when ${surface} is open`,
    );
  }
});

test("an explicit thread override keeps the idle panel in its own focus drawer", () => {
  assert.equal(
    shouldUseFocusIdleDrawer({
      channelManagementOpen: false,
      hasAgentSession: false,
      hasIdleAuxiliaryPanel: true,
      hasIdlePanelCloseHandler: true,
      hasProfilePanel: false,
      hasThreadSurface: true,
      overrideThread: true,
      useSplitAuxiliaryPane: false,
    }),
    true,
  );
});

test("channel intro shares description-over-purpose derivation with the header", () => {
  assert.equal(
    getChannelIntroDescription(
      channel({
        description: "Description paragraphs.\n\nKeep this structure.",
        purpose: "Legacy purpose",
        topic: "",
      }),
    ),
    "Description paragraphs.\n\nKeep this structure.",
  );
});

test("getChannelIntroKind names project homes ahead of regular streams", () => {
  assert.equal(getChannelIntroKind(channel(), true), "project channel");
  assert.equal(getChannelIntroKind(channel(), false), "regular channel");
});

test("getChannelIntroKind keeps private and ephemeral labels for other streams", () => {
  assert.equal(
    getChannelIntroKind(channel({ visibility: "private" })),
    "private channel",
  );
  assert.equal(
    getChannelIntroKind(channel({ ttlSeconds: 3600 })),
    "ephemeral channel",
  );
});

test("idle auxiliary priority does not depend on thread layout mode", () => {
  assert.equal(shouldPrioritizeIdleAuxiliary(true, true), true);
  assert.equal(shouldPrioritizeIdleAuxiliary(true, false), false);
  assert.equal(shouldPrioritizeIdleAuxiliary(false, true), false);
});

test("main composer placeholder names a stale non-member state instead of falling through silently", () => {
  assert.equal(
    getMainComposerPlaceholder({
      activeChannel: channel({
        archivedAt: null,
        channelType: "stream",
        isMember: false,
        name: "client-joy-jenson",
      }),
      isModerationDmChannel: false,
      timeoutActive: false,
    }),
    "You're not currently a member of this channel.",
  );
});

test("main composer placeholder priority: timeout > moderation DM > archived > forum > non-member > normal", () => {
  const base = {
    activeChannel: channel({
      archivedAt: null,
      channelType: "stream",
      isMember: true,
      name: "general",
    }),
    isModerationDmChannel: false,
    timeoutActive: false,
  };

  assert.equal(
    getMainComposerPlaceholder({ ...base, timeoutActive: true }),
    "You're timed out by community moderators.",
  );
  assert.equal(
    getMainComposerPlaceholder({ ...base, isModerationDmChannel: true }),
    "This channel is read-only.",
  );
  assert.equal(
    getMainComposerPlaceholder({
      ...base,
      activeChannel: channel({
        ...base.activeChannel,
        archivedAt: "2026-01-01T00:00:00.000Z",
      }),
    }),
    "Archived channels are read-only.",
  );
  assert.equal(
    getMainComposerPlaceholder({
      ...base,
      activeChannel: channel({ ...base.activeChannel, channelType: "forum" }),
    }),
    "Forum posting is not wired in this pass.",
  );
  assert.equal(
    getMainComposerPlaceholder({
      ...base,
      activeChannel: channel({ ...base.activeChannel, isMember: false }),
    }),
    "You're not currently a member of this channel.",
  );
  assert.equal(getMainComposerPlaceholder(base), "Message #general");
  assert.equal(
    getMainComposerPlaceholder({ ...base, activeChannel: null }),
    "Select a channel",
  );
  assert.equal(
    getMainComposerPlaceholder({
      ...base,
      activeChannel: channel({ ...base.activeChannel, channelType: "dm" }),
      directMessageDisplayName: "Hannah",
    }),
    "Message Hannah",
  );
});
