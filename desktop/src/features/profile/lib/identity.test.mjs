import assert from "node:assert/strict";
import test from "node:test";

import {
  formatOwnerLabel,
  profileLookupsEqual,
  resolveUserLabel,
} from "./identity.ts";

const OWNER_PUBKEY =
  "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

const summary = (over = {}) => ({
  displayName: "Ada",
  avatarUrl: "https://x/a.png",
  nip05Handle: "ada@x",
  ownerPubkey: null,
  isAgent: false,
  ...over,
});

test("formatOwnerLabel resolves a known owner's display name", () => {
  assert.equal(
    formatOwnerLabel(OWNER_PUBKEY, null, {
      [OWNER_PUBKEY]: summary({ displayName: "baxen" }),
    }),
    "baxen",
  );
});

test("formatOwnerLabel calls the viewer-owned agent's owner you", () => {
  assert.equal(formatOwnerLabel(OWNER_PUBKEY, OWNER_PUBKEY, {}), "you");
});

test("formatOwnerLabel returns null when verified ownership is absent", () => {
  assert.equal(formatOwnerLabel(null, OWNER_PUBKEY, {}), null);
});

test("profileLookupsEqual: same reference is equal", () => {
  const a = { p1: summary() };
  assert.equal(profileLookupsEqual(a, a), true);
});

test("profileLookupsEqual: distinct objects, identical values are equal", () => {
  assert.equal(profileLookupsEqual({ p1: summary() }, { p1: summary() }), true);
});

test("profileLookupsEqual: different key count is not equal", () => {
  assert.equal(
    profileLookupsEqual({ p1: summary() }, { p1: summary(), p2: summary() }),
    false,
  );
});

test("profileLookupsEqual: same count, different keys is not equal", () => {
  assert.equal(
    profileLookupsEqual({ p1: summary() }, { p2: summary() }),
    false,
  );
});

test("profileLookupsEqual: a changed field is not equal", () => {
  for (const field of [
    "displayName",
    "avatarUrl",
    "nip05Handle",
    "ownerPubkey",
    "isAgent",
  ]) {
    assert.equal(
      profileLookupsEqual(
        { p1: summary() },
        { p1: summary({ [field]: field === "isAgent" ? true : "changed" }) },
      ),
      false,
      `field ${field} should break equality`,
    );
  }
});

test("profileLookupsEqual: two empty lookups are equal", () => {
  assert.equal(profileLookupsEqual({}, {}), true);
});

// Render-count proof for the Tier-1 typing-storm fix (#1533 discipline).
// MessageRow re-renders iff `prev.profiles === next.profiles` fails, so the
// stabiliser's job is: hold the reference across value-equal re-derives (the
// per-keystroke churn) and release it only on a real value change. This
// replays the exact ChannelScreen ref idiom against a sequence of freshly
// built lookups and asserts reference identity == render decision.
function makeStabiliser() {
  let ref;
  let first = true;
  return (raw) => {
    if (first || !profileLookupsEqual(ref, raw)) {
      ref = raw;
    }
    first = false;
    return ref;
  };
}

test("stabiliser: value-equal re-derives keep the same reference (no re-render)", () => {
  const stabilise = makeStabiliser();
  // Each entry is a fresh object identity — exactly what a users-batch re-key
  // produces on every keystroke-adjacent typing event.
  const first = stabilise({ p1: summary() });
  const churnA = stabilise({ p1: summary() });
  const churnB = stabilise({ p1: summary() });
  assert.equal(churnA, first, "value-equal churn must not swap the reference");
  assert.equal(churnB, first, "repeated churn must not swap the reference");
});

test("stabiliser: a real profile change swaps the reference (re-render fires)", () => {
  const stabilise = makeStabiliser();
  const first = stabilise({ p1: summary() });
  const changed = stabilise({ p1: summary({ displayName: "Grace" }) });
  assert.notEqual(
    changed,
    first,
    "a real value change must swap the reference",
  );
  // ...and then re-stabilises around the new value.
  const held = stabilise({ p1: summary({ displayName: "Grace" }) });
  assert.equal(held, changed, "must re-stabilise around the new value");
});

// ── resolveUserLabel: a pubkey is never a name ──────────────────────────────
//
// `ChannelInfo.participants` is a verbatim clone of `participant_pubkeys`
// (nostr_convert.rs), so DM surfaces hand this function the participant's own
// pubkey as `fallbackName`. Without a guard that renders a raw 64-character
// hex string in the sidebar where a display name belongs.

const DM_PUBKEY =
  "18073dfee86227e4954adc9e93850c371e0731a25266050ef2ef00200e9d85bf";
const TRUNCATED = "18073dfe…85bf";

test("resolveUserLabel: a fallback that is the pubkey falls through to truncation", () => {
  assert.equal(
    resolveUserLabel({ pubkey: DM_PUBKEY, fallbackName: DM_PUBKEY }),
    TRUNCATED,
    "the raw pubkey must not be returned as if it were a display name",
  );
});

test("resolveUserLabel: pubkey fallback is rejected regardless of case or padding", () => {
  for (const variant of [
    DM_PUBKEY.toUpperCase(),
    `  ${DM_PUBKEY}  `,
    `\t${DM_PUBKEY.toUpperCase()}\n`,
  ]) {
    assert.equal(
      resolveUserLabel({ pubkey: DM_PUBKEY, fallbackName: variant }),
      TRUNCATED,
      `hex is case-insensitive and tags carry stray whitespace: ${JSON.stringify(variant)}`,
    );
  }
});

test("resolveUserLabel: a genuine fallback name is still used", () => {
  assert.equal(
    resolveUserLabel({ pubkey: DM_PUBKEY, fallbackName: "Helm" }),
    "Helm",
  );
});

test("resolveUserLabel: a different pubkey as fallback is left alone", () => {
  // Only the participant's *own* pubkey is rejected. Anything else is data
  // this function has no business second-guessing.
  assert.equal(
    resolveUserLabel({ pubkey: DM_PUBKEY, fallbackName: OWNER_PUBKEY }),
    OWNER_PUBKEY,
  );
});

test("resolveUserLabel: a resolved profile still outranks both", () => {
  assert.equal(
    resolveUserLabel({
      pubkey: DM_PUBKEY,
      fallbackName: DM_PUBKEY,
      profiles: { [DM_PUBKEY]: summary({ displayName: "Helm" }) },
    }),
    "Helm",
    "the guard must not shadow a real display name",
  );
});

test("resolveUserLabel: with no fallback at all, behaviour is unchanged", () => {
  assert.equal(resolveUserLabel({ pubkey: DM_PUBKEY }), TRUNCATED);
});
