import assert from "node:assert/strict";
import { describe, it } from "node:test";

import {
  agentLabel,
  formatCost,
  formatTokens,
  sumRows,
} from "./agentUsageLogic.ts";

function row(overrides = {}) {
  return {
    agentPubkey: "a".repeat(64),
    agentName: null,
    turns: 0,
    sessions: 0,
    inputTokens: 0,
    outputTokens: 0,
    cacheReadTokens: 0,
    cacheWriteTokens: 0,
    costUsd: 0,
    undecryptableTurns: 0,
    ...overrides,
  };
}

describe("sumRows", () => {
  it("totals every column the table renders", () => {
    const totals = sumRows([
      row({
        turns: 3,
        inputTokens: 100,
        outputTokens: 20,
        cacheReadTokens: 40,
        cacheWriteTokens: 5,
        costUsd: 1.5,
      }),
      row({
        turns: 2,
        inputTokens: 50,
        outputTokens: 10,
        cacheReadTokens: 8,
        cacheWriteTokens: 1,
        costUsd: 0.25,
      }),
    ]);

    assert.equal(totals.turns, 5);
    assert.equal(totals.inputTokens, 150);
    assert.equal(totals.outputTokens, 30);
    assert.equal(totals.cacheReadTokens, 48);
    assert.equal(totals.cacheWriteTokens, 6);
    assert.equal(totals.costUsd, 1.75);
  });

  it("returns zeroes for no rows rather than NaN", () => {
    const totals = sumRows([]);
    for (const [key, value] of Object.entries(totals)) {
      assert.equal(value, 0, `${key} should be 0`);
    }
  });

  // Undecryptable turns drive the "these totals are a floor" warning. If they
  // did not total, a panel-wide undercount would show no warning at all.
  it("totals undecryptable turns so the floor warning can trigger", () => {
    const totals = sumRows([
      row({ undecryptableTurns: 2 }),
      row({ undecryptableTurns: 3 }),
    ]);
    assert.equal(totals.undecryptableTurns, 5);
  });
});

describe("formatCost", () => {
  it("shows cents for ordinary amounts", () => {
    assert.equal(formatCost(1.5), "$1.50");
    assert.equal(formatCost(0), "$0.00");
  });

  // A cheap-but-real agent must not render as free.
  it("keeps small non-zero costs visible instead of rounding them to zero", () => {
    assert.equal(formatCost(0.0004), "$0.0004");
    assert.notEqual(formatCost(0.0004), "$0.00");
  });

  it("switches to cents at the boundary", () => {
    assert.equal(formatCost(0.01), "$0.01");
  });
});

describe("formatTokens", () => {
  it("separates thousands so large counts stay readable", () => {
    assert.match(formatTokens(1234567), /^1\D234\D567$/);
  });
});

describe("agentLabel", () => {
  it("prefers a published display name", () => {
    assert.equal(agentLabel(row({ agentName: "Forge" })), "Forge");
  });

  // A whitespace-only name is effectively absent; rendering it leaves a blank
  // cell with no way to tell which agent the row belongs to.
  it("falls back to the pubkey when the name is blank or missing", () => {
    const blank = agentLabel(row({ agentName: "   " }));
    const missing = agentLabel(row({ agentName: null }));
    assert.equal(blank, missing);
    assert.notEqual(blank.trim(), "");
  });

  // Truncated prefixes are grindable, so identity display goes through the
  // canonical helper's head-and-tail form rather than a bare prefix.
  it("truncates the pubkey with both head and tail", () => {
    const label = agentLabel(row({ agentPubkey: `${"a".repeat(60)}beef` }));
    assert.ok(label.startsWith("aaaaaaaa"), label);
    assert.ok(label.endsWith("beef"), label);
    assert.ok(label.length < 64, "must actually be truncated");
  });
});
