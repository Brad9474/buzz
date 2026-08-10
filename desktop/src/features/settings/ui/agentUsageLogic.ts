import { truncatePubkey } from "@/shared/lib/pubkey";
import type { AgentUsageRow } from "@/shared/api/tauriUsage";

/**
 * Presentation logic for the agent usage panel, kept out of the component so it
 * can be tested directly — same split as the neighbouring harness cards.
 */

const numberFormat = new Intl.NumberFormat();

export function formatTokens(value: number): string {
  return numberFormat.format(value);
}

/**
 * Render cost to cents, except for small non-zero amounts.
 *
 * A busy-but-cheap agent rounding to `$0.00` reads as "this agent is free",
 * which is a worse lie than an extra couple of decimal places.
 */
export function formatCost(value: number): string {
  if (value > 0 && value < 0.01) return `$${value.toFixed(4)}`;
  return `$${value.toFixed(2)}`;
}

/**
 * Label a row: published display name when there is one, else the canonical
 * truncated pubkey.
 *
 * Truncation goes through `truncatePubkey` rather than an ad-hoc slice because
 * short prefixes are grindable, so every identity display in the app uses the
 * same recognisable head-and-tail form.
 */
export function agentLabel(row: AgentUsageRow): string {
  const name = row.agentName?.trim();
  return name && name.length > 0 ? name : truncatePubkey(row.agentPubkey);
}

export type UsageTotals = {
  turns: number;
  inputTokens: number;
  outputTokens: number;
  cacheReadTokens: number;
  cacheWriteTokens: number;
  costUsd: number;
  undecryptableTurns: number;
};

/**
 * Column totals across every row.
 *
 * The backend has already collapsed each session to its final cumulative
 * metric, so rows are disjoint per agent and adding them is correct. This is a
 * sum of finished figures, not a second pass at the accounting.
 */
export function sumRows(rows: AgentUsageRow[]): UsageTotals {
  return rows.reduce<UsageTotals>(
    (acc, row) => ({
      turns: acc.turns + row.turns,
      inputTokens: acc.inputTokens + row.inputTokens,
      outputTokens: acc.outputTokens + row.outputTokens,
      cacheReadTokens: acc.cacheReadTokens + row.cacheReadTokens,
      cacheWriteTokens: acc.cacheWriteTokens + row.cacheWriteTokens,
      costUsd: acc.costUsd + row.costUsd,
      undecryptableTurns: acc.undecryptableTurns + row.undecryptableTurns,
    }),
    {
      turns: 0,
      inputTokens: 0,
      outputTokens: 0,
      cacheReadTokens: 0,
      cacheWriteTokens: 0,
      costUsd: 0,
      undecryptableTurns: 0,
    },
  );
}
