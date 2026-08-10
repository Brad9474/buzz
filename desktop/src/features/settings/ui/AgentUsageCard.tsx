import * as React from "react";

import {
  agentUsageRollup,
  type AgentUsageReport,
} from "@/shared/api/tauriUsage";
import {
  agentLabel,
  formatCost,
  formatTokens,
  sumRows,
} from "./agentUsageLogic";
import { SettingsSectionHeader } from "./SettingsSectionHeader";

/**
 * Per-agent token and cost usage.
 *
 * Reads live on mount rather than caching: a panel showing yesterday's spend as
 * though it were current is worse than one that takes a moment to load.
 *
 * There is no total-tokens column. NIP-AM forbids a total derived by summing
 * categories and neither provider reports an independent one, so the four real
 * categories are shown instead of a fabricated sum.
 */

const HEAD_CELL =
  "px-3 py-2 text-xs font-medium uppercase tracking-wide text-muted-foreground";
const NUM_CELL = "px-3 py-2 text-right text-sm tabular-nums text-foreground";

export function AgentUsageCard() {
  const [report, setReport] = React.useState<AgentUsageReport | null>(null);
  const [error, setError] = React.useState<string | null>(null);
  const [loading, setLoading] = React.useState(true);

  const load = React.useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      setReport(await agentUsageRollup());
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setLoading(false);
    }
  }, []);

  React.useEffect(() => {
    void load();
  }, [load]);

  const rows = report?.rows ?? [];
  const totals = React.useMemo(() => sumRows(rows), [rows]);

  return (
    <section className="min-w-0" data-testid="settings-agent-usage">
      <SettingsSectionHeader
        title="Agent usage"
        description="Tokens and cost per agent, decrypted locally. Only you can read this — nothing here leaves your machine."
      />

      <div className="mb-3 flex items-center gap-3">
        <button
          className="inline-flex h-8 items-center rounded-md border border-border/70 px-3 text-sm font-medium text-foreground hover:bg-muted/60 disabled:opacity-50"
          data-testid="agent-usage-refresh"
          disabled={loading}
          onClick={() => void load()}
          type="button"
        >
          {loading ? "Reading…" : "Refresh"}
        </button>
        {report ? (
          <span className="text-xs text-muted-foreground">
            As at {new Date(report.generatedAt * 1000).toLocaleString()}
          </span>
        ) : null}
      </div>

      {error ? (
        <p
          className="rounded-md border border-destructive/40 bg-destructive/10 px-3 py-2 text-sm text-destructive"
          data-testid="agent-usage-error"
        >
          Could not read usage: {error}
        </p>
      ) : null}

      {!error && !loading && rows.length === 0 ? (
        <p
          className="rounded-md border border-border/70 px-3 py-2 text-sm text-muted-foreground"
          data-testid="agent-usage-empty"
        >
          No agent turns recorded yet. Usage is captured from the point turn
          tracking goes live — there is no history before that.
        </p>
      ) : null}

      {rows.length > 0 ? (
        <div className="overflow-x-auto rounded-md border border-border/70">
          <table className="w-full border-collapse text-left">
            <thead className="border-b border-border/70 bg-muted/40">
              <tr>
                <th className={HEAD_CELL}>Agent</th>
                <th className={`${HEAD_CELL} text-right`}>Turns</th>
                <th className={`${HEAD_CELL} text-right`}>Input</th>
                <th className={`${HEAD_CELL} text-right`}>Output</th>
                <th className={`${HEAD_CELL} text-right`}>Cache read</th>
                <th className={`${HEAD_CELL} text-right`}>Cache write</th>
                <th className={`${HEAD_CELL} text-right`}>Cost</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((row) => (
                <tr
                  className="border-b border-border/40 last:border-b-0"
                  key={row.agentPubkey}
                >
                  <td
                    className="px-3 py-2 text-sm font-medium text-foreground"
                    title={row.agentPubkey}
                  >
                    {agentLabel(row)}
                  </td>
                  <td className={NUM_CELL}>{formatTokens(row.turns)}</td>
                  <td className={NUM_CELL}>{formatTokens(row.inputTokens)}</td>
                  <td className={NUM_CELL}>{formatTokens(row.outputTokens)}</td>
                  <td className={NUM_CELL}>
                    {formatTokens(row.cacheReadTokens)}
                  </td>
                  <td className={NUM_CELL}>
                    {formatTokens(row.cacheWriteTokens)}
                  </td>
                  <td className={NUM_CELL}>{formatCost(row.costUsd)}</td>
                </tr>
              ))}
            </tbody>
            <tfoot className="border-t border-border/70 bg-muted/30">
              <tr>
                <td className="px-3 py-2 text-sm font-semibold text-foreground">
                  Total
                </td>
                <td className={`${NUM_CELL} font-semibold`}>
                  {formatTokens(totals.turns)}
                </td>
                <td className={`${NUM_CELL} font-semibold`}>
                  {formatTokens(totals.inputTokens)}
                </td>
                <td className={`${NUM_CELL} font-semibold`}>
                  {formatTokens(totals.outputTokens)}
                </td>
                <td className={`${NUM_CELL} font-semibold`}>
                  {formatTokens(totals.cacheReadTokens)}
                </td>
                <td className={`${NUM_CELL} font-semibold`}>
                  {formatTokens(totals.cacheWriteTokens)}
                </td>
                <td className={`${NUM_CELL} font-semibold`}>
                  {formatCost(totals.costUsd)}
                </td>
              </tr>
            </tfoot>
          </table>
        </div>
      ) : null}

      {rows.length > 0 ? (
        <p className="mt-2 text-xs text-muted-foreground">
          Input is cache-inclusive: cache-read and cache-write are subsets of
          it, shown separately because they bill at different rates.
        </p>
      ) : null}

      {totals.undecryptableTurns > 0 ? (
        <p
          className="mt-2 text-xs text-amber-600 dark:text-amber-500"
          data-testid="agent-usage-undecryptable"
        >
          {formatTokens(totals.undecryptableTurns)} turn(s) could not be
          decrypted and are excluded — the totals above are a floor, not a
          complete count.
        </p>
      ) : null}
    </section>
  );
}
