import { invokeTauri } from "./tauri";

/**
 * Per-agent token and cost usage, decrypted in the Tauri process.
 *
 * The backend reads NIP-AM kind 44200 metrics filtered to the current
 * identity's own pubkey, decrypts them with the key Desktop already holds, and
 * aggregates. The webview never sees key material or ciphertext — only these
 * finished numbers.
 */
export type AgentUsageRow = {
  agentPubkey: string;
  /** `null` when the agent has published no profile name. */
  agentName: string | null;
  turns: number;
  sessions: number;
  /** Inclusive of the cache figures below, per NIP-AM's definition. */
  inputTokens: number;
  outputTokens: number;
  /** A subset of `inputTokens`, billed at a lower rate. */
  cacheReadTokens: number;
  /** A subset of `inputTokens`. */
  cacheWriteTokens: number;
  costUsd: number;
  /**
   * Turns whose payload could not be decrypted. Non-zero means every total
   * here is a floor, and the panel must say so rather than implying the
   * figures are complete.
   */
  undecryptableTurns: number;
};

export type AgentUsageReport = {
  rows: AgentUsageRow[];
  /** Unix seconds at read time. */
  generatedAt: number;
};

/**
 * Read and aggregate the current identity's agent usage.
 *
 * There is deliberately no caching layer: the panel reads live on open so a
 * stale window can never present old spend as current.
 */
export async function agentUsageRollup(): Promise<AgentUsageReport> {
  return invokeTauri<AgentUsageReport>("agent_usage_rollup");
}
