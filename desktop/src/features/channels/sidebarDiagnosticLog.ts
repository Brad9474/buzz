/**
 * Temporary diagnostic log for the sidebar channel-dropout investigation
 * (a member channel is server-confirmed clean but doesn't render in the
 * sidebar until some later event refreshes it). Captures the decision points
 * in `refreshChannelsQuery` (fetch layer) and `AppShell`'s `sidebarChannels`
 * memo (render-filter layer) to capped, on-disk-independent ring buffers so a
 * drop can be diagnosed after the fact instead of requiring devtools to be
 * open at the exact moment it happens.
 *
 * Read it any time via devtools console:
 *   JSON.parse(localStorage.getItem("buzz-sidebar-diagnostic-log.v1"))
 *   JSON.parse(localStorage.getItem("buzz-sidebar-diagnostic-render-log.v1"))
 *
 * Remove this module and its call sites once the root cause is found.
 */

import { setLocalStorageItemWithRecovery } from "@/shared/lib/localStorageQuota";

const FETCH_STORAGE_KEY = "buzz-sidebar-diagnostic-log.v1";
const RENDER_STORAGE_KEY = "buzz-sidebar-diagnostic-render-log.v1";
const MAX_ENTRIES = 60;

export type SidebarDiagnosticEntry = {
  ts: number;
  branch: "not-modified" | "direct-full-fetch" | "full-fetch";
  knownHash: string | null;
  payloadHash: string;
  payloadChannelsWasNull: boolean;
  hasMatchingNotModifiedResponse: boolean;
  cachedPairCount: number | null;
  resultCount: number;
  resultChannelIds: string[];
};

export type SidebarRenderDiagnosticEntry = {
  ts: number;
  queryChannelCount: number;
  memberChannelCount: number;
  sidebarChannelCount: number;
  /** Channels present in the query result but filtered out of the sidebar, with why. */
  droppedByRenderFilter: Array<{
    id: string;
    isMember: boolean;
    archived: boolean;
    hiddenAsHuddleBacking: boolean;
  }>;
};

function readList<T>(key: string): T[] {
  if (typeof window === "undefined") return [];
  try {
    const raw = window.localStorage.getItem(key);
    if (!raw) return [];
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? (parsed as T[]) : [];
  } catch {
    return [];
  }
}

function appendCapped<T>(key: string, entry: T): T[] {
  if (typeof window === "undefined") return [];
  try {
    const next = [...readList<T>(key), entry].slice(-MAX_ENTRIES);
    setLocalStorageItemWithRecovery(key, JSON.stringify(next));
    return next;
  } catch {
    // Diagnostics must never break the real render/refresh path.
    return readList<T>(key);
  }
}

/** Exported for unit testing. Appends one fetch-layer entry, capped to MAX_ENTRIES. */
export function recordSidebarDiagnostic(
  entry: SidebarDiagnosticEntry,
): SidebarDiagnosticEntry[] {
  return appendCapped(FETCH_STORAGE_KEY, entry);
}

export function readSidebarDiagnosticLog(): SidebarDiagnosticEntry[] {
  return readList(FETCH_STORAGE_KEY);
}

/** Exported for unit testing. Appends one render-layer entry, capped to MAX_ENTRIES. */
export function recordSidebarRenderDiagnostic(
  entry: SidebarRenderDiagnosticEntry,
): SidebarRenderDiagnosticEntry[] {
  return appendCapped(RENDER_STORAGE_KEY, entry);
}

export function readSidebarRenderDiagnosticLog(): SidebarRenderDiagnosticEntry[] {
  return readList(RENDER_STORAGE_KEY);
}
