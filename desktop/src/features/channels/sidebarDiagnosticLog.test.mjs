import assert from "node:assert/strict";
import test from "node:test";

import {
  readSidebarDiagnosticLog,
  readSidebarRenderDiagnosticLog,
  recordSidebarDiagnostic,
  recordSidebarRenderDiagnostic,
} from "./sidebarDiagnosticLog.ts";

if (typeof globalThis.window === "undefined") {
  const storage = new Map();
  globalThis.window = {
    localStorage: {
      get length() {
        return storage.size;
      },
      key: (index) => [...storage.keys()][index] ?? null,
      getItem: (key) => storage.get(key) ?? null,
      setItem: (key, value) => storage.set(key, value),
      removeItem: (key) => storage.delete(key),
    },
  };
}

function fetchEntry(overrides = {}) {
  return {
    ts: 1,
    branch: "full-fetch",
    knownHash: null,
    payloadHash: "hash-1",
    payloadChannelsWasNull: false,
    hasMatchingNotModifiedResponse: false,
    cachedPairCount: null,
    resultCount: 1,
    resultChannelIds: ["general"],
    ...overrides,
  };
}

test("recordSidebarDiagnostic appends and readSidebarDiagnosticLog reads it back", () => {
  window.localStorage.removeItem("buzz-sidebar-diagnostic-log.v1");
  recordSidebarDiagnostic(fetchEntry({ ts: 1 }));
  recordSidebarDiagnostic(fetchEntry({ ts: 2 }));

  const log = readSidebarDiagnosticLog();
  assert.deepEqual(
    log.map((entry) => entry.ts),
    [1, 2],
  );
});

test("recordSidebarDiagnostic caps the ring buffer at the most recent entries", () => {
  window.localStorage.removeItem("buzz-sidebar-diagnostic-log.v1");
  for (let i = 0; i < 65; i += 1) {
    recordSidebarDiagnostic(fetchEntry({ ts: i }));
  }

  const log = readSidebarDiagnosticLog();
  assert.equal(log.length, 60);
  assert.equal(log[0].ts, 5);
  assert.equal(log.at(-1).ts, 64);
});

test("recordSidebarRenderDiagnostic tracks channels dropped by the render filter", () => {
  window.localStorage.removeItem("buzz-sidebar-diagnostic-render-log.v1");
  recordSidebarRenderDiagnostic({
    ts: 1,
    queryChannelCount: 2,
    memberChannelCount: 2,
    sidebarChannelCount: 1,
    droppedByRenderFilter: [
      {
        id: "client-joy-jenson",
        isMember: true,
        archived: false,
        hiddenAsHuddleBacking: false,
      },
    ],
  });

  const log = readSidebarRenderDiagnosticLog();
  assert.equal(log.length, 1);
  assert.equal(log[0].droppedByRenderFilter[0].id, "client-joy-jenson");
});
