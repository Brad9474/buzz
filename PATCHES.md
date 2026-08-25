# Local patches against `block/buzz`

Six commits carried on top of upstream `main` (`63496cc1d`). This file tracks
what each one is for, whether it has been submitted upstream, and what depends
on it locally — so a rebuild from a clean tree doesn't silently drop a fix that
something is relying on.

Branch: `upstream/consolidated`
Base: `63496cc1d` — `feat(replica): portable heartbeat-token fence…(#3268)`

| # | Commit | Subject | Upstream status |
|---|--------|---------|-----------------|
| 1 | `e7d1d8268` | feat(relay): preserve media across host changes | Ready to submit |
| 2 | `efa0fcbce` | chore(compose): bind development services to loopback | Ready to submit |
| 3 | `519eb1cf0` | fix: supervise managed agent runtimes | Ready to submit |
| 4 | `e553a1299` | fix(auth): match NIP-42 relay tags across ws:// and wss:// | Ready to submit |
| 5 | `0d651372c` | feat(pairing): allow an external relay URL for mobile pairing | **Held** — pending decision |
| 6 | `0e28ea8e4` | fix(pairing): drive the pairing handshake from the external relay URL | **Held** — pending decision |

Commits 5 and 6 are held only because their *local* value depends on whether
relay hosting moves off the tailnet. They remain worth upstreaming on their own
merits — the default install is exactly the loopback case they fix. The
four-commit PR is `HEAD~2`; the two held commits are deliberately the branch tip
so they can be dropped without touching anything else.

---

## 1. `e7d1d8268` — feat(relay): preserve media across host changes

Adds community host aliases so media URLs survive a change of canonical host,
with matching NIP-11 discovery and Desktop-side resolution of historical media
through registered authorities. Ships migration `0027_community_hosts.sql`.

**Local dependency:** any change of relay host — including a hosting migration —
breaks every historical media URL without this. The stock `ghcr.io/block/buzz`
image does not contain it.

## 2. `efa0fcbce` — chore(compose): bind development services to loopback

`docker compose up` published Postgres, Redis, Adminer, Keycloak, MinIO and
Prometheus on every interface using the dev-default credentials already in the
file. All six are now bound to `127.0.0.1`.

The Postgres host port is parameterised as `BUZZ_PG_HOST_PORT`, **defaulting to
5432** so upstream behaviour is unchanged. `localhost:5432` is hardcoded in ~38
places across the test suites and the `buzz-admin`/`buzz-audit` connection
fallbacks, so changing the default outright would break the documented workflow.

**Local dependency:** this machine sets `BUZZ_PG_HOST_PORT=15432` in its
untracked `.env`, because Hyper-V reserves ranges colliding with 5432 under WSL.
That override is local-only and never ships.

## 3. `519eb1cf0` — fix: supervise managed agent runtimes

Restarts unexpectedly-exited managed agents with bounded backoff and crash-loop
detection, and moves active pairs when a community relay address changes.

**Local dependency:** agents currently reach the relay over loopback, so
unexpected exits are rare. Any move to a networked relay makes them routine, and
the "move active pairs when the relay address changes" behaviour is exactly the
migration event.

## 4. `e553a1299` — fix(auth): match NIP-42 relay tags across ws:// and wss://

The relay derives the expected AUTH `relay` tag from its own configured scheme
plus the inbound request's host. Behind a TLS terminator (Tailscale serve,
nginx, Caddy, Cloudflare) a client correctly signs `wss://<host>` while the relay
expects `ws://<host>`, so every such AUTH failed with `RelayUrlMismatch`.
`normalize_relay_url` now folds `ws://` onto `wss://`; host, port and path still
bind exactly as before.

**Known related gap, not fixed here:** NIP-98 HTTP auth binds its `u` tag the
same way. Media upload and git-over-HTTPS through a TLS terminator are likely
affected by the same class of bug. Not yet investigated.

## 5. `0d651372c` — feat(pairing): allow an external relay URL for mobile pairing

Adds an optional per-community external relay URL used to build the relay
address the mobile peer persists after pairing, because the workspace relay URL
is typically a loopback address the phone cannot reach.

## 6. `0e28ea8e4` — fix(pairing): drive the pairing handshake from the external relay URL

Commit 5 only shaped the URL the phone persisted *after* pairing; the QR's
`relay=` parameter, the NIP-11 probe and the desktop's own handshake socket
still came from the workspace relay. The phone therefore scanned a code telling
it to dial `127.0.0.1`. Both now derive from one parsed value.

**Behaviour change:** the desktop dials the external relay for the handshake
too, so that address must be reachable from the desktop as well as the phone.
With no override set, resolution falls back to the workspace relay as before.

**Depends on commit 5** — commit 5 is non-functional for its stated purpose
without this one. Do not submit 5 without 6.

---

## Pre-submission scrub applied

Both items were fixed while building this branch, not left for review:

1. A real Tailscale device hostname appeared in test fixtures 12 times across
   commits 4, 5 and 6. All replaced with `relay.example.com`, matching the
   convention already used in those files' other tests. What the tests pin is
   scheme-folding and host-binding behaviour, not any particular hostname.
2. Commit 2 originally hardcoded a host-specific Postgres port. Parameterised
   with the upstream default preserved, as described above.
