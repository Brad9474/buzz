# Upstream fork catch-up — 2026-09-21

Briefing for whoever picks this up if the merge/PR is interrupted mid-flight
(e.g. Desktop crashes, as happened 2026-09-18). Written and committed to the
merge branch *before* the real merge is run, per Brad's request.

## Context

`Brad9474/buzz` (`origin`) is a fork of `block/buzz` (`upstream`). The fork
carries a handful of desktop fixes on top; upstream carries the rest of the
project's ongoing work (relay, mobile, push-gateway, db).

A prior real sync already happened once: commit `83bb4808e` ("Merge
remote-tracking branch 'upstream/main' into sync/main", authored by Brad,
2026-09-04) is already an ancestor of `origin/main`. This catch-up is the
*next* sync since then, not the first ever.

**Note on the numbers below:** an earlier snapshot circulated in Buzz chat
(2026-09-21 ~03:00 UTC) cited "59 commits behind, spanning upstream PRs
#7228–#7653, 702 files / +53,425/-7,950, exactly 2 new migrations." That
snapshot was accurate when it was taken, but upstream kept moving while it
sat unactioned. The numbers in this document were re-measured immediately
before the real merge below was run, against current `origin/main`
(`785702de5`) and current `upstream/main` (`ef2aa1ae3`), and supersede the
earlier snapshot.

## Current state (measured 2026-09-21, immediately pre-merge)

- **Merge base:** `75f101d8b` ("chore(release): release Buzz Desktop version
  0.5.21 (#7301)") — this is the commit right after the 2026-09-04 sync
  landed in `origin/main`; upstream and the fork diverge from here.
- **Commits behind upstream:** 79 (not 59), spanning upstream PRs roughly
  #7228 through #7758.
- **Commits the fork carries that upstream doesn't:** 12 — desktop-only
  fixes: PR #3 (sidebar dropout diagnostic logging), PR #4 (archive/rename
  cache race), PR #5 (composer non-member placeholder), PR #6
  (Windows packaged `frontendDist` path fix, upstream PR #7177 /
  `dad5a33`, already cherry-picked onto the fork) plus their merge commits
  and one CI workflow addition (Fork Desktop Canary builds).
- **Diffstat `origin/main..upstream/main`:** 799 files changed,
  +59,682/-9,342.

## Migrations — no numbering collision

- Core (`migrations/`): local fork is at `0044_drop_nip_fi_ledger.sql`.
  Upstream adds **two** new files beyond that, not one:
  `0045_retain_push_revocation_tombstones.sql` and
  `0046_storage_accounting_snapshots.sql`.
- Push gateway (`crates/buzz-push-gateway/migrations/`): local fork is at
  `0004_dogfood_only_profile.sql`. Upstream adds one new file:
  `0005_retain_revocation_tombstones.sql`.
- Both are simple sequential appends onto the fork's current numbering —
  no collision, no renumbering needed.

## Dry-run merge result (disposable worktree, discarded after)

Ran `git merge upstream/main --no-commit --no-ff` against current
`origin/main` in a throwaway detached worktree, inspected the result, then
aborted and deleted the worktree — nothing touched on `origin/main` or any
real branch.

- Result: **clean**. Only 2 files needed git's automatic 3-way merge
  resolution (`desktop/src/app/AppShell.tsx`,
  `desktop/src/features/messages/ui/NewMessageScreen.tsx`, both desktop UI)
  — no conflict markers left in the tree (`git diff --check` clean).
- Final diffstat if committed: 785 files changed, +59,643/-8,423.

## Plan (what happens after this file is committed)

1. This file is committed to branch `forge/fork-catchup-2026-09-21`,
   created off `origin/main` at `785702de5`.
2. The real merge (`git merge upstream/main`) is run on that same branch —
   same mechanism just dry-run, now committed for real.
3. Branch is pushed to `origin`.
4. A PR is opened against `origin/main` for review.
5. Full test suite is run against the merged tree; results posted to the
   PR/channel.
6. Nothing touches `main` until Brad reviews and approves the PR.

If this process is interrupted (Desktop crash, session loss, etc.), the
recovery state is: this file, on branch `forge/fork-catchup-2026-09-21`,
tells you everything needed to either resume the merge or re-run it from
scratch — the dry run above proves the merge itself is mechanically clean,
so a re-run should reproduce the same result unless upstream has moved
further in the meantime (re-measure the numbers above before trusting them
if much time has passed — that's exactly what happened to the snapshot this
document supersedes).
