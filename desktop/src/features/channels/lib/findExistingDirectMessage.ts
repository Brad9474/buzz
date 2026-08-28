import type { Channel } from "@/shared/api/types";
import { normalizePubkey } from "@/shared/lib/pubkey";

/**
 * Finds a cached DM channel whose participants exactly match the requested
 * set (self + recipients), so a compose flow can resume an existing
 * conversation instead of opening a blank one. Order-independent; a partial
 * overlap (e.g. composing a new group that happens to include one existing
 * 1:1 contact) is not a match.
 */
export function findExistingDirectMessage(
  channels: readonly Channel[],
  recipientPubkeys: readonly string[],
  currentPubkey: string | undefined,
): Channel | null {
  if (recipientPubkeys.length === 0) {
    return null;
  }

  const normalizedCurrentPubkey = currentPubkey
    ? normalizePubkey(currentPubkey)
    : null;
  const requestedPubkeys = new Set(
    recipientPubkeys
      .map(normalizePubkey)
      .filter((pubkey) => pubkey !== normalizedCurrentPubkey),
  );
  if (requestedPubkeys.size === 0) {
    return null;
  }

  return (
    channels.find((channel) => {
      if (channel.channelType !== "dm") {
        return false;
      }

      const otherParticipants = new Set(
        channel.participantPubkeys
          .map(normalizePubkey)
          .filter((pubkey) => pubkey !== normalizedCurrentPubkey),
      );

      return (
        otherParticipants.size === requestedPubkeys.size &&
        [...requestedPubkeys].every((pubkey) => otherParticipants.has(pubkey))
      );
    }) ?? null
  );
}
