import type { Channel } from "@/shared/api/types";

type ChannelParticipant = {
  fallbackName: string | null;
  pubkey: string;
};

/**
 * Selects which of a DM channel's participants should render as sidebar
 * avatar/label rows. Filters out self and any participant whose fallback
 * name matches the owner's "note to self" labels. When that leaves nothing
 * (a genuine self-DM), falls back to the full participant list — UNLESS
 * memberCount (server-authoritative) says there are more real participants
 * than participantPubkeys currently holds. That mismatch means the peer
 * hasn't landed in the cache yet (a brief race right after
 * openDm/upsertCachedChannel), not that this is really a self-DM — return no
 * rows rather than a misleading self stand-in.
 */
export function resolveVisibleDmParticipants(
  channel: Channel,
  currentPubkey: string | undefined,
  selfDmLabels: ReadonlySet<string>,
): ChannelParticipant[] {
  const participants = channel.participantPubkeys.map((pubkey, index) => ({
    fallbackName: channel.participants[index] ?? null,
    pubkey,
  }));
  const otherParticipants = participants.filter((participant) => {
    if (participant.pubkey.toLowerCase() === currentPubkey?.toLowerCase()) {
      return false;
    }

    const participantLabel =
      participant.fallbackName?.trim().toLowerCase() ?? null;
    return !participantLabel || !selfDmLabels.has(participantLabel);
  });

  if (otherParticipants.length > 0) {
    return otherParticipants;
  }

  const isParticipantListIncomplete =
    channel.memberCount > participants.length;
  return isParticipantListIncomplete ? [] : participants;
}
