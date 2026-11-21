"""DETERMINISTIC collateral exposure limits (docs/offline-chained-payments.md, §Exposure).

Pure function, critical for consensus: given a slot's state and a claim that lost the race
(conflict), computes how much the collateral pays, or refuses. The result depends only on on-chain state and on the
claim, never on off-chain data, and the order is the order of application on the chain.

Rules (R1-R5, R8, R9):
  R1  the sum of the slot's compensations never exceeds the slot's remaining collateral;
  R2  for each contested note, the sum of compensations never exceeds that note's VALUE
      (what was actually at stake), no matter how many losing branches exist;
  R3  the same claim/voucher is compensated at most once (resubmission is refused);
  R4  each compensation is at most the value of the claimed leaf;
  R5  payment order = order of application on the chain (block, position); once the cap is exhausted, the rest get 0;
  R8  a compensation below the minimum is refused (avoids dust and state growth);
  R9  at most `max_events` compensations per slot (bounds state and verification cost).
"""
from ..errors import ValidationError


def plan_compensation(*, collateral_left: int, compensated_total: int, contested_value: int,
                      paid_leaves, max_events: int, leaf_id: str, leaf_value: int,
                      min_payout: int) -> int:
    """Returns the amount to compensate (> 0) or raises ValidationError.

    `compensated_total`: sum already compensated for THIS contested note.
    `paid_leaves`: ids of claims already compensated in the slot.
    """
    if leaf_value <= 0 or contested_value <= 0:
        raise ValidationError("invalid compensation values")
    if leaf_id in paid_leaves:
        raise ValidationError("claim already compensated")                                   # R3
    if len(paid_leaves) >= max_events:
        raise ValidationError("slot compensation limit reached")               # R9
    if collateral_left <= 0:
        raise ValidationError("slot collateral exhausted")                            # R1
    room = contested_value - compensated_total
    if room <= 0:
        raise ValidationError("compensation limit for the contested value reached")    # R2
    payout = min(leaf_value, collateral_left, room)                                    # R1, R2, R4
    if payout < min_payout:
        raise ValidationError("compensation below the minimum")                          # R8
    return payout
