"""The Policy Engine: decides what a block means.

Signal priority is TPM > phone number > Gmail.

When a block exists, three situations can arise, and the engine handles each:

1. A NEW account appears (UC-04)           -> evaluate_new_account()
2. A new device is linked to an account    -> evaluate_new_account(device_ids=[...])
3. The blocker blocks someone who already
   has other accounts around (UC-03)       -> apply_manual_block()
4. Two accounts try to interact (UC-05)    -> evaluate_interaction()

TPM match rules (the heart of the design):
  * The PC was already shared by 2+ accounts BEFORE the block was made
        -> SOFT: the blocker is asked; messages are held back.
    (A family PC must not silently block the whole family.)
  * Otherwise the PC was a single-person PC (or only became shared AFTER the
    block, which is exactly what block evasion looks like)
        -> BLOCK: treated as the same person, blocked automatically.
Phone match without a TPM match -> REQUEST: messages go to a requests folder.

The Gmail signal is applied earlier, at registration: an address that
normalises to an existing one is refused outright (see account_service).

Blocks are stored one row per (blocker, account). A new account's rows are
written in the same transaction that creates the account, so there is no window
in which the blocked person could slip a message through.
"""
from dataclasses import dataclass
from typing import List, Optional

import audit_log
import clock
import device_service

MODE_RANK = {"BLOCK": 3, "SOFT": 2, "REQUEST": 1}


@dataclass
class PolicyDecision:
    blocker_id: int
    target_id: int
    mode: str
    origin: str
    reason: str


@dataclass
class InteractionVerdict:
    allowed: bool
    delivery: Optional[str] = None    # INBOX, REQUESTS or QUARANTINE
    reason: str = ""
    visible_to_actor: bool = True     # False -> the target must look like "user not found"
    actor_is_blocker: bool = False


class PolicyEngine:
    def __init__(self, db):
        self.db = db

    # ------------------------------------------------------------------ helpers
    def _username(self, account_id: int) -> str:
        row = self.db.one("SELECT username FROM accounts WHERE id = ?", (account_id,))
        return row["username"] if row else f"#{account_id}"

    def _blocked_targets_of(self, blocker_id: int):
        """The accounts this blocker currently blocks outright, together with the
        time of the manual block they trace back to."""
        return self.db.all(
            """SELECT b.id, b.target_id, COALESCE(b.root_block_id, b.id) AS root_id,
                      root.created_at AS root_created_at
               FROM blocks b
               JOIN blocks root ON root.id = COALESCE(b.root_block_id, b.id)
               WHERE b.blocker_id = ? AND b.mode = 'BLOCK' AND b.status = 'ACTIVE'""",
            (blocker_id,),
        )

    def _existing_row(self, blocker_id: int, target_id: int):
        return self.db.one(
            "SELECT * FROM blocks WHERE blocker_id = ? AND target_id = ? ORDER BY id DESC LIMIT 1",
            (blocker_id, target_id),
        )

    def _write_row(self, decision: PolicyDecision, root_block_id: int) -> Optional[int]:
        """Creates (or strengthens) the row for a decision. A released row is an
        explicit 'this is not the same person' from the blocker and is respected."""
        existing = self._existing_row(decision.blocker_id, decision.target_id)
        now = clock.now()
        if existing:
            if existing["status"] == "RELEASED":
                return None
            if MODE_RANK[existing["mode"]] >= MODE_RANK[decision.mode]:
                return existing["id"]
            self.db.execute(
                """UPDATE blocks SET mode = ?, origin = ?, root_block_id = ?, reason = ?, updated_at = ?
                   WHERE id = ?""",
                (decision.mode, decision.origin, root_block_id, decision.reason, now, existing["id"]),
            )
            return existing["id"]
        return self.db.insert(
            """INSERT INTO blocks (blocker_id, target_id, mode, origin, status, root_block_id, reason, created_at, updated_at)
               VALUES (?, ?, ?, ?, 'ACTIVE', ?, ?, ?, ?)""",
            (decision.blocker_id, decision.target_id, decision.mode, decision.origin, root_block_id,
             decision.reason, now, now),
        )

    # ------------------------------------------------- new account / new device
    def evaluate_new_account(self, account_id: int, device_ids: Optional[List[int]] = None,
                             check_phone: bool = True) -> List[PolicyDecision]:
        """Runs when an account is created or gets a new device. Call it inside
        the transaction that creates the account."""
        account = self.db.one("SELECT * FROM accounts WHERE id = ?", (account_id,))
        if device_ids is None:
            device_ids = device_service.device_ids_of(self.db, account_id)
        blockers = [r["blocker_id"] for r in self.db.all(
            "SELECT DISTINCT blocker_id FROM blocks WHERE mode = 'BLOCK' AND status = 'ACTIVE' AND blocker_id != ?",
            (account_id,))]
        decisions: List[PolicyDecision] = []

        for blocker_id in blockers:
            best: Optional[PolicyDecision] = None
            best_root = None
            for blocked in self._blocked_targets_of(blocker_id):
                other_id = blocked["target_id"]
                if other_id == account_id:
                    continue
                candidate = None

                # 1) TPM: the strongest signal
                for device_id in device_ids:
                    if not device_service.is_linked(self.db, other_id, device_id):
                        continue
                    earlier_shared = device_service.shared_since(self.db, device_id, exclude_account_id=account_id)
                    if earlier_shared is not None and earlier_shared < blocked["root_created_at"]:
                        candidate = PolicyDecision(
                            blocker_id, account_id, "SOFT", "TPM",
                            f"Shares a PC with {self._username(other_id)}, whom you blocked. "
                            "The PC was already shared before the block, so this might be a different person.")
                    else:
                        candidate = PolicyDecision(
                            blocker_id, account_id, "BLOCK", "TPM",
                            f"Uses the same TPM-verified PC as {self._username(other_id)}, whom you blocked.")
                        break

                # 2) phone number, only when the TPM did not match
                if candidate is None and check_phone and account["phone_normalized"] == self._phone_of(other_id):
                    candidate = PolicyDecision(
                        blocker_id, account_id, "REQUEST", "PHONE",
                        f"Uses the same phone number as {self._username(other_id)}, whom you blocked.")

                if candidate and (best is None or MODE_RANK[candidate.mode] > MODE_RANK[best.mode]):
                    best, best_root = candidate, blocked["root_id"]

            if best:
                row_id = self._write_row(best, best_root)
                if row_id is not None:
                    decisions.append(best)
                    audit_log.record(
                        self.db, "POLICY_DECISION", actor_id=blocker_id, subject_id=account_id,
                        mode=best.mode, origin=best.origin, reason=best.reason, trigger="NEW_ACCOUNT_OR_DEVICE")
        return decisions

    def _phone_of(self, account_id: int) -> Optional[str]:
        row = self.db.one("SELECT phone_normalized FROM accounts WHERE id = ?", (account_id,))
        return row["phone_normalized"] if row else None

    # ------------------------------------------------------------ manual block
    def apply_manual_block(self, blocker_id: int, target_id: int) -> int:
        """UC-03. Blocks the target and looks for the target's other existing
        accounts. Call inside a transaction."""
        if blocker_id == target_id:
            raise ValueError("cannot block yourself")
        now = clock.now()
        existing = self._existing_row(blocker_id, target_id)
        if existing and existing["status"] == "ACTIVE" and existing["mode"] == "BLOCK" \
                and existing["origin"] in ("MANUAL", "CONFIRMED"):
            return existing["id"]
        if existing:
            block_id = existing["id"]
            self.db.execute(
                """UPDATE blocks SET mode = 'BLOCK', origin = 'MANUAL', status = 'ACTIVE', root_block_id = NULL,
                          reason = 'Blocked by you', created_at = ?, updated_at = ? WHERE id = ?""",
                (now, now, block_id))
        else:
            block_id = self.db.insert(
                """INSERT INTO blocks (blocker_id, target_id, mode, origin, status, root_block_id, reason, created_at, updated_at)
                   VALUES (?, ?, 'BLOCK', 'MANUAL', 'ACTIVE', NULL, 'Blocked by you', ?, ?)""",
                (blocker_id, target_id, now, now))
        audit_log.record(self.db, "BLOCK_CREATED", actor_id=blocker_id, subject_id=target_id, block_id=block_id)

        # Other existing accounts of the same person. Every device the target uses
        # has at least two accounts then, so it was shared BEFORE this block: SOFT.
        related = {}
        for device_id in device_service.device_ids_of(self.db, target_id):
            for other_id in device_service.account_ids_on(self.db, device_id):
                if other_id not in (target_id, blocker_id):
                    related[other_id] = ("SOFT", "TPM",
                                         f"Shares a PC with {self._username(target_id)}, whom you blocked. "
                                         "The PC is shared, so this might be a different person.")
        target_phone = self._phone_of(target_id)
        for row in self.db.all("SELECT id FROM accounts WHERE phone_normalized = ? AND id NOT IN (?, ?)",
                               (target_phone, target_id, blocker_id)):
            related.setdefault(row["id"], ("REQUEST", "PHONE",
                                           f"Uses the same phone number as {self._username(target_id)}, whom you blocked."))
        for other_id, (mode, origin, reason) in related.items():
            decision = PolicyDecision(blocker_id, other_id, mode, origin, reason)
            if self._write_row(decision, block_id) is not None:
                audit_log.record(self.db, "POLICY_DECISION", actor_id=blocker_id, subject_id=other_id,
                                 mode=mode, origin=origin, reason=reason, trigger="MANUAL_BLOCK")
        return block_id

    # ------------------------------------------------------------- interactions
    def evaluate_interaction(self, actor_id: int, target_id: int) -> InteractionVerdict:
        """UC-05. Called for every search result, profile view and message.
        Fails closed: if anything goes wrong the interaction is denied."""
        try:
            if actor_id == target_id:
                return InteractionVerdict(False, reason="SELF", visible_to_actor=False)

            # Has the target restricted the actor?
            row = self.db.one(
                """SELECT mode FROM blocks WHERE blocker_id = ? AND target_id = ? AND status = 'ACTIVE'
                   ORDER BY CASE mode WHEN 'BLOCK' THEN 3 WHEN 'SOFT' THEN 2 ELSE 1 END DESC LIMIT 1""",
                (target_id, actor_id))
            if row:
                if row["mode"] == "BLOCK":
                    return InteractionVerdict(False, reason="TARGET_BLOCKED_ACTOR", visible_to_actor=False)
                delivery = "QUARANTINE" if row["mode"] == "SOFT" else "REQUESTS"
                return InteractionVerdict(True, delivery=delivery, reason=f"TARGET_{row['mode']}")

            # Has the actor blocked the target?
            mine = self.db.one(
                "SELECT 1 FROM blocks WHERE blocker_id = ? AND target_id = ? AND status = 'ACTIVE' AND mode = 'BLOCK'",
                (actor_id, target_id))
            if mine:
                return InteractionVerdict(False, reason="ACTOR_BLOCKED_TARGET", actor_is_blocker=True)
            return InteractionVerdict(True, delivery="INBOX", reason="ALLOWED")
        except Exception as error:  # fail closed
            try:
                audit_log.record(self.db, "POLICY_ENGINE_ERROR", actor_id=actor_id, subject_id=target_id,
                                 error=str(error))
            except Exception:
                pass  # the database being down is exactly why we are here; still deny
            return InteractionVerdict(False, reason="POLICY_ERROR", visible_to_actor=False)

    def is_listed_for(self, actor_id: int, target_id: int) -> bool:
        """Should the target show up in the actor's search results?"""
        verdict = self.evaluate_interaction(actor_id, target_id)
        if not verdict.visible_to_actor or verdict.actor_is_blocker:
            return False
        hidden = self.db.one(
            "SELECT 1 FROM blocks WHERE blocker_id = ? AND target_id = ? AND status = 'ACTIVE' AND mode = 'SOFT'",
            (actor_id, target_id))
        return hidden is None
