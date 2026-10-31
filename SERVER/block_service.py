"""What a user can do with blocks (UC-03, UC-07, UC-08)."""
import audit_log
import clock
from errors import PimError


class BlockService:
    def __init__(self, db, engine):
        self.db = db
        self.engine = engine

    def _account_by_username(self, username: str):
        row = self.db.one("SELECT id, username FROM accounts WHERE username = ?", ((username or "").strip(),))
        if not row:
            raise PimError(404, "User not found.")
        return row

    def _own_row(self, block_id: int, account_id: int):
        row = self.db.one("SELECT * FROM blocks WHERE id = ? AND blocker_id = ?", (block_id, account_id))
        if not row or row["status"] != "ACTIVE":
            raise PimError(404, "That entry no longer exists.")
        return row

    def _deliver_held_messages(self, blocker_id: int, target_id: int):
        self.db.execute(
            """UPDATE messages SET delivery = 'INBOX'
               WHERE recipient_id = ? AND sender_id = ? AND delivery IN ('QUARANTINE', 'REQUESTS')""",
            (blocker_id, target_id))

    def _discard_held_messages(self, blocker_id: int, target_id: int):
        self.db.execute(
            """UPDATE messages SET delivery = 'DISCARDED'
               WHERE recipient_id = ? AND sender_id = ? AND delivery IN ('QUARANTINE', 'REQUESTS')""",
            (blocker_id, target_id))

    # ------------------------------------------------------------------ queries
    def overview(self, account_id: int) -> dict:
        rows = self.db.all(
            """SELECT b.*, t.username AS target_username, r.id AS root_id, rt.username AS root_username,
                      (SELECT COUNT(*) FROM messages m WHERE m.recipient_id = b.blocker_id AND m.sender_id = b.target_id
                         AND m.delivery IN ('QUARANTINE', 'REQUESTS')) AS held_messages
               FROM blocks b
               JOIN accounts t ON t.id = b.target_id
               LEFT JOIN blocks r ON r.id = b.root_block_id
               LEFT JOIN accounts rt ON rt.id = r.target_id
               WHERE b.blocker_id = ? AND b.status = 'ACTIVE'
               ORDER BY b.created_at DESC""",
            (account_id,))
        result = {"blocked": [], "auto_blocked": [], "needs_review": [], "message_requests": []}
        for row in rows:
            item = {
                "id": row["id"], "username": row["target_username"], "mode": row["mode"], "origin": row["origin"],
                "reason": row["reason"], "created_at": row["created_at"], "held_messages": row["held_messages"],
                "linked_to": row["root_username"],
            }
            if row["mode"] == "BLOCK" and row["origin"] in ("MANUAL", "CONFIRMED"):
                result["blocked"].append(item)
            elif row["mode"] == "BLOCK":
                result["auto_blocked"].append(item)
            elif row["mode"] == "SOFT":
                result["needs_review"].append(item)
            else:
                result["message_requests"].append(item)
        return result

    # ---------------------------------------------------------------- UC-03
    def block_user(self, account_id: int, username: str) -> dict:
        target = self._account_by_username(username)
        if target["id"] == account_id:
            raise PimError(400, "You cannot block yourself.")
        with self.db.transaction():
            block_id = self.engine.apply_manual_block(account_id, target["id"])
            self._discard_held_messages(account_id, target["id"])
        return {"id": block_id, "username": target["username"]}

    # ---------------------------------------------------------------- UC-08
    def unblock(self, account_id: int, block_id: int) -> None:
        with self.db.transaction():
            row = self._own_row(block_id, account_id)
            if row["mode"] != "BLOCK":
                raise PimError(400, "Use Allow or Block on this entry.")
            now = clock.now()
            if row["root_block_id"] is None:
                # The manual block itself: everything that was derived from it goes away too.
                derived = self.db.all(
                    "SELECT id, target_id FROM blocks WHERE root_block_id = ? AND status = 'ACTIVE'", (block_id,))
                for item in derived:
                    self._deliver_held_messages(account_id, item["target_id"])
                    self.db.execute("DELETE FROM blocks WHERE id = ?", (item["id"],))
                self.db.execute("UPDATE blocks SET status = 'RELEASED', updated_at = ? WHERE id = ?", (now, block_id))
                audit_log.record(self.db, "BLOCK_REMOVED", actor_id=account_id, subject_id=row["target_id"],
                                 block_id=block_id, cascaded=len(derived))
            else:
                # One wrongly linked account: only it is freed, and it stays freed ("not the same person").
                self.db.execute("UPDATE blocks SET status = 'RELEASED', updated_at = ? WHERE id = ?", (now, block_id))
                audit_log.record(self.db, "LINKED_BLOCK_REMOVED", actor_id=account_id, subject_id=row["target_id"],
                                 block_id=block_id, origin=row["origin"])

    # ---------------------------------------------------------------- UC-07
    def confirm_block(self, account_id: int, block_id: int) -> None:
        """The blocker agrees that a soft-blocked / requesting account is the same person."""
        with self.db.transaction():
            row = self._own_row(block_id, account_id)
            if row["mode"] not in ("SOFT", "REQUEST"):
                raise PimError(400, "This account is already blocked.")
            self.db.execute(
                "UPDATE blocks SET mode = 'BLOCK', origin = 'CONFIRMED', updated_at = ? WHERE id = ?",
                (clock.now(), block_id))
            self._discard_held_messages(account_id, row["target_id"])
            audit_log.record(self.db, "SOFT_BLOCK_CONFIRMED", actor_id=account_id, subject_id=row["target_id"],
                             block_id=block_id)

    def allow(self, account_id: int, block_id: int) -> None:
        """The blocker says this is a different person: held messages are delivered."""
        with self.db.transaction():
            row = self._own_row(block_id, account_id)
            if row["mode"] not in ("SOFT", "REQUEST"):
                raise PimError(400, "Use Unblock on a blocked account.")
            self.db.execute("UPDATE blocks SET status = 'RELEASED', updated_at = ? WHERE id = ?",
                            (clock.now(), block_id))
            self._deliver_held_messages(account_id, row["target_id"])
            audit_log.record(self.db, "SOFT_BLOCK_ALLOWED", actor_id=account_id, subject_id=row["target_id"],
                             block_id=block_id)
