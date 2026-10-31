"""Search, conversations and messages. Every call goes through the Policy Engine."""
import clock
from errors import PimError

MAX_MESSAGE_LENGTH = 2000


class ChatService:
    def __init__(self, db, engine):
        self.db = db
        self.engine = engine

    def _account_by_username(self, username: str):
        row = self.db.one("SELECT id, username FROM accounts WHERE username = ?", ((username or "").strip(),))
        if not row:
            raise PimError(404, "User not found.")
        return row

    def _visible_peer(self, me: int, username: str):
        """Looks the peer up; a peer who blocked me looks exactly like a missing user."""
        peer = self._account_by_username(username)
        verdict = self.engine.evaluate_interaction(me, peer["id"])
        if not verdict.allowed and not verdict.visible_to_actor:
            raise PimError(404, "User not found.")
        return peer, verdict

    # --------------------------------------------------------------- search
    def search_users(self, me: int, query: str) -> list:
        query = (query or "").strip()
        if not query:
            return []
        like = query.replace("%", "").replace("_", "") + "%"
        rows = self.db.all("SELECT id, username FROM accounts WHERE username LIKE ? AND id != ? ORDER BY username LIMIT 25",
                           (like, me))
        return [{"username": r["username"]} for r in rows if self.engine.is_listed_for(me, r["id"])]

    # ------------------------------------------------------------- messages
    def send_message(self, me: int, to_username: str, body: str) -> dict:
        body = (body or "").strip()
        if not body:
            raise PimError(400, "Write a message first.")
        if len(body) > MAX_MESSAGE_LENGTH:
            raise PimError(400, f"Messages can have at most {MAX_MESSAGE_LENGTH} characters.")
        peer = self._account_by_username(to_username)
        verdict = self.engine.evaluate_interaction(me, peer["id"])
        if not verdict.allowed:
            if verdict.actor_is_blocker:
                raise PimError(403, "You blocked this user. Unblock them to send messages.")
            raise PimError(404, "User not found.")
        message_id = self.db.insert(
            "INSERT INTO messages (sender_id, recipient_id, body, delivery, created_at) VALUES (?, ?, ?, ?, ?)",
            (me, peer["id"], body, verdict.delivery, clock.now()))
        # The sender always sees a normal "sent": held or filed messages look the same to them.
        return {"id": message_id}

    def thread(self, me: int, peer_username: str, after_id: int = 0) -> dict:
        peer, _ = self._visible_peer(me, peer_username)
        rows = self.db.all(
            """SELECT id, sender_id, body, created_at FROM messages
               WHERE id > ? AND ((sender_id = ? AND recipient_id = ?)
                              OR (sender_id = ? AND recipient_id = ? AND delivery = 'INBOX'))
               ORDER BY id""",
            (after_id, me, peer["id"], peer["id"], me))
        self.db.execute(
            """UPDATE messages SET read_at = ? WHERE recipient_id = ? AND sender_id = ?
               AND delivery = 'INBOX' AND read_at IS NULL""", (clock.now(), me, peer["id"]))
        return {
            "peer": peer["username"],
            "messages": [{"id": r["id"], "mine": r["sender_id"] == me, "body": r["body"], "at": r["created_at"]}
                         for r in rows],
        }

    def conversations(self, me: int) -> list:
        rows = self.db.all(
            """SELECT a.id AS peer_id, a.username,
                      MAX(m.id) AS last_id,
                      SUM(CASE WHEN m.recipient_id = ? AND m.read_at IS NULL AND m.delivery = 'INBOX' THEN 1 ELSE 0 END) AS unread
               FROM messages m
               JOIN accounts a ON a.id = CASE WHEN m.sender_id = ? THEN m.recipient_id ELSE m.sender_id END
               WHERE (m.sender_id = ? OR (m.recipient_id = ? AND m.delivery = 'INBOX'))
               GROUP BY a.id, a.username ORDER BY last_id DESC""",
            (me, me, me, me))
        result = []
        for row in rows:
            verdict = self.engine.evaluate_interaction(me, row["peer_id"])
            if not verdict.allowed and not verdict.visible_to_actor:
                continue  # they blocked me: the conversation silently disappears
            last = self.db.one("SELECT body, sender_id FROM messages WHERE id = ?", (row["last_id"],))
            result.append({"username": row["username"], "last_message": last["body"][:80],
                           "last_was_mine": last["sender_id"] == me, "unread": row["unread"] or 0,
                           "blocked_by_me": verdict.actor_is_blocker})
        return result

    # ------------------------------------------------------------- requests
    def request_senders(self, me: int) -> list:
        rows = self.db.all(
            """SELECT a.username, COUNT(*) AS n, MAX(m.id) AS last_id FROM messages m
               JOIN accounts a ON a.id = m.sender_id
               WHERE m.recipient_id = ? AND m.delivery = 'REQUESTS' GROUP BY a.username ORDER BY last_id DESC""",
            (me,))
        return [{"username": r["username"], "count": r["n"]} for r in rows]

    def request_thread(self, me: int, sender_username: str) -> dict:
        sender = self._account_by_username(sender_username)
        rows = self.db.all(
            "SELECT id, body, created_at FROM messages WHERE recipient_id = ? AND sender_id = ? AND delivery = 'REQUESTS' ORDER BY id",
            (me, sender["id"]))
        return {"peer": sender["username"],
                "messages": [{"id": r["id"], "mine": False, "body": r["body"], "at": r["created_at"]} for r in rows]}
