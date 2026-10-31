"""Every security-relevant decision is written down so it can be shown in the
demo and reviewed in the threat model (repudiation)."""
import json
import time


def record(db, event: str, actor_id=None, subject_id=None, **detail):
    db.insert(
        "INSERT INTO audit_log (ts, event, actor_id, subject_id, detail) VALUES (?, ?, ?, ?, ?)",
        (time.time(), event, actor_id, subject_id, json.dumps(detail, default=str)),
    )


def recent(db, limit: int = 100):
    rows = db.all(
        """SELECT l.id, l.ts, l.event, l.detail, a.username AS actor, s.username AS subject
           FROM audit_log l
           LEFT JOIN accounts a ON a.id = l.actor_id
           LEFT JOIN accounts s ON s.id = l.subject_id
           ORDER BY l.id DESC LIMIT ?""",
        (limit,),
    )
    return [dict(r) for r in rows]
