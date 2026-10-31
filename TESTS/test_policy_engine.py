"""UC-03 / UC-04 / UC-05: what a block means. TPM > phone > Gmail."""
from simulated_pc import ApiError  # noqa: F401  (kept for readability of failures)


def not_found(response):
    return response.status_code == 404 and response.json()["detail"] == "User not found."


# --------------------------------------------------------------------------- basics
def test_unrelated_users_chat_normally(world):
    alice = world.pc("PC-1").register("alice")
    bob = world.pc("PC-2").register("bob")
    assert bob.send("alice", "hi alice").status_code == 200
    assert alice.bodies("bob") == ["hi alice"]
    assert alice.send("bob", "hi bob").status_code == 200
    assert bob.bodies("alice") == ["hi alice", "hi bob"]
    assert alice.search("bo") == ["bob"]


def test_a_manual_block_hides_the_blocker_and_stops_messages(world):
    alice = world.pc("PC-1").register("alice")
    bob = world.pc("PC-2").register("bob")
    bob.send("alice", "before the block")
    alice.block("bob")

    assert not_found(bob.send("alice", "after the block"))
    assert not_found(bob.thread("alice"))
    assert bob.search("ali") == []                       # alice is invisible to bob
    assert "alice" not in bob.conversations()            # and the old conversation disappears
    assert alice.search("bo") == []                      # alice no longer finds bob either
    # alice herself is told why she cannot write to bob
    refused = alice.send("bob", "hello?")
    assert refused.status_code == 403
    # a blocked person cannot tell a block from a non-existent user
    missing = bob.call("POST", "/messages", json={"to": "does_not_exist", "body": "x"})
    assert missing.status_code == 404 and missing.json() == bob.send("alice", "x").json()


def test_blocking_yourself_or_a_stranger_is_refused(world):
    alice = world.pc("PC-1").register("alice")
    assert alice.call("POST", "/blocks", json={"username": "alice"}).status_code == 400
    assert alice.call("POST", "/blocks", json={"username": "nobody"}).status_code == 404


# ------------------------------------------------------------------ TPM: same person
def test_new_account_on_the_blockers_target_pc_is_blocked_automatically(world):
    """The core scenario: bob is blocked, then makes a fresh account on the same PC."""
    alice = world.pc("PC-1").register("alice")
    bob_pc = world.pc("PC-2")
    bob = bob_pc.register("bob")
    alice.block("bob")

    bob2 = bob_pc.register("bob_again", email="completely.new@gmail.com", phone="+91 77777 77777")
    assert not_found(bob2.send("alice", "it's me, bob"))
    assert bob2.search("ali") == []
    entry = alice.entry("auto_blocked", "bob_again")
    assert entry and entry["origin"] == "TPM" and entry["linked_to"] == "bob"
    decisions = [r for r in world.db.all("SELECT detail FROM audit_log WHERE event = 'POLICY_DECISION'")]
    assert any('"BLOCK"' in d["detail"] and '"TPM"' in d["detail"] for d in decisions)


def test_tpm_outranks_phone_number(world):
    alice = world.pc("PC-1").register("alice")
    bob_pc = world.pc("PC-2")
    bob = bob_pc.register("bob", phone="+91 55555 55555")
    alice.block("bob")
    # same PC AND same phone: the stronger TPM verdict (hard block) wins over the phone verdict (request)
    twin = bob_pc.register("twin", phone="+91 55555 55555")
    assert alice.entry("auto_blocked", "twin")["origin"] == "TPM"
    assert alice.entry("message_requests", "twin") is None
    assert not_found(twin.send("alice"))


def test_different_pc_and_different_phone_is_not_linked(world):
    alice = world.pc("PC-1").register("alice")
    bob = world.pc("PC-2").register("bob")
    alice.block("bob")
    stranger = world.pc("PC-3").register("bob_on_a_borrowed_pc", phone="+91 66666 66666")
    assert stranger.send("alice", "hi").status_code == 200     # the known limitation: new PC + new phone evades
    assert alice.bodies("bob_on_a_borrowed_pc") == ["hi"]
    assert alice.blocks()["auto_blocked"] == []


# ------------------------------------------------------------------ TPM: shared PC
def test_family_pc_shared_before_the_block_gives_a_soft_block(world):
    alice = world.pc("PC-1").register("alice")
    family_pc = world.pc("FAMILY-PC")
    ravi = family_pc.register("ravi")
    priya = family_pc.register("priya")        # second account: the PC is shared from now on
    alice.block("ravi")

    entry = alice.entry("needs_review", "priya")
    assert entry and entry["mode"] == "SOFT" and entry["origin"] == "TPM"
    # priya is not told anything and can still write: her message is only held back
    assert priya.send("alice", "hello alice").status_code == 200
    assert alice.bodies("priya") == []                             # not in alice's inbox
    assert "priya" not in alice.conversations()
    assert alice.search("pri") == []                               # hidden until alice decides
    assert alice.entry("needs_review", "priya")["held_messages"] == 1
    # ravi, on the other hand, is blocked outright
    assert not_found(ravi.send("alice"))


def test_soft_block_allowed_delivers_the_held_messages(world):
    alice = world.pc("PC-1").register("alice")
    family_pc = world.pc("FAMILY-PC")
    family_pc.register("ravi")
    priya = family_pc.register("priya")
    alice.block("ravi")
    priya.send("alice", "first")
    priya.send("alice", "second")

    alice.action(alice.entry("needs_review", "priya")["id"], "allow")
    assert alice.bodies("priya") == ["first", "second"]
    assert priya.send("alice", "third").status_code == 200
    assert alice.bodies("priya")[-1] == "third"
    assert alice.blocks()["needs_review"] == []
    assert "SOFT_BLOCK_ALLOWED" in world.audit_events()


def test_soft_block_confirmed_becomes_a_real_block(world):
    alice = world.pc("PC-1").register("alice")
    family_pc = world.pc("FAMILY-PC")
    family_pc.register("ravi")
    priya = family_pc.register("priya")
    alice.block("ravi")
    priya.send("alice", "held")

    alice.action(alice.entry("needs_review", "priya")["id"], "confirm")
    assert not_found(priya.send("alice", "now blocked"))
    assert alice.entry("blocked", "priya")["origin"] == "CONFIRMED"
    assert alice.bodies("ravi") == []
    assert world.db.one("SELECT COUNT(*) AS n FROM messages WHERE delivery = 'DISCARDED'")["n"] == 1


def test_new_account_on_a_pc_that_was_shared_before_the_block_is_only_soft_blocked(world):
    alice = world.pc("PC-1").register("alice")
    family_pc = world.pc("FAMILY-PC")
    family_pc.register("ravi")
    family_pc.register("priya")
    alice.block("ravi")
    cousin = family_pc.register("cousin")
    assert alice.entry("needs_review", "cousin")["mode"] == "SOFT"
    assert cousin.send("alice", "hi").status_code == 200
    assert alice.bodies("cousin") == []


def test_family_member_registering_after_the_block_is_auto_blocked_but_can_be_freed(world):
    """The accepted trade-off of ranking TPM first, and its escape hatch (UC-07)."""
    alice = world.pc("PC-1").register("alice")
    family_pc = world.pc("FAMILY-PC")
    family_pc.register("ravi")
    alice.block("ravi")
    priya = family_pc.register("priya")             # joins AFTER the block
    entry = alice.entry("auto_blocked", "priya")
    assert entry["mode"] == "BLOCK"
    assert not_found(priya.send("alice"))

    alice.unblock(entry["id"])                       # "not the same person"
    assert priya.send("alice", "hi alice").status_code == 200
    assert alice.bodies("priya") == ["hi alice"]
    assert alice.entry("blocked", "ravi") is not None      # ravi stays blocked
    # blocking ravi again later must not drag priya back in
    ravi_block_id = alice.entry("blocked", "ravi")["id"]
    alice.unblock(ravi_block_id)
    alice.block("ravi")
    assert priya.send("alice", "still fine").status_code == 200


def test_blocking_a_person_with_an_existing_second_account_soft_blocks_that_account(world):
    alice = world.pc("PC-1").register("alice")
    bob_pc = world.pc("PC-2")
    bob_pc.register("bob")
    bob_pc.register("bob_alt")                 # both existed before the block: the PC is shared
    alice.block("bob")
    assert alice.entry("needs_review", "bob_alt")["mode"] == "SOFT"


# ------------------------------------------------------------------------- phone
def test_phone_match_without_tpm_match_goes_to_message_requests(world):
    alice = world.pc("PC-1").register("alice")
    bob = world.pc("PC-2").register("bob", phone="+91 88888 88888")
    alice.block("bob")
    carol = world.pc("PC-3").register("carol", phone="088888 88888")       # same number, written differently
    entry = alice.entry("message_requests", "carol")
    assert entry and entry["origin"] == "PHONE"

    assert carol.send("alice", "hi, it is carol").status_code == 200         # nothing visible to carol
    assert alice.bodies("carol") == []
    assert [r["username"] for r in alice.ok("GET", "/requests")["senders"]] == ["carol"]
    assert alice.ok("GET", "/requests/carol")["messages"][0]["body"] == "hi, it is carol"
    assert carol.search("ali") == ["alice"]                                   # not hidden, only filed

    alice.action(entry["id"], "allow")                                       # accept
    assert alice.bodies("carol") == ["hi, it is carol"]


def test_phone_match_can_be_turned_into_a_block(world):
    alice = world.pc("PC-1").register("alice")
    world.pc("PC-2").register("bob", phone="+91 88888 88888")
    alice.block("bob")
    carol = world.pc("PC-3").register("carol", phone="+91 88888 88888")
    carol.send("alice", "x")
    alice.action(alice.entry("message_requests", "carol")["id"], "confirm")
    assert not_found(carol.send("alice", "y"))


def test_blocking_someone_files_existing_phone_sharers_as_requests(world):
    alice = world.pc("PC-1").register("alice")
    world.pc("PC-2").register("bob", phone="+91 99999 11111")
    world.pc("PC-3").register("sister", phone="+91 99999 11111")
    alice.block("bob")
    assert alice.entry("message_requests", "sister") is not None


# ------------------------------------------------------------------------- gmail
def test_gmail_alias_of_a_blocked_account_is_refused_and_logged(world):
    alice = world.pc("PC-1").register("alice")
    world.pc("PC-2").register("bob", email="b.o.b@gmail.com")
    alice.block("bob")
    try:
        world.pc("PC-3").register("bob_again", email="bob+new@gmail.com")
        assert False, "alias registration must fail"
    except ApiError as error:
        assert error.status == 409
    assert "EMAIL_ALIAS_EVASION_ATTEMPT" in world.audit_events()


# ------------------------------------------------------------------ unblock / cascade
def test_unblocking_the_original_block_frees_every_linked_account(world):
    alice = world.pc("PC-1").register("alice")
    bob_pc = world.pc("PC-2")
    bob = bob_pc.register("bob")
    alice.block("bob")
    bob2 = bob_pc.register("bob2")
    carol = world.pc("PC-3").register("carol", phone=world.db.one("SELECT phone_normalized FROM accounts WHERE username='bob'")["phone_normalized"])
    assert alice.entry("auto_blocked", "bob2") and alice.entry("message_requests", "carol")
    carol.send("alice", "pending request")

    alice.unblock(alice.entry("blocked", "bob")["id"])
    blocks = alice.blocks()
    assert blocks["blocked"] == blocks["auto_blocked"] == blocks["message_requests"] == []
    assert bob.send("alice", "free again").status_code == 200
    assert bob2.send("alice", "me too").status_code == 200
    assert alice.bodies("carol") == ["pending request"]     # the held message was delivered
    assert "BLOCK_REMOVED" in world.audit_events()


def test_blocking_again_after_unblocking_re_applies_the_policy(world):
    alice = world.pc("PC-1").register("alice")
    bob_pc = world.pc("PC-2")
    bob_pc.register("bob")
    alice.block("bob")
    bob2 = bob_pc.register("bob2")
    alice.unblock(alice.entry("blocked", "bob")["id"])
    alice.block("bob")
    # bob and bob2 share the PC since before this new block, so the engine asks alice instead of blocking silently
    assert alice.entry("needs_review", "bob2")["mode"] == "SOFT"
    assert alice.entry("auto_blocked", "bob2") is None


def test_blocks_of_one_user_do_not_affect_other_users(world):
    alice = world.pc("PC-1").register("alice")
    carol = world.pc("PC-3").register("carol")
    bob_pc = world.pc("PC-2")
    bob = bob_pc.register("bob")
    alice.block("bob")
    bob2 = bob_pc.register("bob2")
    assert not_found(bob2.send("alice"))
    assert bob2.send("carol", "hello carol").status_code == 200      # only alice is protected
    assert carol.bodies("bob2") == ["hello carol"]


# --------------------------------------------------------------- new device (UC-06)
def test_linking_a_blocked_pc_to_an_existing_account_triggers_the_policy(world):
    alice = world.pc("PC-1").register("alice")
    bob_pc = world.pc("PC-2")
    bob_pc.register("bob")
    dave_home = world.pc("PC-4")
    dave = dave_home.register("dave")
    alice.block("bob")
    assert alice.entry("auto_blocked", "dave") is None
    dave_on_bobs_pc = bob_pc.login("dave")            # dave signs in on bob's PC: enrolment links that PC to dave
    assert alice.entry("auto_blocked", "dave") is not None
    assert not_found(dave_on_bobs_pc.send("alice"))


# ----------------------------------------------------------------- fail closed
def test_policy_engine_fails_closed(world):
    alice = world.pc("PC-1").register("alice")
    world.pc("PC-2").register("bob")
    engine = world.app.state.services.engine

    class BrokenDatabase:
        def one(self, *args, **kwargs):
            raise RuntimeError("database down")

        def insert(self, *args, **kwargs):
            raise RuntimeError("database down")

    real_db = engine.db
    engine.db = BrokenDatabase()
    try:
        verdict = engine.evaluate_interaction(1, 2)
    finally:
        engine.db = real_db
    assert verdict.allowed is False and verdict.visible_to_actor is False
