"""UC-01 registration, UC-02 login, UC-06 new device login."""
import pytest

import settings
from simulated_pc import ApiError
from software_authenticator import ORIGIN


def test_register_then_login_with_password_and_windows_hello(world):
    pc = world.pc("PC-1")
    session = pc.register("alice")
    me = session.ok("GET", "/me")
    assert me["username"] == "alice"
    assert me["device"]["tpm_mode"] == "SIMULATED"
    assert me["device"]["shared_pc"] is False

    again = pc.login("alice")
    assert again.token != session.token
    assert again.ok("GET", "/me")["username"] == "alice"


def test_wrong_password_is_rejected_without_revealing_which_part_was_wrong(world):
    pc = world.pc("PC-1")
    pc.register("alice")
    wrong_password = pc.call("POST", "/login/password", json={"username": "alice", "password": "nope-nope-1"})
    unknown_user = pc.call("POST", "/login/password", json={"username": "nobody", "password": "nope-nope-1"})
    assert wrong_password.status_code == unknown_user.status_code == 401
    assert wrong_password.json() == unknown_user.json()


def test_login_is_locked_after_repeated_failures(world):
    pc = world.pc("PC-1")
    pc.register("alice")
    for _ in range(settings.LOGIN_MAX_FAILURES):
        assert pc.call("POST", "/login/password", json={"username": "alice", "password": "bad-bad-bad"}).status_code == 401
    locked = pc.call("POST", "/login/password", json={"username": "alice", "password": "correct horse 1"})
    assert locked.status_code == 429


def test_wrong_otp_codes_stop_registration(world):
    pc = world.pc("PC-1")
    started = pc.post("/register/start", {"username": "alice", "password": "correct horse 1",
                                          "email": "alice@gmail.com", "phone": "+91 98765 43210"})
    response = pc.call("POST", "/register/verify", json={"flow_id": started["flow_id"], "email_code": "000000", "phone_code": "000000"})
    assert response.status_code == 400
    # and Windows Hello is never offered before the codes are right
    response = pc.call("POST", "/register/complete", json={"flow_id": started["flow_id"], "credential": {}})
    assert response.status_code == 400


def test_gmail_aliases_count_as_the_same_address(world):
    pc = world.pc("PC-1")
    pc.register("ravi", email="ra.vi@gmail.com")
    with pytest.raises(ApiError) as error:
        world.pc("PC-2").register("ravi2", email="ravi+spare@googlemail.com")
    assert error.value.status == 409


def test_username_must_be_unique_ignoring_case(world):
    world.pc("PC-1").register("Alice")
    with pytest.raises(ApiError) as error:
        world.pc("PC-2").register("alice")
    assert error.value.status == 409


def test_weak_password_and_bad_phone_are_refused(world):
    pc = world.pc("PC-1")
    assert pc.call("POST", "/register/start", json={"username": "alice", "password": "short", "email": "a@gmail.com", "phone": "+91 98765 43210"}).status_code == 400
    assert pc.call("POST", "/register/start", json={"username": "alice", "password": "long enough 1", "email": "a@gmail.com", "phone": "12"}).status_code == 400


def test_registration_from_the_wrong_origin_is_rejected(world):
    pc = world.pc("PC-1")
    started = pc.post("/register/start", {"username": "alice", "password": "correct horse 1",
                                          "email": "alice@gmail.com", "phone": "+91 98765 43210"})
    codes = started["demo_codes"]
    verified = pc.post("/register/verify", {"flow_id": started["flow_id"], "email_code": codes["email_code"], "phone_code": codes["phone_code"]})
    forged = pc.authenticator.create(verified["webauthn_options"], origin="http://evil.example")
    response = pc.call("POST", "/register/complete", json={"flow_id": started["flow_id"], "credential": forged})
    assert response.status_code == 400
    assert pc.call("POST", "/login/password", json={"username": "alice", "password": "correct horse 1"}).status_code == 401


def test_requests_without_tpm_information_are_refused(world):
    pc = world.pc("PC-1")
    response = pc.call("POST", "/register/start", header=False,
                       json={"username": "alice", "password": "correct horse 1", "email": "a@gmail.com", "phone": "+91 98765 43210"})
    assert response.status_code == 400
    assert "TPM" in response.json()["detail"]


def test_simulated_tpm_is_refused_when_the_server_wants_real_ones(world, monkeypatch):
    pc = world.pc("PC-1")
    started = pc.post("/register/start", {"username": "alice", "password": "correct horse 1",
                                          "email": "alice@gmail.com", "phone": "+91 98765 43210"})
    codes = started["demo_codes"]
    verified = pc.post("/register/verify", {"flow_id": started["flow_id"], "email_code": codes["email_code"], "phone_code": codes["phone_code"]})
    monkeypatch.setattr(settings, "ALLOW_SIMULATED_TPM", False)
    response = pc.call("POST", "/register/complete", json={"flow_id": started["flow_id"], "credential": pc.authenticator.create(verified["webauthn_options"])})
    assert response.status_code == 400


def test_login_from_a_new_pc_enrols_it_after_otp_and_windows_hello(world):
    """UC-06"""
    alice_pc1 = world.pc("PC-1").register("alice")
    new_pc = world.pc("PC-2")
    step = new_pc.post("/login/password", {"username": "alice", "password": "correct horse 1"})
    assert step["step"] == "NEW_DEVICE"        # password alone does not get a session on an unknown PC

    session = new_pc.login("alice")
    assert session.ok("GET", "/me")["username"] == "alice"
    linked = world.db.all("SELECT device_id FROM account_devices WHERE account_id = 1")
    assert len(linked) == 2
    assert "NEW_DEVICE_LINKED" in world.audit_events()
    # the next login from PC-2 is now a plain password + Windows Hello login
    assert new_pc.post("/login/password", {"username": "alice", "password": "correct horse 1"})["step"] == "WEBAUTHN"


def test_new_device_enrolment_needs_the_otp_codes(world):
    world.pc("PC-1").register("alice")
    new_pc = world.pc("PC-2")
    step = new_pc.post("/login/password", {"username": "alice", "password": "correct horse 1"})
    response = new_pc.call("POST", "/login/new-device/verify", json={"flow_id": step["flow_id"], "email_code": "111111", "phone_code": "222222"})
    assert response.status_code == 400


def test_login_ceremony_cannot_be_finished_on_another_pc(world):
    pc1, pc2 = world.pc("PC-1"), world.pc("PC-2")
    pc1.register("alice")
    step = pc1.post("/login/password", {"username": "alice", "password": "correct horse 1"})
    assertion = pc1.authenticator.get(step["webauthn_options"])
    response = pc2.call("POST", "/login/webauthn", json={"flow_id": step["flow_id"], "credential": assertion})
    assert response.status_code == 400


def test_a_stolen_password_with_someone_elses_windows_hello_fails(world):
    pc1, attacker_pc = world.pc("PC-1"), world.pc("PC-X")
    pc1.register("alice")
    attacker_pc.register("mallory")          # has a perfectly valid Windows Hello of its own
    step = pc1.post("/login/password", {"username": "alice", "password": "correct horse 1"})
    forged = attacker_pc.authenticator.get({**step["webauthn_options"], "allowCredentials": [
        {"id": next(iter(__import__("software_authenticator").b64url(c) for c in attacker_pc.authenticator.credentials))}]})
    response = pc1.call("POST", "/login/webauthn", json={"flow_id": step["flow_id"], "credential": forged})
    assert response.status_code == 401


def test_session_is_required_and_logout_ends_it(world):
    session = world.pc("PC-1").register("alice")
    assert world.pc("PC-1").call("GET", "/me").status_code == 401
    session.ok("POST", "/logout")
    assert session.call("GET", "/me").status_code == 401
