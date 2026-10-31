"""The client agent: serves the GUI, adds the TPM identity to forwarded calls."""
from fastapi.testclient import TestClient

from client_agent import create_agent_app
from software_authenticator import SoftwareAuthenticator
from tpm_reader import read_simulated_tpm


def make_agent(world, tpm_name):
    info = read_simulated_tpm(tpm_name)
    return TestClient(create_agent_app("http://testserver", info, http_client=world.client)), info


def test_agent_serves_the_chat_page_and_reports_status(world):
    agent, info = make_agent(world, "AGENT-PC")
    page = agent.get("/")
    assert page.status_code == 200 and "PIM Chat" in page.text
    assert agent.get("/chat_app.js").status_code == 200
    status = agent.get("/agent/status").json()
    assert status["tpm_mode"] == "SIMULATED" and status["server_reachable"] is True


def test_full_registration_and_chat_through_the_agent(world):
    """The browser never sends the device header; the agent adds it."""
    agent, _ = make_agent(world, "AGENT-PC")
    authenticator = SoftwareAuthenticator()
    started = agent.post("/api/register/start", json={"username": "alice", "password": "correct horse 1",
                                                      "email": "alice@gmail.com", "phone": "+91 98765 43210"}).json()
    codes = started["demo_codes"]
    options = agent.post("/api/register/verify", json={"flow_id": started["flow_id"], "email_code": codes["email_code"],
                                                       "phone_code": codes["phone_code"]}).json()["webauthn_options"]
    done = agent.post("/api/register/complete", json={"flow_id": started["flow_id"],
                                                      "credential": authenticator.create(options)}).json()
    me = agent.get("/api/me", headers={"authorization": "Bearer " + done["token"]}).json()
    assert me["username"] == "alice" and me["device"]["tpm_mode"] == "SIMULATED"
    # the same TPM identity is what the server stored
    assert world.db.one("SELECT COUNT(*) AS n FROM devices")["n"] == 1


def test_agent_reports_an_unreachable_server():
    import httpx
    info = read_simulated_tpm("AGENT-PC")
    agent = TestClient(create_agent_app("http://127.0.0.1:9", info, http_client=httpx.Client(timeout=1)))
    assert agent.get("/agent/status").json()["server_reachable"] is False
    response = agent.get("/api/me")
    assert response.status_code == 502 and "not reachable" in response.json()["detail"]


def test_two_agents_with_different_tpms_are_two_devices(world):
    first, _ = make_agent(world, "TPM-A")
    second, _ = make_agent(world, "TPM-B")
    assert first.get("/agent/status").json()["ek_hash_short"] != second.get("/agent/status").json()["ek_hash_short"]


def test_the_simulated_tpm_identity_is_stable_across_restarts():
    assert read_simulated_tpm("STABLE-PC")["ek_public_key"] == read_simulated_tpm("STABLE-PC")["ek_public_key"]


def test_server_checks_that_the_tpm_certificate_matches_the_key(world):
    from device_service import DeviceClaim, ensure_device
    import base64
    info = read_simulated_tpm("CERT-PC")
    genuine = DeviceClaim("SIMULATED", base64.b64decode(info["ek_public_key"]), base64.b64decode(info["ek_certificate"]))
    other = read_simulated_tpm("OTHER-PC")
    mismatched = DeviceClaim("SIMULATED", base64.b64decode(info["ek_public_key"]), base64.b64decode(other["ek_certificate"]))
    id_genuine = ensure_device(world.db, genuine)
    assert world.db.one("SELECT cert_checked FROM devices WHERE id = ?", (id_genuine,))["cert_checked"] == 1
    forged_key = read_simulated_tpm("FORGED-PC")
    forged = DeviceClaim("SIMULATED", base64.b64decode(forged_key["ek_public_key"]), base64.b64decode(other["ek_certificate"]))
    id_forged = ensure_device(world.db, forged)
    assert world.db.one("SELECT cert_checked FROM devices WHERE id = ?", (id_forged,))["cert_checked"] == 0
