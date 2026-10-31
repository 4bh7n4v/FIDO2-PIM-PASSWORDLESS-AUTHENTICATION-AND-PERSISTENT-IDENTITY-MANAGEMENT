"""Simulated PCs and users for the tests. A Pc does what the client agent + browser
do on a real machine: it sends its TPM identity with every request and uses its own
(software) Windows Hello."""
import itertools

from software_authenticator import SoftwareAuthenticator
from tpm_reader import device_header_value, read_simulated_tpm

_phone_numbers = itertools.count(1)


class ApiError(Exception):
    def __init__(self, response):
        super().__init__(f"{response.status_code}: {response.text}")
        self.status = response.status_code
        self.detail = response.json().get("detail") if response.headers.get("content-type", "").startswith("application/json") else None


class Session:
    def __init__(self, pc, token, username):
        self.pc, self.token, self.username = pc, token, username

    def call(self, method, path, **kwargs):
        return self.pc.call(method, path, token=self.token, **kwargs)

    def ok(self, method, path, **kwargs):
        response = self.call(method, path, **kwargs)
        if response.status_code >= 400:
            raise ApiError(response)
        return response.json()

    # chat
    def send(self, to, body="hello"):
        return self.call("POST", "/messages", json={"to": to, "body": body})

    def thread(self, peer):
        return self.call("GET", f"/messages/{peer}")

    def bodies(self, peer):
        return [m["body"] for m in self.ok("GET", f"/messages/{peer}")["messages"]]

    def search(self, query):
        return [u["username"] for u in self.ok("GET", f"/users/search?q={query}")["users"]]

    def conversations(self):
        return [c["username"] for c in self.ok("GET", "/conversations")["conversations"]]

    # blocks
    def block(self, username):
        return self.ok("POST", "/blocks", json={"username": username})

    def blocks(self):
        return self.ok("GET", "/blocks")

    def entry(self, section, username):
        """The block-list entry for a username in one section, or None."""
        return next((e for e in self.blocks()[section] if e["username"] == username), None)

    def unblock(self, block_id):
        return self.ok("DELETE", f"/blocks/{block_id}")

    def action(self, block_id, name):
        return self.ok("POST", f"/blocks/{block_id}/{name}")


class Pc:
    def __init__(self, world, name):
        self.world, self.name = world, name
        self.info = read_simulated_tpm(name)
        self.header = device_header_value(self.info)
        self.authenticator = SoftwareAuthenticator()

    def call(self, method, path, token=None, json=None, header=True):
        headers = {}
        if header:
            headers["x-device-info"] = self.header
        if token:
            headers["authorization"] = f"Bearer {token}"
        return self.world.client.request(method, "/api" + path, headers=headers, json=json)

    def post(self, path, json, **kwargs):
        response = self.call("POST", path, json=json, **kwargs)
        if response.status_code >= 400:
            raise ApiError(response)
        return response.json()

    def register(self, username, email=None, phone=None, password="correct horse 1") -> Session:
        email = email or f"{username}@gmail.com"
        phone = phone or f"+91 90000 {next(_phone_numbers):05d}"
        started = self.post("/register/start", {"username": username, "password": password, "email": email, "phone": phone})
        codes = started["demo_codes"]
        verified = self.post("/register/verify", {"flow_id": started["flow_id"], "email_code": codes["email_code"],
                                                   "phone_code": codes["phone_code"]})
        credential = self.authenticator.create(verified["webauthn_options"])
        done = self.post("/register/complete", {"flow_id": started["flow_id"], "credential": credential})
        return Session(self, done["token"], username)

    def login(self, username, password="correct horse 1") -> Session:
        step = self.post("/login/password", {"username": username, "password": password})
        if step["step"] == "NEW_DEVICE":
            codes = step["demo_codes"]
            verified = self.post("/login/new-device/verify", {"flow_id": step["flow_id"], "email_code": codes["email_code"],
                                                               "phone_code": codes["phone_code"]})
            credential = self.authenticator.create(verified["webauthn_options"])
            step = self.post("/login/new-device/complete", {"flow_id": step["flow_id"], "credential": credential})
        assertion = self.authenticator.get(step["webauthn_options"])
        done = self.post("/login/webauthn", {"flow_id": step["flow_id"], "credential": assertion})
        return Session(self, done["token"], username)


class PcWorld:
    def __init__(self, client, database, application):
        self.client, self.db, self.app = client, database, application
        self._pcs = {}

    def pc(self, name) -> Pc:
        if name not in self._pcs:
            self._pcs[name] = Pc(self, name)
        return self._pcs[name]

    def audit_events(self):
        return [r["event"] for r in self.db.all("SELECT event FROM audit_log ORDER BY id")]
