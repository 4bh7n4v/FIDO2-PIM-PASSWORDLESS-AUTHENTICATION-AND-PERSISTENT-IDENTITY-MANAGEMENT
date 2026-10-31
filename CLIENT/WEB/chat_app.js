// PIM Chat front end: onboarding (UC-01, UC-02, UC-06), messaging, blocking and review (UC-03, UC-07, UC-08).

const state = {
  token: sessionStorage.getItem("pim_token"),
  tab: "chats",
  pane: null,            // { kind: "thread", peer } or { kind: "request", peer, blockId }
  lastMessageId: 0,
  pending: null,         // the ceremony in progress: { kind: register|login|newdevice, flowId, options }
};

const $ = (id) => document.getElementById(id);

// ------------------------------------------------------------------ helpers
function make(tag, props = {}, ...children) {
  const node = document.createElement(tag);
  Object.entries(props).forEach(([key, value]) => {
    if (key === "class") node.className = value;
    else if (key.startsWith("on")) node.addEventListener(key.slice(2), value);
    else node.setAttribute(key, value);
  });
  children.flat().forEach((child) => node.append(child instanceof Node ? child : document.createTextNode(child)));
  return node;
}

async function api(method, path, body) {
  const headers = { "Content-Type": "application/json" };
  if (state.token) headers["Authorization"] = "Bearer " + state.token;
  let response;
  try {
    response = await fetch("/api" + path, { method, headers, body: body === undefined ? undefined : JSON.stringify(body) });
  } catch (networkError) {
    throw new Error("The client agent is not reachable. Is it still running?");
  }
  let data = null;
  try { data = await response.json(); } catch (ignored) { /* empty body */ }
  if (!response.ok) {
    let message = (data && data.detail) || response.statusText;
    if (Array.isArray(message)) message = message.map((m) => m.msg).join("; ");
    if (response.status === 401 && state.token && !path.startsWith("/login")) { leaveChat(); }
    throw new Error(message);
  }
  return data;
}

function toast(message) {
  const box = $("toast");
  box.textContent = message;
  box.hidden = false;
  clearTimeout(toast.timer);
  toast.timer = setTimeout(() => (box.hidden = true), 3500);
}

function showAuthError(message) {
  const box = $("auth-error");
  box.textContent = message || "";
  box.hidden = !message;
}

// ------------------------------------------------------------ auth: panels
function showPanel(name) {
  ["login", "register", "otp", "hello"].forEach((panel) => ($("panel-" + panel).hidden = panel !== name));
  showAuthError("");
}

document.querySelectorAll("[data-goto]").forEach((link) =>
  link.addEventListener("click", (event) => {
    event.preventDefault();
    state.pending = null;
    showPanel(link.dataset.goto);
  }));

function showOtp(message, demoCodes) {
  $("otp-message").textContent = message;
  $("otp-email").value = "";
  $("otp-phone").value = "";
  const demo = $("otp-demo");
  demo.hidden = !demoCodes;
  if (demoCodes) demo.textContent = `Demo mode: e-mail code ${demoCodes.email_code}, phone code ${demoCodes.phone_code}`;
  showPanel("otp");
}

function showHello(message) {
  $("hello-message").textContent = message;
  showPanel("hello");
}

async function guarded(action) {
  try {
    await action();
  } catch (error) {
    showAuthError(friendlyWebAuthnError(error));
  }
}

$("panel-login").addEventListener("submit", (event) => {
  event.preventDefault();
  guarded(async () => {
    const result = await api("POST", "/login/password", {
      username: $("login-username").value, password: $("login-password").value });
    if (result.step === "WEBAUTHN") {
      state.pending = { kind: "login", flowId: result.flow_id, options: result.webauthn_options };
      showHello("Password accepted. Verify with Windows Hello to finish logging in.");
    } else {
      state.pending = { kind: "newdevice", flowId: result.flow_id };
      showOtp(result.message, result.demo_codes);
    }
  });
});

$("panel-register").addEventListener("submit", (event) => {
  event.preventDefault();
  guarded(async () => {
    const result = await api("POST", "/register/start", {
      username: $("reg-username").value, password: $("reg-password").value,
      email: $("reg-email").value, phone: $("reg-phone").value });
    state.pending = { kind: "register", flowId: result.flow_id };
    showOtp(result.message, result.demo_codes);
  });
});

$("panel-otp").addEventListener("submit", (event) => {
  event.preventDefault();
  guarded(async () => {
    const body = { flow_id: state.pending.flowId, email_code: $("otp-email").value, phone_code: $("otp-phone").value };
    const path = state.pending.kind === "register" ? "/register/verify" : "/login/new-device/verify";
    const result = await api("POST", path, body);
    state.pending.options = result.webauthn_options;
    showHello(state.pending.kind === "register"
      ? "Codes verified. Create your Windows Hello credential for this PC."
      : "Codes verified. Register Windows Hello for this new PC.");
  });
});

$("hello-button").addEventListener("click", () => {
  guarded(async () => {
    const pending = state.pending;
    if (!pending) return;
    if (pending.kind === "register") {
      const credential = await createCredential(pending.options);
      const result = await api("POST", "/register/complete", { flow_id: pending.flowId, credential });
      await enterChat(result.token);
    } else if (pending.kind === "newdevice") {
      const credential = await createCredential(pending.options);
      const result = await api("POST", "/login/new-device/complete", { flow_id: pending.flowId, credential });
      state.pending = { kind: "login", flowId: result.flow_id, options: result.webauthn_options };
      showHello("This PC is now linked to your account. Sign in once with the new credential.");
    } else {
      const credential = await getAssertion(pending.options);
      const result = await api("POST", "/login/webauthn", { flow_id: pending.flowId, credential });
      await enterChat(result.token);
    }
  });
});

// ------------------------------------------------------------------- chat
async function enterChat(token) {
  state.token = token;
  sessionStorage.setItem("pim_token", token);
  const profile = await api("GET", "/me");
  $("me-name").textContent = "@" + profile.username;
  const chip = $("device-chip");
  if (profile.device) {
    chip.textContent = `TPM ${profile.device.ek_hash_short} · ${profile.device.tpm_mode.toLowerCase()}` +
      (profile.device.shared_pc ? " · shared PC" : "");
    chip.classList.toggle("shared", profile.device.shared_pc);
  }
  $("auth-view").hidden = true;
  $("chat-view").hidden = false;
  state.pane = null;
  renderPane();
  await refreshAll();
  startPolling();
}

function leaveChat() {
  stopPolling();
  state.token = null;
  state.pane = null;
  sessionStorage.removeItem("pim_token");
  $("chat-view").hidden = true;
  $("auth-view").hidden = false;
  $("login-password").value = "";
  showPanel("login");
}

$("logout-button").addEventListener("click", async () => {
  try { await api("POST", "/logout"); } catch (ignored) { /* already gone */ }
  leaveChat();
});

document.querySelectorAll(".tab").forEach((button) =>
  button.addEventListener("click", () => {
    state.tab = button.dataset.tab;
    document.querySelectorAll(".tab").forEach((b) => b.classList.toggle("active", b === button));
    ["chats", "review", "blocked"].forEach((name) => ($("tab-" + name).hidden = name !== state.tab));
    refreshAll();
  }));

// ------------------------------------------------------------------ search
let searchTimer = null;
$("search-input").addEventListener("input", () => {
  clearTimeout(searchTimer);
  const query = $("search-input").value.trim();
  const box = $("search-results");
  if (!query) { box.hidden = true; return; }
  searchTimer = setTimeout(async () => {
    try {
      const { users } = await api("GET", "/users/search?q=" + encodeURIComponent(query));
      box.replaceChildren(...(users.length
        ? users.map((u) => make("div", { onclick: () => { box.hidden = true; $("search-input").value = ""; openThread(u.username); } }, "@" + u.username))
        : [make("div", {}, "No users found")]));
      box.hidden = false;
    } catch (error) { toast(error.message); }
  }, 200);
});
document.addEventListener("click", (event) => {
  if (!event.target.closest(".search")) $("search-results").hidden = true;
});

// ---------------------------------------------------------------- lists
async function refreshChats() {
  const { conversations } = await api("GET", "/conversations");
  const list = $("tab-chats");
  list.replaceChildren(...(conversations.length ? conversations.map((c) =>
    make("div", { class: "item" + (state.pane && state.pane.kind === "thread" && state.pane.peer === c.username ? " active" : ""),
                  onclick: () => openThread(c.username) },
      make("div", { class: "row" }, make("span", { class: "name" }, "@" + c.username),
           c.unread ? make("span", { class: "badge" }, String(c.unread)) : "",
           c.blocked_by_me ? make("span", { class: "chip" }, "blocked") : ""),
      make("div", { class: "preview" }, (c.last_was_mine ? "You: " : "") + c.last_message)))
    : [make("div", { class: "empty-list" }, "No chats yet. Search for a user above.")]));
}

async function refreshBlocks() {
  const data = await api("GET", "/blocks");
  const pending = data.needs_review.length + data.message_requests.length;
  const badge = $("review-badge");
  badge.hidden = pending === 0;
  badge.textContent = String(pending);
  renderReview(data);
  renderBlocked(data);
}

function reviewCard(item, buttons, soft) {
  return make("div", { class: "card" + (soft ? " soft" : "") },
    make("strong", {}, "@" + item.username),
    item.held_messages ? make("span", { class: "chip", style: "margin-left:8px" }, item.held_messages + " held message(s)") : "",
    make("div", { class: "why" }, item.reason || ""),
    make("div", { class: "buttons" }, buttons));
}

function renderReview(data) {
  const nodes = [];
  nodes.push(make("div", { class: "section-title" }, "Needs your decision"));
  if (!data.needs_review.length) nodes.push(make("div", { class: "empty-list" }, "Nothing to review."));
  data.needs_review.forEach((item) => nodes.push(reviewCard(item, [
    make("button", { class: "danger", onclick: () => blockAction("confirm", item.id, "Blocked @" + item.username) }, "Block"),
    make("button", { onclick: () => blockAction("allow", item.id, "Allowed @" + item.username) }, "Allow"),
  ], true)));

  nodes.push(make("div", { class: "section-title" }, "Message requests"));
  if (!data.message_requests.length) nodes.push(make("div", { class: "empty-list" }, "No message requests."));
  data.message_requests.forEach((item) => nodes.push(reviewCard(item, [
    make("button", { onclick: () => openRequest(item) }, "View messages"),
    make("button", { onclick: () => blockAction("allow", item.id, "Accepted @" + item.username) }, "Accept"),
    make("button", { class: "danger", onclick: () => blockAction("confirm", item.id, "Blocked @" + item.username) }, "Block"),
  ])));

  nodes.push(make("div", { class: "section-title" }, "Blocked automatically"));
  if (!data.auto_blocked.length) nodes.push(make("div", { class: "empty-list" }, "No automatic blocks."));
  data.auto_blocked.forEach((item) => nodes.push(reviewCard(item, [
    make("button", { onclick: () => blockAction("unblock", item.id, "Unblocked @" + item.username) }, "Not the same person – unblock"),
  ])));
  $("tab-review").replaceChildren(...nodes);
}

function renderBlocked(data) {
  $("tab-blocked").replaceChildren(...(data.blocked.length ? data.blocked.map((item) =>
    reviewCard(item, [make("button", { onclick: () => blockAction("unblock", item.id, "Unblocked @" + item.username) }, "Unblock")]))
    : [make("div", { class: "empty-list" }, "You have not blocked anyone.")]));
}

async function blockAction(action, id, doneMessage) {
  try {
    if (action === "unblock") await api("DELETE", "/blocks/" + id);
    else await api("POST", `/blocks/${id}/${action}`);
    toast(doneMessage);
    if (state.pane && state.pane.kind === "request") { state.pane = null; renderPane(); }
    await refreshAll();
  } catch (error) { toast(error.message); }
}

// ----------------------------------------------------------------- thread
function openThread(peer) {
  state.pane = { kind: "thread", peer };
  state.lastMessageId = 0;
  renderPane();
  refreshThread(true);
}

function openRequest(item) {
  state.pane = { kind: "request", peer: item.username, blockId: item.id };
  renderPane();
  refreshThread(true);
}

function renderPane() {
  const pane = state.pane;
  $("empty-state").hidden = !!pane;
  $("thread-view").hidden = !pane;
  if (!pane) return;
  $("thread-messages").replaceChildren();
  $("thread-title").textContent = "@" + pane.peer + (pane.kind === "request" ? "  (message request)" : "");
  const actions = $("thread-actions");
  if (pane.kind === "thread") {
    actions.replaceChildren(make("button", { class: "danger", onclick: blockCurrentPeer }, "Block user"));
  } else {
    actions.replaceChildren(
      make("button", { onclick: () => blockAction("allow", pane.blockId, "Accepted @" + pane.peer) }, "Accept"),
      make("button", { class: "danger", onclick: () => blockAction("confirm", pane.blockId, "Blocked @" + pane.peer) }, "Block"));
  }
  $("composer").hidden = pane.kind === "request";
  $("composer-note").hidden = true;
}

async function blockCurrentPeer() {
  const peer = state.pane && state.pane.peer;
  if (!peer || !confirm(`Block @${peer}?\n\nThey will no longer be able to find you or message you, and the Policy Engine will also block their other accounts it can link to them.`)) return;
  try {
    await api("POST", "/blocks", { username: peer });
    toast("Blocked @" + peer);
    state.pane = null;       // nothing left to say to them: close the conversation
    renderPane();
    await refreshAll();
  } catch (error) { toast(error.message); }
}

async function refreshThread(reset) {
  const pane = state.pane;
  if (!pane) return;
  const box = $("thread-messages");
  try {
    const data = pane.kind === "request"
      ? await api("GET", "/requests/" + encodeURIComponent(pane.peer))
      : await api("GET", `/messages/${encodeURIComponent(pane.peer)}?after=${reset ? 0 : state.lastMessageId}`);
    if (state.pane !== pane) return;
    const stick = box.scrollTop + box.clientHeight >= box.scrollHeight - 40;
    if (reset || pane.kind === "request") box.replaceChildren();   // request threads are always returned in full
    data.messages.forEach((message) => {
      box.append(make("div", { class: "bubble" + (message.mine ? " mine" : "") }, message.body));
      state.lastMessageId = Math.max(state.lastMessageId, message.id);
    });
    if (reset || stick) box.scrollTop = box.scrollHeight;
  } catch (error) {
    if (state.pane === pane && pane.kind === "thread") {
      // the other person blocked us (or the account is gone): it simply looks like a missing user
      state.pane = null;
      renderPane();
      toast(error.message);
    }
  }
}

$("composer").addEventListener("submit", async (event) => {
  event.preventDefault();
  const input = $("composer-input");
  const body = input.value.trim();
  if (!body || !state.pane) return;
  try {
    await api("POST", "/messages", { to: state.pane.peer, body });
    input.value = "";
    await refreshThread(false);
    refreshChats();
  } catch (error) {
    const note = $("composer-note");
    note.textContent = error.message;
    note.hidden = false;
    setTimeout(() => (note.hidden = true), 4000);
  }
});

// ---------------------------------------------------------------- polling
async function refreshAll() {
  try {
    await Promise.all([refreshChats(), refreshBlocks()]);
  } catch (error) { /* a failed poll is retried on the next tick */ }
}

function startPolling() {
  stopPolling();
  state.polling = setInterval(() => {
    refreshAll();
    refreshThread(false);
  }, 2000);
}
function stopPolling() { clearInterval(state.polling); state.polling = null; }

// ------------------------------------------------------------------ start
async function showAgentStatus() {
  try {
    const status = await (await fetch("/agent/status")).json();
    $("agent-status").textContent =
      `${status.tpm_label} · device ${status.ek_hash_short} · server ` + (status.server_reachable ? "connected" : "NOT REACHABLE");
  } catch (ignored) {
    $("agent-status").textContent = "Client agent not reachable.";
  }
}

(async function start() {
  showPanel("login");
  showAgentStatus();
  if (state.token) {
    try { await enterChat(state.token); } catch (error) { leaveChat(); }
  }
})();
