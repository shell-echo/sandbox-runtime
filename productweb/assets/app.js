import { callProduct } from "/assets/client.generated.js";

const $ = (selector) => document.querySelector(selector);
const state = { csrf: "", workspaces: [], workspace: null, sessions: [], socket: null };
const status = $("#status");

function announce(message, error = false) {
  status.textContent = message;
  status.classList.toggle("error", error);
}

function idempotencyKey(prefix) {
  return `${prefix}-${crypto.randomUUID()}`;
}

function mutationHeaders(prefix) {
  return { "Content-Type": "application/json", "Idempotency-Key": idempotencyKey(prefix), "X-CSRF-Token": state.csrf };
}

async function establishSession(token) {
  const response = await fetch("/web/session", { method: "POST", credentials: "same-origin", headers: { Authorization: `Bearer ${token}`, Origin: location.origin } });
  const document = await response.json();
  if (!response.ok) throw new Error(document.message || "登录失败");
  activate(document);
}

async function restoreSession() {
  const response = await fetch("/web/session", { credentials: "same-origin" });
  if (!response.ok) return;
  activate(await response.json());
}

function activate(document) {
  state.csrf = document.csrf_token;
  $("#identity").textContent = `${document.principal.actor_id} · ${document.principal.role}`;
  $("#logout").hidden = false;
  $("#login-panel").hidden = true;
  $("#app").hidden = false;
  loadWorkspaces().catch(report);
}

async function loadWorkspaces() {
  const page = await callProduct("listWorkspaces", { query: { limit: "100" } });
  state.workspaces = page.items;
  const list = $("#workspace-list");
  list.replaceChildren();
  for (const workspace of state.workspaces) {
    const item = document.createElement("li");
    const button = document.createElement("button");
    button.type = "button";
    button.dataset.workspaceId = workspace.workspace_id;
    button.innerHTML = `<span></span><small></small>`;
    button.querySelector("span").textContent = workspace.display_name;
    button.querySelector("small").textContent = workspace.observed_state;
    button.addEventListener("click", () => selectWorkspace(workspace.workspace_id).catch(report));
    item.append(button);
    list.append(item);
  }
  if (!state.workspaces.length) {
    const item = document.createElement("li");
    item.className = "muted";
    item.textContent = "尚无工作空间";
    list.append(item);
  }
}

async function selectWorkspace(workspaceId) {
  const workspace = await callProduct("getWorkspace", { path: { workspace_id: workspaceId } });
  state.workspace = workspace;
  $("#workspace-title").textContent = workspace.display_name;
  $("#workspace-state").textContent = `${workspace.observed_state} · v${workspace.version}`;
  $("#reload-workspace").disabled = false;
  for (const button of document.querySelectorAll("[data-workspace-id]")) button.setAttribute("aria-current", String(button.dataset.workspaceId === workspaceId));
  for (const selector of ["#new-terminal", "#browse-files", "#refresh-files"]) $(selector).disabled = false;
  await loadSessions();
}

async function loadSessions() {
  const page = await callProduct("listWorkspaceSessions", { path: { workspace_id: state.workspace.workspace_id }, query: { limit: "100" } });
  state.sessions = page.items;
  const select = $("#session-select");
  select.replaceChildren();
  for (const session of state.sessions) {
    const option = document.createElement("option");
    option.value = session.session_id;
    option.textContent = `${session.session_id} · ${session.state}`;
    select.append(option);
  }
  if (!state.sessions.length) {
    const option = document.createElement("option");
    option.value = "";
    option.textContent = "暂无会话";
    select.append(option);
  }
  select.disabled = !state.sessions.length;
  $("#connect-terminal").disabled = !state.sessions.length;
}

async function createTerminal() {
  await callProduct("createRuntimeSession", {
    path: { workspace_id: state.workspace.workspace_id },
    headers: mutationHeaders("terminal"),
    body: { expected_workspace_version: state.workspace.version, slot_key: "primary-code", kind: "terminal", protocol_profile: "product-terminal.v1", expires_in_seconds: 3600, recording_policy: "disabled" },
  });
  announce("终端创建已受理；正在等待协调结果");
  await new Promise((resolve) => setTimeout(resolve, 1200));
  await loadSessions();
}

async function connectTerminal() {
  const session = state.sessions.find((item) => item.session_id === $("#session-select").value);
  if (!session) return;
  let control = {};
  if (session.requires_control_lease) {
    const lease = await callProduct("acquireControlLease", {
      path: { workspace_id: state.workspace.workspace_id }, headers: mutationHeaders("control"),
      body: { expected_workspace_version: state.workspace.version, scope: { scope_type: "session", scope_id: session.session_id }, duration_seconds: 120 },
    });
    control = { control_lease_id: lease.lease_id, control_fence: lease.fence };
  }
  const grant = await callProduct("createSessionConnectionGrant", {
    path: { session_id: session.session_id }, headers: mutationHeaders("connect"),
    body: { expected_session_version: session.version, protocol_profile: "product-terminal.v1", ...control },
  });
  disconnectTerminal();
  const socket = new WebSocket(grant.gateway_uri, ["product-terminal.v1", `product-ticket.${grant.connection_ticket}`]);
  socket.binaryType = "arraybuffer";
  socket.addEventListener("open", () => { announce("终端已连接"); setTerminalEnabled(true); });
  socket.addEventListener("message", (event) => {
    const bytes = event.data instanceof ArrayBuffer ? new Uint8Array(event.data) : new TextEncoder().encode(String(event.data));
    $("#terminal").textContent += new TextDecoder().decode(bytes);
    $("#terminal").scrollTop = $("#terminal").scrollHeight;
  });
  socket.addEventListener("close", () => { setTerminalEnabled(false); announce("终端连接已关闭"); });
  socket.addEventListener("error", () => announce("终端连接失败", true));
  state.socket = socket;
}

function setTerminalEnabled(enabled) {
  $("#disconnect-terminal").disabled = !enabled;
  $("#terminal-input").disabled = !enabled;
  $("#terminal-input-form button").disabled = !enabled;
}

function disconnectTerminal() {
  if (state.socket) state.socket.close(1000, "user disconnect");
  state.socket = null;
  setTerminalEnabled(false);
}

async function loadFiles(refresh = false) {
  const root = `/web/data/workspaces/${encodeURIComponent(state.workspace.workspace_id)}/slots/primary-code/files`;
  const path = $("#file-path").value;
  if (refresh) {
    const response = await fetch(`${root}/refresh?${new URLSearchParams({ path })}`, { method: "POST", credentials: "same-origin", headers: { Origin: location.origin, "X-CSRF-Token": state.csrf } });
    if (!response.ok) throw new Error((await response.json()).message || "文件同步失败");
  }
  const response = await fetch(`${root}?${new URLSearchParams({ path, limit: "100" })}`, { credentials: "same-origin" });
  const page = await response.json();
  if (!response.ok) throw new Error(page.message || "文件读取失败");
  const body = $("#file-list");
  body.replaceChildren();
  for (const entry of page.items) {
    const row = document.createElement("tr");
    for (const value of [entry.name, entry.type, String(entry.size_bytes), new Date(entry.modified_at).toLocaleString()]) {
      const cell = document.createElement("td");
      cell.textContent = value;
      row.append(cell);
    }
    if (entry.type === "directory") row.firstChild.addEventListener("dblclick", () => { $("#file-path").value = entry.path; loadFiles().catch(report); });
    body.append(row);
  }
  if (!page.items.length) body.innerHTML = '<tr><td colspan="4" class="empty">目录为空</td></tr>';
  announce(refresh ? "文件快照已同步" : "文件列表已载入");
}

function selectTab(name) {
  const terminal = name === "terminal";
  $("#terminal-tab").setAttribute("aria-selected", String(terminal));
  $("#files-tab").setAttribute("aria-selected", String(!terminal));
  $("#terminal-panel").hidden = !terminal;
  $("#files-panel").hidden = terminal;
}

function report(error) { announce(error?.message || "请求失败", true); }

$("#login-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const input = $("#bearer");
  try { await establishSession(input.value); input.value = ""; announce("安全会话已建立"); } catch (error) { report(error); }
});
$("#logout").addEventListener("click", async () => {
  disconnectTerminal();
  await fetch("/web/session", { method: "DELETE", credentials: "same-origin", headers: { Origin: location.origin, "X-CSRF-Token": state.csrf } });
  location.reload();
});
$("#refresh-workspaces").addEventListener("click", () => loadWorkspaces().catch(report));
$("#reload-workspace").addEventListener("click", () => selectWorkspace(state.workspace.workspace_id).catch(report));
$("#create-workspace-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  try {
    await callProduct("createWorkspace", { headers: mutationHeaders("workspace"), body: { display_name: $("#display-name").value, lifetime_seconds: Number($("#lifetime").value), primary_slot: { slot_key: "primary-code", kind: "code", profile_id: "coding-shell-v1", required_capabilities: [{ capability_id: "sandbox.exec", version: "1.0.0", profile_id: "exec-v1" }], desired_state: "ready" } } });
    announce("工作空间创建已受理");
    await loadWorkspaces();
  } catch (error) { report(error); }
});
$("#new-terminal").addEventListener("click", () => createTerminal().catch(report));
$("#connect-terminal").addEventListener("click", () => connectTerminal().catch(report));
$("#disconnect-terminal").addEventListener("click", disconnectTerminal);
$("#terminal-input-form").addEventListener("submit", (event) => {
  event.preventDefault();
  const input = $("#terminal-input");
  if (state.socket?.readyState === WebSocket.OPEN) state.socket.send(new TextEncoder().encode(input.value + "\n"));
  input.value = "";
});
$("#browse-files").addEventListener("click", () => loadFiles().catch(report));
$("#refresh-files").addEventListener("click", () => loadFiles(true).catch(report));
$("#terminal-tab").addEventListener("click", () => selectTab("terminal"));
$("#files-tab").addEventListener("click", () => selectTab("files"));

restoreSession().catch(report);
