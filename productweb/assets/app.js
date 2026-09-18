import { callProduct } from "/assets/client.generated.js";

const $ = (selector) => document.querySelector(selector);
const delay = (milliseconds) => new Promise((resolve) => setTimeout(resolve, milliseconds));
const state = {
  csrf: "", workspaces: [], workspace: null, sessions: [], socket: null,
  peer: null, channel: null, browserLease: null, browserGeneration: 0,
  reconnectAttempts: 0, reconnectTimer: null, intentionalBrowserClose: false,
  sequence: 0, pendingControls: new Map(),
  video: { codec: "video/VP8", width: 1280, height: 720, max_fps: 30, max_bitrate_kbps: 1800 },
};
const status = $("#status");

function announce(message, error = false) {
  status.textContent = message;
  status.classList.toggle("error", error);
}

function idempotencyKey(prefix) { return `${prefix}-${crypto.randomUUID()}`; }
function mutationHeaders(prefix) { return { "Content-Type": "application/json", "Idempotency-Key": idempotencyKey(prefix), "X-CSRF-Token": state.csrf }; }

async function establishSession(token) {
  const response = await fetch("/web/session", { method: "POST", credentials: "same-origin", headers: { Authorization: `Bearer ${token}` } });
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
    const name = document.createElement("span");
    const observed = document.createElement("small");
    button.type = "button";
    button.dataset.workspaceId = workspace.workspace_id;
    name.textContent = workspace.display_name;
    observed.textContent = workspace.observed_state;
    button.append(name, observed);
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
  if (state.workspace?.workspace_id !== workspaceId) await disconnectBrowser(true);
  const workspace = await callProduct("getWorkspace", { path: { workspace_id: workspaceId } });
  state.workspace = workspace;
  $("#workspace-title").textContent = workspace.display_name;
  $("#workspace-state").textContent = `${workspace.observed_state} · v${workspace.version}`;
  $("#reload-workspace").disabled = false;
  for (const button of document.querySelectorAll("[data-workspace-id]")) button.setAttribute("aria-current", String(button.dataset.workspaceId === workspaceId));
  for (const selector of ["#new-terminal", "#browse-files", "#refresh-files", "#refresh-recordings"]) $(selector).disabled = false;
  renderBrowserSlot();
  await Promise.all([loadSessions(), loadRecordings()]);
}

function browserSlot() { return state.workspace?.slots?.find((slot) => slot.slot_key === "browser-main") || null; }

function renderBrowserSlot() {
  const slot = browserSlot();
  $("#browser-slot-state").textContent = slot ? `槽位：${slot.observed_state} · ${slot.desired_state}` : "尚未创建浏览器槽位";
  $("#create-browser-slot").disabled = !state.workspace || Boolean(slot);
  $("#resume-browser-slot").disabled = !slot || slot.desired_state === "ready" || slot.desired_state === "terminated";
  $("#suspend-browser-slot").disabled = !slot || slot.desired_state !== "ready";
  $("#terminate-browser-slot").disabled = !slot || slot.desired_state === "terminated";
  const usable = slot?.observed_state === "ready" && slot.desired_state === "ready";
  $("#new-browser").disabled = !usable;
  $("#browser-recording-policy").disabled = !usable;
}

async function putBrowserSlot(desiredState) {
  const slot = browserSlot();
  await callProduct("putWorkspaceSlot", {
    path: { workspace_id: state.workspace.workspace_id, slot_key: "browser-main" }, headers: mutationHeaders("browser-slot"),
    body: {
      expected_workspace_version: state.workspace.version, kind: "browser", profile_id: "sandbox-runtime-browser-v1",
      required_capabilities: [{ capability_id: "sandbox.browser", version: "1.0.0", profile_id: "browser-v1" }], desired_state: desiredState,
    },
  });
  announce(slot ? `浏览器槽位${desiredState === "ready" ? "恢复" : desiredState === "suspended" ? "暂停" : "终止"}已受理` : "浏览器槽位创建已受理");
  await delay(500);
  await selectWorkspace(state.workspace.workspace_id);
}

async function loadSessions() {
  const page = await callProduct("listWorkspaceSessions", { path: { workspace_id: state.workspace.workspace_id }, query: { limit: "100" } });
  state.sessions = page.items;
  renderSessionSelect("#session-select", state.sessions.filter((item) => item.kind === "terminal"), "暂无终端会话");
  renderSessionSelect("#browser-session-select", state.sessions.filter((item) => item.kind === "browser_live"), "暂无浏览器会话");
  updateBrowserControls();
}

function renderSessionSelect(selector, sessions, emptyLabel) {
  const select = $(selector);
  const retained = select.value;
  select.replaceChildren();
  for (const session of sessions) {
    const option = document.createElement("option");
    option.value = session.session_id;
    option.textContent = `${session.session_id} · ${session.state} · ${session.recording_policy}`;
    select.append(option);
  }
  if (!sessions.length) {
    const option = document.createElement("option");
    option.value = "";
    option.textContent = emptyLabel;
    select.append(option);
  } else if (sessions.some((item) => item.session_id === retained)) {
    select.value = retained;
  }
  select.disabled = !sessions.length;
  if (selector === "#session-select") $("#connect-terminal").disabled = !sessions.length;
}

async function createTerminal() {
  await callProduct("createRuntimeSession", {
    path: { workspace_id: state.workspace.workspace_id }, headers: mutationHeaders("terminal"),
    body: { expected_workspace_version: state.workspace.version, slot_key: "primary-code", kind: "terminal", protocol_profile: "product-terminal.v1", expires_in_seconds: 3600, recording_policy: "disabled" },
  });
  announce("终端创建已受理；正在等待协调结果");
  await delay(1200);
  await selectWorkspace(state.workspace.workspace_id);
}

async function createBrowserSession() {
  const operation = await callProduct("createRuntimeSession", {
    path: { workspace_id: state.workspace.workspace_id }, headers: mutationHeaders("browser-session"),
    body: {
      expected_workspace_version: state.workspace.version, slot_key: "browser-main", kind: "browser_live",
      protocol_profile: "product-browser-live.v1", expires_in_seconds: 3600, recording_policy: $("#browser-recording-policy").value,
    },
  });
  announce("浏览器会话创建已受理；正在等待就绪");
  await delay(900);
  await selectWorkspace(state.workspace.workspace_id);
  if (operation.session_id) $("#browser-session-select").value = operation.session_id;
  updateBrowserControls();
}

function selectedBrowserSession() { return state.sessions.find((item) => item.session_id === $("#browser-session-select").value); }

function updateBrowserControls() {
  const session = selectedBrowserSession();
  const connected = Boolean(state.peer);
  const ready = session?.state === "ready" || session?.state === "active";
  $("#browser-access").disabled = !ready || connected;
  $("#connect-browser").disabled = !ready || connected;
  $("#disconnect-browser").disabled = !connected;
  $("#close-browser").disabled = !session || ["closed", "expired", "failed"].includes(session.state);
  const required = session?.recording_policy === "required";
  $("#recording-consent-row").hidden = !required;
  $("#recording-consent").disabled = connected;
  setControlInputs(connected && $("#browser-access").value === "control" && state.channel?.readyState === "open");
}

async function ensureBrowserLease(session) {
  if (!session.requires_control_lease || $("#browser-access").value !== "control") return null;
  if (state.browserLease && Date.parse(state.browserLease.expires_at) > Date.now() + 10000) return state.browserLease;
  state.workspace = await callProduct("getWorkspace", { path: { workspace_id: state.workspace.workspace_id } });
  state.browserLease = await callProduct("acquireControlLease", {
    path: { workspace_id: state.workspace.workspace_id }, headers: mutationHeaders("browser-control"),
    body: { expected_workspace_version: state.workspace.version, scope: { scope_type: "session", scope_id: session.session_id }, duration_seconds: 120 },
  });
  return state.browserLease;
}

function iceGathered(peer) {
  if (peer.iceGatheringState === "complete") return Promise.resolve();
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => { peer.removeEventListener("icegatheringstatechange", changed); reject(new Error("ICE 候选收集超时")); }, 10000);
    function changed() {
      if (peer.iceGatheringState === "complete") { clearTimeout(timer); peer.removeEventListener("icegatheringstatechange", changed); resolve(); }
    }
    peer.addEventListener("icegatheringstatechange", changed);
  });
}

async function connectBrowser(recovery = false) {
  const session = selectedBrowserSession();
  if (!session) return;
  if (session.recording_policy === "required" && !$("#recording-consent").checked) throw new Error("完整录制会话需要先明确同意录制");
  cleanupBrowserPeer();
  state.intentionalBrowserClose = false;
  const generation = ++state.browserGeneration;
  const peer = new RTCPeerConnection();
  state.peer = peer;
  peer.addTransceiver("video", { direction: "recvonly" });
  const control = $("#browser-access").value === "control";
  if (control) installControlChannel(peer.createDataChannel("product-browser-control.v1", { ordered: true }));
  peer.addEventListener("track", (event) => {
    if (generation !== state.browserGeneration) return;
    $("#browser-video").srcObject = event.streams[0] || new MediaStream([event.track]);
    $("#browser-screen").classList.add("connected");
  });
  peer.addEventListener("connectionstatechange", () => handleBrowserConnectionState(peer, generation));
  await peer.setLocalDescription(await peer.createOffer());
  await iceGathered(peer);
  const lease = await ensureBrowserLease(session);
  const grantBody = { expected_session_version: session.version, protocol_profile: "product-browser-live.v1", access_mode: control ? "control" : "view" };
  if (lease) Object.assign(grantBody, { control_lease_id: lease.lease_id, control_fence: lease.fence });
  const grant = await callProduct("createSessionConnectionGrant", { path: { session_id: session.session_id }, headers: mutationHeaders("browser-connect"), body: grantBody });
  const gatewayURL = new URL(grant.gateway_uri, location.origin);
  if (gatewayURL.protocol !== "https:" || gatewayURL.origin !== location.origin) throw new Error("浏览器网关必须通过当前站点的 HTTPS 边缘暴露");
  const signal = { offer: { type: peer.localDescription.type, sdp: peer.localDescription.sdp }, video: state.video, control_data_channel: control };
  if (session.recording_policy === "required") signal.recording_consent_reference = `web-consent-${crypto.randomUUID()}`;
  const response = await fetch(gatewayURL, {
    method: "POST", credentials: "omit", headers: { Authorization: `Ticket ${grant.connection_ticket}`, "Content-Type": "application/json" }, body: JSON.stringify(signal),
  });
  const answer = await response.json().catch(() => null);
  if (!response.ok || !answer?.answer?.sdp) throw new Error("浏览器实时连接协商失败");
  await peer.setRemoteDescription(answer.answer);
  state.video = answer.video;
  setRecordingMode(answer.recording_mode);
  $("#controller-state").textContent = answer.access_mode === "control" ? `控制者 · fence ${lease?.fence}` : "查看者模式";
  $("#browser-screen").classList.toggle("controller", answer.access_mode === "control");
  $("#browser-connection-state").textContent = recovery ? "正在恢复" : "正在连接";
  updateBrowserControls();
}

function handleBrowserConnectionState(peer, generation) {
  if (generation !== state.browserGeneration || peer !== state.peer) return;
  const current = peer.connectionState;
  $("#browser-connection-state").textContent = current === "connected" ? "已连接" : current;
  if (current === "connected") {
    state.reconnectAttempts = 0;
    announce("浏览器实时画面已连接");
    updateBrowserControls();
  } else if (["failed", "closed"].includes(current) && !state.intentionalBrowserClose) {
    scheduleBrowserRecovery();
  } else if (current === "disconnected" && !state.intentionalBrowserClose) {
    scheduleBrowserRecovery(6000);
  }
}

function scheduleBrowserRecovery(wait = 800) {
  if (state.reconnectTimer || state.reconnectAttempts >= 3 || state.intentionalBrowserClose) {
    if (state.reconnectAttempts >= 3) announce("浏览器连接恢复失败；请手动重新连接", true);
    return;
  }
  const attempt = ++state.reconnectAttempts;
  $("#browser-connection-state").textContent = `等待恢复 ${attempt}/3`;
  state.reconnectTimer = setTimeout(async () => {
    state.reconnectTimer = null;
    try {
      await loadSessions();
      await connectBrowser(true);
    } catch (error) {
      cleanupBrowserPeer();
      announce(`第 ${attempt} 次恢复失败`, true);
      scheduleBrowserRecovery(Math.min(6000, 800 * 2 ** attempt));
    }
  }, wait);
}

function installControlChannel(channel) {
  state.channel = channel;
  channel.addEventListener("open", () => { setControlInputs(true); announce("浏览器控制通道已就绪"); });
  channel.addEventListener("close", () => setControlInputs(false));
  channel.addEventListener("message", (event) => {
    let result;
    try { result = JSON.parse(event.data); } catch { return; }
    const pending = state.pendingControls.get(result.sequence);
    if (pending) {
      clearTimeout(pending.timer);
      state.pendingControls.delete(result.sequence);
      result.ok ? pending.resolve(result) : pending.reject(new Error("浏览器操作被拒绝"));
    }
  });
}

function setControlInputs(enabled) {
  for (const selector of ["#browser-source-origin", "#browser-target-url", "#browser-navigate", "#browser-resync", "#browser-upload", "#send-upload", "#download-transfer-id", "#download-digest", "#download-size", "#request-download"]) $(selector).disabled = !enabled;
}

function sendControl(type, action) {
  if (!state.channel || state.channel.readyState !== "open") return Promise.reject(new Error("控制通道尚未就绪"));
  const sequence = ++state.sequence;
  const document = { type, sequence };
  if (action) document.action = action;
  state.channel.send(JSON.stringify(document));
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => { state.pendingControls.delete(sequence); reject(new Error("浏览器操作响应超时")); }, 10000);
    state.pendingControls.set(sequence, { resolve, reject, timer });
  });
}

function cleanupBrowserPeer() {
  if (state.reconnectTimer) clearTimeout(state.reconnectTimer);
  state.reconnectTimer = null;
  for (const pending of state.pendingControls.values()) { clearTimeout(pending.timer); pending.reject(new Error("浏览器连接已关闭")); }
  state.pendingControls.clear();
  if (state.channel) state.channel.close();
  if (state.peer) { state.peer.onconnectionstatechange = null; state.peer.close(); }
  state.channel = null;
  state.peer = null;
  state.sequence = 0;
  $("#browser-video").srcObject = null;
  $("#browser-screen").classList.remove("connected", "controller");
  $("#browser-connection-state").textContent = "未连接";
  setRecordingMode("disabled", false);
  updateBrowserControls();
}

async function disconnectBrowser(releaseLease = true) {
  state.intentionalBrowserClose = true;
  state.browserGeneration++;
  cleanupBrowserPeer();
  if (releaseLease && state.browserLease && state.workspace) {
    const lease = state.browserLease;
    state.browserLease = null;
    try {
      await callProduct("releaseControlLease", {
        path: { workspace_id: state.workspace.workspace_id, lease_id: lease.lease_id }, headers: mutationHeaders("browser-release"),
        body: { fence: lease.fence, reason: "web client disconnected" },
      });
    } catch (error) { report(error); }
  }
}

async function closeBrowserSession() {
  const session = selectedBrowserSession();
  if (!session) return;
  await disconnectBrowser(true);
  await callProduct("closeRuntimeSession", {
    path: { session_id: session.session_id }, headers: mutationHeaders("browser-close"),
    body: { expected_version: session.version, reason: "owner requested close from Product Web" },
  });
  announce("浏览器会话关闭已受理");
  await delay(600);
  await loadSessions();
}

function setRecordingMode(mode, committed = true) {
  const indicator = $("#recording-indicator");
  indicator.dataset.mode = mode;
  indicator.textContent = committed ? `录制：${mode}` : "录制：未提交";
}

async function navigateBrowser() {
  await sendControl("input", { kind: "navigate", source_origin: $("#browser-source-origin").value, target_url: $("#browser-target-url").value, user_activation: true });
  announce("导航请求已由浏览器策略接受");
}

async function uploadBrowserFile() {
  const file = $("#browser-upload").files[0];
  if (!file) throw new Error("请选择要上传的文件");
  if (file.size > 64 * 1024 * 1024 || file.name === "." || file.name === ".." || /[/\\\0]/.test(file.name)) throw new Error("文件名或大小不符合 Web 传输限制");
  announce("正在计算文件摘要并上传…");
  const bytes = await file.arrayBuffer();
  const digestBytes = new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
  const digest = `sha256:${Array.from(digestBytes, (byte) => byte.toString(16).padStart(2, "0")).join("")}`;
  state.workspace = await callProduct("getWorkspace", { path: { workspace_id: state.workspace.workspace_id } });
  const query = new URLSearchParams({ workspace_id: state.workspace.workspace_id, expected_workspace_version: String(state.workspace.version), digest, size_bytes: String(file.size) });
  const response = await fetch(`/web/browser-transfers/uploads?${query}`, {
    method: "POST", credentials: "same-origin", headers: { "Content-Type": "application/octet-stream", "Idempotency-Key": idempotencyKey("browser-upload"), "X-CSRF-Token": state.csrf }, body: bytes,
  });
  const transfer = await response.json();
  if (!response.ok) throw new Error(transfer.message || "上传失败");
  await sendControl("input", { kind: "upload", files: [{ transfer_id: transfer.transfer_id, name: file.name, media_type: file.type || "application/octet-stream", digest, size_bytes: file.size }], user_activation: true, consent: true });
  announce("文件已校验并交给远程浏览器");
}

async function downloadBrowserFile() {
  const transferId = $("#download-transfer-id").value.trim();
  const digest = $("#download-digest").value.trim();
  const size = Number($("#download-size").value);
  if (!transferId || !/^sha256:[0-9a-f]{64}$/.test(digest) || !Number.isSafeInteger(size) || size < 0 || size > 64 * 1024 * 1024) throw new Error("下载元数据无效或超过 64 MiB Web 限制");
  await sendControl("input", { kind: "download", files: [{ transfer_id: transferId, name: "browser-download.bin", media_type: "application/octet-stream", digest, size_bytes: size }], user_activation: true, consent: true });
  const response = await fetch(`/web/browser-transfers/${encodeURIComponent(transferId)}`, { credentials: "same-origin" });
  if (!response.ok) throw new Error((await response.json()).message || "下载失败");
  const blob = await response.blob();
  const received = new Uint8Array(await blob.arrayBuffer());
  const receivedDigest = new Uint8Array(await crypto.subtle.digest("SHA-256", received));
  const verifiedDigest = `sha256:${Array.from(receivedDigest, (byte) => byte.toString(16).padStart(2, "0")).join("")}`;
  if (blob.size !== size || verifiedDigest !== digest) throw new Error("下载内容未通过大小或摘要校验");
  const href = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = href;
  link.download = "browser-download.bin";
  link.click();
  URL.revokeObjectURL(href);
  announce("下载已通过 Product 授权并完成");
}

async function loadRecordings() {
  if (!state.workspace) return;
  const page = await callProduct("listWorkspaceRecordings", { path: { workspace_id: state.workspace.workspace_id }, query: { limit: "100" } });
  const body = $("#recording-list");
  body.replaceChildren();
  for (const recording of page.items) {
    const row = document.createElement("tr");
    for (const value of [recording.recording_id, recording.recording_type, recording.state, recording.size_bytes == null ? "—" : String(recording.size_bytes), new Date(recording.started_at).toLocaleString(), new Date(recording.retention_expires_at).toLocaleString()]) {
      const cell = document.createElement("td");
      cell.textContent = value;
      row.append(cell);
    }
    body.append(row);
  }
  if (!page.items.length) appendEmptyRow(body, 6, "暂无录制");
}

async function connectTerminal() {
  const session = state.sessions.find((item) => item.session_id === $("#session-select").value);
  if (!session) return;
  let control = {};
  if (session.requires_control_lease) {
    state.workspace = await callProduct("getWorkspace", { path: { workspace_id: state.workspace.workspace_id } });
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
    const response = await fetch(`${root}/refresh?${new URLSearchParams({ path })}`, { method: "POST", credentials: "same-origin", headers: { "X-CSRF-Token": state.csrf } });
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
  if (!page.items.length) appendEmptyRow(body, 4, "目录为空");
  announce(refresh ? "文件快照已同步" : "文件列表已载入");
}

function appendEmptyRow(body, columns, message) {
  const row = document.createElement("tr");
  const cell = document.createElement("td");
  cell.colSpan = columns;
  cell.className = "empty";
  cell.textContent = message;
  row.append(cell);
  body.append(row);
}

function selectTab(name) {
  for (const tabName of ["terminal", "files", "browser", "recordings"]) {
    const selected = tabName === name;
    $(`#${tabName}-tab`).setAttribute("aria-selected", String(selected));
    $(`#${tabName}-panel`).hidden = !selected;
  }
  if (name === "recordings") loadRecordings().catch(report);
}

function browserPointer(event, kind) {
  if (!state.channel || state.channel.readyState !== "open") return;
  const bounds = $("#browser-video").getBoundingClientRect();
  const x = Math.max(0, Math.min(state.video.width - 1, Math.floor((event.clientX - bounds.left) * state.video.width / bounds.width)));
  const y = Math.max(0, Math.min(state.video.height - 1, Math.floor((event.clientY - bounds.top) * state.video.height / bounds.height)));
  const boundedDelta = (value) => Math.max(-4096, Math.min(4096, Math.trunc(value)));
  sendControl("input", { kind: "pointer", event: kind, x, y, button: Math.max(0, event.button), delta_x: kind === "wheel" ? boundedDelta(event.deltaX) : 0, delta_y: kind === "wheel" ? boundedDelta(event.deltaY) : 0, user_activation: kind === "down" }).catch(report);
}

function browserKeyboard(event, kind) {
  if (!state.channel || state.channel.readyState !== "open" || event.isComposing) return;
  if (!/^[A-Za-z][A-Za-z0-9]{0,31}$/.test(event.code) || Array.from(event.key).length > 16) return;
  const modifiers = [];
  if (event.altKey) modifiers.push("alt");
  if (event.ctrlKey) modifiers.push("control");
  if (event.metaKey) modifiers.push("meta");
  if (event.shiftKey) modifiers.push("shift");
  sendControl("input", { kind: "keyboard", event: kind, code: event.code, key: event.key, modifiers, user_activation: kind === "down" }).catch(report);
  event.preventDefault();
}

function report(error) { announce(error?.message || "请求失败", true); }

$("#login-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const input = $("#bearer");
  try { await establishSession(input.value); input.value = ""; announce("安全会话已建立"); } catch (error) { report(error); }
});
$("#logout").addEventListener("click", async () => {
  disconnectTerminal();
  await disconnectBrowser(true);
  await fetch("/web/session", { method: "DELETE", credentials: "same-origin", headers: { "X-CSRF-Token": state.csrf } });
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
$("#create-browser-slot").addEventListener("click", () => putBrowserSlot("ready").catch(report));
$("#resume-browser-slot").addEventListener("click", () => putBrowserSlot("ready").catch(report));
$("#suspend-browser-slot").addEventListener("click", () => putBrowserSlot("suspended").catch(report));
$("#terminate-browser-slot").addEventListener("click", () => putBrowserSlot("terminated").catch(report));
$("#new-browser").addEventListener("click", () => createBrowserSession().catch(report));
$("#browser-session-select").addEventListener("change", updateBrowserControls);
$("#browser-access").addEventListener("change", updateBrowserControls);
$("#connect-browser").addEventListener("click", () => connectBrowser().catch((error) => { cleanupBrowserPeer(); report(error); }));
$("#disconnect-browser").addEventListener("click", () => disconnectBrowser(true).catch(report));
$("#close-browser").addEventListener("click", () => closeBrowserSession().catch(report));
$("#browser-navigate").addEventListener("click", () => navigateBrowser().catch(report));
$("#browser-resync").addEventListener("click", () => sendControl("stream.resync").then(() => announce("画面已请求关键帧同步")).catch(report));
$("#send-upload").addEventListener("click", () => uploadBrowserFile().catch(report));
$("#request-download").addEventListener("click", () => downloadBrowserFile().catch(report));
$("#refresh-recordings").addEventListener("click", () => loadRecordings().catch(report));
$("#browser-video").addEventListener("pointerdown", (event) => { $("#browser-video").focus(); browserPointer(event, "down"); });
$("#browser-video").addEventListener("pointerup", (event) => browserPointer(event, "up"));
$("#browser-video").addEventListener("wheel", (event) => { event.preventDefault(); browserPointer(event, "wheel"); }, { passive: false });
$("#browser-video").addEventListener("keydown", (event) => browserKeyboard(event, "down"));
$("#browser-video").addEventListener("keyup", (event) => browserKeyboard(event, "up"));
for (const name of ["terminal", "files", "browser", "recordings"]) $(`#${name}-tab`).addEventListener("click", () => selectTab(name));

restoreSession().catch(report);
