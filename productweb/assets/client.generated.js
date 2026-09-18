// Code generated from the locked Product OpenAPI. DO NOT EDIT.
export const productOperations = Object.freeze({
  "acquireControlLease": Object.freeze({ method: "POST", path: "/api/v1/workspaces/{workspace_id}/control-leases" }),
  "cancelAgentRun": Object.freeze({ method: "POST", path: "/api/v1/agent-runs/{agent_run_id}:cancel" }),
  "closeRuntimeSession": Object.freeze({ method: "POST", path: "/api/v1/sessions/{session_id}:close" }),
  "createAgentRun": Object.freeze({ method: "POST", path: "/api/v1/workspaces/{workspace_id}/agent-runs" }),
  "createRuntimeSession": Object.freeze({ method: "POST", path: "/api/v1/workspaces/{workspace_id}/sessions" }),
  "createSessionConnectionGrant": Object.freeze({ method: "POST", path: "/api/v1/sessions/{session_id}/connections" }),
  "createWorkspace": Object.freeze({ method: "POST", path: "/api/v1/workspaces" }),
  "getAgentRun": Object.freeze({ method: "GET", path: "/api/v1/agent-runs/{agent_run_id}" }),
  "getArtifact": Object.freeze({ method: "GET", path: "/api/v1/artifacts/{artifact_id}" }),
  "getProductCapabilities": Object.freeze({ method: "GET", path: "/api/v1/capabilities" }),
  "getProductOperation": Object.freeze({ method: "GET", path: "/api/v1/operations/{operation_id}" }),
  "getRecording": Object.freeze({ method: "GET", path: "/api/v1/recordings/{recording_id}" }),
  "getRuntimeSession": Object.freeze({ method: "GET", path: "/api/v1/sessions/{session_id}" }),
  "getWorkspace": Object.freeze({ method: "GET", path: "/api/v1/workspaces/{workspace_id}" }),
  "getWorkspaceSlot": Object.freeze({ method: "GET", path: "/api/v1/workspaces/{workspace_id}/slots/{slot_key}" }),
  "listWorkspaceArtifacts": Object.freeze({ method: "GET", path: "/api/v1/workspaces/{workspace_id}/artifacts" }),
  "listWorkspaceEvents": Object.freeze({ method: "GET", path: "/api/v1/workspaces/{workspace_id}/events" }),
  "listWorkspaceOperations": Object.freeze({ method: "GET", path: "/api/v1/workspaces/{workspace_id}/operations" }),
  "listWorkspaceRecordings": Object.freeze({ method: "GET", path: "/api/v1/workspaces/{workspace_id}/recordings" }),
  "listWorkspaceSessions": Object.freeze({ method: "GET", path: "/api/v1/workspaces/{workspace_id}/sessions" }),
  "listWorkspaces": Object.freeze({ method: "GET", path: "/api/v1/workspaces" }),
  "putWorkspaceSlot": Object.freeze({ method: "PUT", path: "/api/v1/workspaces/{workspace_id}/slots/{slot_key}" }),
  "releaseControlLease": Object.freeze({ method: "POST", path: "/api/v1/workspaces/{workspace_id}/control-leases/{lease_id}:release" }),
  "renewControlLease": Object.freeze({ method: "POST", path: "/api/v1/workspaces/{workspace_id}/control-leases/{lease_id}:renew" }),
  "resizeRuntimeSession": Object.freeze({ method: "POST", path: "/api/v1/sessions/{session_id}:resize" }),
  "setWorkspaceDesiredState": Object.freeze({ method: "POST", path: "/api/v1/workspaces/{workspace_id}/desired-state" }),
  "streamWorkspaceEvents": Object.freeze({ method: "GET", path: "/api/v1/workspaces/{workspace_id}/events:stream" }),
});

export async function callProduct(operationId, options = {}) {
  const operation = productOperations[operationId];
  if (!operation) throw new Error("Unknown Product operation");
  let path = operation.path;
  for (const [name, value] of Object.entries(options.path || {})) {
    path = path.replace("{" + name + "}", encodeURIComponent(value));
  }
  if (path.includes("{")) throw new Error("Missing Product path parameter");
  const query = new URLSearchParams(options.query || {});
  const response = await fetch("/web" + path + (query.size ? "?" + query : ""), {
    method: operation.method,
    credentials: "same-origin",
    headers: options.headers || {},
    body: options.body === undefined ? undefined : JSON.stringify(options.body),
  });
  const document = response.status === 204 ? null : await response.json();
  if (!response.ok) {
    const error = new Error(document?.message || "Product request failed");
    error.code = document?.code || "PRODUCT_REQUEST_FAILED";
    error.status = response.status;
    throw error;
  }
  return document;
}
