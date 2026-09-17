#!/usr/bin/env bash

set -euo pipefail

repository_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
manifest_directory="${repository_root}/deploy/kubernetes/development"
live="${SANDBOX_RUNTIME_KUBERNETES_LIVE:-0}"
image="${SANDBOX_RUNTIME_KUBERNETES_IMAGE:-sandbox-runtime:local}"
host_port="${SANDBOX_RUNTIME_KUBERNETES_SMOKE_PORT:-18082}"
keep_namespace="${SANDBOX_RUNTIME_KUBERNETES_KEEP_NAMESPACE:-0}"
run_suffix="$(date -u +%Y%m%dt%H%M%Sz)-$$"
namespace="sandbox-runtime-smoke-${run_suffix}"
instance_name="kubernetes-smoke-${run_suffix}"
temporary_directory="$(mktemp -d "${TMPDIR:-/tmp}/sandbox-runtime-kubernetes-smoke.XXXXXX")"
namespace_created=0
port_forward_pid=""

cleanup() {
  cleanup_status=$?
  set +e

  if [[ -n "${port_forward_pid}" ]]; then
    kill "${port_forward_pid}" >/dev/null 2>&1
    wait "${port_forward_pid}" >/dev/null 2>&1
  fi

  if [[ "${cleanup_status}" -ne 0 && "${namespace_created}" -eq 1 ]]; then
    kubectl get pods -n "${namespace}" -o wide >&2
    kubectl describe deployment/sandbox-runtime -n "${namespace}" >&2
    kubectl logs deployment/sandbox-runtime -n "${namespace}" --all-containers >&2
  fi

  if [[ "${namespace_created}" -eq 1 && "${keep_namespace}" != "1" ]]; then
    kubectl delete namespace "${namespace}" --wait=false >/dev/null 2>&1
  fi

  rm -rf "${temporary_directory}"
  exit "${cleanup_status}"
}

trap cleanup EXIT
trap 'exit 130' INT TERM

for required_command in kubectl grep; do
  if ! command -v "${required_command}" >/dev/null 2>&1; then
    echo "required command not found: ${required_command}" >&2
    exit 1
  fi
done

case "${live}" in
  0|1) ;;
  *)
    echo "SANDBOX_RUNTIME_KUBERNETES_LIVE must be 0 or 1" >&2
    exit 1
    ;;
esac

case "${host_port}" in
  ''|*[!0-9]*)
    echo "SANDBOX_RUNTIME_KUBERNETES_SMOKE_PORT must be a numeric TCP port" >&2
    exit 1
    ;;
esac

if [[ "${host_port}" -lt 1 || "${host_port}" -gt 65535 ]]; then
  echo "SANDBOX_RUNTIME_KUBERNETES_SMOKE_PORT must be between 1 and 65535" >&2
  exit 1
fi

rendered_manifest="${temporary_directory}/rendered.yaml"
kubectl kustomize "${manifest_directory}" >"${rendered_manifest}"

for required_value in \
  'kind: Deployment' \
  'kind: Service' \
  'kind: NetworkPolicy' \
  'runAsNonRoot: true' \
  'type: RuntimeDefault' \
  'allowPrivilegeEscalation: false' \
  'readOnlyRootFilesystem: true' \
  'imagePullPolicy: Never' \
  'automountServiceAccountToken: false' \
  'sizeLimit: 16Mi' \
  'type: ClusterIP' \
  'path: /health'; do
  if ! grep -Fq "${required_value}" "${rendered_manifest}"; then
    echo "rendered manifest is missing: ${required_value}" >&2
    exit 1
  fi
done

if [[ "${live}" != "1" ]]; then
  echo "Kubernetes manifest smoke test passed"
  echo "  mode: offline Kustomize render and security invariant checks"
  echo "  live cluster execution: not requested"
  exit 0
fi

if (exec 3<>"/dev/tcp/127.0.0.1/${host_port}") 2>/dev/null; then
  echo "local TCP port ${host_port} is already in use" >&2
  exit 1
fi

for required_command in curl; do
  if ! command -v "${required_command}" >/dev/null 2>&1; then
    echo "required command not found: ${required_command}" >&2
    exit 1
  fi
done

if ! kubectl cluster-info >/dev/null 2>&1; then
  echo "the current Kubernetes cluster is unavailable" >&2
  exit 1
fi

if ! kubectl create namespace "${namespace}" >/dev/null; then
  echo "unable to create the isolated smoke-test namespace: ${namespace}" >&2
  exit 1
fi
namespace_created=1

kubectl apply --namespace "${namespace}" --kustomize "${manifest_directory}" >/dev/null
kubectl set image \
  --namespace "${namespace}" \
  deployment/sandbox-runtime \
  "sandbox-runtime=${image}" >/dev/null
kubectl rollout status \
  --namespace "${namespace}" \
  deployment/sandbox-runtime \
  --timeout=180s

port_forward_log="${temporary_directory}/port-forward.log"
kubectl port-forward \
  --namespace "${namespace}" \
  service/sandbox-runtime \
  "${host_port}:8080" >"${port_forward_log}" 2>&1 &
port_forward_pid=$!

port_forward_ready=0
for ((attempt = 0; attempt < 50; attempt++)); do
  if ! kill -0 "${port_forward_pid}" >/dev/null 2>&1; then
    echo "kubectl port-forward exited before becoming ready" >&2
    cat "${port_forward_log}" >&2
    exit 1
  fi
  if grep -Fq "Forwarding from 127.0.0.1:${host_port}" "${port_forward_log}"; then
    port_forward_ready=1
    break
  fi
  sleep 0.1
done

if [[ "${port_forward_ready}" -ne 1 ]]; then
  echo "kubectl port-forward did not become ready" >&2
  cat "${port_forward_log}" >&2
  exit 1
fi

base_url="http://127.0.0.1:${host_port}"
health_response="${temporary_directory}/health.json"
create_response="${temporary_directory}/create.json"
list_response="${temporary_directory}/list.json"

curl \
  --fail \
  --silent \
  --show-error \
  --retry 30 \
  --retry-connrefused \
  --retry-delay 1 \
  --connect-timeout 2 \
  --max-time 5 \
  "${base_url}/health" >"${health_response}"

if ! grep -Fq '"success":true' "${health_response}" ||
  ! grep -Fq '"status":"ok"' "${health_response}"; then
  echo "health response did not contain the expected success status" >&2
  echo "health response: $(tr -d '\n' <"${health_response}")" >&2
  exit 1
fi

curl \
  --fail \
  --silent \
  --show-error \
  --connect-timeout 2 \
  --max-time 5 \
  --header 'Content-Type: application/json' \
  --data "{\"name\":\"${instance_name}\",\"workload\":\"shell\"}" \
  "${base_url}/instances" >"${create_response}"

if ! grep -Fq '"success":true' "${create_response}" ||
  ! grep -Fq "\"name\":\"${instance_name}\"" "${create_response}"; then
  echo "instance creation response did not contain the expected instance" >&2
  exit 1
fi

curl \
  --fail \
  --silent \
  --show-error \
  --connect-timeout 2 \
  --max-time 5 \
  "${base_url}/instances" >"${list_response}"

if ! grep -Fq '"success":true' "${list_response}" ||
  ! grep -Fq "\"name\":\"${instance_name}\"" "${list_response}"; then
  echo "instance list response did not contain the created instance" >&2
  exit 1
fi

echo "Kubernetes live smoke test passed"
echo "  namespace: ${namespace}"
echo "  image: ${image}"
echo "  API: health, create instance, list instances"
echo "  scope: development mode with the in-memory fake runtime"

if [[ "${keep_namespace}" == "1" ]]; then
  echo "  retained namespace: ${namespace}"
fi
