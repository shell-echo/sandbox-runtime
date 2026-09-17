#!/usr/bin/env bash

set -euo pipefail

repository_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
host_port="${SANDBOX_RUNTIME_DOCKER_SMOKE_PORT:-18081}"
keep_image="${SANDBOX_RUNTIME_DOCKER_SMOKE_KEEP_IMAGE:-0}"
run_suffix="$(date -u +%Y%m%dT%H%M%SZ)-$$"
image="sandbox-runtime:docker-smoke-${run_suffix}"
container_name="sandbox-runtime-docker-smoke-${run_suffix}"
instance_name="docker-smoke-${run_suffix}"
temporary_directory="$(mktemp -d "${TMPDIR:-/tmp}/sandbox-runtime-docker-smoke.XXXXXX")"
container_started=0

cleanup() {
  cleanup_status=$?
  set +e

  if [[ "${cleanup_status}" -ne 0 && "${container_started}" -eq 1 ]]; then
    docker logs "${container_name}" >&2
  fi

  if [[ "${container_started}" -eq 1 ]]; then
    docker rm --force "${container_name}" >/dev/null 2>&1
  fi

  if [[ "${keep_image}" != "1" ]]; then
    docker image rm "${image}" >/dev/null 2>&1
  fi

  rm -rf "${temporary_directory}"
  exit "${cleanup_status}"
}

trap cleanup EXIT
trap 'exit 130' INT TERM

for required_command in docker curl grep; do
  if ! command -v "${required_command}" >/dev/null 2>&1; then
    echo "required command not found: ${required_command}" >&2
    exit 1
  fi
done

case "${host_port}" in
  ''|*[!0-9]*)
    echo "SANDBOX_RUNTIME_DOCKER_SMOKE_PORT must be a numeric TCP port" >&2
    exit 1
    ;;
esac

if [[ "${host_port}" -lt 1 || "${host_port}" -gt 65535 ]]; then
  echo "SANDBOX_RUNTIME_DOCKER_SMOKE_PORT must be between 1 and 65535" >&2
  exit 1
fi

if ! docker info >/dev/null 2>&1; then
  echo "the Docker daemon is unavailable" >&2
  exit 1
fi

echo "Building ${image} with Docker"
docker build --tag "${image}" "${repository_root}"

configured_user="$(docker image inspect --format '{{.Config.User}}' "${image}")"
if [[ "${configured_user}" != "1000:1000" ]]; then
  echo "image user = ${configured_user}, want 1000:1000" >&2
  exit 1
fi

echo "Starting ${container_name} on 127.0.0.1:${host_port}"
docker run \
  --detach \
  --name "${container_name}" \
  --publish "127.0.0.1:${host_port}:8080" \
  --env SANDBOX_RUNTIME_APPLICATION_MODE=development \
  --env SANDBOX_RUNTIME_SERVER_API_HOST=0.0.0.0 \
  --read-only \
  --tmpfs /tmp:rw,noexec,nosuid,nodev,size=16m \
  --cap-drop ALL \
  --security-opt no-new-privileges \
  --pids-limit 128 \
  "${image}" >/dev/null
container_started=1

if [[ "$(docker inspect --format '{{.HostConfig.ReadonlyRootfs}}' "${container_name}")" != "true" ]]; then
  echo "container root filesystem is not read-only" >&2
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

echo "Docker smoke test passed"
echo "  image: ${image}"
echo "  container: ${container_name}"
echo "  isolation: user 1000:1000, read-only root, all capabilities dropped"
echo "  API: health, create instance, list instances"
echo "  scope: development mode with the in-memory fake runtime"

if [[ "${keep_image}" == "1" ]]; then
  echo "  retained image: ${image}"
fi
