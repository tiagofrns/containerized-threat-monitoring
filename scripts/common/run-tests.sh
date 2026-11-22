#!/usr/bin/env bash
# Run unit controls and isolated HTTP/SQLite fixtures; no deployed endpoint is used.
set -euo pipefail
project_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
test_image="${TEST_IMAGE:-analytics:case1-final-v1}"

use_local=false
if [[ "${1:-}" == "--local" ]]; then
  use_local=true
  shift
fi
usage() {
  echo "Usage: $0 [--local] [common|monitoring|scalability|availability|dns-integrity|mail-security]" >&2
  exit 2
}
[[ $# -le 1 ]] || usage
case "${1:-}" in
  "") test_dir=tests ;;
  common|monitoring|scalability) test_dir="tests/$1" ;;
  availability) test_dir=tests/scenarios/availability ;;
  dns-integrity) test_dir=tests/scenarios/dns_integrity ;;
  mail-security) test_dir=tests/scenarios/mail_security ;;
  *) usage ;;
esac

if "$use_local"; then
  export CACHE_RESPONSE_SOURCE="$project_root/security/analytics-cache.py"
  export ANALYTICS_SOURCE="$project_root/apps/analytics.py"
  export PUSH_PUBLISHER_SOURCE="$project_root/monitoring/push_publisher.py"
  export PYTHONPATH="$project_root/monitoring${PYTHONPATH:+:$PYTHONPATH}"
  export PYTHONDONTWRITEBYTECODE=1
  exec python3 -m unittest discover -s "$project_root/$test_dir" -t "$project_root/tests" -v
fi

command -v incus >/dev/null
if ! incus exec docker -- docker image inspect "$test_image" >/dev/null 2>&1; then
  # Compatibility with the already installed dependency image. The source under
  # test is mounted below; this is not a renamed application image or deployment.
  legacy_test_image="ssle-analytics:case1-final-v1"
  if [[ -z "${TEST_IMAGE+x}" ]] && incus exec docker -- docker image inspect "$legacy_test_image" >/dev/null 2>&1; then
    test_image="$legacy_test_image"
    echo 'Using the installed legacy dependency image to test the current source.'
  else
    echo 'Test image is unavailable. Set TEST_IMAGE to an installed dependency image.' >&2
    exit 1
  fi
fi
host_work="$(mktemp -d /tmp/service-tests.XXXXXX)"
container_work=""
cleanup() {
  if [[ "$container_work" == /tmp/service-tests.* ]]; then
    incus exec docker -- rm -rf -- "$container_work" || true
  fi
  rm -rf -- "$host_work"
}
trap cleanup EXIT
tar -czf "$host_work/source.tar.gz" -C "$project_root" apps monitoring tests security scripts
container_work="$(incus exec docker -- mktemp -d /tmp/service-tests.XXXXXX)"
incus file push "$host_work/source.tar.gz" "docker$container_work/source.tar.gz"
incus exec docker -- tar -xzf "$container_work/source.tar.gz" -C "$container_work"
incus exec docker -- chmod -R a+rX "$container_work"
incus exec docker -- docker run --rm --network none --read-only \
  --tmpfs /tmp --cap-drop ALL --security-opt no-new-privileges \
  --mount "type=bind,source=$container_work,target=/workspace,readonly" \
  --workdir /workspace \
  --env PYTHONDONTWRITEBYTECODE=1 \
  --env PYTHONPATH=/workspace/monitoring \
  --env CACHE_RESPONSE_SOURCE=/workspace/security/analytics-cache.py \
  --env ANALYTICS_SOURCE=/workspace/apps/analytics.py \
  --env PUSH_PUBLISHER_SOURCE=/workspace/monitoring/push_publisher.py \
  --entrypoint python "$test_image" -m unittest discover -s "$test_dir" -t tests -v
