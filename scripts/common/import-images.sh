#!/usr/bin/env bash
set -euo pipefail

images=(
  registry:k3s-v1
  storage:k3s-v1
  ingestion:k3s-v2
  analytics:case1-final-v1
  sensor:k3s-v1
)
nodes=(k3s-master k3s-node1)
project_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
artifact_dir="${SSLE_IMAGE_OUTPUT:-$project_root/../ssle-runtime-artifacts/images}"
archive="$artifact_dir/k3s-images.tar"

command -v incus >/dev/null
incus exec k3s-master -- k3s kubectl wait \
  --for=condition=Ready node/k3s-master node/k3s-node1 --timeout=90s

echo 'Checking the five images in the Incus docker container...'
incus exec docker -- docker image inspect \
  --format '{{index .RepoTags 0}} {{.Id}}' "${images[@]}"

echo 'Exporting Docker images...'
incus exec docker -- docker save \
  --output /tmp/k3s-images.tar "${images[@]}"
mkdir -p "$artifact_dir"
incus file pull docker/tmp/k3s-images.tar "$archive"

for node in "${nodes[@]}"; do
  echo "Importing images into containerd on $node..."
  incus file push "$archive" "$node/tmp/k3s-images.tar"
  incus exec "$node" -- k3s ctr --namespace k8s.io \
    images import /tmp/k3s-images.tar
  # Verify that the Kubernetes runtime can see all five images.
  for image in "${images[@]}"; do
    incus exec "$node" -- k3s crictl inspecti \
      "docker.io/library/$image" >/dev/null
  done
  echo "$node: five images available."
done

echo 'Image import completed. This script does not change Kubernetes Deployments.'
echo "Archive saved at $archive and at /tmp/k3s-images.tar inside the containers."
