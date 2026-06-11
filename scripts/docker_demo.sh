#!/usr/bin/env bash
#
# racemap Docker demo — one image, runs anywhere with Docker installed.
#   ./scripts/docker_demo.sh            # build + validate + scan ./kernel + stats
#   KERNEL=/path/to/linux ./scripts/docker_demo.sh
set -euo pipefail
cd "$(dirname "$0")/.."

IMAGE="racemap:latest"
KERNEL_SRC="${KERNEL:-./kernel}"

echo "==> [1/4] Building image ($IMAGE)"
docker build -t "$IMAGE" .

echo
echo "==> [2/4] Ground-truth validation (offline, no kernel needed)"
docker run --rm "$IMAGE" validate

echo
echo "==> [3/4] Scanning $KERNEL_SRC/net and $KERNEL_SRC/crypto"
if [ -d "$KERNEL_SRC/net" ] || [ -d "$KERNEL_SRC/crypto" ]; then
    docker run --rm -v "$(realpath "$KERNEL_SRC")":/kernel:ro "$IMAGE" \
        scan /kernel --subsystem net --subsystem crypto --llm heuristic \
        --kernel-version "${KERNEL_VERSION:-6.8}" --json /app/results/docker_scan.json
else
    echo "  (no kernel source at $KERNEL_SRC — scanning bundled sample_kernel instead)"
    docker run --rm "$IMAGE" \
        scan tests/sample_kernel --llm heuristic --kernel-version 6.8
fi

echo
echo "==> [4/4] Headline metric"
docker run --rm --entrypoint python "$IMAGE" scripts/benchmark.py 10 >/dev/null
docker run --rm --entrypoint python "$IMAGE" scripts/stats.py || true
echo
echo "Done. Mount your kernel with: docker run --rm -v /path/to/linux:/kernel $IMAGE scan /kernel/net/"
