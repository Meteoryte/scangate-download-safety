# SCANGATE stage-2 detonation sandbox.
#
# This container EXECUTES untrusted code on purpose. It exists because static analysis is
# structurally blind to self-extracting payloads — code that hides in an ignored folder or
# a scrambled blob and reassembles itself only when the skill actually runs. A file-tree
# diff across execution is the only thing that sees it.
#
# HONEST LIMIT: Docker is not a kernel-strength boundary. This raises the cost of an
# attack; it does not guarantee containment. Recorded as residual risk in the spec rather
# than dressed up as a guarantee.
#
# Run-time hardening is applied by the caller, not baked in here:
#   --network none --read-only --cap-drop ALL --security-opt no-new-privileges
#   --pids-limit 128 --memory 512m --cpus 1 --tmpfs /work
# The Docker socket is NEVER mounted.
#
# Build: docker build -f docker/detonator.Dockerfile -t detonator:pinned .

FROM python:3.12-slim

# nodejs so JavaScript lifecycle hooks detonate too, not just Python ones.
RUN apt-get update \
 && apt-get install -y --no-install-recommends nodejs coreutils findutils \
 && rm -rf /var/lib/apt/lists/*

RUN useradd -m -u 10002 det
USER det
WORKDIR /work

ENTRYPOINT ["/bin/sh", "-c"]
