# SCANGATE stage-1 scanner: NVIDIA SkillSpector, pinned by commit SHA.
#
# Network is used at BUILD time only. Every scan runs with `--network none`, so even a
# fully compromised scanner has no channel to exfiltrate what it reads. That containment
# is what makes a weekly-cadence anchor inspection sufficient rather than requiring
# continuous verification.
#
# Build:
#   REF=$(node -p "require('./docker/skillspector.pin.json').ref")
#   docker build -f docker/skillspector.Dockerfile --build-arg SKILLSPECTOR_REF=$REF -t skillspector:$REF .
#   docker tag skillspector:$REF skillspector:pinned

FROM python:3.12-slim

ARG SKILLSPECTOR_REF
RUN test -n "$SKILLSPECTOR_REF" || (echo "SKILLSPECTOR_REF build-arg is required — refusing to build from a floating ref" && exit 1)

RUN apt-get update \
 && apt-get install -y --no-install-recommends git \
 && pip install --no-cache-dir "git+https://github.com/NVIDIA/SkillSpector.git@${SKILLSPECTOR_REF}" \
 && apt-get purge -y git \
 && apt-get autoremove -y \
 && rm -rf /var/lib/apt/lists/*

# Record the pin inside the image so `docker inspect` can prove which ref is running.
LABEL org.scangate.skillspector_ref="${SKILLSPECTOR_REF}"
ENV SCANGATE_SKILLSPECTOR_REF=${SKILLSPECTOR_REF}

RUN useradd -m -u 10001 scanner
USER scanner
WORKDIR /scan

ENTRYPOINT ["skillspector"]
