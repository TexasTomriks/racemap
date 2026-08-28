# racemap — Linux kernel shared page-cache race scanner with LLM triage.
# Single self-contained image: Coccinelle + Semgrep + the racemap CLI.
#
#   docker build -t racemap .
#   docker run --rm -v /path/to/linux:/kernel racemap scan /kernel/net/
#
FROM python:3.11-slim

# Coccinelle provides `spatch`; build-essential is handy for spatch internals.
RUN apt-get update \
    && apt-get install -y --no-install-recommends coccinelle \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python deps first for layer caching. Semgrep is in requirements.txt.
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

# Copy the project.
COPY . /app

# Run as an unprivileged user. /app and /kernel need to stay writable by it:
# the cache db (~/.racemap), scan exports, and (for --external-tools) spatch
# temp files all land under paths this user owns. Must come before VOLUME,
# not after: a RUN following VOLUME does not reliably affect what a
# container sees mounted there.
RUN useradd --create-home --uid 1000 racemap \
    && mkdir -p /kernel \
    && chown -R racemap:racemap /app /kernel
USER racemap

# Mount point for the user's kernel source tree. In practice this is always
# either bind-mounted (-v /path/to/linux:/kernel, or docker-compose's
# ./kernel:/kernel:ro) or left as the empty dir above -- a bind mount's
# ownership comes from the host side regardless of the chown above.
VOLUME ["/kernel"]

# `docker run --rm racemap <args>` -> `python main.py <args>`.
ENTRYPOINT ["python", "main.py"]
CMD ["--help"]
