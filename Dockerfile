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

# Mount point for the user's kernel source tree.
VOLUME ["/kernel"]
RUN mkdir -p /kernel

# `docker run --rm racemap <args>` -> `python main.py <args>`.
ENTRYPOINT ["python", "main.py"]
CMD ["--help"]
