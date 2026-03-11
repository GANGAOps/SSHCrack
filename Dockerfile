# ─────────────────────────────────────────────────────────────────────────────
# ssh-crack v1 — Docker image (GPU-enabled)
#
# Build variants:
#   CPU-only (default):
#     docker build -t sshcrack:cpu .
#
#   NVIDIA GPU (requires CUDA 12.x toolkit on host):
#     docker build --build-arg BASE=nvidia/cuda:12.3.1-devel-ubuntu22.04 \
#                  -t sshcrack:gpu .
#
# Run:
#   CPU:  docker run --rm -v $(pwd):/work sshcrack:cpu \
#               -k /work/id_ed25519 -w /work/rockyou.txt
#
#   GPU:  docker run --rm --gpus all -v $(pwd):/work sshcrack:gpu \
#               -k /work/id_ed25519 -w /work/rockyou.txt
#
#   Distributed master:
#         docker run --rm --network host -v $(pwd):/work sshcrack:cpu \
#               -k /work/id_ed25519 -w /work/rockyou.txt --distributed-master
#
#   Distributed worker:
#         docker run --rm --network host sshcrack:cpu \
#               --distributed-worker --master 192.168.1.10
# ─────────────────────────────────────────────────────────────────────────────

ARG BASE=python:3.12-slim-bookworm
FROM ${BASE}

LABEL maintainer="Bhanu Guragain <@Bh4nu>"
LABEL version="1.0.0"
LABEL description="ssh-crack — SSH Private Key Passphrase Cracker"
LABEL org.opencontainers.image.source="https://github.com/GANGAOps/SSHCrack"

# ── System dependencies ───────────────────────────────────────────────────────
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
        libffi-dev \
        libssl-dev \
        libopenblas-dev \
        && rm -rf /var/lib/apt/lists/*

# ── Python deps (pinned versions from requirements.txt) ──────────────────────
COPY requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt

# Optional: ZeroMQ for distributed cracking
RUN pip install --no-cache-dir pyzmq || true

# Optional: CUDA (only activates if NVIDIA runtime present)
# pycuda is not installed by default — too large for CPU image
# GPU users: build with ARG BASE=nvidia/cuda:12.3.1-devel-ubuntu22.04
#   and run: pip install pycuda

# ── Application ───────────────────────────────────────────────────────────────
WORKDIR /app
COPY . /app/
RUN pip install --no-cache-dir -e .

# ── Non-root user ─────────────────────────────────────────────────────────────
RUN useradd -m -u 1000 cracker
USER cracker

# ── Volume mount for keys + wordlists ─────────────────────────────────────────
VOLUME ["/work"]
WORKDIR /work

# ── Health check ──────────────────────────────────────────────────────────────
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python3 -c "import sshcrack; print(sshcrack.__version__)" || exit 1

# ── Entry point ───────────────────────────────────────────────────────────────
ENTRYPOINT ["sshcrack"]
CMD ["--help"]
