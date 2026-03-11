# Changelog — ssh-crack

All notable changes to this project are documented here.
Format: [Semantic Versioning](https://semver.org/)

---

## [1.0.0] — 2026-03-09

### Added (Batch 2)

**GPU Acceleration**
- `sshcrack/gpu/accelerator.py` — Auto-detect CUDA (NVIDIA) or OpenCL (any GPU)
- `sshcrack/gpu/opencl_kernel.cl` — OpenCL bcrypt-KDF + AES checkints kernel
- `sshcrack/gpu/cuda_kernel.cu` — NVIDIA CUDA bcrypt kernel (sm_86/sm_89)
- `--gpu-info` CLI flag — display detected GPU and estimated speed
- `--no-gpu` CLI flag — force CPU-only mode
- Graceful fallback to CPU when no GPU present (one-time warning)

**CPU SIMD Batching**
- `sshcrack/cpu/simd.py` — NumPy vectorised AES checkints + ctypes AES-NI
- Pre-filter heuristics (discard empty/whitespace/overlong candidates before bcrypt)
- Capability probe: auto-detects bcrypt module availability
- `get_optimal_batch_size()` — RAM-aware batch sizing

**Smart Wordlist Ordering**
- `sshcrack/cpu/wordfreq.py` — Breach-frequency heuristic candidate ordering
- `smart_sort()` — O(n log n) numpy argsort by pattern score
- `FrequencyIndex` — multi-wordlist breach-frequency map
- `priority_candidates()` — top-probability mutations per base word
- `top_k_first()` — streaming iterator with high-probability front-loading
- `--no-smart-order` CLI flag — disable for reproducible benchmarks
- Keyboard walk detector (`is_keyboard_walk()`)

**Distributed Cracking**
- `sshcrack/distributed/master.py` — ZeroMQ PUSH/PULL/PUB master node
- `sshcrack/distributed/worker.py` — Worker node with GPU/CPU auto-routing
- `--distributed-master` CLI flag — start master node
- `--distributed-worker` CLI flag — start worker node
- `--master HOST` CLI flag — worker connection target
- `--work-port`, `--result-port` — custom ZMQ ports
- Linear N-worker scaling, no synchronisation overhead
- `docker-compose.yml` — multi-container distributed cracking

**Cloud Deployment**
- `scripts/deploy_aws.py` — AWS G5 spot instance auto-deploy
- Supports g5.xlarge through g5.48xlarge (NVIDIA A10G)
- Spot pricing with auto-termination

**Documentation**
- `docs/GPU_SETUP.md` — CUDA/OpenCL/AMD/Docker/AWS setup guide
- `docs/DISTRIBUTED.md` — Distributed cracking complete guide
- `docs/BENCHMARKS.md` — Hardware benchmarks, rounds impact, legacy key speeds

**Infrastructure**
- `Dockerfile` — GPU-enabled Docker image (ARG BASE for CPU/CUDA variants)
- `docker-compose.yml` — Master + N workers via `--scale worker=N`

**Tests** (62 new, 163 total)
- `tests/test_batch2.py` — 62 tests across 7 classes
  - TestGPUDetection (8), TestSIMDBatch (8), TestWordFreq (15),
    TestDistributedMsgs (8), TestCLINewFlags (7),
    TestCrackerBatch2 (10), TestIntegrationB2 (6)

### Changed

- `sshcrack/__init__.py` — version bumped to 1.0.0
- `sshcrack/cracker.py` — integrates GPU, SIMD, smart-order, distributed
- `sshcrack/cli.py` — 7 new arguments added
- `sshcrack/cpu/__init__.py` — exports SIMD and wordfreq APIs

---

## [1.0.0] — 2026-03-09

### Added (Batch 1)

**Core engine**
- `sshcrack/parser.py` — OpenSSH new format, legacy PEM, PPK v2/v3
- `sshcrack/engine.py` — fast-path checkints + full key-load confirmation
- `sshcrack/cracker.py` — multiprocessing orchestrator
- `sshcrack/wordlist.py` — streaming byte-range chunker (OOM-safe)
- `sshcrack/session.py` — save/resume sessions
- `sshcrack/display.py` — progress bar, result boxes, benchmark output
- `sshcrack/cli.py` — 24-argument CLI entry point

**Attack modes**
- Wordlist (streaming, O(1) memory per worker)
- Built-in mutation rules (~100 mutations per word)
- Hashcat .rule file support (25+ opcodes, Best64 built-in)
- Mask attack (?l?u?d?s?a?b + custom charsets)
- Hybrid (wordlist × mask)

**Key format support**
- OpenSSH new format: Ed25519, RSA, ECDSA, DSA
- OpenSSH legacy PEM: RSA, ECDSA, DSA
- PuTTY PPK v2 (HMAC-SHA1 + AES-256-CBC + MD5 KDF)
- PuTTY PPK v3 (HMAC-SHA256 + AES-256-CBC + Argon2id KDF)

**Bug fixes over original sshcrack.py**
- Fixed OOM on large wordlists (streaming chunker)
- Fixed ECDSA fast-path (wrong block size)
- Fixed legacy key full-confirm (wrong loader)
- Fixed ChaCha20-Poly1305 fast-path (missing MAC verification)

**Tests** (101)
- `tests/test_all.py` — 101 tests across 9 classes
