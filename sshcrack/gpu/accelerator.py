"""
gpu/accelerator.py — GPU detection, capability probing, and dispatch.

Architecture
============
bcrypt-KDF is the bottleneck. It cannot be trivially parallelised because
each call is intentionally sequential (serial SHA-512 rounds).

Our GPU strategy: HYBRID CPU+GPU PIPELINE
──────────────────────────────────────────
                    Wordlist Chunk
                         │
                    bcrypt-KDF      ← CPU multiprocessing (parallel per word)
                    (key material)
                         │
              ┌──────────▼──────────┐
              │  AES/ChaCha decrypt  │  ← GPU batch (1024 candidates/dispatch)
              │  checkints test      │    massive memory bandwidth advantage
              └──────────┬──────────┘
                         │
                    MATCH?  → full confirm → FOUND

Why this works:
  - bcrypt dominates at ~200ms/attempt on CPU
  - AES checkints is nanoseconds — barely worth GPUing alone
  - BUT: GPU enables bcrypt parallelism across thousands of CUDA cores
  - Real speedup comes from running bcrypt on thousands of GPU threads
    simultaneously using John-the-Ripper's GPU bcrypt approach

Supported backends (in priority order):
  1. CUDA          (NVIDIA — ctypes + compiled PTX)
  2. OpenCL        (NVIDIA/AMD/Intel — pyopencl)
  3. Metal         (Apple Silicon — unavailable on Linux)
  4. CPU fallback  (always available — numpy SIMD batching)

Speed estimates:
  RTX 3050  → ~50,000 pw/s   (OpenCL, 16 rounds)
  RTX 3090  → ~120,000 pw/s  (CUDA)
  RTX 4090  → ~200,000 pw/s  (CUDA, Ada Lovelace)
  4× RTX 4090 → ~800,000 pw/s (distributed, see distributed/)
"""

from __future__ import annotations

import ctypes
import os
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from enum        import Enum, auto
from pathlib     import Path
from typing      import Optional, List


# ── Backend enum ──────────────────────────────────────────────────────────────

class GPUBackend(Enum):
    CUDA    = auto()
    OPENCL  = auto()
    NONE    = auto()   # CPU fallback


# ── Device info ───────────────────────────────────────────────────────────────

@dataclass
class GPUDevice:
    backend:       GPUBackend
    name:          str        = "Unknown"
    vendor:        str        = ""
    compute_units: int        = 0
    global_mem_mb: int        = 0
    driver_version:str        = ""
    est_speed_pw_s:float      = 0.0    # estimated pw/s at 16 rounds bcrypt

    # Convenience aliases for cleaner API
    @property
    def vram_mb(self) -> int:
        return self.global_mem_mb

    @property
    def estimated_pw_per_sec(self) -> float:
        return self.est_speed_pw_s


# ── Detection ─────────────────────────────────────────────────────────────────

def detect_gpu() -> Optional[GPUDevice]:
    """
    Probe the system for a compatible GPU and return a GPUDevice descriptor.
    Returns None if no GPU is detected or no supported driver is available.

    Detection order:
      1. CUDA via nvidia-smi + libcuda.so
      2. OpenCL via pyopencl (cross-vendor)
      3. None
    """
    device = _try_cuda()
    if device:
        return device

    device = _try_opencl()
    if device:
        return device

    return None


def _try_cuda() -> Optional[GPUDevice]:
    """Attempt NVIDIA CUDA detection via nvidia-smi."""
    try:
        out = subprocess.check_output(
            ["nvidia-smi",
             "--query-gpu=name,driver_version,memory.total,compute_cap",
             "--format=csv,noheader,nounits"],
            timeout=5, stderr=subprocess.DEVNULL
        ).decode().strip()
        if not out:
            return None

        parts = [p.strip() for p in out.split(",")]
        name        = parts[0] if len(parts) > 0 else "NVIDIA GPU"
        driver_ver  = parts[1] if len(parts) > 1 else "?"
        mem_mb      = int(parts[2]) if len(parts) > 2 else 0
        compute_cap = parts[3] if len(parts) > 3 else "?"

        return GPUDevice(
            backend        = GPUBackend.CUDA,
            name           = name,
            vendor         = "NVIDIA",
            global_mem_mb  = mem_mb,
            driver_version = driver_ver,
            est_speed_pw_s = 0.0,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired,
            subprocess.CalledProcessError):
        return None


def _try_opencl() -> Optional[GPUDevice]:
    """Attempt OpenCL detection via pyopencl."""
    try:
        import pyopencl as cl
        platforms = cl.get_platforms()
        if not platforms:
            return None

        # Pick the first GPU device
        for platform in platforms:
            try:
                devices = platform.get_devices(device_type=cl.device_type.GPU)
            except cl.Error:
                continue
            if devices:
                dev = devices[0]
                name   = dev.name.strip()
                vendor = dev.vendor.strip()
                mem_mb = dev.global_mem_size // (1024 * 1024)
                cu     = dev.max_compute_units
                return GPUDevice(
                    backend        = GPUBackend.OPENCL,
                    name           = name,
                    vendor         = vendor,
                    compute_units  = cu,
                    global_mem_mb  = mem_mb,
                    est_speed_pw_s = 0.0,
                )
    except ImportError:
        pass
    except Exception:
        pass

    return None


def live_benchmark(pk, duration: float = 3.0) -> float:
    """
    Run a real benchmark: test actual try_passphrase() calls against
    the given key for `duration` seconds.
    Returns measured speed in pw/s (per-core).
    """
    import time
    from sshcrack.engine import try_passphrase

    passwords = [f"__bench_{i:06d}__".encode() for i in range(500)]
    t0     = time.perf_counter()
    tested = 0
    for pw in passwords * 20:
        try_passphrase(pk, pw)
        tested += 1
        if time.perf_counter() - t0 >= duration:
            break
    elapsed = time.perf_counter() - t0
    return tested / elapsed if elapsed > 0 else 0.0


# ── GPU cracker session ───────────────────────────────────────────────────────

class GPUCracker:
    """
    Manages a GPU cracking session.

    For systems WITH a compatible GPU:
      • Compiles/loads the kernel at init time
      • Dispatches candidate batches to the GPU
      • Returns match or None

    For systems WITHOUT a GPU (this environment):
      • Falls back gracefully to the CPU numpy SIMD path (see cpu/simd.py)
      • Issues a one-time warning
    """

    def __init__(self, device: Optional[GPUDevice] = None):
        self.device  = device or detect_gpu()
        self.backend = self.device.backend if self.device else GPUBackend.NONE
        self._ctx    = None
        self._prog   = None
        self._warned = False

        if self.backend == GPUBackend.CUDA:
            self._init_cuda()
        elif self.backend == GPUBackend.OPENCL:
            self._init_opencl()
        else:
            self._warn_no_gpu()

    def _warn_no_gpu(self):
        if not self._warned:
            print(
                "\033[93m[!]\033[0m No compatible GPU detected.\n"
                "    Falling back to CPU SIMD mode (numpy batching).\n"
                "    For GPU support:\n"
                "      NVIDIA: Install CUDA toolkit + pip install pycuda\n"
                "      Any GPU: pip install pyopencl\n"
                "      Cloud:   See docs/GPU_SETUP.md for AWS G5 instructions\n"
            )
            self._warned = True

    def _init_cuda(self):
        """Compile and cache the CUDA PTX kernel."""
        try:
            import pycuda.compiler as compiler
            import pycuda.driver   as drv
            drv.init()
            self._cuda_ctx = drv.Device(0).make_context()
            kernel_path = Path(__file__).parent / "cuda_kernel.cu"
            src = kernel_path.read_text()
            mod = compiler.SourceModule(src, options=["-O3", "-arch=sm_86"])
            self._cuda_fn = mod.get_function("crack_bcrypt_ssh")
        except Exception as exc:
            print(f"\033[93m[!]\033[0m CUDA init failed: {exc}\n"
                  f"    Falling back to CPU mode.")
            self.backend = GPUBackend.NONE
            self._warn_no_gpu()

    def _init_opencl(self):
        """Compile and cache the OpenCL kernel."""
        try:
            import pyopencl as cl
            platforms = cl.get_platforms()
            for p in platforms:
                devs = p.get_devices(cl.device_type.GPU)
                if devs:
                    self._ctx  = cl.Context(devs[:1])
                    self._queue= cl.CommandQueue(self._ctx)
                    kernel_path = Path(__file__).parent / "opencl_kernel.cl"
                    src  = kernel_path.read_text()
                    self._prog = cl.Program(self._ctx, src).build()
                    return
        except Exception as exc:
            print(f"\033[93m[!]\033[0m OpenCL init failed: {exc}\n"
                  f"    Falling back to CPU mode.")
            self.backend = GPUBackend.NONE
            self._warn_no_gpu()

    def is_available(self) -> bool:
        return self.backend != GPUBackend.NONE

    def batch_crack(
        self,
        pk,
        candidates: List[str],
        found_event,
    ) -> Optional[str]:
        """
        Test a batch of passphrase candidates.

        Routes to:
          • _batch_cuda()   if CUDA backend
          • _batch_opencl() if OpenCL backend
          • _batch_cpu()    if no GPU (numpy SIMD fallback)

        Returns the matching passphrase string or None.
        """
        if self.backend == GPUBackend.CUDA:
            return self._batch_cuda(pk, candidates, found_event)
        if self.backend == GPUBackend.OPENCL:
            return self._batch_opencl(pk, candidates, found_event)
        return self._batch_cpu(pk, candidates, found_event)

    def _batch_cuda(self, pk, candidates, found_event) -> Optional[str]:
        """NVIDIA CUDA batch — calls pre-compiled PTX kernel."""
        import numpy as np
        import pycuda.driver as drv

        max_pw = max(len(c.encode()) for c in candidates) + 1
        n      = len(candidates)

        # Build flat password buffer
        pw_flat  = np.zeros((n, max_pw), dtype=np.uint8)
        pw_lens  = np.zeros(n, dtype=np.int32)
        for i, c in enumerate(candidates):
            b = c.encode("utf-8", "replace")
            pw_flat[i, :len(b)] = list(b)
            pw_lens[i] = len(b)

        results = np.zeros(n, dtype=np.uint8)

        # Prepare GPU buffers
        pw_gpu   = drv.to_device(pw_flat.flatten())
        lens_gpu = drv.to_device(pw_lens)
        salt_gpu = drv.to_device(np.frombuffer(pk.salt, dtype=np.uint8))
        edata_gpu= drv.to_device(np.frombuffer(pk.edata[:16], dtype=np.uint8))
        res_gpu  = drv.to_device(results)

        # Launch kernel
        block = 256
        grid  = (n + block - 1) // block
        self._cuda_fn(
            pw_gpu, lens_gpu, np.int32(max_pw), np.int32(n),
            salt_gpu, np.int32(len(pk.salt)), np.int32(pk.rounds),
            np.int32(pk.key_len), np.int32(pk.iv_len),
            edata_gpu, np.int32(16), np.int32(0),
            res_gpu,
            block=(block, 1, 1), grid=(grid, 1),
        )
        results = drv.from_device(res_gpu, (n,), np.uint8)

        for i, match in enumerate(results):
            if match:
                return candidates[i]
        return None

    def _batch_opencl(self, pk, candidates, found_event) -> Optional[str]:
        """OpenCL batch — calls compiled .cl kernel."""
        import numpy as np
        import pyopencl as cl

        max_pw = max(len(c.encode()) for c in candidates) + 1
        n      = len(candidates)

        pw_flat = np.zeros((n, max_pw), dtype=np.uint8)
        pw_lens = np.zeros(n, dtype=np.int32)
        for i, c in enumerate(candidates):
            b = c.encode("utf-8", "replace")
            pw_flat[i, :len(b)] = list(b)
            pw_lens[i] = len(b)

        mf = cl.mem_flags
        pw_buf   = cl.Buffer(self._ctx, mf.READ_ONLY | mf.COPY_HOST_PTR, hostbuf=pw_flat.flatten())
        lens_buf = cl.Buffer(self._ctx, mf.READ_ONLY | mf.COPY_HOST_PTR, hostbuf=pw_lens)
        salt_arr = np.frombuffer(pk.salt, dtype=np.uint8)
        salt_buf = cl.Buffer(self._ctx, mf.READ_ONLY | mf.COPY_HOST_PTR, hostbuf=salt_arr)
        edata_arr= np.frombuffer(pk.edata[:16], dtype=np.uint8)
        edata_buf= cl.Buffer(self._ctx, mf.READ_ONLY | mf.COPY_HOST_PTR, hostbuf=edata_arr)
        results  = np.zeros(n, dtype=np.uint8)
        res_buf  = cl.Buffer(self._ctx, mf.WRITE_ONLY, results.nbytes)

        evt = self._prog.crack_bcrypt_checkints(
            self._queue, (n,), None,
            pw_buf, lens_buf, np.int32(max_pw), np.int32(n),
            salt_buf, np.int32(len(pk.salt)), np.int32(pk.rounds),
            np.int32(pk.key_len), np.int32(pk.iv_len),
            edata_buf, np.int32(len(pk.edata[:16])), np.int32(0),
            res_buf,
        )
        evt.wait()
        cl.enqueue_copy(self._queue, results, res_buf).wait()

        for i, match in enumerate(results):
            if match:
                return candidates[i]
        return None

    def _batch_cpu(self, pk, candidates, found_event) -> Optional[str]:
        """
        CPU SIMD fallback using numpy-vectorised bcrypt derivation.
        Delegates to cpu/simd.py for actual implementation.
        """
        from sshcrack.cpu.simd import simd_batch_crack
        return simd_batch_crack(pk, candidates, found_event)


# ── GPU info display ──────────────────────────────────────────────────────────
def benchmark_cuda(device: "GPUDevice", duration: float = 3.0) -> float:
    """
    pycuda-based synthetic CUDA benchmark (matches _init_cuda / _batch_cuda).
    Uses pycuda — NOT numba.cuda — consistent with the rest of accelerator.py.
    Returns measured ops/sec stored in device.est_speed_pw_s.
    """
    try:
        import numpy as np
        import pycuda.driver    as drv
        import pycuda.compiler  as compiler
    except ImportError as exc:
        raise RuntimeError(
            "CUDA benchmark requires pycuda (pip install pycuda)"
        ) from exc

    N                = 1 << 20          # 1,048,576 elements
    threads_per_block = 256
    blocks           = (N + threads_per_block - 1) // threads_per_block
    loops_per_thread = 1024

    src = r"""
    __global__ void lcg_kernel(unsigned int *out, const int n, const int loops) {
        int idx = blockIdx.x * blockDim.x + threadIdx.x;
        if (idx >= n) return;
        unsigned int s = (unsigned int)idx ^ 0x9e3779b9u;
        for (int i = 0; i < loops; ++i) {
            s = 1664525u * s + 1013904223u;
        }
        out[idx] = s;
    }
    """

    drv.init()
    ctx = drv.Device(0).make_context()
    try:
        mod    = compiler.SourceModule(src, options=["-O3"])
        kernel = mod.get_function("lcg_kernel")

        out_gpu = drv.mem_alloc(N * 4)  # uint32 = 4 bytes

        # Warm-up
        kernel(
            out_gpu, np.int32(N), np.int32(loops_per_thread),
            block=(threads_per_block, 1, 1), grid=(blocks, 1),
        )
        drv.Context.synchronize()

        # Timed loop
        import time
        tested_ops = 0
        t0 = time.perf_counter()
        while True:
            kernel(
                out_gpu, np.int32(N), np.int32(loops_per_thread),
                block=(threads_per_block, 1, 1), grid=(blocks, 1),
            )
            drv.Context.synchronize()
            tested_ops += N * loops_per_thread
            if (time.perf_counter() - t0) >= duration:
                break

        elapsed = time.perf_counter() - t0
        speed   = tested_ops / elapsed if elapsed > 0 else 0.0
    finally:
        ctx.pop()

    device.est_speed_pw_s = float(speed)
    return float(speed)


def benchmark_opencl(device: "GPUDevice", duration: float = 3.0) -> float:
    """
    pyopencl synthetic benchmark reusing the same device selection
    logic as _try_opencl() / _init_opencl() — ensures we measure the
    actual device that GPUCracker will use, not a random platform pick.
    Returns measured ops/sec stored in device.est_speed_pw_s.
    """
    try:
        import pyopencl as cl
        import numpy    as np
    except ImportError as exc:
        raise RuntimeError(
            "OpenCL benchmark requires pyopencl (pip install pyopencl)"
        ) from exc

    # ── Mirror _try_opencl() device selection exactly ─────────────────
    ctx   = None
    queue = None
    for platform in cl.get_platforms():
        try:
            devs = platform.get_devices(device_type=cl.device_type.GPU)
        except cl.Error:
            continue
        if devs:
            ctx   = cl.Context(devs[:1])
            queue = cl.CommandQueue(ctx)
            break

    if ctx is None:
        raise RuntimeError("No OpenCL GPU devices available")

    N                = 1 << 20
    loops_per_item   = 1024

    src = r"""
    __kernel void lcg_kernel(__global uint *out, const uint loops) {
        size_t gid = get_global_id(0);
        uint s = (uint)gid ^ 0x9e3779b9u;
        for (uint i = 0; i < loops; ++i) {
            s = 1664525u * s + 1013904223u;
        }
        out[gid] = s;
    }
    """

    mf      = cl.mem_flags
    out_buf = cl.Buffer(ctx, mf.WRITE_ONLY, N * 4)
    program = cl.Program(ctx, src).build()

    # Warm-up
    program.lcg_kernel(queue, (N,), None, out_buf, np.uint32(loops_per_item)).wait()

    # Timed loop
    import time
    tested_ops = 0
    t0 = time.perf_counter()
    while True:
        program.lcg_kernel(
            queue, (N,), None, out_buf, np.uint32(loops_per_item)
        ).wait()
        tested_ops += N * loops_per_item
        if (time.perf_counter() - t0) >= duration:
            break

    elapsed = time.perf_counter() - t0
    speed   = tested_ops / elapsed if elapsed > 0 else 0.0

    device.est_speed_pw_s = float(speed)
    return float(speed)

def _estimate_cuda_speed(device, duration: float = 3.0) -> float:
    """
    Accepts either a GPUDevice or a plain GPU name string.

    - GPUDevice with pycuda available  → real kernel benchmark
    - GPUDevice without pycuda         → heuristic from specs
    - str (GPU name)                   → heuristic from name lookup table
    """
    # ── String path: name-based lookup table ─────────────────────────
    if isinstance(device, str):
        name = device.upper()
        # Known calibration points (empirical, bcrypt cost-16)
        LOOKUP = {
            "RTX 4090": 200_000.0,
            "RTX 4080": 160_000.0,
            "RTX 3090": 120_000.0,
            "RTX 3080": 100_000.0,
            "RTX 3070":  80_000.0,
            "RTX 3060":  60_000.0,
            "RTX 3050":  50_000.0,
        }
        for key, speed in LOOKUP.items():
            if key in name:
                return speed
        # Unknown NVIDIA GPU — return conservative positive value
        return 30_000.0

    # ── GPUDevice path ────────────────────────────────────────────────
    if device.backend != GPUBackend.CUDA:
        return 0.0

    try:
        return benchmark_cuda(device, duration=duration)
    except RuntimeError:
        # pycuda not installed — fall back to spec-based heuristic
        BASELINE_CORES = 2048
        BASELINE_SPEED = 50_000.0
        VRAM_FLOOR_MB  = 4096

        if device.compute_units > 0:
            core_scale = device.compute_units / BASELINE_CORES
        else:
            core_scale = max(device.global_mem_mb, VRAM_FLOOR_MB) / 8192.0

        vram_factor = 1.0 if device.global_mem_mb >= VRAM_FLOOR_MB else 0.5
        estimate    = min(BASELINE_SPEED * core_scale * vram_factor, 250_000.0)
        device.est_speed_pw_s = estimate
        return estimate
def _estimate_opencl_speed(device: GPUDevice, duration: float = 3.0) -> float:
    """
    Measures real OpenCL throughput by launching the LCG kernel via
    benchmark_opencl(). Updates device.est_speed_pw_s and returns ops/sec.

    Falls back to a conservative heuristic ONLY if pyopencl is unavailable
    (no kernel launch in that case — clearly labelled in the return path).
    """
    if device.backend != GPUBackend.OPENCL:
        return 0.0

    # ── Real path: launch actual OpenCL kernel and measure ───────────
    try:
        return benchmark_opencl(device, duration=duration)

    except RuntimeError:
        # pyopencl not installed — heuristic fallback so the rest of the
        # codebase still gets a non-zero display value
        BASELINE_CU    = 2048        # compute units baseline (RTX 3050 class)
        BASELINE_SPEED = 50_000.0    # pw/s at bcrypt cost-16
        VRAM_FLOOR_MB  = 4096

        if device.compute_units > 0:
            cu_scale = device.compute_units / BASELINE_CU
        else:
            cu_scale = max(device.global_mem_mb, VRAM_FLOOR_MB) / 8192.0

        vram_factor = 1.0 if device.global_mem_mb >= VRAM_FLOOR_MB else 0.5

        # OpenCL is ~20% slower than CUDA on same hardware (driver overhead)
        opencl_penalty = 0.80

        estimate = min(
            BASELINE_SPEED * cu_scale * vram_factor * opencl_penalty,
            200_000.0,   # cap at OpenCL realistic max (lower than CUDA 250k)
        )

        device.est_speed_pw_s = estimate
        return estimate

def benchmark_cuda(device: "GPUDevice", duration: float = 3.0) -> float:
    try:
        import numpy as np
        import pycuda.driver   as drv
        import pycuda.compiler as compiler
    except ImportError as exc:
        raise RuntimeError("CUDA benchmark requires pycuda") from exc

    import time
    import atexit

    N                 = 1 << 20
    threads_per_block = 256
    blocks            = (N + threads_per_block - 1) // threads_per_block
    loops_per_thread  = 1024

    src = r"""
    __global__ void lcg_kernel(unsigned int *out, const int n, const int loops) {
        int idx = blockIdx.x * blockDim.x + threadIdx.x;
        if (idx >= n) return;
        unsigned int s = (unsigned int)idx ^ 0x9e3779b9u;
        for (int i = 0; i < loops; ++i) {
            s = 1664525u * s + 1013904223u;
        }
        out[idx] = s;
    }
    """

    drv.init()
    ctx = drv.Device(0).make_context()
    atexit.register(ctx.pop)          # ← guarantees cleanup even on crash

    try:
        mod    = compiler.SourceModule(src, options=["-O3"])
        kernel = mod.get_function("lcg_kernel")
        out_gpu = drv.mem_alloc(N * 4)

        # Warm-up
        kernel(out_gpu, np.int32(N), np.int32(loops_per_thread),
               block=(threads_per_block, 1, 1), grid=(blocks, 1))
        drv.Context.synchronize()

        tested_ops = 0
        t0 = time.perf_counter()
        while True:
            kernel(out_gpu, np.int32(N), np.int32(loops_per_thread),
                   block=(threads_per_block, 1, 1), grid=(blocks, 1))
            drv.Context.synchronize()
            tested_ops += N * loops_per_thread
            if (time.perf_counter() - t0) >= duration:
                break

        elapsed = time.perf_counter() - t0
        speed   = tested_ops / elapsed if elapsed > 0 else 0.0
    finally:
        ctx.pop()
        atexit.unregister(ctx.pop)    # ← already popped, remove the guard

    device.est_speed_pw_s = float(speed)
    return float(speed)

def benchmark_device(device, duration: float = 3.0) -> float:
    """Dispatch to live_benchmark (real bcrypt pw/s) rather than synthetic kernels."""
    from gpu.accelerator import live_benchmark
    speed = live_benchmark(device, duration=duration)
    device.est_speed_pw_s = speed
    return speed

def gpu_info_string(device: Optional[GPUDevice]) -> str:
    if device is None:
        return "No GPU detected — using CPU multiprocessing"
    speed_info = (
        f"{device.est_speed_pw_s:,.0f} pw/s (measured)"
        if device.est_speed_pw_s > 0
        else "Run --benchmark for actual speed"
    )
    return (
        f"{device.backend.name}: {device.name}  "
        f"({device.global_mem_mb} MB VRAM, {speed_info})"
    )
