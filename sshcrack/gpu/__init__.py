"""
gpu/ — GPU acceleration layer for ssh-crack v2.

Backends (auto-detected at runtime, best available wins):
  1. CUDA    (NVIDIA RTX/Tesla — requires pycuda + CUDA toolkit)
  2. OpenCL  (NVIDIA/AMD/Intel — requires pyopencl)
  3. None    → falls back to cpu/simd.py numpy batching

Usage:
    from sshcrack.gpu.accelerator import GPUCracker, detect_gpu
    device  = detect_gpu()
    cracker = GPUCracker(device)
    result  = cracker.batch_crack(pk, candidates, found_event)
"""

from sshcrack.gpu.accelerator import GPUCracker, GPUDevice, GPUBackend, detect_gpu, gpu_info_string

__all__ = ["GPUCracker", "GPUDevice", "GPUBackend", "detect_gpu", "gpu_info_string"]
