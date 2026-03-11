"""
cpu/ — CPU acceleration layer for ssh-crack v2.

Modules:
  simd.py     — NumPy vectorised batch AES checkints + ctypes AES-NI
  wordfreq.py — Breach-frequency smart candidate ordering

Both modules are imported lazily by cracker.py and only activated
when use_smart_order=True or use_gpu=False respectively.
"""

from sshcrack.cpu.simd     import simd_batch_crack, benchmark_simd, get_optimal_batch_size
from sshcrack.cpu.wordfreq import smart_sort, top_k_first, FrequencyIndex, priority_candidates

__all__ = [
    "simd_batch_crack", "benchmark_simd", "get_optimal_batch_size",
    "smart_sort", "top_k_first", "FrequencyIndex", "priority_candidates",
]
