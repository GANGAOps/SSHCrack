"""
sshcrack — SSH Private Key Passphrase Cracker v1

GANGA Offensive Ops // Bhanu Guragain (Lead Developer / Author)

Highlights:
  • OpenSSH (Ed25519/RSA/ECDSA/DSA) + PuTTY PPK v2/v3
  • GPU acceleration: CUDA (NVIDIA) + OpenCL (any)
  • CPU SIMD batching via numpy + ctypes AES-NI
  • Smart breach-frequency candidate ordering
  • Distributed cracking via ZeroMQ (linear N-machine scaling)
  • Wordlist / Rules / Hashcat .rule / Mask / Hybrid
  • Session save/resume across restarts
  • SSH live verification post-crack
"""

__version__ = "1.0.0"
__author__  = "Bhanu Guragain (@Bh4nu)"
__license__ = "Apache-2.0"

from sshcrack.cracker import crack
from sshcrack.parser  import parse_key_file, ParsedKey

__all__ = ["crack", "parse_key_file", "ParsedKey", "__version__"]
