"""
sshcrack/__main__.py — Enable running as: python -m sshcrack

Usage:
    python -m sshcrack -k id_ed25519 -w rockyou.txt
    python -m sshcrack --help
"""

from sshcrack.cli import main

if __name__ == "__main__":
    main()
