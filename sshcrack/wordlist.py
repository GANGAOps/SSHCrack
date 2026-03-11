"""
wordlist.py — Memory-safe wordlist handling.

Fixes the OOM bug in v1.0: the original _chunk_wordlist() loaded the entire
wordlist into RAM as a list-of-lists.  For rockyou.txt (133 MB) × 16 workers
that's 2+ GB just for wordlist copies.

This module provides:
  • WordlistStreamer  — streams lines from disk, never loads all into RAM
  • chunk_wordlist()  — produces byte-offset ranges (not line copies) for workers
  • WordlistSource    — abstraction over file / stdin / generator

Each worker receives a (start_byte, end_byte) range and seeks directly to
its chunk in the file.  Zero duplication, constant memory usage.

Also supports:
  • --stdin  (wordlist piped via stdin)
  • Compressed wordlists (.gz, .bz2, .xz)
"""

from __future__ import annotations

import gzip
import bz2
import lzma
import os
import sys
import tempfile
from pathlib import Path
from typing  import Generator, Iterator, Optional


class WordlistStreamer:
    """
    Stream passphrase candidates from a wordlist file.

    Supports plain text, .gz, .bz2, .xz, and stdin ('-').
    Handles both bytes and str lines transparently.
    """

    def __init__(self, path: str, encoding: str = "utf-8"):
        self.path     = path
        self.encoding = encoding
        self._is_stdin     = (path == "-")
        self._is_compressed = path.endswith((".gz", ".bz2", ".xz"))

    @property
    def is_seekable(self) -> bool:
        """True if we can split the wordlist into byte-range chunks."""
        return not self._is_stdin and not self._is_compressed

    def count_lines(self) -> int:
        """Count total lines (for progress calculation).  Streams the file once."""
        if self._is_stdin:
            return 0  # unknown
        count = 0
        with self._open_raw() as f:
            for _ in f:
                count += 1
        return count

    def file_size(self) -> int:
        """Return file size in bytes (for byte-range chunking)."""
        if not self.is_seekable:
            return 0
        return os.path.getsize(self.path)

    def lines(self,
              start_byte: int = 0,
              end_byte:   int = -1) -> Generator[bytes, None, None]:
        """
        Yield raw bytes lines from start_byte to end_byte.
        If end_byte == -1, read to EOF.
        Skips partial first line when start_byte > 0.
        """
        if self._is_stdin:
            for line in sys.stdin.buffer:
                yield line
            return

        with self._open_raw() as f:
            if start_byte > 0:
                f.seek(start_byte)
                f.readline()           # skip partial line at boundary

            pos = f.tell() if hasattr(f, "tell") else 0
            for raw_line in f:
                yield raw_line
                if end_byte > 0:
                    pos += len(raw_line)
                    if pos >= end_byte:
                        break

    def _open_raw(self):
        """Open the wordlist with appropriate decompression."""
        if self.path.endswith(".gz"):
            return gzip.open(self.path, "rb")
        if self.path.endswith(".bz2"):
            return bz2.open(self.path, "rb")
        if self.path.endswith(".xz"):
            return lzma.open(self.path, "rb")
        return open(self.path, "rb")


def chunk_wordlist(
    path:     str,
    n_chunks: int,
) -> tuple[list[tuple[int, int]], int]:
    """
    Split a wordlist file into n_chunks byte-range tuples.

    For seekable plain-text files: returns (start_byte, end_byte) pairs.
    Workers open the file independently and seek to their chunk.

    For non-seekable (stdin / compressed): returns [(0, -1)] single chunk.

    Returns:
        (chunks, total_lines)
        chunks: list of (start_byte, end_byte) — end_byte=-1 means EOF
        total_lines: approximate line count (0 if stdin/compressed)
    """
    streamer = WordlistStreamer(path)

    if not streamer.is_seekable:
        return [(0, -1)], 0

    file_size   = streamer.file_size()
    total_lines = streamer.count_lines()

    if file_size == 0 or n_chunks <= 1:
        return [(0, -1)], total_lines

    chunk_size = file_size // n_chunks
    chunks: list[tuple[int, int]] = []

    for i in range(n_chunks):
        start = i * chunk_size
        end   = (i + 1) * chunk_size if i < n_chunks - 1 else file_size
        chunks.append((start, end))

    return chunks, total_lines


def validate_wordlist(path: str) -> None:
    """
    Raise ValueError with a helpful message if the wordlist is unusable.
    """
    if path == "-":
        return  # stdin is always valid

    p = Path(path)
    if not p.exists():
        raise ValueError(
            f"Wordlist not found: {path}\n"
            f"  Common locations:\n"
            f"  • /usr/share/wordlists/rockyou.txt\n"
            f"  • /usr/share/seclists/Passwords/rockyou.txt\n"
            f"  • ~/wordlists/rockyou.txt"
        )
    if not p.is_file():
        raise ValueError(f"Wordlist path is not a file: {path}")
    if p.stat().st_size == 0:
        raise ValueError(f"Wordlist is empty: {path}")
