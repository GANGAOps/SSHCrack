"""
display.py — Terminal display and progress rendering.

Provides:
  • Coloured banner
  • Real-time progress bar with speed, ETA, and worker stats
  • Result box (found / not found)
  • Key info table
  • Session list table
  • Benchmark summary table

Designed to degrade gracefully on terminals without ANSI support
(e.g. Windows cmd without VT mode, piped output).
"""

from __future__ import annotations

import os
import sys
import time
from typing import Optional

# ── ANSI colour constants ─────────────────────────────────────────────────────

def _ansi_supported() -> bool:
    """True if the terminal supports ANSI escape sequences."""
    if sys.platform == "win32":
        try:
            import ctypes
            ctypes.windll.kernel32.SetConsoleMode(
                ctypes.windll.kernel32.GetStdHandle(-11), 7
            )
            return True
        except Exception:
            return False
    return hasattr(sys.stdout, "isatty") and sys.stdout.isatty()


_USE_ANSI = _ansi_supported()

# Standard + Bright pairs
RED           = "\033[31m" if _USE_ANSI else ""
BRIGHT_RED    = "\033[91m" if _USE_ANSI else ""
GREEN         = "\033[32m" if _USE_ANSI else ""
BRIGHT_GREEN  = "\033[92m" if _USE_ANSI else ""
YELLOW        = "\033[33m" if _USE_ANSI else ""
BRIGHT_YELLOW = "\033[93m" if _USE_ANSI else ""
BLUE          = "\033[34m" if _USE_ANSI else ""
BRIGHT_BLUE   = "\033[94m" if _USE_ANSI else ""
PURPLE        = "\033[35m" if _USE_ANSI else ""
BRIGHT_PURPLE = "\033[95m" if _USE_ANSI else ""
CYAN          = "\033[36m" if _USE_ANSI else ""
BRIGHT_CYAN   = "\033[96m" if _USE_ANSI else ""

# Non-color formatting (no bright variants needed)
WHITE  = "\033[97m" if _USE_ANSI else ""
GREY   = "\033[90m" if _USE_ANSI else ""
BOLD   = "\033[1m"  if _USE_ANSI else ""
RESET  = "\033[0m"  if _USE_ANSI else ""

BANNER = f"""
{RESET}{CYAN} ─────────────────────────────────────────────────────────{RESET}
{BOLD}{WHITE}           SSH Private Key Passphrase Cracker v1{RESET}
{RESET}{CYAN} ─────────────────────────────────────────────────────────{RESET}
{BOLD}{PURPLE}
  ██████╗ ██╗  ██╗ ██████╗██████╗  █████╗  ██████╗██╗  ██╗
 ██╔════╝ ██║  ██║██╔════╝██╔══██╗██╔══██╗██╔════╝██║ ██╔╝
 ╚█████╗  ███████║██║     ██████╔╝███████║██║     █████╔╝
  ╚═══██╗ ██╔══██║██║     ██╔══██╗██╔══██║██║     ██╔═██╗
 ██████╔╝ ██║  ██║╚██████╗██║  ██║██║  ██║╚██████╗██║  ██╗
 ╚═════╝  ╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝
{RESET}{CYAN} ─────────────────────────────────────────────────────────{RESET}
{BOLD}{BRIGHT_YELLOW}          OpenSSH / PPK v2–v3 · bcrypt / Argon2id{RESET}
{BOLD}{BRIGHT_CYAN} GPU-Accelerated · Distributed · Rule-Based · Session Resume{RESET}
{CYAN} ─────────────────────────────────────────────────────────{RESET}
{BOLD}{BRIGHT_RED}        GANGA Offensive Ops  ·  Authorized Use Only
{RESET}"""


class Display:
    """
    All terminal output funnelled through one class.
    Makes it easy to suppress output in tests or switch to structured logging.
    """

    def __init__(self, verbose: bool = False, quiet: bool = False):
        self.verbose = verbose
        self.quiet   = quiet
        self._last_bar_len = 0

    # ── Banners / info ────────────────────────────────────────────────────────

    def banner(self) -> None:
        if not self.quiet:
            print(BANNER)

    def key_info(self, pk) -> None:
        """Print key metadata table."""
        if self.quiet:
            return
        print(f"{BOLD}[*]{RESET} Key file  : {CYAN}{pk.raw_bytes[:40]!r}...{RESET}")
        print(f"    Type      : {YELLOW}{pk.key_type}{RESET}")
        print(f"    Cipher    : {YELLOW}{pk.cipher_display}{RESET}")
        print(f"    KDF       : {YELLOW}{pk.kdf_display}{RESET}")
        if pk.is_encrypted and pk.rounds:
            cost_note = (
                f"{GREY}  ← {self._rounds_note(pk.rounds)}{RESET}"
            )
            print(f"    KDF rounds: {YELLOW}{pk.rounds}{RESET}{cost_note}")
        if not pk.is_encrypted:
            print(f"\n{GREEN}[+] Key is NOT encrypted — no passphrase needed.{RESET}")

    def _rounds_note(self, rounds: int) -> str:
        if rounds >= 64:  return "very slow  (~1 pw/s/core) — will take a while"
        if rounds >= 32:  return "slow       (~2–4 pw/s/core)"
        if rounds >= 16:  return "standard   (~5–10 pw/s/core)"
        return "fast       (>10 pw/s/core)"

    def attack_header(self, wordlist: str, workers: int, use_rules: bool,
                       total_candidates: int, mode: str = "wordlist",
                       mask: Optional[str] = None,
                       resuming: bool = False) -> None:
        if self.quiet:
            return
        prefix = f"{GREEN}[~]{RESET} Resuming" if resuming else f"{BOLD}[*]{RESET} Starting"
        print(f"\n{prefix} {YELLOW}{mode}{RESET} attack...")
        print(f"{BOLD}[*]{RESET} Wordlist  : {CYAN}{wordlist}{RESET}")
        if mask:
            print(f"{BOLD}[*]{RESET} Mask      : {CYAN}{mask}{RESET}")
        print(f"{BOLD}[*]{RESET} Workers   : {GREEN}{workers}{RESET} processes")
        print(f"{BOLD}[*]{RESET} Rules     : {GREEN}{'ON' if use_rules else 'OFF'}{RESET}")
        print(f"{BOLD}[*]{RESET} Candidates: {WHITE}{total_candidates:,}{RESET}")
        print()

    # ── Progress bar ──────────────────────────────────────────────────────────

    def progress(self,
                 tried:   int,
                 total:   int,
                 speed:   float,
                 workers: int,
                 width:   int = 38) -> None:
        """Print an in-place progress bar."""
        if self.quiet:
            return
        if self.verbose:
            self._verbose_progress(tried, total, speed, workers)
            return

        pct    = tried / total if total > 0 else 0
        filled = int(width * pct)
        bar    = "█" * filled + "░" * (width - filled)

        remaining = (total - tried) / speed if speed > 0 and total > 0 else 0
        eta       = f"{int(remaining)//3600:02d}:{(int(remaining)%3600)//60:02d}:{int(remaining)%60:02d}"

        if total > 0:
            total_s = f"{total:,}"
            pct_s   = f"{pct*100:.1f}%"
        else:
            total_s = "?"
            pct_s   = "?"

        line = (
            f"\r{CYAN}[{bar}]{RESET} "
            f"{WHITE}{tried:>9,}/{total_s}{RESET} "
            f"{YELLOW}({pct_s}){RESET} "
            f"{GREEN}{speed:>7.1f} pw/s{RESET} "
            f"{GREY}ETA {eta}{RESET}  "
        )
        print(line, end="", flush=True)
        self._last_bar_len = len(line)

    def _verbose_progress(self, tried: int, total: int, speed: float, workers: int):
        elapsed = tried / speed if speed > 0 else 0
        print(
            f"{GREY}[~]{RESET} Tried {WHITE}{tried:,}{RESET}  "
            f"Speed {GREEN}{speed:.1f} pw/s{RESET}  "
            f"Workers {workers}  "
            f"Elapsed {elapsed:.1f}s",
            flush=True
        )

    def clear_progress(self) -> None:
        """Erase the progress bar line."""
        if not self.quiet and not self.verbose:
            print("\r" + " " * (self._last_bar_len + 5) + "\r", end="", flush=True)

    # ── Result display ────────────────────────────────────────────────────────

    def found(self,
              passphrase: str,
              key_path:   str,
              tried:      int,
              elapsed:    float,
              speed:      float) -> None:
        self.clear_progress()
        w = 62
        print(f"\n{'═'*w}")
        print(f"  {GREEN}{BOLD}✔  PASSPHRASE FOUND!{RESET}")
        print(f"{'═'*w}")
        print(f"  Key file   : {CYAN}{key_path}{RESET}")
        print(f"  Passphrase : {GREEN}{BOLD}{passphrase!r}{RESET}")
        print(f"  Tried      : {WHITE}{tried:,}{RESET} candidates")
        print(f"  Time       : {WHITE}{elapsed:.2f}s{RESET}")
        print(f"  Speed      : {WHITE}{speed:.1f} pw/s{RESET}")
        print(f"{'═'*w}\n")

    def not_found(self, tried: int, elapsed: float) -> None:
        self.clear_progress()
        print(f"\n{RED}[✘] Passphrase NOT found in wordlist.{RESET}")
        print(f"    Tried    : {tried:,} candidates in {elapsed:.2f}s")
        print(f"\n{YELLOW}[?] Suggestions:{RESET}")
        print(f"    • Add --rules for ~60× more mutations per word")
        print(f"    • Add --mask '?d?d?d?d' to append digit patterns")
        print(f"    • Use a larger wordlist: kaonashi, weakpass_3, hashes.org")
        print(f"    • Try --rule-file best64.rule or OneRuleToRuleThemAll.rule")
        print(f"    • Combine: cat rockyou.txt custom.txt > combined.txt")

    def ssh_verify(self, ok: bool) -> None:
        if ok:
            print(f"{GREEN}[+] SSH connection VERIFIED — key + passphrase confirmed.{RESET}")
        else:
            print(f"{YELLOW}[-] SSH verify failed (key may still be correct){RESET}")

    # ── Benchmark display ─────────────────────────────────────────────────────

    def benchmark_result(self,
                          key_path:  str,
                          rounds:    int,
                          speed_per_core: float,
                          workers:   int) -> None:
        total_speed = speed_per_core * workers
        rockyou_14m = 14_000_000

        def _fmt_time(seconds: float) -> str:
            if seconds < 60:    return f"{seconds:.0f}s"
            if seconds < 3600:  return f"{seconds/60:.1f}m"
            if seconds < 86400: return f"{seconds/3600:.1f}h"
            return f"{seconds/86400:.1f}d"

        print(f"\n{BOLD}{'─'*58}{RESET}")
        print(f"  {BOLD}Benchmark Results{RESET}")
        print(f"{'─'*58}")
        print(f"  Key            : {key_path}")
        print(f"  KDF rounds     : {rounds}")
        print(f"  Speed/core     : {YELLOW}{speed_per_core:.2f} pw/s{RESET}")
        print(f"  Workers        : {workers}")
        print(f"  Total speed    : {GREEN}{total_speed:.1f} pw/s{RESET}")
        print(f"{'─'*58}")
        print(f"  Time estimates ({workers} workers):")
        print(f"    top 1k   words : {_fmt_time(1_000    / total_speed)}")
        print(f"    top 10k  words : {_fmt_time(10_000   / total_speed)}")
        print(f"    rockyou 14M    : {_fmt_time(rockyou_14m / total_speed)}")
        print(f"    rockyou + rules: {_fmt_time(rockyou_14m * 60 / total_speed)}")
        print(f"{'─'*58}\n")

    # ── Session list ──────────────────────────────────────────────────────────

    def session_list(self, sessions: list[dict]) -> None:
        if not sessions:
            print(f"{YELLOW}No saved sessions found.{RESET}")
            return
        w = 72
        print(f"\n{'─'*w}")
        print(f"  {'NAME':<16}  {'KEY':<22}  {'TRIED':>10}  {'ELAPSED':>8}  MODE")
        print(f"{'─'*w}")
        for s in sessions:
            elapsed = f"{s['elapsed']/3600:.1f}h" if s['elapsed'] > 3600 else f"{s['elapsed']/60:.1f}m"
            key_short = s['key_path'][-22:] if len(s['key_path']) > 22 else s['key_path']
            print(
                f"  {s['name']:<16}  {key_short:<22}  "
                f"{s['words_tried']:>10,}  {elapsed:>8}  {s['mode']}"
            )
        print(f"{'─'*w}\n")

    # ── Info print ────────────────────────────────────────────────────────────

    def info(self, msg: str) -> None:
        if not self.quiet:
            print(f"{BOLD}[*]{RESET} {msg}")

    def ok(self, msg: str) -> None:
        if not self.quiet:
            print(f"{GREEN}[+]{RESET} {msg}")

    def warn(self, msg: str) -> None:
        print(f"{YELLOW}[!]{RESET} {msg}", file=sys.stderr)

    def error(self, msg: str) -> None:
        print(f"{RED}[!]{RESET} {msg}", file=sys.stderr)
