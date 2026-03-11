"""
cli.py — Command-line interface for ssh-crack v2.

All argument parsing and dispatch lives here.
The actual cracking logic is in cracker.py.

Usage:
    sshcrack -k KEY -w WORDLIST [options]
    sshcrack -k KEY --mask '?l?l?l?d?d?d'
    sshcrack -k KEY -w WORDLIST --mask '?d?d?d?d'  # hybrid
    sshcrack -k KEY -w WORDLIST --restore           # resume session
    sshcrack --list-sessions
    sshcrack -k KEY --benchmark
    sshcrack -k KEY --info
"""

from __future__ import annotations

import argparse
import multiprocessing
import sys
from typing import Optional

from sshcrack.cracker import crack
from sshcrack.display import Display, BANNER
from sshcrack.parser  import parse_key_file
from sshcrack.session import Session
from sshcrack.rules.mask import MaskEngine


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog        = "sshcrack",
        description = "SSH Private Key Passphrase Cracker  v1  (GANGA Offensive Ops)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Attack modes:
  Wordlist     :  sshcrack -k key -w rockyou.txt
  + rules      :  sshcrack -k key -w rockyou.txt --rules
  + rule file  :  sshcrack -k key -w rockyou.txt --rule-file best64.rule
  Mask         :  sshcrack -k key --mask '?l?l?l?d?d?d'
  Hybrid       :  sshcrack -k key -w rockyou.txt --mask '?d?d?d?d'

Examples:
  # Basic wordlist
  sshcrack -k id_ed25519 -w /usr/share/wordlists/rockyou.txt

  # 16 workers + built-in mutations
  sshcrack -k id_rsa -w rockyou.txt -t 16 --rules

  # Mask attack (3 lowercase + 3 digits)
  sshcrack -k id_ed25519 --mask '?l?l?l?d?d?d'

  # Hybrid: each word + 4-digit suffix
  sshcrack -k id_rsa -w rockyou.txt --mask '?d?d?d?d'

  # Resume an interrupted session
  sshcrack -k id_ed25519 -w rockyou.txt --restore

  # Benchmark this key
  sshcrack -k id_ed25519 --benchmark

  # Crack + verify via live SSH
  sshcrack -k id_ed25519 -w rockyou.txt \\
      --verify-host 127.0.0.1 --verify-port 2222 --verify-user svc_user@domain.vl

  # GPU-accelerated (auto-detected, NVIDIA/AMD)
  sshcrack -k id_ed25519 -w rockyou.txt

  # Distributed master (other machines connect as workers)
  sshcrack -k id_ed25519 -w rockyou.txt --distributed-master

  # Distributed worker (connect to master at 192.168.1.10)
  sshcrack --distributed-worker --master 192.168.1.10

  # Show GPU info
  sshcrack -k id_ed25519 --gpu-info
        """,
    )

    # ── Key / wordlist ─────────────────────────────────────────────────────────
    p.add_argument(
        "-k", "--key",
        required=False,
        default=None,
        metavar="FILE",
        help="Path to encrypted SSH private key (OpenSSH / PuTTY PPK)"
    )
    p.add_argument(
        "-w", "--wordlist",
        metavar="FILE",
        default=None,
        help="Path to wordlist (use '-' for stdin).  Not needed for mask-only attacks."
    )

    # ── Workers ────────────────────────────────────────────────────────────────
    p.add_argument(
        "-t", "--threads",
        type=int,
        default=0,
        metavar="N",
        help=f"Parallel worker processes (default: auto = {multiprocessing.cpu_count()} CPUs)"
    )

    # ── Mutation rules ─────────────────────────────────────────────────────────
    p.add_argument(
        "--rules",
        action="store_true",
        help="Apply built-in mutation rules to each word (capitalize, l33t, suffixes…)"
    )
    p.add_argument(
        "--rule-file",
        metavar="FILE",
        help="Path to Hashcat .rule file (e.g. best64.rule, OneRuleToRuleThemAll.rule)"
    )

    # ── Mask attack ────────────────────────────────────────────────────────────
    p.add_argument(
        "--mask",
        metavar="MASK",
        help=(
            "Hashcat-style mask for brute-force or hybrid attacks.\n"
            "  Tokens: ?l=lower ?u=upper ?d=digit ?s=special ?a=all\n"
            "  Example: '?u?l?l?l?d?d?d'  or  'Pass?d?d?d?d'"
        )
    )
    p.add_argument(
        "-1", "--custom-charset1",
        metavar="CS",
        dest="cs1",
        help="Custom charset for ?1 (e.g. 'abc123')"
    )
    p.add_argument(
        "-2", "--custom-charset2",
        metavar="CS",
        dest="cs2",
        help="Custom charset for ?2"
    )
    p.add_argument(
        "-3", "--custom-charset3",
        metavar="CS",
        dest="cs3",
        help="Custom charset for ?3"
    )
    p.add_argument(
        "-4", "--custom-charset4",
        metavar="CS",
        dest="cs4",
        help="Custom charset for ?4"
    )

    # ── Output ─────────────────────────────────────────────────────────────────
    p.add_argument(
        "-o", "--output",
        metavar="FILE",
        help="Save cracked passphrase to file"
    )
    p.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Verbose output: per-worker stats instead of progress bar"
    )
    p.add_argument(
        "-q", "--quiet",
        action="store_true",
        help="Suppress all output except the passphrase itself"
    )

    # ── Session management ─────────────────────────────────────────────────────
    p.add_argument(
        "--restore",
        action="store_true",
        help="Resume a previously interrupted session (auto-detects by key+wordlist)"
    )
    p.add_argument(
        "--session",
        metavar="NAME",
        dest="session_name",
        help="Named session (overrides auto-generated name)"
    )
    p.add_argument(
        "--list-sessions",
        action="store_true",
        help="List all saved sessions and exit"
    )
    p.add_argument(
        "--delete-session",
        metavar="NAME",
        help="Delete a named session and exit"
    )

    # ── SSH verify ─────────────────────────────────────────────────────────────
    p.add_argument(
        "--verify-host",
        metavar="HOST",
        help="SSH host to test the cracked passphrase against"
    )
    p.add_argument(
        "--verify-port",
        type=int,
        default=22,
        metavar="PORT",
        help="SSH port (default: 22)"
    )
    p.add_argument(
        "--verify-user",
        metavar="USER",
        help="SSH username for live verification"
    )

    # ── Utility modes ──────────────────────────────────────────────────────────
    p.add_argument(
        "--info",
        action="store_true",
        help="Display key metadata and exit (no cracking)"
    )
    p.add_argument(
        "--benchmark",
        action="store_true",
        help="Benchmark passphrase testing speed for this key and exit"
    )
    p.add_argument(
        "--estimate",
        metavar="WORDS",
        type=int,
        help="Estimate crack time for N wordlist entries and exit"
    )


    # ── GPU acceleration ───────────────────────────────────────────────────────
    p.add_argument(
        "--no-gpu",
        action="store_true",
        help="Disable GPU acceleration (use CPU-only multiprocessing)"
    )
    p.add_argument(
        "--gpu-info",
        action="store_true",
        help="Display detected GPU info and exit"
    )

    # ── Distributed cracking ───────────────────────────────────────────────────
    p.add_argument(
        "--distributed-master",
        action="store_true",
        help="Run as distributed master node (dispatches work to workers)"
    )
    p.add_argument(
        "--distributed-worker",
        action="store_true",
        help="Run as distributed worker node (receives work from master)"
    )
    p.add_argument(
        "--master",
        metavar="HOST",
        dest="master_host",
        help="Master node hostname/IP (required for --distributed-worker)"
    )
    p.add_argument(
        "--work-port",
        type=int,
        default=5555,
        metavar="PORT",
        help="ZMQ work dispatch port (default: 5555)"
    )
    p.add_argument(
        "--result-port",
        type=int,
        default=5556,
        metavar="PORT",
        help="ZMQ result collection port (default: 5556)"
    )
    p.add_argument(
        "--no-smart-order",
        action="store_true",
        help="Disable frequency-based candidate reordering"
    )

    # ── Debug / Audit ───────────────────────────────────────────────────────────
    p.add_argument(
        "--log-candidates",
        metavar="FILE",
        help="Log all tried candidates to file (for audit/debug)"
    )

    return p


def main() -> None:
    multiprocessing.freeze_support()

    parser = _build_parser()
    args   = parser.parse_args()
    disp   = Display(verbose=args.verbose, quiet=args.quiet)

    # ── --list-sessions ────────────────────────────────────────────────────────
    if args.list_sessions:
        disp.banner()
        disp.session_list(Session.list_sessions())
        sys.exit(0)

    # ── --delete-session ───────────────────────────────────────────────────────
    if args.delete_session:
        Session().delete(args.delete_session)
        disp.ok(f"Session '{args.delete_session}' deleted.")
        sys.exit(0)

    # ── --info ─────────────────────────────────────────────────────────────────
    if args.info:
        if not args.key:
            parser.error("--info requires --key / -k")
        disp.banner()
        try:
            pk = parse_key_file(args.key)
            print(f"{'─'*50}")
            print(f"  File      : {args.key}")
            print(f"  Format    : {pk.fmt.name}")
            print(f"  Key type  : {pk.key_type}")
            print(f"  Cipher    : {pk.cipher_display}")
            print(f"  KDF       : {pk.kdf_display}")
            print(f"  Encrypted : {pk.is_encrypted}")
            if pk.is_encrypted and pk.rounds:
                print(f"  KDF rounds: {pk.rounds}")
            if pk.salt:
                print(f"  Salt (hex): {pk.salt.hex()}")
            print(f"{'─'*50}")
        except Exception as exc:
            disp.error(str(exc))
            sys.exit(1)
        sys.exit(0)


    # ── --gpu-info ─────────────────────────────────────────────────────────────
    if args.gpu_info:
        disp.banner()
        try:
            from sshcrack.gpu.accelerator import detect_gpu, gpu_info_string
            device = detect_gpu()
            print(f"  {gpu_info_string(device)}")
        except Exception as exc:
            print(f"  GPU probe error: {exc}")
        sys.exit(0)

    # ── --estimate ─────────────────────────────────────────────────────────────
    if args.estimate:
        disp.banner()
        try:
            pk = parse_key_file(args.key)
        except Exception as exc:
            disp.error(str(exc))
            sys.exit(1)
        cpu = multiprocessing.cpu_count()
        n   = args.threads if args.threads > 0 else cpu
        from sshcrack.cracker import benchmark as do_bench
        speed_core = do_bench(pk, disp, n)
        total_speed = speed_core * n
        words = args.estimate
        secs  = words / total_speed if total_speed > 0 else float("inf")
        print(f"\n  Estimate for {words:,} words @ {total_speed:.1f} pw/s:")
        if secs < 60:
            print(f"    ~{secs:.1f} seconds")
        elif secs < 3600:
            print(f"    ~{secs/60:.1f} minutes")
        elif secs < 86400:
            print(f"    ~{secs/3600:.1f} hours")
        else:
            print(f"    ~{secs/86400:.1f} days")
        sys.exit(0)

    # ── Require --key for all other modes ──────────────────────────────────────
    if not args.key:
        parser.error("--key / -k is required for this operation")

    # ── Require wordlist or mask ───────────────────────────────────────────────
    if not args.wordlist and not args.mask and not args.benchmark:
        parser.error("Provide at least --wordlist or --mask (or --benchmark)")

    # ── Build custom charset dict ──────────────────────────────────────────────
    custom_charsets: dict[str, str] = {}
    if args.cs1: custom_charsets["?1"] = args.cs1
    if args.cs2: custom_charsets["?2"] = args.cs2
    if args.cs3: custom_charsets["?3"] = args.cs3
    if args.cs4: custom_charsets["?4"] = args.cs4

    # ── Dispatch to crack() ────────────────────────────────────────────────────
    passphrase = crack(
        key_path            = args.key,
        wordlist            = args.wordlist or "",
        threads             = args.threads,
        use_rules           = args.rules,
        rule_file           = args.rule_file,
        mask                = args.mask,
        custom_charsets     = custom_charsets or None,
        verbose             = args.verbose,
        quiet               = args.quiet,
        output              = args.output,
        session_name        = args.session_name,
        restore             = args.restore,
        do_benchmark        = args.benchmark,
        use_gpu             = not args.no_gpu,
        use_smart_order     = not args.no_smart_order,
        distributed_master  = args.distributed_master,
        distributed_worker  = args.distributed_worker,
        master_host         = args.master_host,
        verify_host         = args.verify_host,
        verify_port         = args.verify_port,
        verify_user         = args.verify_user,
        log_candidates      = args.log_candidates,
    )

    # Quiet mode: just print the passphrase
    if args.quiet and passphrase is not None:
        print(passphrase)

    sys.exit(0 if passphrase is not None or args.benchmark else 1)


if __name__ == "__main__":
    main()
