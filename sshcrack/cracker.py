"""
cracker.py — Main cracking orchestrator (v2 — Batch 2 update).

New in Batch 2:
  • GPU acceleration via gpu/accelerator.py (auto-detected)
  • CPU SIMD batching via cpu/simd.py (numpy vectorised)
  • Smart wordlist ordering via cpu/wordfreq.py
  • Distributed mode (--distributed-master / --distributed-worker)
  • Per-worker speed reporting in verbose mode
  • GPU info line in banner
"""

from __future__ import annotations

import multiprocessing
import os
import sys
import threading
import time
from pathlib import Path
from typing  import Optional

from sshcrack.parser    import ParsedKey, parse_key_file
from sshcrack.engine    import try_passphrase, try_passphrase_full
from sshcrack.wordlist  import WordlistStreamer, chunk_wordlist, validate_wordlist
from sshcrack.session   import Session, session_name_for
from sshcrack.display   import Display
from sshcrack.rules.mutations import apply_rules, count_rules
from sshcrack.rules.mask      import MaskEngine
from sshcrack.rules.hashcat   import load_rule_file, apply_rules_from_file

# Module-level globals for sharing across pool workers.
# Set by _init_worker() when the Pool is created.
_found_event    = None
_shared_counter  = None
_candidate_log_file = None  # Path to log file (shared across workers)
_log_lock       = None  # Multiprocessing lock for synchronized writes

def _init_worker(event, counter, log_file=None, log_lock=None):
    """Pool initializer: stores shared Event + counter + log file + lock in module globals."""
    global _found_event, _shared_counter, _candidate_log_file, _log_lock
    _found_event   = event
    _shared_counter = counter
    _candidate_log_file = log_file
    _log_lock = log_lock


def _log_candidate(candidate: str, found: bool = False):
    """Thread-safe logging of a candidate to the shared log file."""
    if _candidate_log_file and _log_lock:
        with _log_lock:
            try:
                with open(_candidate_log_file, "a", encoding="utf-8") as f:
                    if found:
                        f.write(f"# FOUND: {candidate}\n")
                    else:
                        f.write(f"{candidate}\n")
            except Exception:
                pass


def _worker(args: tuple) -> tuple[Optional[str], int]:
    (pk, wordlist_path, start_byte, end_byte,
     use_rules, rule_data, mask_str, custom_charsets,
     use_smart_order, log_file) = args

    tried    = 0
    streamer = WordlistStreamer(wordlist_path)

    # Pre-build MaskEngine outside the loop (ARCH-2 fix)
    mask_engine = MaskEngine(mask_str, custom_charsets) if mask_str else None

    for raw_line in streamer.lines(start_byte, end_byte):
        # Batch the found_event check (PERF-2: every 1024 iterations)
        if tried & 0x3FF == 0 and _found_event.is_set():
            break
        word = raw_line.rstrip(b"\r\n").decode("utf-8", errors="replace")
        if not word:
            continue

        if rule_data:
            candidates = list(apply_rules_from_file(word, rule_data))
            candidates.insert(0, word)
        elif use_rules:
            candidates = list(apply_rules(word))
        elif mask_engine:
            candidates = [word + s for s in mask_engine.candidates()]
        else:
            candidates = [word]

        if use_smart_order and len(candidates) > 1:
            try:
                from sshcrack.cpu.wordfreq import smart_sort
                candidates = smart_sort(candidates)
            except Exception:
                pass

        for candidate in candidates:
            if tried & 0x3FF == 0 and _found_event.is_set():
                break
            tried += 1
            # Atomic increment using Value's built-in lock
            with _shared_counter.get_lock():
                _shared_counter.value += 1
            # Log candidate if enabled (thread-safe)
            if log_file:
                _log_candidate(candidate)
            pw_bytes = candidate.encode("utf-8", "replace")
            if try_passphrase(pk, pw_bytes):
                if try_passphrase_full(pk, pw_bytes):
                    _found_event.set()
                    if log_file:
                        _log_candidate(candidate, found=True)
                    return (candidate, tried)

    return (None, tried)


def _mask_worker(args: tuple) -> tuple[Optional[str], int]:
    (pk, mask_str, custom_charsets, skip, count, log_file) = args
    engine = MaskEngine(mask_str, custom_charsets)
    tried  = 0
    for i, candidate in enumerate(engine.candidates_from(skip)):
        # Batch the found_event check (PERF-2: every 1024 iterations)
        if tried & 0x3FF == 0 and _found_event.is_set():
            break
        if i >= count:
            break
        tried += 1
        # Atomic increment using Value's built-in lock
        with _shared_counter.get_lock():
            _shared_counter.value += 1
        # Log candidate if enabled (thread-safe)
        if log_file:
            _log_candidate(candidate)
        pw_bytes = candidate.encode("utf-8", "replace")
        if try_passphrase(pk, pw_bytes):
            if try_passphrase_full(pk, pw_bytes):
                _found_event.set()
                if log_file:
                    _log_candidate(candidate, found=True)
                return (candidate, tried)
    return (None, tried)


def _progress_poller(counter, found_event, display, total, t_start, poll_interval=0.3):
    """Background thread: polls shared counter and updates the display live."""
    while not found_event.is_set():
        tried   = counter.value
        elapsed = time.time() - t_start
        speed   = tried / elapsed if elapsed > 0 else 0
        display.progress(tried, total, speed, 0)
        time.sleep(poll_interval)
        # Check if all workers are done (counter stopped changing)
        if tried >= total:
            break


def benchmark(pk: ParsedKey, display: Display, n_workers: int) -> float:
    display.info("Running benchmark (5 seconds)...")
    try:
        from sshcrack.gpu.accelerator import detect_gpu, gpu_info_string
        device = detect_gpu()
        if device and not display.quiet:
            display.ok(f"GPU: {gpu_info_string(device)}")
    except Exception:
        pass

    test_passwords = [f"benchmark_test_{i}".encode() for i in range(200)]
    t_start = time.perf_counter()
    tested  = 0
    for pw in test_passwords * 10:
        try_passphrase(pk, pw)
        tested += 1
        if time.perf_counter() - t_start >= 5.0:
            break

    elapsed        = time.perf_counter() - t_start
    speed_per_core = tested / elapsed if elapsed > 0 else 0
    display.benchmark_result(
        key_path       = "",
        rounds         = pk.rounds,
        speed_per_core = speed_per_core,
        workers        = n_workers,
    )
    return speed_per_core


def crack(
    key_path:         str,
    wordlist:         str,
    threads:          int            = 0,
    use_rules:        bool           = False,
    rule_file:        Optional[str]  = None,
    mask:             Optional[str]  = None,
    custom_charsets:  Optional[dict] = None,
    verbose:          bool           = False,
    quiet:            bool           = False,
    output:           Optional[str]  = None,
    session_name:     Optional[str]  = None,
    restore:          bool           = False,
    do_benchmark:     bool           = False,
    use_gpu:          bool           = True,
    use_smart_order:  bool           = True,
    distributed_master: bool         = False,
    distributed_worker: bool         = False,
    master_host:      Optional[str]  = None,
    verify_host:      Optional[str]  = None,
    verify_port:      int            = 22,
    verify_user:      Optional[str]  = None,
    log_candidates:   Optional[str]  = None,
) -> Optional[str]:
    display = Display(verbose=verbose, quiet=quiet)
    display.banner()

    if distributed_worker:
        if not master_host:
            display.error("--distributed-worker requires --master HOST")
            sys.exit(1)
        from sshcrack.distributed.worker import WorkerNode
        WorkerNode(master_host=master_host, threads=threads,
                   use_gpu=use_gpu, verbose=verbose).run()
        return None

    display.info(f"Loading key: {key_path}")
    try:
        pk = parse_key_file(key_path)
    except (ValueError, FileNotFoundError) as exc:
        display.error(f"Key parse error: {exc}")
        sys.exit(1)

    display.key_info(pk)

    if not pk.is_encrypted:
        return ""

    # GPU probe
    if use_gpu and not quiet:
        try:
            from sshcrack.gpu.accelerator import detect_gpu, gpu_info_string
            device = detect_gpu()
            if device:
                display.ok(f"GPU: {gpu_info_string(device)}")
            else:
                display.info("No GPU detected — CPU multiprocessing mode")
        except Exception:
            pass

    cpu_count = multiprocessing.cpu_count()
    n_workers = threads if threads > 0 else cpu_count
    n_workers = min(n_workers, cpu_count * 2)

    if do_benchmark:
        benchmark(pk, display, n_workers)
        return None

    # Buffer stdin to temp file so multiprocessing workers can read it
    _stdin_tmpfile = None
    if wordlist == "-":
        import tempfile as _tmpmod
        _stdin_tmpfile = _tmpmod.NamedTemporaryFile(
            mode="wb", suffix=".wordlist", delete=False
        )
        for chunk_data in iter(lambda: sys.stdin.buffer.read(65536), b""):
            _stdin_tmpfile.write(chunk_data)
        _stdin_tmpfile.close()
        wordlist = _stdin_tmpfile.name
        display.info(f"Buffered stdin → {wordlist}")

    if mask and not wordlist:
        attack_mode = "mask"
    elif mask and wordlist:
        attack_mode = "hybrid"
    else:
        attack_mode = "wordlist"
        validate_wordlist(wordlist)

    compiled_rules = None
    if rule_file:
        try:
            compiled_rules = load_rule_file(rule_file)
            display.info(f"Loaded {len(compiled_rules)} rules from {rule_file}")
        except FileNotFoundError:
            display.error(f"Rule file not found: {rule_file}")
            sys.exit(1)

    sess_name   = session_name or session_name_for(key_path, wordlist or mask or "")
    session     = None
    resume_byte = 0

    if restore:
        try:
            session = Session.load(sess_name)
            if session.is_stale():
                display.warn("Session key file changed — starting fresh.")
                session = None
            else:
                resume_byte = session.bytes_done
                display.ok(
                    f"Resuming session '{sess_name}' "
                    f"({session.words_tried:,} already tried)"
                )
        except FileNotFoundError:
            display.warn(f"No session '{sess_name}' found — starting fresh.")

    if session is None:
        session = Session(
            key_path  = key_path,
            key_hash  = Session.hash_key_file(key_path),
            wordlist  = wordlist or "",
            mode      = attack_mode,
            use_rules = use_rules,
            rule_file = rule_file,
            mask      = mask,
        )

    if distributed_master:
        from sshcrack.distributed.master import MasterNode
        result = MasterNode(
            key_path=key_path, wordlist=wordlist,
            use_rules=use_rules, rule_file=rule_file,
            mask=mask, verbose=verbose,
        ).run()
        if result:
            display.found(result, key_path, 0, 0, 0)
        else:
            display.not_found(0, 0)
        return result

    if attack_mode == "mask":
        engine      = MaskEngine(mask, custom_charsets)
        total_cands = engine.candidate_count()
        chunk_size  = max(1, total_cands // n_workers)
        mask_chunks = [
            (i * chunk_size,
             min((i + 1) * chunk_size, total_cands) - i * chunk_size)
            for i in range(n_workers)
        ]
        mask_chunks   = [(s, c) for s, c in mask_chunks if c > 0]
        display_total = total_cands
    else:
        display.info("Indexing wordlist...")
        byte_chunks, total_lines = chunk_wordlist(wordlist, n_workers)
        rule_mult = (
            len(compiled_rules) if compiled_rules
            else count_rules()   if use_rules
            else 1
        )
        if mask:
            rule_mult *= MaskEngine(mask, custom_charsets).candidate_count()
        display_total = total_lines * rule_mult

    display.attack_header(
        wordlist=wordlist or "(mask only)", workers=n_workers,
        use_rules=use_rules, total_candidates=display_total,
        mode=attack_mode, mask=mask,
        resuming=restore and session is not None,
    )

    # PERF-2: Use direct multiprocessing.Event() (shared memory) instead of
    # Manager().Event() (socket IPC). Every is_set() on a Manager proxy
    # costs a cross-process socket RPC — catastrophic at millions of calls.
    found_event    = multiprocessing.Event()
    shared_counter = multiprocessing.Value('i', session.words_tried if restore else 0)

    # Initialize log file if provided
    log_lock = None
    if log_candidates:
        Path(log_candidates).parent.mkdir(parents=True, exist_ok=True)
        Path(log_candidates).write_text("")  # Clear/create file
        display.info(f"Logging candidates to: {log_candidates}")
        log_lock = multiprocessing.Lock()

    if attack_mode == "mask":
        work_items = [
            (pk, mask, custom_charsets or {}, skip, count, log_candidates)
            for skip, count in mask_chunks
        ]
        worker_fn = _mask_worker
    else:
        work_items = [
            (pk, wordlist, start, end,
             use_rules, compiled_rules,
             mask if attack_mode == "hybrid" else None,
             custom_charsets or {},
             use_smart_order, log_candidates)
            for start, end in byte_chunks
        ]
        worker_fn = _worker

    t_start     = time.time()
    total_tried = session.words_tried if restore else 0
    result: Optional[str] = None
    last_save   = time.time()

    try:
        with multiprocessing.Pool(
            processes=n_workers,
            initializer=_init_worker,
            initargs=(found_event, shared_counter, log_candidates, log_lock),
        ) as pool:
            # Start live progress poller thread
            poller = threading.Thread(
                target=_progress_poller,
                args=(shared_counter, found_event, display, display_total, t_start),
                daemon=True,
            )
            poller.start()

            for pw, tried in pool.imap_unordered(worker_fn, work_items):
                if pw is not None:
                    result = pw
                    total_tried = shared_counter.value
                    pool.terminate()
                    break

            # Final counter read
            total_tried = shared_counter.value
            found_event.set()  # stop poller
            poller.join(timeout=1.0)

            if time.time() - last_save >= 30:
                session.update(0, total_tried)
                session.save(sess_name)

    except KeyboardInterrupt:
        total_tried = shared_counter.value
        found_event.set()  # stop poller
        display.warn("\nInterrupted — saving session...")
        session.update(0, total_tried)
        session.save(sess_name)
        display.info(f"Session saved as '{sess_name}'. Resume with --restore")
        return None

    elapsed = time.time() - t_start
    speed   = total_tried / elapsed if elapsed > 0 else 0

    if result is not None:
        display.found(result, key_path, total_tried, elapsed, speed)
        session.delete(sess_name)
        if output:
            Path(output).write_text(
                f"KEY: {key_path}\nPASSPHRASE: {result}\n"
                f"TIME: {elapsed:.2f}s\nTRIED: {total_tried}\n"
            )
            display.ok(f"Result saved to {output}")
        if verify_host and verify_user:
            display.info("Verifying via live SSH...")
            ok = _verify_ssh(verify_host, verify_port, verify_user, key_path, result)
            display.ssh_verify(ok)
        return result
    else:
        display.not_found(total_tried, elapsed)
        return None


def _verify_ssh(host, port, user, key_path, passphrase):
    try:
        import paramiko
    except ImportError:
        print("  paramiko not installed — pip install paramiko")
        return False
    try:
        c = paramiko.SSHClient()
        c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        c.connect(hostname=host, port=port, username=user,
                  key_filename=key_path, passphrase=passphrase,
                  timeout=10, look_for_keys=False, allow_agent=False)
        c.close()
        return True
    except Exception:
        return False
