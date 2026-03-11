"""
distributed/master.py — Distributed cracking master node.

Architecture
============
                    ┌─────────────────────────────────┐
                    │         MASTER NODE              │
                    │  sshcrack --distributed-master   │
                    │                                  │
                    │  ┌─────────────┐                 │
                    │  │ Wordlist    │ → chunks         │
                    │  │ Chunker     │                 │
                    │  └─────────────┘                 │
                    │         │                        │
                    │  ┌──────▼──────┐                 │
                    │  │  ZMQ PUSH   │:5555 ──────────────► Worker 1
                    │  │  (work)     │                 │
                    │  └─────────────┘                 │
                    │                                  │
                    │  ┌─────────────┐                 │
                    │  │  ZMQ PULL   │:5556 ◄──────────────── Worker 1
                    │  │  (results)  │                 │
                    │  └─────────────┘                 │
                    │                                  │
                    │  ┌─────────────┐                 │
                    │  │  ZMQ PUB    │:5557 ──────────────► All workers
                    │  │  (control)  │  STOP/PAUSE     │
                    │  └─────────────┘                 │
                    └─────────────────────────────────┘

Worker nodes can be:
  • Additional machines on the same LAN
  • Cloud spot instances (AWS G5, Lambda Labs)
  • Different GPU types (mix NVIDIA + AMD freely)

Scaling: Linear — N workers = N× speed (no synchronisation overhead).
"""

from __future__ import annotations

import json
import os
import signal
import sys
import time
from dataclasses import asdict, dataclass, field
from pathlib     import Path
from typing      import Dict, Optional

from sshcrack.wordlist import WordlistStreamer, chunk_wordlist
from sshcrack.session  import Session, session_name_for
from sshcrack.display  import Display


# ── ZMQ message types ─────────────────────────────────────────────────────────

MSG_WORK    = "WORK"
MSG_RESULT  = "RESULT"
MSG_STOP    = "STOP"
MSG_PAUSE   = "PAUSE"
MSG_RESUME  = "RESUME"
MSG_STATUS  = "STATUS"
MSG_DONE    = "DONE"    # worker signals wordlist exhausted


# ── Work item ─────────────────────────────────────────────────────────────────

@dataclass
class WorkItem:
    """
    A unit of work dispatched to one worker.
    Contains a byte-range slice of the wordlist — no password data transmitted.
    Workers must have access to the same key file and wordlist paths.
    """
    job_id:      str
    key_path:    str      # path to SSH private key (same on all workers)
    wordlist:    str      # path to wordlist (same on all workers)
    start_byte:  int
    end_byte:    int
    use_rules:   bool          = False
    rule_file:   Optional[str] = None
    mask:        Optional[str] = None


@dataclass
class WorkResult:
    """Result message from worker back to master."""
    job_id:    str
    found:     bool
    passphrase: Optional[str]
    tried:     int
    speed:     float   # pw/s this worker achieved


@dataclass
class WorkerStatus:
    """Aggregate stats per registered worker."""
    worker_id: str
    host:      str
    tried:     int   = 0
    speed:     float = 0.0
    last_seen: float = field(default_factory=time.time)
    gpu:       str   = "none"


# ── Master node ───────────────────────────────────────────────────────────────

class MasterNode:
    """
    Orchestrates distributed cracking across multiple worker nodes.

    Usage:
        master = MasterNode(
            key_path   = "id_ed25519",
            wordlist   = "rockyou.txt",
            bind_host  = "0.0.0.0",
            work_port  = 5555,
            result_port= 5556,
            ctrl_port  = 5557,
        )
        result = master.run()
    """

    def __init__(
        self,
        key_path:    str,
        wordlist:    str,
        bind_host:   str  = "0.0.0.0",
        work_port:   int  = 5555,
        result_port: int  = 5556,
        ctrl_port:   int  = 5557,
        use_rules:   bool = False,
        rule_file:   Optional[str] = None,
        mask:        Optional[str] = None,
        verbose:     bool = False,
        chunk_size:  int  = 50_000,   # words per work item
    ):
        self.key_path    = key_path
        self.wordlist    = wordlist
        self.bind_host   = bind_host
        self.work_port   = work_port
        self.result_port = result_port
        self.ctrl_port   = ctrl_port
        self.use_rules   = use_rules
        self.rule_file   = rule_file
        self.mask        = mask
        self.verbose     = verbose
        self.chunk_size  = chunk_size

        self._display  = Display(verbose=verbose)
        self._workers: Dict[str, WorkerStatus] = {}
        self._result:  Optional[str] = None

    def run(self) -> Optional[str]:
        """
        Start the master node, dispatch work, wait for result.
        Returns found passphrase or None.
        """
        try:
            import zmq
        except ImportError:
            self._display.error(
                "ZeroMQ not installed.\n"
                "  Install: pip install pyzmq\n"
                "  Then run worker nodes: sshcrack --distributed-worker --master HOST"
            )
            return None

        ctx        = zmq.Context()
        work_sock  = ctx.socket(zmq.PUSH)
        result_sock= ctx.socket(zmq.PULL)
        ctrl_sock  = ctx.socket(zmq.PUB)

        # Set high-water mark so work items can queue before workers connect
        work_sock.setsockopt(zmq.SNDHWM, 10000)

        work_sock.bind(f"tcp://{self.bind_host}:{self.work_port}")
        result_sock.bind(f"tcp://{self.bind_host}:{self.result_port}")
        ctrl_sock.bind(f"tcp://{self.bind_host}:{self.ctrl_port}")

        self._display.info(
            f"Master listening — work:{self.work_port} "
            f"results:{self.result_port} ctrl:{self.ctrl_port}"
        )
        self._display.info(
            f"Start workers:  sshcrack --distributed-worker "
            f"--master {self.bind_host}"
        )

        try:
            self._result = self._dispatch_loop(work_sock, result_sock, ctrl_sock)
        finally:
            # Signal all workers to stop
            ctrl_sock.send_string(f"{MSG_STOP}:")
            time.sleep(0.5)
            work_sock.close()
            result_sock.close()
            ctrl_sock.close()
            ctx.term()

        return self._result

    def _dispatch_loop(self, work_sock, result_sock, ctrl_sock) -> Optional[str]:
        """Main dispatch loop — send chunks, receive results."""
        import zmq

        poller = zmq.Poller()
        poller.register(result_sock, zmq.POLLIN)

        # Build work queue from wordlist chunks
        streamer = WordlistStreamer(self.wordlist)
        file_size = streamer.file_size()
        n_chunks  = max(1, file_size // (self.chunk_size * 10))
        chunks, total_lines = chunk_wordlist(self.wordlist, n_chunks)

        self._display.info(f"Wordlist: {total_lines:,} lines → {n_chunks} chunks")

        pending:    list[WorkItem] = []
        in_flight:  dict[str, WorkItem] = {}
        total_tried = 0
        t_start     = time.time()
        job_counter = 0

        # Pre-populate work queue
        for start, end in chunks:
            job_id = f"job_{job_counter:08d}"
            job_counter += 1
            pending.append(WorkItem(
                job_id    = job_id,
                key_path  = self.key_path,
                wordlist  = self.wordlist,
                start_byte= start,
                end_byte  = end,
                use_rules = self.use_rules,
                rule_file = self.rule_file,
                mask      = self.mask,
            ))

        # Drain queue — use blocking send (5s timeout) so items queue properly
        while pending or in_flight:
            # Send work to any available worker
            while pending:
                item = pending.pop(0)
                try:
                    work_sock.send_json(asdict(item), zmq.NOBLOCK)
                except zmq.error.Again:
                    # HWM reached — put item back and wait for results
                    pending.insert(0, item)
                    break
                in_flight[item.job_id] = item

            # Poll for results (100ms timeout)
            events = dict(poller.poll(100))
            if result_sock in events:
                msg     = result_sock.recv_json()
                result  = WorkResult(**msg)
                total_tried += result.tried

                # Update worker stats
                if result.found and result.passphrase:
                    return result.passphrase

                in_flight.pop(result.job_id, None)

                elapsed = time.time() - t_start
                speed   = total_tried / elapsed if elapsed > 0 else 0

                if self.verbose:
                    self._display.info(
                        f"Progress: {total_tried:,} tried  "
                        f"Speed: {speed:.1f} pw/s  "
                        f"In-flight: {len(in_flight)}"
                    )

        return None

    def status(self) -> dict:
        """Return aggregate stats across all connected workers."""
        total_speed = sum(w.speed for w in self._workers.values())
        total_tried = sum(w.tried for w in self._workers.values())
        return {
            "workers":     len(self._workers),
            "total_speed": total_speed,
            "total_tried": total_tried,
            "worker_list": [
                {"id": w.worker_id, "host": w.host,
                 "speed": w.speed, "gpu": w.gpu}
                for w in self._workers.values()
            ],
        }
