"""
distributed/ — Linear-scale distributed cracking across multiple machines.

Architecture: ZeroMQ PUSH/PULL for work dispatch, PUB/SUB for control signals.
Scaling: N workers = N× throughput (fully embarrassingly parallel).

Quick start:
    # Master (has the key + wordlist)
    sshcrack -k id_ed25519 -w rockyou.txt --distributed-master

    # Worker(s) — any machine on the same network
    sshcrack --distributed-worker --master 192.168.1.10

    # AWS G5 auto-deploy (see docs/DISTRIBUTED.md)
    sshcrack --deploy-aws --workers 4 --instance g5.xlarge
"""

from sshcrack.distributed.master import MasterNode, WorkItem, WorkResult
from sshcrack.distributed.worker import WorkerNode

__all__ = ["MasterNode", "WorkerNode", "WorkItem", "WorkResult"]
