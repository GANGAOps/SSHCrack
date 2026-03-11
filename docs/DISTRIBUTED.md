# Distributed Cracking Guide — ssh-crack v1

> **Scaling**: Linear — N workers = N× throughput. No bottleneck. No sync overhead.

---

## Architecture

```
                    ┌────────────────────────────┐
                    │       MASTER NODE          │
                    │  (your machine or cloud)   │
                    │                            │
                    │  Wordlist → byte chunks    │
                    │  ZMQ PUSH :5555 ──────────►│─── Worker 1 (local GPU)
                    │  ZMQ PULL :5556 ◄──────────│─── Worker 2 (LAN machine)
                    │  ZMQ PUB  :5557 ──────────►│─── Worker 3 (AWS G5)
                    │                            │─── Worker 4 (AWS G5)
                    └────────────────────────────┘
```

Workers can be any mix of:

- Local CPU threads
- Local GPU
- LAN machines (Kali VMs, workstations)
- Cloud instances (AWS G5 spot, Lambda Labs)

---

## Quick Start (2 machines, same LAN)

**Machine 1 — Master** (has the key and wordlist):

```bash
sshcrack -k id_ed25519 -w rockyou.txt --distributed-master -v
# Listening on :5555 (work), :5556 (results), :5557 (control)
# Start workers:  sshcrack --distributed-worker --master 192.168.1.10
```

**Machine 2 — Worker** (any machine with network access to master):

```bash
# Install ssh-crack first
pip install sshcrack

# Connect to master
sshcrack --distributed-worker --master 192.168.1.10
# Connected — Threads: 8  GPU: CUDA NVIDIA RTX 3090
```

**That's it.** The worker immediately starts processing chunks from the master.

---

## Multiple Workers

```bash
# Start 3 workers on different machines
# Machine 2:
sshcrack --distributed-worker --master 192.168.1.10

# Machine 3:
sshcrack --distributed-worker --master 192.168.1.10

# Machine 4 (GPU):
sshcrack --distributed-worker --master 192.168.1.10

# Scale: 3 machines × their individual speeds = total combined speed
```

---

## Custom Ports

```bash
# Master with custom ports
sshcrack -k id_ed25519 -w rockyou.txt \
    --distributed-master \
    --work-port 9555 --result-port 9556

# Workers must use matching ports
sshcrack --distributed-worker \
    --master 192.168.1.10 \
    --work-port 9555 --result-port 9556
```

---

## Docker Compose (easiest multi-worker)

```bash
# Clone repo on master machine
git clone https://github.com/GANGAOps/SSHCrack
cd ssh-crack

# Build image
docker build -t sshcrack:cpu .

# Start master + 4 workers
KEY=/path/to/id_ed25519 WORDLIST=/path/to/rockyou.txt \
docker-compose up --scale worker=4

# Watch logs
docker-compose logs -f master
```

---

## AWS Auto-Deploy

See `docs/GPU_SETUP.md` and `scripts/deploy_aws.py`.

```bash
# Deploy 4× g5.xlarge (4× A10G = ~320,000 pw/s total)
python3 scripts/deploy_aws.py \
    --key id_ed25519 \
    --wordlist s3://my-bucket/rockyou.txt \
    --workers 4 \
    --instance g5.xlarge \
    --spot-price 1.50

# Start master locally
sshcrack -k id_ed25519 -w s3://my-bucket/rockyou.txt \
    --distributed-master -v

# Terminate after cracking
python3 scripts/deploy_aws.py --terminate --key id_ed25519 --wordlist x
```

---

## Attack Mode Flags (distributed)

All attack modes work in distributed mode. Pass flags to master — workers inherit:

```bash
# Distributed + rules
sshcrack -k id_ed25519 -w rockyou.txt --distributed-master --rules

# Distributed + rule file
sshcrack -k id_ed25519 -w rockyou.txt --distributed-master \
    --rule-file best64.rule

# Distributed + mask (hybrid)
sshcrack -k id_ed25519 -w rockyou.txt --distributed-master \
    --mask '?d?d?d?d'
```

---

## Performance Examples

| Setup | Speed | rockyou.txt (14M) |
|-------|-------|-------------------|
| 1× CPU (2 cores) | ~9,600 pw/s | ~24 min |
| 1× RTX 4090 | ~200,000 pw/s | ~72 sec |
| 4× RTX 4090 | ~800,000 pw/s | ~18 sec |
| 4× AWS g5.xlarge | ~320,000 pw/s | ~44 sec |
| 8× AWS g5.xlarge | ~640,000 pw/s | ~22 sec |

With `--rules` (100× candidates): multiply times by ~100.

---

## Firewall Requirements

Open these ports on the master machine for workers to connect:

| Port | Protocol | Direction | Purpose |
|------|----------|-----------|---------|
| 5555 | TCP | Inbound | Work dispatch (PUSH) |
| 5556 | TCP | Inbound | Result collection (PULL) |
| 5557 | TCP | Inbound | Control signals (PUB) |

```bash
# UFW (Ubuntu)
sudo ufw allow 5555/tcp
sudo ufw allow 5556/tcp
sudo ufw allow 5557/tcp

# iptables
iptables -A INPUT -p tcp --dport 5555:5557 -j ACCEPT
```

---

## Security Note

The distributed protocol transmits **byte-range indices** of the wordlist — no
passphrase plaintext is sent over the network. Workers need access to the same
wordlist path. The SSH key file is **never** transmitted in the default setup —
workers must have the same key file accessible locally at the same path.

For cloud workers without local key access, use the `--deploy-aws` auto-deploy
script which securely uploads the key via EC2 user-data (HTTPS, ephemeral).

---

## Troubleshooting

| Problem | Fix |
|---------|-----|
| Worker can't connect | Check firewall ports 5555-5557 |
| `pyzmq not installed` | `pip install pyzmq` on all machines |
| Worker connects but slow | Check `nvidia-smi` on worker — GPU may not be utilised |
| Master exits immediately | Wordlist path must be accessible on master |
| Workers finish, no result | Password not in wordlist — try `--rules` or different wordlist |
