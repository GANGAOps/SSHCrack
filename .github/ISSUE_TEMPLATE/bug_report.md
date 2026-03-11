---
name: Bug Report
about: Something broken? Reproduce it here.
title: "[BUG] "
labels: bug, needs-triage
assignees: BhanuGuragain0
---

## Environment

| Field | Value |
|-------|-------|
| ssh-crack version | <!-- e.g. v1 --> |
| Python version | <!-- python3 --version --> |
| OS | <!-- e.g. Kali 2024.4, Ubuntu 24.04 --> |
| GPU (if relevant) | <!-- nvidia-smi or none --> |
| Key type | <!-- Ed25519 / RSA / ECDSA / PPK --> |
| Attack mode | <!-- wordlist / mask / hybrid / distributed --> |

## Command Used

```bash
# Paste exact command (redact the key path if sensitive)
sshcrack -k id_ed25519 -w rockyou.txt ...
```

## Expected Behaviour

<!-- What should happen -->

## Actual Behaviour

<!-- What actually happens — include full error output -->

```
paste error output here
```

## Minimal Reproduction

```bash
# Minimal steps to reproduce (generate a test key if needed):
ssh-keygen -t rsa -b 2048 -f /tmp/test.key -N "testpass" -m PEM -q
sshcrack -k /tmp/test.key -w /tmp/mini_wordlist.txt
```

## Additional Context

<!-- Screenshots, logs, key metadata (sshcrack -k key --info output) -->
