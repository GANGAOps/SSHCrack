"""
rules/ — Passphrase mutation engines.

  mutations.py  — Built-in rules (~100 mutations: capitalize, leet, suffixes, prefixes)
  hashcat.py    — Full Hashcat .rule file parser (25+ opcodes, Best64 built-in)
  mask.py       — Mask attack engine (?l?u?d?s?a?b and custom charsets ?1-?4)
"""

from sshcrack.rules.mutations import apply_rules, count_rules
from sshcrack.rules.hashcat   import load_rule_file, apply_rules_from_file, get_builtin_rules
from sshcrack.rules.mask      import MaskEngine

__all__ = [
    # mutations
    "apply_rules",
    "count_rules",
    # hashcat
    "load_rule_file",
    "apply_rules_from_file",
    "get_builtin_rules",
    # mask
    "MaskEngine",
]
