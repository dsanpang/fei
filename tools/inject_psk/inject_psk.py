#!/usr/bin/env python3
"""Inject certs/psk.bin (and optionally an agent id) into entry.asm.

Usage:
    python inject_psk.py <psk.bin> <entry.asm> [agent_id_hex]

Rewrites the `psk:` db block (32 bytes) and, when given, the `agent_id:`
db block (8 bytes) so the assembled agent.exe carries deployment values
instead of the build-time placeholders.
"""
import re
import sys


def main():
    if len(sys.argv) < 3:
        sys.exit(__doc__)
    psk_path, asm_path = sys.argv[1], sys.argv[2]
    psk = open(psk_path, "rb").read()
    if len(psk) != 32:
        sys.exit("psk must be exactly 32 bytes")

    src = open(asm_path).read()
    lines = []
    for i in range(0, 32, 8):
        chunk = ", ".join(f"0x{b:02X}" for b in psk[i:i + 8])
        lines.append(f"    db {chunk}")
    repl = "psk:\n" + "\n".join(lines) + "\n"
    src2 = re.sub(r"psk:\n(?:\s+db[^\n]*\n){4}", repl, src, count=1)
    if src2 == src:
        sys.exit("psk label pattern not found in %s" % asm_path)

    if len(sys.argv) > 3:
        aid = bytes.fromhex(sys.argv[3].replace("-", "")[:16])
        if len(aid) != 8:
            sys.exit("agent id hex must decode to 8 bytes")
        aid_line = "    db " + ", ".join(f"0x{b:02X}" for b in aid) + "\n"
        src2 = re.sub(r"agent_id:\n\s+db[^\n]*\n", "agent_id:\n" + aid_line,
                      src2, count=1)

    open(asm_path, "w").write(src2)
    print("psk injected into", asm_path)


if __name__ == "__main__":
    main()
