#!/usr/bin/env python3
"""Session 9 xref: find code refs to a VA/immediate in fsp (g21). Usage:
  python session9_xref.py va 0xc003c0e6 [n]      -> sites referencing value
  python session9_xref.py imms                   -> scan all cmp/mov push imms >= 0x400000
"""
import struct, sys
from capstone import Cs, CS_ARCH_X86, CS_MODE_32

BASE = 0xc0022000
DATA = open(r"C:/Users/yash/arc-fw-research/gsc/decoded/g21/fsp", "rb").read()
md = Cs(CS_ARCH_X86, CS_MODE_32)

def dis(start_off, n=200, backward=0):
    out = []
    for ins in md.disasm(DATA[start_off:start_off + n*16], BASE + start_off):
        out.append(f"{ins.address:08x}  {ins.mnemonic} {ins.op_str}")
        if ins.mnemonic == "ret": break
    return out

def find_func_start(o):
    # scan back for common prologue 55 8b ec / 55 89 e5 / endbr32 f3 0f 1e fb? or push ebp;mov ebp,esp
    for p in range(o, max(0, o-0x2000), -1):
        if DATA[p:p+3] in (b"\x55\x8b\xec", b"\x55\x89\xe5"):
            return p
        if DATA[p:p+4] == b"\xf3\x0f\x1e\xfb" and DATA[p+4:p+7] in (b"\x55\x8b\xec", b"\x55\x89\xe5"):
            return p
    return None

def va_hits(val):
    b = struct.pack("<I", val)
    hits = [m.start() for m in __import__("re").finditer(__import__("re").escape(b), DATA)]
    return hits

def cmd_va():
    val = int(sys.argv[2], 0)
    n = int(sys.argv[3]) if len(sys.argv) > 3 else 3
    hits = va_hits(val)
    print(f"0x{val:x} refs: {[hex(h) for h in hits[:20]]}")
    for h in hits[:n]:
        fs = find_func_start(h)
        print(f"--- site 0x{h:x} (func start ~{hex(fs) if fs else '?'}) ---")
        s = max(0, h - 48)
        print("\n".join(dis(s, 40)))

def cmd_imms():
    seen = {}
    for ins in md.disasm(DATA, BASE):
        if ins.mnemonic in ("cmp", "mov", "push", "test", "sub") and "0x" in ins.op_str:
            for tok in ins.op_str.split(","):
                tok = tok.strip()
                if tok.startswith("0x"):
                    try: v = int(tok, 16)
                    except ValueError: continue
                    if v >= 0x400000 and v < BASE and v != 0x1000:
                        seen.setdefault(v, []).append((ins.address, ins.mnemonic, ins.op_str))
    for v in sorted(seen):
        if len(seen[v]) <= 40:
            print(f"imm 0x{v:x} x{len(seen[v])}: {[f'{a:08x} {m} {o}' for a,m,o in seen[v][:6]]}")

if __name__ == "__main__":
    {"va": cmd_va, "imms": cmd_imms}[sys.argv[1]]()
