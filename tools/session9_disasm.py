#!/usr/bin/env python3
"""Session 9: fsp disassembly analysis (g21).
Usage: python session9_disasm.py callgraph|fn <va>|table <off> <n>|ctx <off>|strings"""
import re, struct, sys
from capstone import Cs, CS_ARCH_X86, CS_MODE_32

BASE = 0xc0022000
DATA = open(r"C:/Users/yash/arc-fw-research/gsc/decoded/g21/fsp", "rb").read()
md = Cs(CS_ARCH_X86, CS_MODE_32)
md.detail = False

def off(va): return va - BASE

def dis(start_off, n=400):
    out = []
    for ins in md.disasm(DATA[start_off:start_off + n*16], BASE + start_off):
        out.append(f"{ins.address:08x}  {ins.mnemonic} {ins.op_str}")
        if ins.mnemonic == "ret": break
    return out

def callgraph():
    # collect call rel32 targets
    calls = {}
    for ins in md.disasm(DATA, BASE):
        if ins.mnemonic == "call" and ins.op_str.startswith("0x"):
            t = int(ins.op_str, 16)
            calls.setdefault(t, []).append(ins.address)
    print(f"total call targets: {len(calls)}")
    # import stubs (negative rel32)
    imps = set()
    for ins in md.disasm(DATA, BASE):
        if ins.mnemonic == "call" and ins.op_str.startswith("0x"):
            t = int(ins.op_str, 16)
            if t < BASE:
                imps.add(t)
    print("imports:", sorted(hex(t) for t in imps))
    # functions: known start 0xc0023674; find its caller 0xc0022717 context
    print("\n=== fn@0xc0023674 (MRC loader) ===")
    print("\n".join(dis(off(0xc0023674), 120)))
    print("\n=== caller ctx @0xc0022717 ===")
    s = off(0xc0022717) - 96
    for a in dis(s, 60): print(a)

def fn(va):
    print("\n".join(dis(off(va), int(sys.argv[3]) if len(sys.argv) > 3 else 300)))

def table(args):
    o, n = int(args[0], 0), int(args[1], 0)
    for i in range(n):
        v = struct.unpack_from("<I", DATA, o + i*4)[0]
        print(f"0x{o+i*4:05x}: 0x{v:08x}")

def ctx(off_):
    o = int(off_, 0)
    for a in dis(max(0, o-64), 80): print(a)

def strings():
    for m in re.finditer(rb"[\x20-\x7e]{5,}", DATA):
        print(f"0x{m.start()+BASE:08x} (f 0x{m.start():05x}) {m.group().decode()[:110]}")

if __name__ == "__main__":
    cmd = sys.argv[1]
    {"callgraph": callgraph, "fn": fn, "table": lambda: table(sys.argv[2:]), "ctx": lambda: ctx(sys.argv[2]), "strings": strings}[cmd]()
