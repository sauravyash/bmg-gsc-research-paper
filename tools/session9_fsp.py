#!/usr/bin/env python3
"""Session 9: fsp G21 vs G31 delta + strings dump + density-constant scan.
Usage: python session9_fsp.py diff|strings|scan"""
import re, struct, sys, os

D = r"C:/Users/yash/arc-fw-research/gsc/decoded/"
DELTA = 0x22000  # VA = 0xc0000000 + 0x22000 + file_off

def fsp(die):
    return open(D + die + "/fsp", "rb").read()

def diff():
    a, b = fsp("g21"), fsp("g31")
    regions = []
    prev = None
    for i in range(len(a)):
        if a[i] != b[i]:
            if prev is None or i > prev[1] + 16:
                regions.append([i, i])
            else:
                regions[-1][1] = i
            prev = regions[-1]
    print(f"total diff bytes: {sum(e-s+1 for s,e in regions)}")
    for s, e in regions:
        print(f"region 0x{s:05x}-0x{e:05x} ({e-s+1} B)")
        print("  g21:", a[s:e+1].hex())
        print("  g31:", b[s:e+1].hex())
        # context as dwords
        base = max(0, s-8)
        for d in ("g21", "g31"):
            v = (a if d=="g21" else b)[base:e+9]
            for j in range(0, len(v)-3, 4):
                if base+j <= e:
                    print(f"  {d} dword 0x{base+j:05x} = 0x{struct.unpack_from('<I', v, j)[0]:08x}")

def strings(die="g21"):
    data = fsp(die)
    for m in re.finditer(rb"[\x20-\x7e]{4,}", data):
        o = m.start()
        print(f"0x{o+DELTA:08x} (f 0x{o:05x}) {m.group().decode()[:100]}")

def scan():
    pats = [
        ("1GB/ch", 0x40000000), ("2GB/ch", 0x80000000),
        ("8Gbit bytes", 0x10000000), ("4GB/ch lo", 0x00000000),
        ("mr? 0x1000", 0x1000),
    ]
    for die in ("g21", "g31"):
        data = fsp(die)
        print(f"== {die} fsp ==")
        for name, val in pats:
            b = struct.pack("<I", val)
            hits = [m.start() for m in re.finditer(re.escape(b), data)]
            if hits:
                print(f" {name} 0x{val:08x}: {[hex(h) for h in hits[:20]]}")
        # 64-bit-ish channel sizes, channel counts as imms 6/8/12 handled in disasm
        for val, name in [(0x4000000000, "64GB?"), (0x1_0000_0000 & 0xffffffff, "4GB lo32")]:
            pass
    # interesting: search both dies for immediates 0x0c/0x18/0x30 (6/12/24 GB<<20?)
    for die in ("g21", "g31"):
        data = fsp(die)
        for gb, val in [(1, 0x40000), (2, 0x80000), (3, 0xC0000), (4, 0x100000), (6,0x180000), (12,0x300000), (16,0x400000), (24,0x600000), (32,0x800000)]:
            b = struct.pack("<I", val)
            hits = [m.start() for m in re.finditer(re.escape(b), data)]
            if hits:
                print(f"{die}: {gb}GB-in-MB imm 0x{val:x}: {[hex(h) for h in hits[:10]]}")

if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else "diff"
    {"diff": diff, "strings": strings, "scan": scan}[cmd]()
