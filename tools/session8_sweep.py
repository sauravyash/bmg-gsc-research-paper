#!/usr/bin/env python3
"""Session 8 sweep: disassemble modules, dump string xrefs + target-immediate hits.
VA = 0xc0000000 + 0x22000 + file_off (uniform link VA, all Huffman modules).
Usage: python session8_sweep.py <module> [<module>...]
Writes notes/session8_<module>.txt
"""
import re, struct, os, sys
from capstone import Cs, CS_ARCH_X86, CS_MODE_32

D = r"C:/Users/yash/arc-fw-research/gsc/decoded/g21/"
OUT = r"C:/Users/yash/arc-fw-research/notes/"
DELTA = 0x22000

TARGET_IMMS = {
    0x6c0: "entry-table start", 0x6c8: "tag VBT entry", 0x6dc: "SHA384#1 off",
    0x730: "SHA384#2 off", 0x77e: "device-ID byte off", 0x782: "rev byte off",
    0x79c: "SHA384#3 off", 0x778: "device block start", 0x790: "device block end",
    0x800: "IntelGraphicsMem OROM", 0x2440: "VBT start", 0x520: "RSA sig off",
    0xE20B: "PCI DID E20B(B580)", 0x1100: "PCI DID/subid 1100", 0xE212: "PCI DID E212(B60)",
    0x1114: "DID 1114", 0xE223: "PCI DID E223(B70)", 0xAA55: "55AA magic", 0x55AA: "55AA magic",
}
TAGS = {b"VBT\x00": "'VBT'", b"OROM": "'OROM'", b"GDTA": "'GDTA'", b"CODE": "'CODE'"}
MEM_STR = re.compile(r"mrc|mem|sram|vram|rank|chan|train|gddr|ddr|size|geometry|straps|fuse|fuses|gfxt|fsp", re.I)

def load(name): return open(D + name, "rb").read()

def strings(data, minlen=4):
    return [(m.start(), m.group().decode()) for m in re.finditer(rb"[\x20-\x7e]{%d,}" % minlen, data)]

def main(mod):
    data = load(mod)
    so = {o: s for o, s in strings(data)}
    lines = [f"### {mod}: {len(data)} bytes (0x{len(data):x})"]
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    ins = list(md.disasm(data, 0xc0000000 + DELTA))
    lines.append(f"linear decode: {len(ins)} instructions")

    # 1) string xrefs
    xr = {}
    for i in ins:
        for tok in re.findall(r"0x[0-9a-f]+", i.op_str):
            v = int(tok, 16)
            off = v - 0xc0000000 - DELTA
            if off in so:
                xr.setdefault(off, []).append(i)
    lines.append("\n== STRING XREFS ==")
    interesting = []
    for o in sorted(xr):
        s = so[o]
        lines.append(f"str@0x{o:x} '{s[:70]}'")
        for i in xr[o][:3]:
            lines.append(f"    {i.address:08x}  {i.mnemonic} {i.op_str}")
        if MEM_STR.search(s):
            interesting.append((o, s, xr[o]))

    # 2) target immediates
    lines.append("\n== TARGET IMMEDIATES ==")
    hits = 0
    for i in ins:
        for tok in re.findall(r"0x[0-9a-f]+", i.op_str):
            v = int(tok, 16)
            if v in TARGET_IMMS:
                lines.append(f"{i.address:08x}  {i.mnemonic} {i.op_str}   ; {TARGET_IMMS[v]}")
                hits += 1
    # also raw dword tag searches in data
    for tag, name in TAGS.items():
        offs = [m.start() for m in re.finditer(re.escape(tag), data)]
        if offs:
            lines.append(f"tag {name} raw at: {[hex(x) for x in offs[:12]]}")

    lines.append("\n== MEM-RELATED STRINGS WITH CONTEXT ==")
    for o, s, xs in interesting:
        lines.append(f"\n--- str@0x{o:x} '{s[:90]}'")
        for i in xs[:8]:
            lines.append(f"    {i.address:08x}  {i.mnemonic} {i.op_str}")
    open(os.path.join(OUT, f"session8_{mod}.txt"), "w").write("\n".join(lines))
    print(mod, "done:", len(ins), "ins,", len(xr), "string xrefs,", hits, "target imms ->",
          f"notes/session8_{mod}.txt")

for m in sys.argv[1:]:
    main(m)
