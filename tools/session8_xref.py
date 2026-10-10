#!/usr/bin/env python3
"""Session 8 xref map: brute-force dword scan for VA refs (VA=0xc0000000+0x22000+off),
then disassembly context around ref sites. Usage:
  python session8_xref.py <module> list            -> all string->imm xrefs
  python session8_xref.py <module> ctx <off> [n]   -> disasm context around ref site of string@off
"""
import re, struct, sys
from capstone import Cs, CS_ARCH_X86, CS_MODE_32

D = r"C:/Users/yash/arc-fw-research/gsc/decoded/g21/"
DELTA = 0x22000

def main():
    mod, cmd = sys.argv[1], sys.argv[2]
    data = open(D + mod, "rb").read()
    strs = [(m.start(), m.group().decode()) for m in re.finditer(rb"[\x20-\x7e]{4,}", data)]
    dw = {}
    for i in range(len(data) - 3):
        dw.setdefault(struct.unpack_from("<I", data, i)[0], []).append(i)
    md = Cs(CS_ARCH_X86, CS_MODE_32)

    def ctx(site, back=48, fwd=40):
        out = []
        start = max(0, site - back)
        for ins in md.disasm(data[start:site + fwd], 0xc0000000 + DELTA + start):
            out.append(f"  {ins.address:08x}  {ins.mnemonic} {ins.op_str}")
        return out

    if cmd == "list":
        for o, s in strs:
            hits = dw.get(o + DELTA)
            if hits:
                print(f"str@0x{o:x} '{s[:64]}' refs@{[hex(h) for h in hits]}")
    else:
        off = int(sys.argv[3], 0)
        hits = dw.get(off + DELTA, [])
        n = int(sys.argv[4]) if len(sys.argv) > 4 else 3
        print(f"str@0x{off:x} refs: {[hex(h) for h in hits[:n]]}")
        for h in hits[:n]:
            print(f"--- site 0x{h:x} ---")
            print("\n".join(ctx(h)))

if __name__ == "__main__":
    main()
