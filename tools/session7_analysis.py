#!/usr/bin/env python3
"""Session 7: fwupdate/rbe VA-baseline recovery, call graph, const@0x7f48 consumer,
config-blob SHA-384 brute force.

Key correction vs Session 6: decoded module VAs are imm-encoded as VA - 0xc0000000.
fwupdate base VA = 0xc0022000 (proved by 15 exact string/const refs: descriptor-table
string VAs 0x29e05/0x29e1f/0x29e28/0x29e31, OROM.man 0x29ef0, VBT 0x29ef9, CODE 0x29efd,
/snowball/FspInfo 0x29f02/0x29f22/0x29f34, GDTA.man 0x29f14, GDTA 0x29f1d, const 0x29f48
-> file offsets 0x7e05..0x7f48). rbe base VA = 0xc0040000 (push 0x6d957 -> str@0x2d957,
mov eax,0x6deb8 -> str@0x2deb8). Every Huffman module starts with an SSSS-GOT PIC
bootstrap (endbr32; push imm; ...; cmp [ebx],'SSSS').
"""
import os, struct, hashlib, hmac, bisect, sys
from capstone import Cs, CS_ARCH_X86, CS_MODE_32

G21 = os.path.join(os.path.dirname(__file__), '..', 'gsc', 'decoded', 'g21')
GSC = os.path.join(os.path.dirname(__file__), '..', 'gsc')
md = Cs(CS_ARCH_X86, CS_MODE_32)

def module_base(name, decode_drop=0xc0000000):
    d = open(os.path.join(G21, name), 'rb').read()
    k = d.find(bytes.fromhex('8d4c8410be'), 0, 0x80)  # lea ecx,[esp+eax*4+0x10]; mov esi,imm
    if k < 0:
        return None
    return decode_drop + struct.unpack_from('<I', d, k + 5)[0]

def fn_starts(d):
    s = set([8])
    for p in range(4, len(d) - 3):
        if d[p:p+3] in (b'\x55\x89\xe5', b'\x55\x8b\xec') and d[p-1] in (0xc3, 0xcc, 0x90, 0xcb, 0xf4):
            s.add(p)
    return sorted(s)

def callgraph(d):
    starts = fn_starts(d)
    def fn_of(off):
        i = bisect.bisect_right(starts, off) - 1
        return starts[i] if i >= 0 else None
    g = {}
    for p in range(8, len(d) - 5):
        if d[p] == 0xe8:
            t = p + 5 + int.from_bytes(d[p+1:p+5], 'little', signed=True)
            if 0 <= t < len(d):
                f = fn_of(p)
                if f is not None:
                    g.setdefault(f, set()).add(t)
    return g, fn_of

def ancestors(g, f):
    seen, st = set(), [f]
    while st:
        x = st.pop()
        for a, cs in g.items():
            if x in cs and a not in seen:
                seen.add(a); st.append(a)
    return seen

def descendants(g, f):
    seen, st = set(), [f]
    while st:
        x = st.pop()
        for c in g.get(x, ()):
            if c not in seen:
                seen.add(c); st.append(c)
    return seen

def main():
    d = open(os.path.join(G21, 'fwupdate'), 'rb').read()
    g, fn_of = callgraph(d)
    mn2, gdt, rsa = fn_of(0x3c84), fn_of(0x5749), fn_of(0x7229)
    print('MN2_verify fn=0x%x callers=%s' % (mn2, [hex(x) for x in ancestors(g, mn2)]))
    print('GDTA.man fn=0x%x callers=%s' % (gdt, [hex(x) for x in ancestors(g, gdt)]))
    dg = descendants(g, gdt)
    print('GDTAman transitive callees contain MN2_verify:',
          mn2 in dg, '/ rsa ioctl:', rsa in dg)
    print('bases:', {m: hex(module_base(m) or 0) for m in
          ('fwupdate','mca_boot','crypto','pm','gfx_srv','fsp','sigma','vfs','heci','storage')})

    # config blob SHA-384 brute force
    d19 = open(os.path.join(GSC, 'bmg_e20b_1100_config19.bin'), 'rb').read()
    hset = {d19[a:a+0x30]: n for a, n in ((0x6dc,'h1'),(0x730,'h2'),(0x79c,'h3'))}
    bounds = list(range(0, len(d19) + 1, 0x40))
    for a in bounds:
        for b in bounds:
            if b <= a: continue
            if hashlib.sha384(d19[a:b]).digest() in hset:
                print('config hash MATCH', hex(a), hex(b))
    op = open(os.path.join(GSC, 'bmg_OpromCode.bin'), 'rb').read()
    print('oprom sha384 in set:', hashlib.sha384(op).digest() in hset)

if __name__ == '__main__':
    main()
