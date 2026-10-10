#!/usr/bin/env python3
"""Decompress all Huffman-compressed CPD modules from Intel Arc BMG GSC firmware images."""
import io, os, struct, sys

sys.path.insert(0, 'tools/sae-csmeunpacker/required_modules')
sys.path.insert(0, 'tools/sae-csmeunpacker')
from decoder.csme_unpack import read_ascii_huffman_table_from_file as _read_tab, LUTentry as _LUTentry, decode_page_from_input_file_i as _decode_page

CPD_BASE = 0x2000
IMG_BASE = 0x2000  # CPD offsets are relative to this base

def parse_cpd(data):
    off = 0x2010
    entries = []
    while True:
        typ, name, pad, eoff, size = struct.unpack_from('<I8sIII', data, off)
        nm = name.split(b'\x00', 1)[0]
        if not nm or not all(0x20 <= b < 0x7f for b in nm):
            break
        entries.append((typ, nm.decode('latin-1'), eoff, size))
        off += 24
    return entries

def decode_module(data, eoff, size, table_file):
    _read_tab(table_file)
    raw = data[IMG_BASE + (eoff & 0x01FFFFFF): IMG_BASE + (eoff & 0x01FFFFFF) + size]
    # sanity: expect LUT start
    assert raw[:4] in (b'\x00\x00\x00\x40', b'\x00\x00\x00\xc0'), raw[:8].hex()
    # parse LUT
    n_total = size // 4096
    lut = []
    lut_end = n_total * 4
    for i in range(n_total):
        v = struct.unpack_from('<I', raw, i * 4)[0]
        top = (v >> 24) & 0xC0
        if top not in (0x40, 0xC0):
            continue  # official reader skips invalid entries but still advances 4 bytes
        lut.append((1 if top == 0xC0 else 0, v & 0x3FFFFFFF))
    data_start = lut_end  # page offsets relative to end-of-LUT
    out = bytearray()
    n = len(lut)
    for idx, (sel, poff) in enumerate(lut):
        start = lut_end + poff
        if idx + 1 < n:
            pend = lut_end + lut[idx + 1][1]
            psize = pend - start
        else:
            psize = 4096
        e = _LUTentry(start, sel)
        e.size = psize
        outp = io.BytesIO()
        _decode_page(io.BytesIO(raw), e, outp, 0, use_relative_seek=False)
        page = outp.getbuffer()
        out.extend(page[:min(len(page), 4096)])
    if len(out) > size:
        out = out[:size]
    return bytes(out), n, lut_end

def main(img_path, out_dir, table):
    data = open(img_path, 'rb').read()
    os.makedirs(out_dir, exist_ok=True)
    entries = parse_cpd(data)
    print(f'{img_path}: {len(entries)} CPD entries')
    results = []
    for typ, name, eoff, size in entries:
        comp = bool(eoff & 0x02000000)
        real_off = IMG_BASE + (eoff & 0x01FFFFFF)
        if not comp:
            blob = data[real_off:real_off + size]
            open(os.path.join(out_dir, name), 'wb').write(blob)
            print(f'  {name:10s} plain   off=0x{real_off:06x} size=0x{size:x} -> copied')
            results.append((name, 'plain', size))
            continue
        try:
            out, npages, lut_end = decode_module(data, eoff, size, table)
        except Exception as ex:
            print(f'  {name:10s} FAILED: {ex}')
            results.append((name, 'FAIL', str(ex)))
            continue
        path = os.path.join(out_dir, name)
        open(path, 'wb').write(out)
        # entropy
        from collections import Counter
        c = Counter(out)
        n_ = len(out)
        ent = -sum(v / n_ * math_log2(v / n_) for v in c.values()) if n_ else 0
        # x86 prologue heuristic
        probs = out.count(b'\x55\x8b\xec') + out.count(b'\xe8') + out.count(b'\x0f')
        print(f'  {name:10s} decoded off=0x{real_off:06x} size=0x{size:x} pages={npages} '
              f'out=0x{len(out):x} entropy={ent:.2f} x86markers={probs} -> {path}')
        results.append((name, 'decoded', len(out), ent, probs))
    return results

def math_log2(x):
    import math
    return math.log2(x)

if __name__ == '__main__':
    import math
    table = sys.argv[1] if len(sys.argv) > 1 else 'tools/sae-csmeunpacker/resources/csme12_huffmantable.txt'  # verified correct for BMG GSC
    for img, outd in [('gsc/bmg_g21_fwupdate.bin', 'gsc/decoded/g21'),
                      ('gsc/bmg_g31_fwupdate.bin', 'gsc/decoded/g31')]:
        main(img, outd, table)