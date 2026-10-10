import struct, sys

data = open(r"C:\Users\yash\arc-fw-research\gsc\bmg_g21_fwupdate.bin","rb").read()

def parse_cpd(base):
    entries=[]
    off = base+0x10
    while True:
        t, name, pad, o, s = struct.unpack_from("<I8sIII", data, off)
        name = name.rstrip(b"\x00").decode()
        if name == "": break
        entries.append({"type":t,"name":name,"off":o & 0x7FFFFFF,"size":s,"comp":bool(o & 0x02000000)})
        off += 24
    return entries

ents = parse_cdp = parse_cpd(0x2000)
print("== CPD entries ==")
for e in ents:
    print(f"{e['name']:<10} type=0x{e['type']:08x} off=0x{e['off']:x} size=0x{e['size']:x} comp={e['comp']}")

# RBEP.man module
man = [e for e in ents if e['name']=='RBEP.man'][0]
mbase = 0x2000 + man['off']
mdata = data[mbase:mbase+man['size']]
open(r"C:\Users\yash\arc-fw-research\gsc\RBEP.man.bin","wb").write(mdata)
print("\nRBEP.man size", hex(len(mdata)))
# find $MN2
i = mdata.find(b"$MN2")
print("$MN2 at", hex(i))
hdr = mdata[i:i+0x100]
print(hdr[:0x40].hex())
# dump structural: look at known CSME manifest layout hints
for off in range(i, min(i+0x200, len(mdata)), 4):
    w = struct.unpack_from("<I", mdata, off)[0]
    if w in (0x60, 96) or off == i:
        pass
print("\nwords from $MN2:")
for k in range(0, 0x100, 4):
    w = struct.unpack_from("<I", mdata, i+k)[0]
    print(f"+0x{k:03x}: 0x{w:08x}")
