# arc-bmg-firmware-notes

An offline unpacking and analysis of the Intel Arc **Battlemage (BMG) GSC firmware** —
config-data verification, memory-geometry policy, and what actually separates a
12 GB B580 from a 24 GB B60.

## Abstract

Intel's Arc B580 (12 GB GDDR6) and B60 (24 GB GDDR6) share the BMG-G21 die and differ,
at the firmware level, in a single signed 64 KB "config-data" blob. We fully unpacked
the Battlemage GSC firmware from the public LVFS/fwupd update package — including the
first public, to our knowledge, complete Huffman decompression of a BMG GSC code
partition (all 20 modules, both dies) — and traced the config-data deploy and boot
paths at the disassembly level.

The central finding: **config-data integrity is enforced only at deploy time, by
host-side tooling.** The GSC `fwupdate` module accepts the 64 KB config blob with
structural checks only, writes it to flash, and *no GSC module re-verifies it at
boot*. The GSC's hard RSA-3072/PSS gate — anchored to fuse-derived key material via
`/snowball/ipub_key` — protects **code manifests** (RBEP/PCOD/PHYP/OMSM) only.
Meanwhile the B580↔B60 config diff is exactly 14 regions (one RSA signature, three
SHA-384s, a device-ID byte, a revision byte, and a few VBT display bytes) with **no
memory-geometry tables**, and the memory-training module `fsp` is **byte-identical**
between the 12/24 GB die and the 32 GB die — memory sizing is computed at run time
from cached training results, not parsed from config content.

**Consequence:** the firmware-visible difference between a 12 GB and a 24 GB board is
a signed identity token; the binding constraint on any modification is the signing
key at deploy time plus board wiring, not on-die verification code.

## Contents

```
paper/PAPER.md          — the full research compilation (10 sections, all evidence)
analysis/g21/           — all 20 Huffman-decoded GSC modules, BMG-G21 die (B580/B60)
analysis/g31/           — all 20 Huffman-decoded GSC modules, BMG-G31 die (B65/B70)
firmware/config-data/   — the three real 64 KB config blobs (+ recovery variants)
                          E20B=B580 12GB, E212=B60 24GB, E223=B70
firmware/manifest_rsa3072_key.txt — Intel GSC code-signing RSA-3072 public modulus
notes/                  — raw session evidence dumps (xrefs, callgraphs, disasm)
tools/                  — the unpacking/analysis toolkit
```

### Highlights in `analysis/`

- `fwupdate` — the deploy path: partition-type dispatcher, structural-only verifier
  for OROM.man/GDTA.man, the `/snowball/GfxDtaUpdSts` status variable, the bp1
  partition-descriptor table, and the service GUID at file offset 0x7F48.
- `rbe` — the boot ROM: `PreOs_VerifyHash`, the `ipub_key` trusted-store parser
  (up to 8 × SHA-384 key-hash slots), fused-key name strings — and the proof that
  it never references OROM/GDTA.
- `fsp` — the memory-training consumer: `/snowball/mrc_data`/`mrc_bdat` staging into
  SRAM, PHY register-descriptor tables, and the only G21↔G31 delta (a message-ID
  table).

## Reproducing

Raw images (not redistributed here) come from the LVFS cab
`intel-arc-bmg-21.1180.cab` (fwupd: `cdn.fwupd.org/downloads/firmware.xml.gz`) and the
linux-firmware `xe/` tree (`bmg_guc_70.bin`, `bmg_huc.bin`). Verify the B580 config
against the published sha256 `4103d75a…`.

```bash
# 1. Unpack GSC image: $FPT → $CPD → Huffman decode (csme12 table)
python tools/decode_gsc_cpd.py firmware/bmg_g21_fwupdate.bin analysis/g21/

# 2. Decode $MN2 R2 manifests (RSA-3072 key/sig, module hash table)
python tools/parse_manifest.py analysis/g21/RBEP.man

# 3. Call-graph / hash-brute / xref analyses behind paper §4–§7
python tools/session7_analysis.py     # VA bases, dispatcher call-graph, SHA brute
python tools/session8_sweep.py        # string xrefs + immediate scans, all modules
python tools/session9_fsp.py          # G21↔G31 fsp byte-diff (1237 bytes, 1 table)
```

Dependencies: Python 3, `capstone` (≥5.0). Decoded-module layout uses the CSME R2
conventions documented in paper §2.3 (LUT selector mapping and fixed-length LUT —
the two things that will break your first attempt).

## Key results at a glance

| Question | Answer |
|---|---|
| Who verifies the config-data signature? | Nobody on-die at run time. Host tooling (igsc/LVFS) at deploy; GSC fwupdate does structural checks only. |
| Is it re-verified at boot? | No — `rbe` never references OROM/GDTA; boot-time readers check update *status* only. |
| What's in the B580↔B60 diff? | 538/65,536 bytes: RSA-3072 sig, 3× SHA-384, device-ID byte, rev byte, ~9 VBT display bytes. No memory tables. |
| Is there a per-die density cap in GSC? | No — `fsp` is byte-identical across the 12/24 GB and 32 GB dies except a message-ID table. |
| Where does memory size come from? | Memory-training results cached in NVM (`mrc_data`/`mrc_bdat`), staged to SRAM by `fsp`; size programmed dynamically. |
| Can you flash a tampered config? | SPI-level writes boot unverified; passing the update path requires Intel's config-signing key. |

## Status & open questions

Complete through session 9. Open items are listed in paper §9 (PSS verify inputs,
why standalone PSS verify fails, SHA-384→bp1 region mapping, `mrc_data` internals,
host-side igsc device-ID enforcement, PCOD).

## Disclaimer

Firmware © Intel. The config blobs are redistributed as shipped by the LVFS update
mechanism. This is research documentation; nothing here provides a working VRAM
modification. Do not flash anything described here.
