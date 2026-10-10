# Intel Arc BMG Firmware Research — Session Notes (2026-10-09)

## Artifacts obtained (~/arc-fw-research/)
- guc/bmg_guc_70.bin (385,856 B), guc/bmg_huc.bin (585,728 B) — linux-firmware xe/ tree
- gsc/intel-arc-bmg-21.1180.cab — LVFS (fwupd) package, extracted:
  - bmg_OpromCode.bin (960KB) + recovery — VBIOS/OpROM, ALL BMG SKUs (B50/B570/B580/B60/B65/B70)
  - bmg_g21_fwupdate.bin (2.1MB) — GSC fw, BMG-G21 die (B580/B570/B50/B60)
  - bmg_g31_fwupdate.bin (2.1MB) — GSC fw, BMG-G31 die (B65/B70)
  - config-data per device ID:
    - bmg_e20b_1100_config19.bin — E20B = **B580 (12GB)**
    - bmg_e212_1114_config23.bin — E212 = **B60 (24GB)**
    - board-specific 258KB config blobs (Sparkle/ASRock/Shangke B60/B65/B70)

## Finding 1: GSC images use Intel $FPT (flash partition table / IFWI) format
- Magic `24 46 50 54` ($FPT) at offset 0; "INFO" tags. ~44% of 4KB blocks low-entropy → container is parseable, not fully encrypted. Unglued next: parse $FPT partition entries.

## Finding 2: config-data blobs are PLAINTEXT (entropy 1.51), 55AA PCI expansion ROM header
## Finding 3: B580 vs B60 config differ in only 538/65,536 bytes, 14 regions:
- 0x0520–0x069F (384 B): high-entropy → RSA-3072 SIGNATURE (one per config)
- 0x06DC–0x070B, 0x0730–0x075F, 0x079C–0x07CB (3× 48 B): high-entropy → SHA-384 hashes
- 0x077E: device-ID byte embedded (0B vs 12 = E20B vs E212)
- 0x0782: 0x00 vs 0x14 (config rev 1100 vs 1114?)
- ~8 scattered single-byte values at 0x2856–0x2AB7 → likely the ACTUAL memory-geometry/rank/board config deltas
- SAME RSA signature covers the whole table → patching config-data requires forging or re-signing with GSC-held key... UNLESS verification is flash-time-only (igsc) and not boot-time. UNKNOWN — top research question.

## Interpretation
- 12GB vs 24GB difference at firmware level = a signed 64KB config table + board wiring. The table is tiny and readable. The gate is the signature chain (presumably GSC-verified).
- What separated us from the AMD-style mod is exactly and only: who verifies the config signature, and when (flash-time vs every boot).

## Session 2 results — GSC image UNPACKED (bmg_g21_fwupdate.bin)

### $FPT header
- magic `$FPT`, 3 partitions: INFO (2,560B descriptor table), IMGI, FWIM. Entries: name[4]+off+size.
- IMGI @0xa00: `BMG_` tag, contains "PCOD" (p-code) sections. FWIM @0x1000: the GSC firmware volume.

### CPD (Code Partition Directory) — FULLY PARSED
- `$CPD` @0x2000. Entries @0x2010, stride 24: [type u32][name 8][pad u32][offset u32][size u32].
- Offsets relative to CPD base 0x2000. Bit 25 (0x02000000) = compressed.
- 24 modules: RBEP.man(0x314,0xa30,plain), rbe.met(plain), intl.cfg(plain),
  then compressed: rbe(0xe40,0x38000), kernel(0x27800,0x1b000), syslib, pm, vfs, evtdisp,
  fpf, loadmgr, crypto, heci, storage, maestro, fwupdate, mca_boot, gfx_srv, fsp, sigma,
  cpassist, mca_srv.
- Byte map: entry struct offset = CPD entry + 16 (off) / +20 (size). Compression flag bit = 0x02000000.

### RBEP.man manifest ($MN2 @ +0x1c)
- Structure: ver 04 00 00 00 / id e1 00 00 00 / 0x201000 flags... $MN2 header cb 00 00 00 (203 byte module?)
- @0x7c: length field 0x60 (96B) followed by 96 bytes high-entropy @0x80 — first key-material candidate (SHA-384 x2 or a key hash + hash). NOT yet decoded.

### Compression
- LZMA alone/xz/raw fail on 'kernel'. Head: `000000c0 400d00c0 401900c0 801d00c0...` — looks like a table of descriptors, NOT raw LZMA. CSME uses Huffman+LZMA layered compression (per ME research). Next: implement/dump Huffman table decode, or find compressed stream start after descriptor table.

### Provenance
- bmg_e20b_1100_config19.bin sha256 verified == LVFS published (4103d75a...). Chain of custody clean.

### Answered questions
- GSC firmware is NOT a black box: directory layer 100% mapped; ~all module names known (ME lineage: heci, crypto, kernel, fpf...).
- Config-data is deployed via com.intel.gsc protocol → GSC is the verification point for config blobs (fwupd merely transports).
- OpROM has zero config-verification logic (generic MS-signed UEFI driver).

## Session 3 results — manifest decoded, config structure mapped

### $MN2 header = CSE **R2** layout (MEA.py MN2_Manifest_R2 struct match)
- Header @0x00 (not +0x1c): HeaderLength 0xe1 dwords = 0x384 B total. Tag '$MN2' @0x1c.
- PublicKeySize 96 dwords @0x78, ExponentSize 1 @0x7c, **RSAPublicKey @0x80..0x200**,
  **exponent @0x200 = 0x00010001 (65537)**, **RSASignature @0x204..0x384 (3072-bit)**.
- Signature is SSA-PSS (R2 scheme), NOT PKCS#1 v1.5. Verify attempt FAILED so far:
  decrypted sig is not valid PSS EM for any endianness pairing; brute-force over all
  4-byte-aligned 384B windows found no valid (key,sig) pair (only 2 chance 0xbc tails).
  => either fwupdate-container manifests are obfuscated, or signing key differs from
  embedded key (FPF key-hash anchored). OPEN.
- Key (modulus @0x80, little-endian) is IDENTICAL in G21 and G31 manifests → genuine
  Intel GSC code-signing key. Saved hex in gsc/manifest_rsa3072_key.txt.
- Behind key/sig: PCOD/PHYP/OMSM tags + module table (rbe hash 0x5d91910a..., intl.cfg hash).
- MEAnalyzer (tools/MEA.py) downloaded for struct references.

### config-data blobs (64KB, E20B/E212/E223)
- **Partner 258KB config-data files are ALL 0xFF placeholders** (Asrock/Sparkle/Shangke/IBC).
  Only 3 real configs ship: E20B(B580) config19, E212(B60) config23, E223(B70) config20.
- Recovery variants: same content, separately signed (crypto regions + 4 version bytes differ).
- FULL B580↔B60 diff = 14 regions → ONLY: RSA-3072 sig, 3× SHA-384 hashes, device-ID byte
  @0x77e (0B vs 12), rev byte @0x782, and ~9 bytes inside the **VBT** @0x2440+
  (display/panel blocks — NOT memory timing). **No memory-geometry tables in the blob.**
- Blob contents: 55AA OROM header @0, RSA sig @0x520, hashes @0x6dc/0x730/0x79c,
  device-id block @0x77e, "GraphicsMem" identifier OROM @0x800 (version string
  "2.5.0.1066", not a size), $VBT BATTLEMAGE @0x2440 (BIOS_DATA_BLOCK, LFP panels...).
- 3 SHA-384 hashes do NOT match sha384/sha256 of any window/chunk of the blob itself,
  even with crypto regions zeroed → they reference external data or are keyed (HMAC).
- Implication: 12GB vs 24GB firmware-wise is essentially ONLY device-ID + signature.
  Actual memory size policy likely lives in GSC (boot-time, per device ID) or is
  determined by memory training. Supports "config verify is the gate" hypothesis.

### GSC module decompression attempts
- Modules (rbe/kernel/crypto/fpf/fwupdate) confirmed high-entropy (7.7–7.9) = compressed/encrypted.
- Each module starts with a PLAINTEXT TOC: ascending 0xc0000000-based dword table
  (section load addresses), then opaque payload.
- NOT LZMA-alone/xz: brute-scan for LZMA-alone headers (props<0xE0 + sane dict size)
  over rbe/kernel/crypto found zero decodable streams.
- me-tools (skochinsky) is Py2 + old-ME ($MAN Huffman era); not directly reusable.
- Next: port/locate a CSE R2 decompressor (look at fwupdate/mca_boot code, or search
  for community tools: "cse_decompress", MEAnalyzer issues, coreboot me_cleaner refs).

## Session 6 — fwupdate verify internals (disassembled, g21)

- **No key material in fwupdate**: exhaustive scan — no RSA modulus, no SHA-384 IV, no 384B
  high-entropy block. Crypto is imported (negative rel32 stubs → syslib). syslib holds the
  SHA-512 K table @0x1fd80 (LE word order, verified) and a 65537 exponent imm @0x2085c.
  Only RSA-3072 modulus in the entire image set = RBEP.man @0x80 (code-signing key).
- **$MN2 verify pipeline (fn@0x3c84)**: parses manifest, builds per-module SHA-384 digest
  table, hashes **manifest[0x00:0x80] + manifest[0x384:end]** (skips key@0x80-0x200 and
  sig@0x204-0x384 — R2 layout confirmed by the CODE ITSELF), 48-byte memcmp vs
  parent-manifest expected digest @0x3f99. So modules are verified by DIGEST CHAIN;
  the RSA-PSS sig over the header runs in the imported syslib/crypto service
  (device 0x29df1, ioctl fn@0x7229). Structural verifier fn@0x6f7d also checks module
  entries vs 8/12-byte flash values (device 0x29fe1).
- **OROM/GDTA path is separate & structural only**: fn@0x98b (bp-slot 55AA magic checks),
  fn@0x1f32 (PCIR walker). ZERO immediates for config offsets 0x520/0x6a0/0x6dc/0x730/
  0x79c/0x77e/0x782 — the 64KB config blob is consumed whole as GDTA.man via the generic
  $MN2 machinery; its internal sig/hashes are not poked at by offset.
- **Device-ID NOT enforced in fwupdate**: no cmp 0x0B/0x12 anywhere; acceptance is implicit
  via the signing chain. CPU/die fields only logged (fn@0xc3e), not compared.
- **No anti-rollback** found in fwupdate (rev byte @0x782 never compared to a floor).
- **Unresolved 16-byte constant @0x7f48** in OROM/GDTA metadata table:
  `a5 0c d9 87 95 34 59 45 81 05 3f bf a3 7b 8b 79` — candidate expected key-hash/digest
  for config; reference via PIC indirection, unresolved.
- **Verdict**: deploy-time verification is the ONLY gate; flash-level (SPI) writes of
  GDTA/OROM would boot unverified (confirmed rbe never references them). But the config
  blob travels as a whole signed manifest, so swapping requires a blob that passes the
  digest chain + imported RSA-PSS anchored to a fused key hash. Re-signing impossible
  without Intel's private key.

### Open (Session 6)
1. RSA-PSS verify location/inputs in syslib/crypto (device 0x29df1 ioctl surface)
2. FPF/fused key-hash anchor check — where ('CSE Manifests Hash Key' in rbe)
3. Definitive mapping of blob's 3 SHA-384 → bp1 sub-regions (VBT/CODE/GDTA tags @0x7ef8-0x7f1d)
4. Identity of const @0x7f48
5. Does host-side igsc enforce device-ID @0x77e?
6. Exact per-page load addresses from CPD LUTs would fix cross-module VA xrefs

## Next steps (priority order)
1. ~~$MN2 decode~~ DONE (R2 layout). Open: why PSS verify fails — try verify against
   recovery images, or extract key-hash anchoring (FPF) assumptions.
2. CSE R2 module decompression — find/port decompressor, then grep 'crypto'/'fwupdate'
   modules for config-hash verification code and the config RSA modulus.
3. Determine config verify timing (GSC boot-time vs flash-time) — decompressed 'fwupdate'
   module is the most likely place to find the com.intel.gsc config-deploy + verify path.
4. Interpret VBT deltas @0x2a75 (12GB: "15 00..12" vs 24GB "00 00..11") — could be
   display-memory carveout fields, check BDB spec.

## Session 4 results — ALL GSC modules DECOMPRESSED (both dies)

### Huffman decode of BMG GSC is SOLVED
- Tool: tools/decode_gsc_cpd.py (parses $CPD, LUTs, calls csmeunpacker decode_page_from_input_file_i).
- Table: **csme12_huffmantable.txt is correct** for BMG GSC (csme11 decodes to garbage).
  Arbitrated by strings: csme12 gives '/dev/maestro', '../../src/os/servers/vfs/device.c',
  'CSCP Kernel Memory Guard Key' etc.; csme11 gives noise.
- TWO parser corrections vs the earlier mental model (both matter):
  1. LUT selector mapping: entry top-2 bits 0xC0 -> dict2 (selector 1), 0x40 -> dict1 (selector 0).
     (Old model said 0x40->sel0 by 'top byte' but the LE-dword 'top bits' != selector value.)
  2. LUT length is FIXED: exactly size/4096 entries; invalid entries (top bits neither 0x40/0xC0)
     are SKIPPED (advance 4 bytes) not terminating; lut_end = (size/4096)*4. Offsets are
     LUT-end-relative; page sizes = next valid entry's offset - this offset; last page size 0
     -> consume up to 4096 bytes of input, decoded page size max 4096.
- Every decoded page: out buffer must be a real file-like (io.BytesIO), NOT bytearray.

### Result
- g21 and g31: 20 Huffman modules each decoded, output size == CPD size field EXACTLY,
  zero "no matching code" errors, zero aborts. Outputs in gsc/decoded/g21/ and gsc/decoded/g31/
  (plain modules RBEP.man, rbe.met, intl.cfg copied as-is; fitc.cfg is empty 0B).
- Plausibility verified: dense readable strings everywhere — '/dev/events', '/dev/tty01',
  '/dev/crypto', '/dev/flash/bp1', '/snowball/bootpath', '/susram/chassis_inf',
  'init: open failed, errno = %d', 'BIOSPendVal', 'WLAN_CALIB', 'VerifierSK',
  'CSCP Data IPK', 'CSME Svnx Crypto Wrap Key', evtdisp log format strings,
  vfs source path '../../src/os/servers/vfs/device.c', sigma ioctl table names.
- rbe/fsp mostly code with sparse strings (x86: push ebp/mov ebp,esp prologues present,
  e.g. 55 89 e5 / 55 8b ec, 83 ec xx, e8 call rel32).
- G21 vs G31 modules are near-identical builds (many modules byte-equal sizes; minor diffs).
- Next: grep fwupdate/crypto/loadmgr for config-data verify path + com.intel.gsc handling.

## Session 5 — Config-data verify timing: FLASH/UPDATE time, by the fwupdate module

### Evidence (g21 == g31 builds, strings + descriptor tables in decoded modules)
1. fwupdate module (GSC-side update service behind com.intel.gsc HECI protocol) is the ONLY
   module in either die whose strings/tables mention OROM or GDTA:
   - '/dev/flash/bp1', '/dev/flash/bp2', '/dev/flash/region11', '/dev/flash/fitb'
   - 'OROM.man' (x2), 'GDTA.man', 'GDTA', 'VBT', 'CODE' tags
   - '/susram/GfxDtaUpdSts' — update-status variable written after config deploy
   - '/bin/0000.man', '/dev/ldr_ver_man', '/snowball/rbe.man', RBEP/PCOD/PHYP/OMSM.man
2. fwupdate contains a partition-descriptor table @0x7e44: RBEP, PCOD, PHYP, OMSM entries
   each with tag, slot#, and 5 sub-region IDs (0x100b-0x1014, 0x101a-0x101e) = BPDT-style
   bp1 layout; OROM.man and GDTA.man are separate named entries followed by '/snowball/FspInfo'.
   So the 64KB config blob is a bp1 flash partition (GDTA/OROM) deployed by fwupdate.
3. fwupdate parses $MN2 manifests in code (memcmp-style '$MN2' tag strings at ~0x6c44-0x7174,
   PCIR/55AA checks at 0x1fec) — i.e. signature/manifest verification happens in the update
   path, before writing flash. No 0x520/0x6dc/0x79c/0x77e immediates (offsets into the config
   blob) found in fwupdate code — verification is done via the .man manifest mechanism/crypto
   service, not by offset-poking the OROM blob directly.
4. BOOT path (rbe module = boot ROM / BP loader): manifest-name table @0x30f88 lists ONLY
   omsm_man/OMSM.man, pcod_man/PCOD.man, gscPhy_man/PHYP.man (+ rbe.man, oem_key_man/OEMP.man,
   oem_sign, intl.cfg/int_cfg_hsh, soc_cfg_lok, feature_map). PreOs_VerifyHash
   ('Hash Authentication failed', Expected/Calculated Hash) covers GSC's own code manifests.
   rbe NEVER references OROM.man/GDTA.man/GfxDta — no boot-time config re-verification.
5. mca_boot reads '/dev/cfg_files' + '/susram/GfxDtaUpdSts' = boot-time check of update
   STATUS only, not signature. storage just exposes /snowball/bpdt, cur_bp_inf. crypto
   exposes only key names (CSE/SVNx root keys). loadmgr verifies loaded code modules via
   ipub_key + oem_key_man (code, not config).
6. 'VerifierSK'/'VerifierIV' in sigma = Sigma security-controller session keys — unrelated.

### Implication for the B580->B60 24GB question
- The signature gate is at DEPLOY time: GSC fwupdate accepts a config blob only if its
  signature/manifest verifies (host igsc additionally checks before send). Once written to
  flash, no module re-verifies it at boot, so a tampered flash partition would boot.
  The hard gate is therefore the signing key + device-ID acceptance logic in the update path.
- Residual unknown: exactly which key verifies the OROM/GDTA manifest (same GSC code-signing
  RSA-3072 root vs a separate Intel config key, anchored via FPF/ipub_key in rbe), and what
  the 3x SHA-384 @0x6dc/0x730/0x79c in the blob hash (external bp1 regions or HMAC).

## Session 7 — key anchor resolved, GDTA path is structural-only, const@0x7f48 = service GUID

### VA-baseline correction (important for all future cross-ref work)
- Every Huffman module starts with the Intel x86-32 PIC bootstrap: endbr32; ...;
  `mov esi,<imm>; mov ebx,<imm2>; cmp ebx,<imm3>; ... cmp [ebx],'SSSS'` (SSSS-GOT scheme).
  Immediates encode VAs as **VA = 0xc0000000 + imm**.
- fwupdate base VA = **0xc0022000**: 15 exact refs (RBEP/PCOD/PHYP/OMSM .man string VAs
  0x29e05/1f/28/31, OROM.man 0x29ef0, VBT 0x29ef9, CODE 0x29efd, /snowball/FspInfo
  0x29f02/0x29f22/0x29f34, GDTA.man 0x29f14, GDTA 0x29f1d, const 0x29f48 → file offsets
  0x7e05..0x7f48, delta exactly 0x22000 every time).
- rbe base VA = **0xc0040000** (push 0x6d957 → 'PreOs_VerifyHash...' str@0x2d957;
  mov eax,0x6deb8 → 'ftpm_fuses'@0x2deb8; rbe uses plain absolute addressing, no GOT).
- Other bases (bootstrap `mov esi,imm`): pm 0xc003f000, gfx_srv 0xc0030000, loadmgr
  0xc003b000, fwupdate 0xc0022000*, heci 0xc004c000, crypto 0xc0056000, mca_srv 0xc006a000,
  sigma 0xc0075000, vfs 0xc0077000, mca_boot 0xc0086000, fsp 0xc0093000, storage 0xc0097000,
  maestro 0xc002a000, cpassist 0xc002d000, evtdisp 0xc002d000. (Bases overlap if all taken
  at face value — treat bootstrap imms as the module's own data/GOT segment anchor, and
  cross-module targets as call-gate VAs 0xc0001000-0xc0002000 / kernel data 0xc0041000+.)
- Negative rel32 call targets from fwupdate all land in a compact **call-gate/import page**
  region ~0xc0001000-0xc0002000 (0xc0001266 register-handler, 0xc0001421 flash write,
  0xc000166a/0xc0001661/0xc000166f log, 0xc0001770 service connect, 0xc00017b0/0xc0001784
  handle close, 0xc0001a00 read chunk, 0xc0001b62/0xc0001b67 memcpy/memset, 0xc0001a4b
  alloc, 0xc000196f...). Session-6 'device 0x29df1 ioctl' refs are these VAs, not devices.
- Tool: tools/session7_analysis.py (bases, call graph, ancestors/descendants, hash brute).

### Q1 — key-hash anchor: rbe, no constant in code (fuse/NVM-derived)
- rbe (boot module) keeps a **key-store name table** @rbe 0x2df60: epid_keys, ftpm_fuses,
  curr_keys, const_keys, prev_keys, rpmb_key, rpmc_keys, d_rpmc_keys, cse_gpk, gen_priv_k,
  rom_prk, LcWrapKey; then the fused-key name strings 'CSE Manifests Hash Key'@0x2dfc0,
  'CSE RBE Root Key'@0x2dfdc, 'CSME ODCA Integrity Key', 'CSE App Internal Key',
  'CSCP SVNx FW Root Key'. These are key-derivation NAMES resolved by the crypto service —
  i.e. manifest hash/MAC keys are **derived from eFuse/FPF key material on device**; there
  is NO expected-key-hash constant embedded in any module.
- The anchor data structure is **'/snowball/ipub_key'** (+'oem_key_man'/'OEMP.man'/
  'oem_sign'/'oem_smip'): fn@rbe 0x4511 looks it up (call 0xc0042d24 = name lookup),
  reads header byte [ptr+0x12] = slot count (≤7) + validity bitmask [ptr+0x13], then
  **memcpy 0x30 (48) bytes per slot** from [ptr+0x16+slot*4] into globals 0x606bb9c/
  0x606bc20 → the trusted store is a list of up to 8 **48-byte SHA-384 public-key hashes**.
- PreOs_VerifyHash (fn@rbe 0x42a8) builds a 0x3d0-byte descriptor, hashes (0x24/0x30-size
  fields) and **memcmps 0x30 bytes** against the expected value ('Expected Hash:'/
  'Calculated Hash:' strings) — the digest-chain verification of module manifests.
- loadmgr independently references '/snowball/ipub_key' + '/snowball/oem_key_man' for
  loaded-module verification. So the $MN2-embedded RSA-3072 key is trusted iff its
  SHA-384 is one of the ipub_key slots; ipub_key itself is authenticated by the
  fuse-anchored chain ('CSE Manifests Hash Key' etc.). No 384B modulus or 48B expected
  hash constant exists in any of the 20 modules (re-scan confirmed).

### Q2 — OROM/GDTA.man does NOT pass the $MN2+RSA path (deploy time)
- fwupdate update dispatcher fn@0x14d2 (HECI state machine, states 1-5) routes by
  partition type in [0x42230]: types 3/4 → buffered path → finalize calls fn@0x4321 →
  **$MN2 verify fn@0x3c84** (digest chain) → SHA/RSA-PSS via import (call fn@0x3382 →
  ioctl stub fn@0x7229). Types **18 (0x12) and 19 (0x13) = OROM.man/GDTA.man** take a
  per-0x1000-chunk flash-write path (fn@0x5b85, import 0xc0001421) with the LAST-chunk
  branch calling **fn@0x56f0** — which reads 'GDTA.man'/'GDTA'/'OROM.man' entries from
  flash (find-by-name fns 0x6ecb/0x6e34, reads via region ids 0x1047/0x1048, size caps
  0x46000, field compares vs [edi+0x358..0x360], FspInfo read 0x29f22/0x29f34) and calls
  only the **structural verifier fn@0x6f7d**.
- Call-graph proof (tools/session7_analysis.py): transitive callees of fn@0x56f0 contain
  NEITHER 0x3c84 (MN2 verify) NOR 0x7229 (RSA-PSS ioctl). GDTA.man and code manifests
  share only the dispatcher ancestors (0x14d2).
- Consequence: the 64KB config blob is written to flash with **structural checks only**;
  its internal RSA-3072 sig @0x520 and 3× SHA-384 are not evaluated by fwupdate code
  (no 0x520/0x6dc/0x730/0x79c/0x77e/0x782 immediates anywhere — re-confirmed). The RSA
  gate for config data is effectively the host-side igsc/tooling + the fact that the
  descriptor table @0x7e44 only ACCEPTS the named partitions; nothing in GSC re-verifies
  the blob contents after write (matches Session 5).

### Q3 — const @0x7f48 resolved: it is the fwupdate service registration GUID, not a hash
- fn@0x6814 (fwupdate init, VA 0xc0028814): `push 0x1c; push 0x29f48; push buf; call
  0xc0001b62` copies **28 bytes** = {16-byte GUID a5 0c d9 87 95 34 59 45 81 05 3f bf
  a3 7b 8b 79, u32 0x100c (bp1 FspInfo region id), 0, 0x010101} into a local struct.
- It then calls the kernel register-handler import 0xc0001266 three times with function
  pointers stored at [ebp-0x34/-0x30/-0x2c] = VAs 0x285e7/0x28540/0x28513 (file offsets
  0x65e7/0x6540/0x6513 — fwupdate code: handlers), then 0xc0001770 (service connect),
  storing the handle at kernel-shared data [0x41120]/[0x41128] (VA 0xc0041120, the
  kernel module table region — same region the SSSS bootstrap scans at 0xc00410ec).
- So the 16 bytes are an **identification GUID for the fwupdate/GFX-update service**
  (HECI-protocol-style GUID 870d0ca5-3495-4559-8105-3fbfa37b8b79 in mixed-endian form),
  not an expected digest or key hash. Identical in g31 (same file offset 0x7f48, same
  push at 0x682a). 'CSE Manifests Hash Key' is unrelated to it (Q1).

### Q4 — config blob 3× SHA-384: no plaintext region matches; per-entry, per-build
- The 0x6c0-0x7cc region of the 64KB blob is a **tagged entry table**: entry1 tag 'VBT'
  @0x6c8 (+0, 0x302, 0x48) + hash @0x6dc; entry2 (0x16, 0x68, tag 'OROM', 0x50,
  **0x100000** = 1MB, 0, 1, 0, 0x3303) + hash @0x730; entry3 device block (type 0x25,
  IDs 0x8086:0xE20B / 0x8086:0x1100, 0xa, 0x48, ...) + hash @0x79c; ff-padding to 0x800.
- Brute force (tools/session7_analysis.py): sha384/sha256/sha512-truncated over every
  0x40-aligned [a,b) window of the blob, targeted unaligned starts/ends, zeroed-crypto
  variants, whole/sliced bmg_OpromCode.bin (incl. 0x7c00/0x10000/0x18000/0x20000 tails),
  HMAC-SHA384/256 with keys {'CSE Manifests Hash Key','CSE RBE Root Key','CSCP SVNx FW
  Root Key', the 16B GUID}: **zero matches**.
- The OROM entry's 0x100000 size field exceeds the blob ⇒ the hashes describe the
  **deployed flash sub-partitions** (1MB OpROM/VBT/GDTA regions of bp1), computed by the
  signing tool at build time over content not shipped inside the 64KB blob. All 6 config
  variants (normal+recovery × E20B/E212/E223) have 3 distinct hashes → build-specific.
  Verdict: treat them as deploy-time cross-checks of bp1 region content (or HMAC with a
  non-obvious key); they are NOT verified by GSC boot or fwupdate (Q2/Q5).

### Q5 — boot-time consumers of GDTA/OROM: none verify, only status is read
- Exhaustive string scan of all 40 decoded modules (g21+g31): 'GDTA'/'OROM.man'/'GDTA.man'
  appear ONLY in fwupdate. Boot path: rbe manifest-name table lists only
  omsm/pcod/phyp/rbe/oem_key_man/intl.cfg/soc_cfg_lok/feature_map — no OROM/GDTA.
- mca_boot references '/dev/cfg_files' + '/susram/GfxDtaUpdSts' (update STATUS var only);
  vfs maintains the NVM var 'GfxDtaUpdSts' and 'GscBootData' entries; kernel only names
  the 'GfxSrvMainThread'; gfx_srv has zero GDTA references.
- Conclusion: no GSC boot-time code reads or verifies the flash GDTA/OROM partitions;
  the deployed blob is consumed by the host (BIOS/OpROM) and by FSP/pcode, outside GSC.
  Combined with Q2: **config-data integrity enforcement is entirely host-side (igsc)
  plus the accept-or-reject of the partition identity at deploy time.**

### Updated overall verdict for the B580→B60 memory question
- The signed 64KB config blob is accepted by GSC fwupdate with structural-only checks
  (correct 55AA/PCIR/manifest-shape via 0x6f7d, region/size consistency), written to
  flash, and never re-verified. Crypto enforcement of config-data lives in the host
  tooling chain (igsc/LVFS jcat), not in GSC firmware. The GSC-side hard gates (RSA-PSS
  anchored to ipub_key/fuse-derived keys) protect CODE manifests (RBEP/PCOD/PHYP/OMSM)
  only.

## Session 8 — runtime config-data consumers (gfx_srv, fsp, kernel, pm, mca_srv)

### VA-mapping correction (supersedes session 7 per-module base table)
- ALL Huffman-decoded modules link at the SAME link-time VA: string xrefs resolve with
  delta = 0x22000 uniformly (gfx_srv 32/34 strings, pm 7/7, mca_srv 7/7, fsp clean subset).
  The module images are position-fixed at link time (base 0xc0022000) and relocated at
  load by the SSSS-GOT bootstrap. **VA = 0xc0000000 + 0x22000 + file_off for every module.**
  Session-7 "module bases" (bootstrap `mov esi,imm` 0x30000/0x93000/...) are per-module
  DATA-segment anchors, not load bases. Rule for future work: one delta, all modules.

### Method
- tools/session8_sweep.py (linear disasm, string xrefs, target-immediate scan) and
  tools/session8_xref.py (brute-force dword xref map + context disasm). Capstone 5.0.7.

### gfx_srv (24KB, thin service shim — NOT a config consumer)
- Full string-xref inventory (34 strings): devices /dev/events, /dev/maestro,
  /dev/fwu, /dev/fsp_gfx, /dev/ndl_critical, /dev/flash/{region12,utok,flog,descr},
  /dev/nvm_handoff, /susram/{chassis_inf,fsp_info,errrstcnt,cse2sv_info,svimgboot,buperror},
  /snowball/{FspInfo,rbe.man,bpdt,rbe_sku,cur_bp_inf,uniquepid}, /rpfs/time_data,
  'LTES.man','LTEB','ELG Token 1.0','/bin/%s.man','/dev/ldr_ver_man'.
- ZERO references to GfxDta/GscBootData/cfg_files/GDTA/OROM/VBT (confirms + extends session 7).
- No PCI-ID immediates 0xE20B/0xE212/0xE223/0x1114 anywhere in the module (word scan: none);
  the 8-byte-stride word-compare loop @0xc0024a60-0xc0024a7f matches entries of a
  PASSED-IN table (bpdt/partition entries), not hardcoded device IDs.
- '/dev/flash/region12' fn@0xc00239fc: opens region12, reads ONE 0x1000 page, checks
  byte[0]==0/1 — a status/flag page, not geometry. '/dev/fsp_gfx' fn@0xc0026bf4 opens a
  channel to FSP (used by the mailbox fn@0xc0026153, 12 call sites, req codes 0x2001007+).
- 'ELG Token 1.0' fn@0xc002638c: mailbox token exchange with FSP (codes 0x2001007-0x200100a),
  + 0xc000141c crypto op — gfx_srv<->FSP session/token handshake.
- Verdict: gfx_srv = status/token/mailbox shim between FSP, fwupdate and NVM status vars.

### fsp (122KB — the memory/PHY-side module; consumes TRAINING data, not config-data)
- Strings are sparse: '/dev/events', '/susram/fsp_info' (x2 in code + x4 ptr in a data
  table @0x1a07c of {ptr} entries), '/snowball/uniquepid', '/snowball/mrc_data',
  '/snowball/mrc_bdat', '/bin/%s.man'. NO GDTA/OROM/VBT/cfg_files/device-IDs.
- fn@0xc0023674 (single caller @0xc0022717): loads BOTH NVM vars via helper fn@0xc00235b0 —
  '/snowball/mrc_data' -> GSC SRAM 0x10031000 and '/snowball/mrc_bdat' -> SRAM 0x10007000,
  0x7f80 (32640 B) each, with stack-canary prologue. mrc_* = Memory-Reference-Code
  (DDR training) data cached across boots; rbe + vfs also reference mrc_data/mrc_bdat
  (save path). => memory init input = SAVED TRAINING RESULTS, not config bytes.
- Data table @0x1a0e6-0x1a2a0: {SRAM addr, value} register-descriptor pairs over the
  0x0010_0000-0x0010_07xx window (PHY/Memory controller register map) + byte-pattern
  arrays (03 03 03 03 08 03 06 03...) consistent with training patterns.
- The apparent "entry-table" immediates (push 0x6c0 x5, lea [esi+0x520], [ebx+0x730])
  are memcpy SIZES and struct offsets in unrelated functions (e.g. fn@0xc0039de9 memcpy
  0x6c0/0x759-byte blobs into fsp data areas) — FALSE POSITIVES, not config offsets.
- Verdict: fsp = memory-init/training-data consumer (MRC cache in NVM via /snowball),
  geometry comes from training/self-measurement, staged into SRAM for the PHY.

### kernel / pm / mca_srv sweep
- kernel: only thread-name table (FspMainThre, GfxSrvMainT, SigmaMainTh, CpAssistMai,
  McaSrvMainT, McaBootMain, FwupdateApp, FPFMainThre, MaestroMain, StorageMain,
  CryptoMainT, LoaderMainT, EvtDispMain, VFSMainThre, PMMainThrea) + 'CSCP Data IPK',
  'DUMP_DATA_BEGIN'. No config/memory-geometry references. Zero target immediates.
- pm (12KB): '/snowball/{bootpath,boottype,feature_map}', '/bin/%s', process-spawn log —
  process manager only. No config references.
- mca_srv: '/dev/fpf', '/susram/sense_cntr', '/snowball/{bs_arb_inf,rbe_arb_inf}',
  '/dev/{events,maestro,storage_rpmc}' — arbitration/monitoring. No config references.
- cpassist holds '/susram/GscBootData' + '/snowball/{gsc,huc}_arb_inf' + a 16-byte GUID +
  'Remote Storage Verifier' — GscBootData is a susram handoff var for the CP-assist
  (remote-storage verifier) service, NOT the config blob.

### Answer to the key question
- NO on-die GSC code derives memory size from config-data CONTENT. Exhaustive checks:
  (a) no GDTA/OROM/VBT/GfxDta/cfg_files strings outside fwupdate (both g21 and g31);
  (b) no PCI-ID immediates 0xE20B/0xE212/0xE223 in any decoded module;
  (c) no config-blob offset immediates (0x520/0x6c0-0x7cc hits were memcpy sizes/struct
  offsets — false positives verified by disasm);
  (d) gfx_srv/fsp/kernel/pm/mca_srv never open /dev/flash regions pointing at the
  GDTA/OROM partitions (gfx_srv region12 = status flag page only).
- What config-data influences at runtime: IDENTITY + DISPLAY ONLY — it is written to
  bp1 flash (deploy-time, structural checks only) and consumed by the HOST (OpROM/VBT
  via BIOS; device-ID 8086:E20B/1100 vs E212/1114 in the device block @0x778-0x790).
- Memory geometry source: FSP memory init uses /snowball/mrc_data + mrc_bdat — results
  of memory TRAINING cached in NVM (self-measuring path), staged to SRAM
  0x10007000/0x10031000. The 12GB-vs-24GB firmware-visible difference remains only the
  signed device-ID/manifest identity in the config blob; the actual size is determined
  by the memory training/strap path, not by parsing config content.

## Session 9 — fsp memory-training path + G21/G31 density question (32Gbit)

### Method
- tools/session9_fsp.py (binary diff g21↔g31, strings, density-constant scan),
  tools/session9_disasm.py (callgraph, function disasm, dword table dump, strings),
  tools/session9_xref.py (immediate scan + VA xref w/ function-start heuristic).
- Artifacts: notes/s9_callgraph.txt, s9_fsp_strings.txt, s9_imms.txt,
  s9_xref_tbl1.txt, s9_tbl_1a400.txt, s9_tbl_1b600.txt, s9_fn_c0022400.txt.

### Q3 ANSWER — fsp is byte-identical between G21 and G31 except ONE data table
- cmp -l g21/fsp vs g31/fsp: 1237 differing bytes, ALL inside a single region
  0x1bde0-0x1c2b4. That region is a (message-id, event-type) pair table where every
  g31 id = g21 id + 0x10 (0x160→0x170, 0x15e→0x16e, ... 0x2b4→0x2b4+): the G31 build
  has 16 extra message-id slots, shifting ids. ZERO code bytes differ.
- Consequence: the memory-training/PHY code cannot contain a die-specific density
  cap — the same trainer runs on the die that ships 12GB/24GB (G21) and the one that
  ships 32GB (G31, B70).
- rbe (boot loader) differs massively (131015/229376 B) — different build/config —
  but rbe is not the trainer (per sessions 5/8 it only saves mrc_data/mrc_bdat).

### Q1 — training/init flow in fsp
- fn@0xc0023674 (single call site @0xc0022717, inside fn@0xc00226de): fn@0xc00226de
  takes 2 args (-> globals 0x952d4/0x952fc), calls check fn@0xc002260c, logs event
  0x290012 (level 1) if the check returns nonzero, then unconditionally calls
  fn@0xc0023674 which stages BOTH NVM blobs: '/snowball/mrc_data' (str@0xc003c2ab)
  0x7f80 B -> SRAM 0x10031000, '/snowball/mrc_bdat' (str@0xc003c2be) 0x7f80 B ->
  SRAM 0x10007000, via helper fn@0xc00235b0 (only 2 call sites = these two).
- fsp contains real MMIO-level memory-controller init code: read-modify-write helper
  fn@0xc002516a (reg,4,mask,value), write helper fn@0xc00255e2, e.g. writes to regs
  0x8828 (mask 0xfffbffff), 0x8800 (size field: 64-bit value shrd 0x11 / shl 0xe —
  memory size programmed dynamically, NOT a hardcoded constant), 0x4910, 0xa180/0xa194
  (values 0x80200000, 0x800001a0), a global page 0x952xx-0x954xx.
- Two PHY register-descriptor tables: 0x1a0e6-0x1a2a0 (session 8) and 0x1a400+ of
  5-dword records {mask, 0x0010_xxxx PHY reg, mode, data, ...} incl. PAIRED ALTERNATIVE
  records for the same reg (e.g. reg 0x010000d0 with 0x00200000 vs 0x00400000 at
  0x1a414/0x1a418, reg 0x0100001c with 0x00200000 vs 0x00400000, reg 0x01000064 same
  pair) — runtime-selectable options, BOTH present in both dies.
- Event/message-ID system: ids 0x1426-0x142d+ logged via fn@0xc0030350/0xc00302f1;
  the message-id table at 0x1bde0 is the ONLY g21/g31 delta.

### Q2 — density logic
- NO 0x40000000/0x80000000 "per-channel size" constants used as sizes in code; the
  0x800000 (8MB) immediates at 0xc002260f/0xc003064d/0xc00311fc are SRAM buffer
  allocation sizes. Channel/rank/density values are not found as a hardcoded
  (density,rank,speed) lookup; memory size is computed at runtime (shrd/shl into
  reg 0x8800) and/or comes from the staged mrc_data training blob.
- Size/bit-pattern tables at 0x1b600+ (after a 0x89398f2e... checksum-ish header):
  stride tables (0x5069/0xc0a1/0x130d9/0x1a111/0x21149/0x28001 duplicated), flag
  words, address-progressions 0x3db00-0x3d8c0 — training-pattern descriptors.
- GDDR MR programming not seen as distinct MR0-MR6 immediates in fsp code — PHY
  register writes go through the descriptor tables (reg window 0x0010_xxxx).

### Q4 — caps / error paths
- fsp strings: only 85 fragments, ALL data garbage or {STDIO, /dev/events,
  /susram/fsp_info, /snowball/uniquepid, /snowball/mrc_data, /snowball/mrc_bdat,
  /bin/%s.man}. NO 'training failed'/'unsupported'/'dimm'/'density'/'size mismatch'
  strings, no device-ID immediates (0xE20B/E212/E223 — confirmed again), no
  rejection-cap comparison in code immediates >=0x400000 (all are alloc sizes,
  register addresses, event ids).

### Q5 VERDICT
- fsp training code is IDENTICAL on the 32GB-shipping die (G31) and the 12/24GB die
  (G21) -> no fsp-side 16Gbit cap; larger-density support cannot be absent from G21
  fsp while present in G31 fsp. 32Gbit-per-chip training on G21 is PLAUSIBLE at the
  GSC-fsp level (paths exist, no cap found). Residual unknowns: (a) the actual MRC
  training engine may be the SRAM-staged mrc_data blob itself (contents not in our
  images' code), (b) PCOD/pcode side not examined, (c) real-world gates remain the
  signed config blob (deploy-time), board straps/wiring, and BIOS/VBT — not fsp code.",
