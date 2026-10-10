# Intel Arc Battlemage Firmware Research — The Short Version

*Plain-language summary of [PAPER.md](PAPER.md). Same findings, no reverse-engineering depth.*

---

## What we asked

Can you take an Intel Arc **B580** (12 GB) and turn it into its twin, the **B60** (24 GB)?
Both use the same silicon (the BMG-G21 die). The only firmware-visible difference was a
single 64 KB "config-data" file. The gate question: **who checks that file's signature,
and when?**

## What we did

Pulled Intel's public firmware update package, then unpacked the GSC firmware chip
image — the small embedded computer on the card that manages updates, security and
memory training. Every one of its 20 internal modules was successfully decompressed
and analyzed. This is (to our knowledge) the first public full unpack of Battlemage GSC.

## What we found

### 1. The B580 vs B60 difference is tiny — and not about memory

Diffing the B580 and B60 config files: **538 bytes out of 65,536 differ**, and they are
exactly:

- one RSA signature,
- three SHA-384 hashes,
- a **device-ID byte** (this is what makes the card "a B580"),
- a revision byte,
- a few display-config bytes.

**No memory size, timing, or geometry tables anywhere in the file.**

### 2. Nobody checks the signature — after install

This is the headline result. Tracing the update and boot code:

- During a firmware **update**, the card's `fwupdate` module writes the config file to
  flash with **only structural sanity checks** (right shape, right sections). The
  crypto check happens in the *host PC tooling* before the update is sent — not on the
  card.
- At **every boot afterwards**, no firmware code reads or re-verifies the config file.
  The boot ROM's checklist of things to verify doesn't include it at all.

So: the signature is a **one-time gate at install**, enforced by Intel's PC-side
software — not an on-card security check.

### 3. No artificial "density cap" in the firmware

The memory-training code is **byte-identical** between the die that ships 12/24 GB and
the die that ships 32 GB (B70). There is no code path saying "stop at 16 Gbit per
chip". Memory size is measured at boot from training results, not read from a config
table.

### 4. The real security, for comparison

The GSC *does* have a strong signature chain — RSA-3072 with keys anchored to fuses
on the chip — but it protects only **code** (the firmware's own modules). Config-data
simply isn't in that chain.

## What it means

- A modified config file *flashed directly to the card's SPI flash* would boot — no
  firmware check stops it. But a *valid* B60 config differs only by device ID +
  signature, and producing a signature for modified content means having Intel's
  private signing key.
- The firmware-level difference between 12 GB and 24 GB is essentially a **label**.
  The real limits are: the signing key at install time, board wiring, and the BIOS.
- We found no firmware barrier (no "cap") that would prevent the training engine from
  handling larger memory chips.

## What's still unknown

Why our standalone RSA-PSS verification of the code manifests fails, what exactly the
three SHA-384 hashes in the config cover, what's inside the memory-training data blob,
and whether Intel's PC-side installer checks the device ID.

## Read the full paper

All evidence — offsets, function addresses, call graphs, diff tables — is in
[PAPER.md](PAPER.md). Everything is reproducible from the public firmware package with
the scripts in [`tools/`](../tools/).
