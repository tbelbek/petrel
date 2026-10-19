# Releasing Petrel

Petrel ships as **a paired firmware + Flipper app**. A release is identified by one version that both
sides carry, so a user can tell at a glance whether their board firmware and their FAP match.

## Version pairing

| Component | Where the version lives | Format |
|-----------|-------------------------|--------|
| Companion firmware | `RTL8720dn-firmware/RTL8720dn-firmware.ino` — `#define PETREL_FW_VERSION` | `MAJOR.MINOR.PATCH` (e.g. `1.0.0`) |
| Flipper app (FAP) | `flipper-app/application.fam` — `fap_version` | `MAJOR.MINOR` (e.g. `1.0`) |
| Git tag / GitHub release | `vMAJOR.MINOR.PATCH` (e.g. `v1.0.0`) | matches the firmware version |

The firmware reports its version to the FAP over UART (`IDENT: ... fw=<PETREL_FW_VERSION> ...`). The FAP
and firmware **major.minor must match**; a patch-level firmware bump that keeps the protocol stable does
not require a new FAP. When they diverge, re-pair before tagging.

## Cutting a release

1. Bump `PETREL_FW_VERSION` and `fap_version` together so their major.minor agree.
2. Build both and confirm clean:
   - firmware: `firmware-build/build_petrel.sh <sketch> <out> <arduino15>` → `km0_km4_image2.bin`
   - FAP: `cd flipper-app && ufbt`
3. Update `docs/CAPABILITIES.md` if capabilities changed; fill any newly-verified coverage rows.
4. Tag `vX.Y.Z` on the public repo and attach the built `km0_km4_image2.bin` (so users can flash without
   building — see `flasher/`).

## Public repo is a clean-history mirror

The development repository carries the full history (and its upstream delfyRTL lineage). The public repo
**`github.com/tbelbek/petrel`** was started from a single squashed "initial public release" commit with a
neutral author identity, and real-brand captive portals are kept out of it (private overlay only).

Therefore public updates are **not** a `git push` of the dev branch (the histories are unrelated). To
publish an update: clone the public repo, apply the change, commit with the neutral author identity,
push, then tag. Keep the dev repo as the source of truth.
