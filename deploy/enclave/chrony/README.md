# chrony in the reader enclave

The attested reader sets and keeps its clock with `chronyd`. Its only time
source is the Nitro Secure Module, which `nsm-timefeed`
(`deploy/enclave/nsm-attest`) feeds to chronyd's SOCK reference clock. The
design, the caps and the states are in `docs/mcp-enclave.md` (Clock).

## Files

| File | In the image | What it is |
|---|---|---|
| `chrony-4.9.tar.gz` | built into `/usr/sbin/chronyd` | the upstream release, unmodified |
| `chrony-4.9.tar.gz.sha256` | checked by the build | its sha256 |
| `common.conf`, `boot.conf`, `run.conf` | `/etc/chrony/`, mode 0444 | the configuration |
| `wappie-clock-start` | `/usr/local/sbin/`, mode 0555 | starts chronyd and nsm-timefeed; `entrypoint.sh` calls it |
| `test-chrony.sh` | no | runs the image's chronyd against a fake NSM (`make chrony-check`, CI) |
| `README.md` | no | this file |

The files that reach the image are measured into PCR0, and
`scripts/check-reader-inputs.sh` lists each of them.

## The source

- Release: chrony 4.9, from <https://chrony-project.org/releases/chrony-4.9.tar.gz>
- sha256: `4924c6f530105bcd5b9e9e33c48a2ae1bfd889222c8480bc41601110efc864d0`
- Checked on 2026-11-19 against the upstream signature,
  `chrony-4.9-tar-gz-asc.txt`: a good signature by Miroslav Lichvar, the
  chrony maintainer, key `8F37 5C7E 8D0E E125 A3D3 BD51 537E 2B76 F768 0DAC`
  (fetched from keys.openpgp.org). Alpine's `main/chrony` package of 4.9
  names the same file with the same sha512.

The tarball is vendored, not downloaded at build time, so the build makes no
network fetch for it. The build (`deploy/enclave/Dockerfile`, stage `chrony`)
checks the sha256, configures chronyd with every optional feature named and
turned off, fixes the NTP era (whose default is the build date, which would
make every build a different binary), links it statically, and builds
`chronyd` alone: no `chronyc`.
`check-image.sh` compares the exact version and feature list that
`chronyd -v` prints. `build.sh` records the tarball's name, version and
sha256 in `measurements.json`, under `dependencies.sources`.

chrony 4.9 has no configure option to leave NTP out. `port 0`, `cmdport 0`
and the absence of any server, pool or peer keep chronyd from opening a
network socket.

To move to a new release: download the tarball and its signature, verify the
signature against the key above, replace the tarball and the `.sha256` file,
change the version in the Dockerfile's `chrony` stage, in `check-image.sh`
and in `scripts/check-reader-inputs.sh`, and run `make enclave-image` and
`make chrony-check`. `deploy/enclave/test_build.py` fails while those disagree.
This changes PCR0, so it needs a reader release.

## Licences and source for GPL programs in the image

chrony is free software under the GNU General Public License, version 2
(`COPYING` in the tarball). The tarball here, with the build steps in the
Dockerfile's `chrony` stage, is the complete corresponding source of the
`chronyd` in each reader image built from this repository. It is published
with the source commit each reader release names.

Other GPL-2 programs in the image come as Alpine binary packages:
- `socat` and `iproute2`, installed by the Dockerfile's `rootfs` stage;
- `busybox`, part of the Node base image.

The exact package versions are those in the image's `/lib/apk/db/installed`.
Their source is Alpine's `aports` repository at those versions together with
the upstream tarballs it names.
