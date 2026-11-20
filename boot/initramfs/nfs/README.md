# NFS RAM startup

This experimental bring-up runtime starts a systemd root over a dedicated USB
link. It begins when the platform loader starts Linux. The board check uses
the selected descriptor's `dt_compatible`.
It owns configfs USB, the network link, root validation and the PID 1 handoff.
The distro prepares the root filesystem and decides which desktop to start.
Host software supplies the interface and NFS export.

The kernel needs configfs, a USB device controller and built-in support for
ACM and the selected network function (ECM or NCM). AArch64 devices use
NFSv4.0, either built in or supplied as modules from the same kernel build.
The iPad mini 1 (P105) uses the NFSv3 client built into Orchard's ARMv7 kernel.
The exported root needs the matching `/usr/lib/modules/<release>` tree.

The AArch64 runtime has booted on an iPhone 6 (N61). P105 reached the
Omarchy desktop using an earlier version of the ARMv7 runtime. A physical
test of this revision is pending. Use a trusted USB host and writable export.

## Root identity and staging

Prepare the distro root on a filesystem that preserves Linux file
names, numeric ownership and modes. Copy the exact built kernel module tree
into `/usr/lib/modules/<kernel_release>`. Leave `/dev`, `/proc`, `/sys` and
`/run` as real directories. The root's regular, root-owned
`/etc/orchard/nfs-root.json` contains exactly:

```json
{
  "schema": 1,
  "kind": "orchard.nfs-root",
  "profile": "<device-profile>",
  "architecture": "aarch64",
  "kernel_release": "<matching-kernel-release>",
  "root_id": "06106106-1061-4061-8061-061061061061",
  "image_sha256": "<64 lowercase hex digits from the public image archive>",
  "image_receipt_sha256": "<64 lowercase hex digits from its public receipt>"
}
```

Mint a fresh canonical UUID for each private root. The image digests record
the distro inputs; they do not authenticate the exported filesystem. The RAM
builder embeds the SHA-256 of these exact JSON bytes, so host and runtime agree
without a JSON interpreter in RAM.
The running kernel release and device-tree compatible must also match. The
runtime inspects the systemd ELF header before executing the new root.
The trusted host controls the writable export after this check.

```sh
python -m orchard.image.nfs \
  --receipt /path/to/root/etc/orchard/nfs-root.json \
  --busybox /path/to/static-aarch64-busybox \
  --kernel-dir /path/to/staged-kernel \
  --output /path/to/new-ram-root \
  --server 10.61.0.1 --address 10.61.0.2/30 \
  --export /orchard-root --port 32061 --function ecm --handoff manual \
  > /path/to/nfs-runtime-receipt.json
```

For P105, set `profile` to `p105` and `architecture` to `armv7l` in the
root receipt. Supply a static ARM EABI5 hard-float BusyBox and pass the
staged P105 kernel directory. Staging checks its built-in NFSv3 client.
If the directory contains `kernel.notes.sha256`, the RAM runtime checks
the running kernel against that digest before starting systemd.

Staging writes `init`, `orchard.local.toml` and a `rootfs` overlay to a
fresh directory. The P105 build uses the same BusyBox and kernel along with
the board's Cascadia loader.

```sh
bin/orchard build --device p105 --kernel-dir /path/to/staged-kernel \
  --busybox /path/to/static-armhf-busybox --loader /path/to/cascadia-p105.bin \
  /path/to/new-ram-root
```

The P105 project requests board firmware in RAM so the built-in graphics
driver can find it during probe. The image builder produces `linux.bin`.
Starting that image on a physical P105 still requires a separate platform
launcher. Keep the RAM image and staging receipt private because they
identify a writable root.

For AArch64, staging copies the NFSv4 modules and their dependencies from
the supplied kernel. If the kernel has built-in NFSv4, omit `--kernel-dir`
when staging. ECM is the default network function. The receipt records the
MAC addresses derived from the selected IPv4 addresses.

Use the pinned hardware BusyBox recipe, which supplies `awk`, `mount`, `stat`,
`sha256sum`, `od`, `timeout`, `setsid`, `modprobe` and `switch_root`. Mount tracking reads
`/proc/self/mountinfo` with `awk`, including while `/proc` lives under
`/newroot`; the pinned BusyBox omits the `mountpoint` applet. Failure recovery
tracks the retired rescue process explicitly so its replacement starts even
while the old PID still exists.

The example link uses host `10.61.0.1`, device `10.61.0.2/30` and NFS TCP port
`32061`. A dedicated userspace NFS server can expose a Linux volume at an
NFSv4 pseudo path, with `sec=sys`, writable access, numeric IDs and
root ownership preserved. NFSv4.0 uses a single TCP port. For P105, make
rpcbind and TCP mountd reachable over the USB link. Set `--export` to the
path served by mountd and `--port` to the NFS data port (usually 2049).
The NFSv3 client keeps file locks local, so give it a single-client export.
Before arming handoff, verify through the NFS client that the root metadata
and systemd retain UID/GID `0:0`; NFSv4 owner mapping must preserve those IDs.

## Handoff and rescue

The default `--handoff manual` leaves the physical ACM shell running after
configuring USB. This shell is unauthenticated and grants root access to the
connected host, so use it only with a trusted host. Create
`/run/orchard/nfs-handoff` through that shell when the
host interface and export are ready. `--handoff auto` arms that request during
startup. PID 1 attempts the mount once with a 60-second initial timeout and
refuses a mismatched root. Network failure can still stall later I/O to a hard
NFS mount; the physical rescue tools remain in RAM.

After validation, PID 1 moves `/dev`, `/proc`, `/sys` and `/run` into the new
root and calls BusyBox `switch_root`. The new PID 1 starts systemd and the RAM
shell is retired. Configure authenticated access, such as key-only SSH, in the
NFS root before handoff. Keep P105 internal flash out of the root's mount and
swap configuration. Before starting systemd, the runtime rejects mounted
internal partitions, sets the exposed block devices read-only and tells
udisks to ignore them. For experiments that need the RAM shell afterward, pass
`--keep-rescue` during staging. That opt-in starts a transient
`orchard-acm-rescue.service` under `/run/systemd/system`, using the copied static
BusyBox and shell from `/run/orchard/rescue`. The opt-in shell remains
unauthenticated and grants root to the connected USB host. A runtime NetworkManager
configuration keeps `usb0` unmanaged so desktop services preserve the NFS
transport. Configfs keeps ownership of the existing composite gadget.

The experimental USB PID is `05ac:4144`. Its descriptor publishes `PROFILE`,
the selected `ROOT` UUID and the live kernel `BOOT` UUID. This minimal runtime
does not read ECID from the ADT; it does not qualify as the installed recovery
protocol. The boot operator must retain the verified target's physical USB
location when selecting its ACM port.

Before this path can present itself as normal Orchard recovery, adapt the
protected identity flow for each supported device: read and validate its live ADT, publish the
ECID and current boot UUID through the verified serial connection, and retain
that identity across the NFS handoff. Provision the host's public key through
that connection and pin the boot-scoped SSH host key received there. Recheck
the identity after handoff and exercise access retirement and failure recovery.
Until those checks pass, this remains a bring-up runtime.
