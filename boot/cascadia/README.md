# ARM32 iBEC staging payload (Cascadia loader)

What starts Linux on Apple's 32-bit boards in place of m1n1: a patched iBEC
loads one file at the board's `load_address` and jumps to it. The file is
this loader, the board's zImage with its DTB appended, and an initramfs.

`build --profile devices/BOARD/cascadia.toml --output DIR` builds the loader
with Orchard's kernel toolchain through `buildenv` (orchard does this in
`orchard build`, see `build.prepare_payload_loader`). The output directory
contains `loader.bin`, its ELF and a source/profile/toolchain receipt. The
ELF check requires executable ARM code at the upload address and checks
every allocated section against the raw bytes. ARM unwind tables are
discarded so they cannot displace the entry instruction.

`src/orchard/image/cascadia.py` assembles one board's payload (also by file
path: `--profile --loader [--loader-elf] --kernel --dtb --initramfs
--output`). Kernel bytes stay unchanged. The DTB's `/chosen`
`linux,initrd-start`/`-end`, placeholders in the board's tree, are set in
place to the initramfs copy; nothing else in the tree changes, its boot
arguments included.

The layout is a checked loader followed by padding to 32 KiB, the zImage,
the DTB and the initramfs, each data address aligned to eight bytes. The
loader disables the profile's watchdog, then checks its configuration
checksum and bounds; a rejected image stays stopped for inspection. It
copies the initramfs to the profile's `initrd_address` while iBEC's MMU and
caches are still on, then cleans the caches, turns the MMU off and enters
the zImage with the DTB in `r2`. This is the form Project Cascadia's own
P105 boot used (`linux_boot.c` `copy_overlay`, `assemble.py`
`OVERLAY_PHYS = 0x88000000`). The fixed loader stack uses the gap below
offset `0x7000`; code must finish below `0x6000`, and the configuration
starts at `0x7f00`.

The zImage must carry the v6.12 ARM size table and end on an eight-byte
boundary. Its DTB follows immediately so the appended-DTB decompressor
(`CONFIG_ARM_APPENDED_DTB`) can relocate it. Assembly bounds the inflated
kernel together with the relocated decompressor's workspace below the
initramfs destination; unknown table formats and overlapping layouts are
refused. The receipt describes every byte range and its hash.

Upstream Cascadia also built its runtime into the kernel
(`CONFIG_INITRAMFS_SOURCE`) and copied only machine-local files this way.
orchard copies its whole initrd plus the boot's add-on
(`src/orchard/install_direct.py`), which works with either kernel: with an
initrd built into the kernel, the copy is unpacked over it.

## P105 hardware record

An iPad mini 1 (P105) ran the loader in this directory and reached the
Omarchy-A desktop using a root filesystem served over USB NFS. Using the
board identity recorded for that session, the image preparation in
`orchard run` reproduced all 12,132,755 bytes of the payload that booted.

That session used a separate launcher for the handoff from iOS. On the
Mac, `orchard run` hands the finished image to `orchard-launcher`. A
hardware test of that interface on P105 is still pending.

See `NOTICE` for the loader's source and credits.
