#!/usr/bin/env python3
"""Prepare a BusyBox-only RAM runtime bound to one NFS root receipt."""
import argparse
import hashlib
import ipaddress
import json
from pathlib import Path, PurePosixPath
import re
import shlex
import shutil
import struct
import uuid

from ..hardware import ROOT, chip_architecture, device
from . import elf

HERE = ROOT / 'boot/initramfs/nfs'
FIELDS = {'schema', 'kind', 'profile', 'architecture', 'kernel_release', 'root_id',
          'image_sha256', 'image_receipt_sha256'}
SCRIPTS = {'init': 'init', 'usb-gadget': 'sbin/orchard-nfs-usb',
           'handoff': 'sbin/orchard-nfs-handoff', 'validate-root': 'sbin/orchard-nfs-validate',
           'acm-rescue': 'sbin/orchard-acm-rescue'}


def unique_object(pairs):
    result = {}
    for name, value in pairs:
        if name in result:
            raise ValueError('Duplicate root identity field: ' + name)
        result[name] = value
    return result


def identity(blob):
    if len(blob) > 16384:
        raise ValueError('Root identity is too large')
    value = json.loads(blob, object_pairs_hook=unique_object)
    if not isinstance(value, dict) or set(value) != FIELDS:
        raise ValueError('Unexpected root identity fields')
    if type(value['schema']) is not int or value['schema'] != 1 or value['kind'] != 'orchard.nfs-root':
        raise ValueError('Unsupported NFS root identity')
    architecture = value['architecture']
    if architecture not in ('aarch64', 'armv7l'):
        raise ValueError('Unsupported NFS root architecture')
    for key in ('image_sha256', 'image_receipt_sha256'):
        if not isinstance(value[key], str) or not re.fullmatch('[0-9a-f]{64}', value[key]):
            raise ValueError('Invalid root digest: ' + key)
    root_id = value['root_id']
    if not isinstance(root_id, str) or str(uuid.UUID(root_id)) != root_id:
        raise ValueError('Root ID must be a canonical UUID')
    release = value['kernel_release']
    if not isinstance(release, str) or not re.fullmatch('[A-Za-z0-9][A-Za-z0-9._+-]{0,127}', release):
        raise ValueError('Invalid kernel release')
    description = device(value['profile'])
    expected = 'armv7l' if chip_architecture(description) == 'arm' else 'aarch64'
    if architecture != expected:
        raise ValueError('NFS root architecture differs from the device profile')
    if architecture == 'armv7l' and value['profile'] != 'p105':
        raise ValueError('ARMv7 NFS startup currently requires P105')
    compatible = description['device']['dt_compatible']
    if (not compatible or any(not re.fullmatch('[a-z0-9,._+-]+', item) for item in compatible)):
        raise ValueError('Invalid profile device-tree identity')
    return value, compatible


def static_busybox(path, architecture='aarch64'):
    blob = path.read_bytes()
    header = elf._parts(blob)
    expected, label = ((1, 40), 'ARMv7') if architecture == 'armv7l' else ((2, 183), 'AArch64')
    if header is None or header[:2] != expected or struct.unpack_from('<H', blob, 16)[0] not in (2, 3):
        raise ValueError(f'BusyBox must be a little-endian {label} ELF executable')
    if architecture == 'armv7l':
        elf.architecture(blob)  # Also verifies EABI5 and the hard-float ABI.
    segments = header[2]
    if not 1 <= len(segments) <= 1024:
        raise ValueError('Invalid BusyBox program headers')
    if any(segment[0] in (2, 3) for segment in segments):
        raise ValueError('BusyBox must be static; a dynamic segment or interpreter was found')
    return blob


def network(server, address, export, port):
    host = ipaddress.IPv4Address(server)
    guest = ipaddress.IPv4Interface(address)
    if (guest.network.prefixlen != 30 or host not in guest.network or host == guest.ip or
            host in (guest.network.network_address, guest.network.broadcast_address) or
            guest.ip in (guest.network.network_address, guest.network.broadcast_address)):
        raise ValueError('NFS requires distinct usable host and guest addresses in one /30')
    if (not re.fullmatch('/[A-Za-z0-9._/-]+', export) or
            any(part in ('', '.', '..') for part in export[1:].split('/'))):
        raise ValueError('Unsafe NFS export path')
    if type(port) is not int or not 1024 <= port <= 65535:
        raise ValueError('NFS port must be between 1024 and 65535')
    mac = lambda ip: '02:00:' + ':'.join(f'{byte:02x}' for byte in ip.packed)
    return {'NFS_SERVER': str(host), 'NFS_ADDRESS': str(guest), 'NFS_EXPORT': export,
            'NFS_PORT': str(port), 'NFS_HOST_MAC': mac(host), 'NFS_DEVICE_MAC': mac(guest.ip)}


def staged_kernel_image(kernel, release, name):
    kernel = Path(kernel)
    if (kernel / 'kernel.release').read_text().strip() != release:
        raise ValueError('Kernel release differs from the root identity')
    image = kernel / name
    if not image.is_file() or image.is_symlink():
        raise ValueError('Kernel image is missing or linked')
    return image


def nfs_modules(kernel, release):
    """Select the NFSv4 client and its recorded module dependencies."""
    kernel = Path(kernel)
    image = staged_kernel_image(kernel, release, 'Image.gz')
    directory = kernel / 'lib/modules' / release
    if not directory.is_dir() or directory.is_symlink():
        raise ValueError('Kernel module tree is missing or linked')
    metadata = directory / 'modules.dep'
    if not metadata.is_file() or metadata.is_symlink():
        raise ValueError('Kernel module dependencies are missing or linked')

    def module_name(value):
        path = PurePosixPath(value)
        if (not value or path.is_absolute() or any(p in ('', '.', '..') for p in value.split('/')) or
                not re.fullmatch(r'[A-Za-z0-9_./+-]+\.ko', value)):
            raise ValueError('Unsafe kernel module path')
        return path.as_posix()

    dependencies = {}
    for line in metadata.read_text().splitlines():
        name, separator, rest = line.partition(':')
        if not separator:
            raise ValueError('Invalid kernel module dependency entry')
        name = module_name(name)
        if name in dependencies:
            raise ValueError('Duplicate kernel module dependency entry')
        dependencies[name] = [module_name(item) for item in rest.split()]

    roots = ('kernel/fs/nfs/nfs.ko', 'kernel/fs/nfs/nfsv4.ko')
    selected, pending = set(), list(roots)
    while pending:
        name = pending.pop()
        if name in selected:
            continue
        if name not in dependencies:
            raise ValueError('Missing NFS module dependency: ' + name)
        selected.add(name)
        pending.extend(dependencies[name])

    files = {}
    for name in sorted(selected):
        source = directory
        for part in PurePosixPath(name).parts:
            source = source / part
            if source.is_symlink():
                raise ValueError('Linked kernel module refused: ' + name)
        if not source.is_file():
            raise ValueError('Missing kernel module: ' + name)
        files[name] = source
    depfile = ''.join(name + ':' + ''.join(' ' + item for item in dependencies[name]) + '\n'
                      for name in sorted(selected))
    return image, files, depfile


def nfs3_kernel(kernel, release):
    """Check the P105 kernel provides the NFSv3 client without module loading."""
    if kernel is None:
        raise ValueError('P105 NFS startup requires the matching --kernel-dir')
    kernel = Path(kernel)
    image = staged_kernel_image(kernel, release, 'zImage')
    metadata = kernel / 'lib/modules' / release / 'modules.builtin'
    if not metadata.is_file() or metadata.is_symlink():
        raise ValueError('Kernel built-in module list is missing or linked')
    required = {'kernel/fs/nfs/nfs.ko', 'kernel/fs/nfs/nfsv3.ko'}
    if not required.issubset(metadata.read_text().splitlines()):
        raise ValueError('P105 NFS startup requires a built-in NFSv3 client')
    notes = kernel / 'kernel.notes.sha256'
    if notes.is_symlink() or (notes.exists() and not notes.is_file()):
        raise ValueError('Invalid kernel notes digest')
    digest = ''
    if notes.is_file():
        digest = notes.read_text().strip()
        if not re.fullmatch('[0-9a-f]{64}', digest):
            raise ValueError('Invalid kernel notes digest')
    return image, digest


def stage(*, receipt, busybox, output, server, address, export, port,
          function='ecm', handoff='manual', kernel_dir=None, keep_rescue=False):
    receipt, busybox, output = Path(receipt), Path(busybox), Path(output)
    blob = receipt.read_bytes()
    root, compatible = identity(blob)
    armv7 = root['architecture'] == 'armv7l'
    binary = static_busybox(busybox, root['architecture'])
    values = network(server, address, export, port)
    if function not in ('ecm', 'ncm') or handoff not in ('manual', 'auto') or type(keep_rescue) is not bool:
        raise ValueError('Unsupported USB function or handoff policy')
    modules = None
    if armv7:
        image, notes = nfs3_kernel(kernel_dir, root['kernel_release'])
        values['NFS_VERSION'] = '3'
        if notes:
            values['NFS_KERNEL_NOTES_SHA256'] = notes
    elif kernel_dir is not None:
        modules = nfs_modules(kernel_dir, root['kernel_release'])
    values.update(NFS_PROFILE=root['profile'], NFS_ARCHITECTURE=root['architecture'],
                  NFS_KERNEL_RELEASE=root['kernel_release'], NFS_ROOT_ID=root['root_id'],
                  NFS_IDENTITY_SHA256=hashlib.sha256(blob).hexdigest(),
                  NFS_COMPATIBLE=' '.join(compatible), NFS_FUNCTION=function,
                  NFS_HANDOFF=handoff, NFS_CLIENT_MODULES='yes' if modules else 'no',
                  NFS_KEEP_RESCUE='yes' if keep_rescue else 'no')
    if output.exists() or output.is_symlink():
        raise ValueError('Output already exists; choose a fresh RAM root')
    output.mkdir(parents=True)
    for name in ('rootfs/sbin', 'rootfs/etc/orchard'):
        (output / name).mkdir(parents=True, exist_ok=True)
    for source, target in SCRIPTS.items():
        destination = output / target if target == 'init' else output / 'rootfs' / target
        shutil.copyfile(HERE / source, destination)
        destination.chmod(0o755)
    # Generated for this root's device: a local choice, not a project setting.
    (output / 'orchard.local.toml').write_text('device = "' + root['profile'] + '"\n')
    if armv7:
        # The built-in P105 SGX driver probes before the NFS root exists.
        # orchard run adds the board's private firmware as an initramfs layer.
        (output / 'orchard.toml').write_text('name = "p105-nfs-root"\n\n[payload]\nfirmware = true\n')
    (output / 'rootfs/etc/orchard/nfs-root.json').write_bytes(blob)
    config = '# Generated from a validated root receipt; source only from this RAM image.\n'
    config += ''.join(name + '=' + shlex.quote(value) + '\n' for name, value in sorted(values.items()))
    (output / 'rootfs/etc/orchard/nfs.conf').write_text(config)
    (output / 'rootfs/etc/orchard/nfs.conf').chmod(0o600)
    result = {'schema': 1, 'kind': 'orchard.nfs-runtime', 'root': root, 'network': values,
              'busybox_sha256': hashlib.sha256(binary).hexdigest()}
    if armv7:
        result['kernel'] = {'image_sha256': hashlib.sha256(image.read_bytes()).hexdigest(), 'modules': {}}
    if modules:
        image, files, depfile = modules
        destination = output / 'rootfs/lib/modules' / root['kernel_release']
        destination.mkdir(parents=True)
        hashes = {}
        for name, source in files.items():
            target = destination / name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, target)
            hashes[name] = hashlib.sha256(target.read_bytes()).hexdigest()
        (destination / 'modules.dep').write_text(depfile)
        result['kernel'] = {'image_sha256': hashlib.sha256(image.read_bytes()).hexdigest(),
                            'modules': hashes}
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('receipt', 'busybox', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    for name in ('server', 'address', 'export'):
        parser.add_argument('--' + name, required=True)
    parser.add_argument('--port', type=int, required=True)
    parser.add_argument('--function', choices=('ecm', 'ncm'), default='ecm')
    parser.add_argument('--handoff', choices=('manual', 'auto'), default='manual')
    parser.add_argument('--kernel-dir', type=Path, help='staged matching kernel for the selected NFS client')
    parser.add_argument('--keep-rescue', action='store_true', help='keep the physical root shell after handoff')
    args = parser.parse_args()
    try:
        result = stage(**vars(args))
    except (OSError, ValueError) as error:
        parser.error(str(error))
    print(json.dumps(result, sort_keys=True, indent=2))


if __name__ == '__main__':
    main()
