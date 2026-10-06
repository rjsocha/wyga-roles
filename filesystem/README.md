# wyga/filesystem

Filesystems and swap of a host as `setup.filesystem` declares them, on
block devices `wyga/storage` made or any other. `wyga/host-policy` runs it
right after `wyga/storage`, after the packages of the policy and before
the services. `btrfs-progs` is installed by the role when `btrfs` is used.

- Activates on `setup.filesystem`.
- Nothing is reformatted: a device that holds another filesystem fails
  the policy. A filesystem grows to its device; it never shrinks.
- The module `wyga_filesystem` reads the state of the host (`blkid`,
  `findmnt`, `btrfs`) and acts on the difference; the fstab entries it
  returns are applied with `ansible.posix.mount`. `--check` prints the
  plan, including what waits for a device `wyga/storage` has yet to make.

```yaml
setup:
  filesystem:
    btrfs:
      luk:                                 # key = label
        device: /dev/system/luk
        options: [discard=async, noatime]  # of every mount of this filesystem
        volume:
          "@luk":
            mount: /var/lib/luk
            owner: root
            group: luk
            mode: "0750"
          "@archive":
            mount: /storage/archive
            options: [noexec]
      scratch:
        device: /var/lib/storage/scratch.img   # a regular file: mounted through loop
        volume:
          "@scratch":
            mount: /scratch
    swap:
      SWAP:
        device: /dev/system/swap
```

## btrfs

The key is the label (up to 255 characters, spaces allowed). `device`
is a block device or a regular file (then `loop` is added to the mount
options). Without a signature the device gets `mkfs.btrfs -L <label>`;
with another label it is relabelled; larger than the filesystem it gets
`btrfs filesystem resize max` (so a bigger `size` in `wyga/storage`
grows the filesystem in the same run).

`volume` maps a subvolume name to its mount: `mount` (required),
`options` added to the filesystem `options`, and `owner`, `group`,
`mode` of the root of the subvolume when given (the user and group must
exist). A missing subvolume is created through a temporary mount of
the top level. The fstab names a block device by `LABEL=<label>` and a
file by its path.

## swap

The key is the label. `device` is a block device, or a regular file
made with `size` (`fallocate`, nocow on btrfs) when it does not exist.
Without a signature it gets `mkswap -L <label>`, with another label
`swaplabel`; it is activated when not in `/proc/swaps` and goes into
the fstab as `LABEL=<label> none swap sw`.
