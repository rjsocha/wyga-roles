# wyga/storage

Block devices of a host as `setup.storage` declares them: LVM volume
groups and logical volumes, sparse files for loop devices. Filesystems on
them are the work of `wyga/filesystem`, which `wyga/host-policy` runs
right after this role.

- Activates on `setup.storage`.
- Everything is grow-only: nothing is shrunk, removed or reformatted. A
  device with a signature or a partition table is never touched.
- The module `wyga_storage` reads the state of the host (`pvs`, `vgs`,
  `lvs`, `lsblk`) and acts on the difference; `--check` prints the plan.

```yaml
setup:
  storage:
    lvm:
      vg:
        system: {}                 # must exist, otherwise the policy fails
        data:
          device:                  # made of these devices when it does not exist
            - /dev/disk/by-id/virtio-data
      lv:
        swap: {vg: system, size: 4GiB}
        luk:  {vg: system, size: 100G}
    loop:
      scratch:
        file: /var/lib/storage/scratch.img
        size: 20G
```

## lvm.vg

Every group named must exist on the host, or have `device`. A group
with `device` is created from them: each device gets a GPT with one
partition of type LVM, `pvcreate`, then `vgcreate`; a device added to
the list later extends the group (`vgextend`). A device that holds a
filesystem, a partition table or belongs to another group fails the
policy. Names stable across reboots (`/dev/disk/by-id/...`) are
expected; `/dev/vdb` works but is not stable.

## lvm.lv

`vg` must name a group of `lvm.vg`; `size` as `lvcreate -L` reads it
(`4GiB`, `100G`, `1024MiB`). The volume is created at `size` and grown
with `lvextend` when `size` is larger than the volume; a smaller `size`
changes nothing. The device is `/dev/<vg>/<name>`.

## loop

A sparse file of `size` at `file` (0600, root), grown with `truncate`
when `size` is larger. The loop device itself is attached by `mount`
through the `loop` option; `wyga/filesystem` adds it when `device` is a
regular file.

## Migration from setup.swap

`setup.swap` is refused by `wyga/policy-validate`. Its replacement is
`lvm.lv.swap` here plus `filesystem.swap` in `wyga/filesystem`; on a
host the old role set up both report no change.
