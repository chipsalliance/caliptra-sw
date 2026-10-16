This development branch targets Caliptra 2.2 only. The `caliptra-registers` crate
directly re-exports `hw/latest/registers`; there are no hardware-capability flags
or legacy protocol selections. `CALIPTRA_HW_REV=2.2`, `latest`, and an unset
variable select the same target. Requests for older revisions fail the build.

Caliptra-SS is the source of truth for register generation:

```text
hw/latest/caliptra-ss
|-- src/                                  Caliptra-SS registers
`-- third_party/
    |-- caliptra-rtl/                      Caliptra core registers
    |   `-- submodules/adams-bridge/       Adams Bridge registers
    `-- i3c-core/                          I3C registers
```

## Regenerating a pinned revision

Run from the repository root:

```sh
registers/update.sh latest
```

The script initializes Caliptra-SS if necessary and recursively checks out the
dependency commits recorded by its selected commit. It does not advance any
dependency to its branch tip or change the selected Caliptra-SS commit.

To verify that committed accessors match the sources without rewriting them:

```sh
cargo run --locked -p caliptra_registers_generator -- --check \
    hw/latest/caliptra-ss registers/bin/extra-rdl hw/latest/registers/src
```

Generated headers record the exact SS, RTL, Adams Bridge, and I3C commits.
Historical snapshots inherited from upstream are not supported build targets
on this branch and are not regenerated.

Build the development firmware with:

```sh
cargo xtask --rev 2.2 build all
```

The pinned SS snapshot is `743d5f7eaa9a946f405b9087c7ffd2fbb38e1543`,
which selects RTL `f9bc5ab97b885b5e31ccb062eca16634a8e61b5a`. This is
2.2 development hardware, not a finalized or qualified 2.2 release.

Firmware retains `SS_STRAP_GENERIC[2]` for entropy window, lane selection, and
bypass settings. The generated `ENTROPY_CONFIG_2` accessors are not used for
configuration on this branch.

## Updating latest hardware

Advance only Caliptra-SS to its upstream `main`, then regenerate:

```sh
git submodule update --init hw/latest/caliptra-ss
git -C hw/latest/caliptra-ss fetch origin main
git -C hw/latest/caliptra-ss switch --detach origin/main
registers/update.sh latest
```

Caliptra-SS is the only hardware submodule pinned by this repository for each
revision. Its gitlinks select Caliptra RTL and I3C, while Caliptra RTL selects
Adams Bridge. Do not update these nested dependencies with `--remote`; advance
Caliptra-SS and use its recorded dependency commits. Review and commit the updated
Caliptra-SS pin alongside `hw/latest/registers`. Do not advance `hw/rev-2_1` when
updating latest hardware.
