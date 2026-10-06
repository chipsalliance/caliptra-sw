The `caliptra-registers` crate re-exports generated hardware register accessors.
`CALIPTRA_HW_REV=2.1` selects `hw/rev-2_1/registers`; an unset variable or
`CALIPTRA_HW_REV=latest` selects `hw/latest/registers`.

Each hardware revision uses its `caliptra-ss` commit as the source of truth for
register generation:

```text
hw/<revision>/caliptra-ss
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
registers/update.sh rev-2_1
```

The script initializes Caliptra-SS if necessary and recursively checks out the
dependency commits recorded by its selected commit. It does not advance any
dependency to its branch tip or change the selected Caliptra-SS commit.

To verify that committed accessors match the sources without rewriting them:

```sh
cargo run --locked -p caliptra_registers_generator -- --check \
    hw/latest/caliptra-ss/third_party/caliptra-rtl \
    registers/bin/extra-rdl \
    hw/latest/caliptra-ss/third_party/i3c-core \
    hw/latest/caliptra-ss \
    hw/latest/registers/src
```

Use `hw/rev-2_1` in place of `hw/latest` to check the 2.1 snapshot.

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
