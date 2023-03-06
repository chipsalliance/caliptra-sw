# C and Rust bindings for Caliptra RTL (verilated)

## Prerequisites:

### Verilator 5.004 or later

Install the prerequisites for verilator as documented in the [Verilator install instructions](https://verilator.org/guide/latest/install.html#git-quick-install).

Next, build and install verilator:

```shell
git clone https://github.com/verilator/verilator
cd verilator
git checkout v5.006
autoconf
./configure
make -j10
sudo make install
```

## Rust integration tests:

```shell
git submodule update --init"  # Needed the first time
(cd hw-latest/verilated && cargo test --features verilator)
(cd hw-model && cargo test --features verilator)
```

Cargo will compile the RTL into verilated C++, compile the generated C++ into a
static library, and link to this library from the Rust crate.
