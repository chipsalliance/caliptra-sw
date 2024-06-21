# Licensed under the Apache-2.0 license

#!/bin/bash
VERILATOR_VERSION=v5.006

function set_guest_attr()
{
    curl -X PUT --data "$2" "http://metadata.google.internal/computeMetadata/v1/instance/guest-attributes/caliptra-github-ci/$1" -H "Metadata-Flavor: Google"
}

set -x
(
    set -Eeuox pipefail
    # Add a user for the 
    useradd runner --shell /bin/bash --create-home

    # Some actions need to install debian packages as part of their work We
    # don't care if they mess up the VM because it's going to be deleted at at
    # the end of the job anyways.
    echo "runner ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/runner

    apt-get update

    # Install some commonly used packages
    apt-get -y install build-essential autoconf automake libtool manpages-dev flex \
        bison libfl2 libfl-dev help2man git gcc-riscv64-unknown-elf \
        binutils-riscv64-unknown-elf pkg-config libssl-dev jq libtinfo5 \
        gcc-aarch64-linux-gnu squashfs-tools

    # Disable unattended upgrades, as these can interfere with jobs. This image
    # is regenerated once a week so the security risk is minimal.
    apt-get -y remove unattended-upgrades

    echo Retrieving latest GHA runner version
    RUNNER_VERSION="$(curl https://api.github.com/repos/actions/runner/releases/latest | jq -r '.tag_name[1:]')"
    echo Using runner version ${RUNNER_VERSION}

    echo Downloading GHA Runner
    su runner -c "curl -o /tmp/actions-runner.tar.gz -L https://github.com/actions/runner/releases/download/v${RUNNER_VERSION}/actions-runner-linux-x64-${RUNNER_VERSION}.tar.gz"
    echo Unpacking GHA Runner
    su runner -c "mkdir /home/runner/actions-runner"
    su runner -c "cd /home/runner/actions-runner && tar xzf /tmp/actions-runner.tar.gz"
    rm /tmp/actions-runner.tar.gz
    su runner -c "echo 'PATH=/home/runner/.cargo/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin' > /home/runner/actions-runner/.env"

    echo Installing Rust Toolchain
    su runner -c "curl https://sh.rustup.rs -sSf | sh -s -- -y --default-toolchain=1.70"
    su runner -c "/home/runner/.cargo/bin/rustup target add riscv32imc-unknown-none-elf"
    echo Installing cargo-nextest
    su runner -c "/home/runner/.cargo/bin/cargo install cargo-nextest@0.9.64 --locked --no-default-features --features=default-no-update"

    mkdir sw
    (
        cd sw
        git clone -b "${VERILATOR_VERSION}" https://github.com/verilator/verilator
        cd verilator
        autoconf
        ./configure --prefix=/opt/verilator
        make -j32
        make install
    )
    rm -rf sw
)
exit_code=$?
if [[ $exit_code -eq 0 ]]; then 
    set_guest_attr startup-script-result SUCCESS
else
    set_guest_attr startup-script-result ERROR
fi

sleep 1
shutdown -h now
