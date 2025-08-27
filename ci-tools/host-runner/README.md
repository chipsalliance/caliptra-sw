# Introduction

This is a NixOS configuration for Caliptra host runners. A host runner is a Raspberry PI that oversees a cluster of FPGAs running in the Caliptra CI.

## How to cross-compile NixOS

This section describes how to compile from an x86-64 machine to an aarch64 machine.

### NixOS

If you are using a NixOS system, add the following to your NixOS configuration:

```
boot.binfmt.emulatedSystems = [ "aarch64-linux" ];
```

### non-NixOS

If you are not using a NixOS system, follow these steps.

1. Install Nix
1. Install cross-compilation tools
    - E.g. on Debian, `sudo apt-get update -q -y && sudo apt-get install -q -y qemu-system-aarch64 binfmt-support qemu-user-static`
1. Update your Nix config to the following

```bash
cat << EOF > /etc/nix/nix.conf
sandbox = true

experimental-features = nix-command flakes
trusted-users = $USER
extra-platforms = aarch64-linux
extra-sandbox-paths = /usr/bin/qemu-aarch64-static
EOF
```
# Adding secrets

There are a few secrets that this configuration relies on. They are not checked into git so it is up to you to retrieve them.

1. GitHub private key
  - This should be saved at `ci-tools/host-runner/secrets/google/prod`.
  - If you or your company does not already possess a key, the github-runner deployments [README](../github-runner/deployments/README.md) describes how to create one.
1. User password
  - This configuration expects a hashed password to be present at `ci-tools/host-runner/secrets/host-runner-pass`.
  - Create the password by inputting it into the `mkpasswd` CLI tool.
    - You can create a shell that has `mkpasswd` using Nix: `$ nix shell nixpkgs#mkpasswd`.

# Bootstrapping a new Raspberry PI

## Config modifications

It's likely that you will want to make the following modifications to this configuration.

### Add SSH public key as an Authorized User

See [configuration.nix](configuration.nix_) for where this code is located.

```nix
    # Add your ssh public key as a string to this list.
    # Remove keys you don't trust.
    openssh.authorizedKeys.keys = [
        # clundin Mac
        "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDDKTJ6unwymfvdFSTNAXo+wjaX1l2SFPgeSgK/xzC7ex3oGR2ihCg/8luQt1e6FKnbqV83O2v0AT/aRw9p9sEjY7HGNDz+0nQ6lezi4XAuqJMOMshzVlqv4hZJLb8Ab2PMma0se15h1LhnfSUpttv7cDgdLXHqh2kizMQ39l62Lu4j2ITJKFhqW1v7Ez74uo2o++We6EHU2PRZhyKV9tKbYXojOyow+abUXKMfXy01iCSunaQq6KRB6Jl5TskMVmGSz0rUnjyxLCCPEA2h7D0lgQviLuJQtIl/jFYu8QFNqaVwHDHiEUpNfcfQGx6S7hpSs7CdPD29YQSka9TovICyD3dCKGn+tpfRQDmZSTR8Qnqv4mNtxKPcitpMFNVL9V6Echqy83rlo5CgO1tEsL/6g0WEm6nrFBMs/szUfv1qs4/4wL0PsNit1ArxfqYXVaDzGisvA+Y4yRl2IsMPaI7TzB6uDSR0j31jZXSGR8vqPG9rF+aGobF21OfWGHI8Ddc= clundin@clundin-macbookpro.roam.internal"
        # clundin Workstation
        "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDohnyJgm7nztWkxtKaqds13IHJMYpoV2VozRs5wIbct2R98lmyATIR+pOypPv/uv++KnDTUV68/Pt+SFZS6VcOBj/SfDqniqi5/Zmj5qL0dRfLfr4RE1ET7gMPMpvbynUEaXiaochSInikdToDwUeUfhNfs1JGGIbOsoNNhBYAKuNTBo7DXpOUuq8t6oBMqvYWWtCN+kAagkf3tyi94Br52GS++9i7q3RZnvHtw79FW5Sc4xZtuiBqs7aKsK/pplKC7V6emcf0zM1F49knZR+UmLvHhRXzbyxJPyDHgZFGcu7SeDCikAn/2mKxIr8gHjyVSZ5JwOuHekQrVRgwT+CVYBc6AsvCe5aRsrUDJC7TZHsWUVKkaXXDyASYy87wTy+IE3BCZVZmjjZ9OufX7jqXT/lenJbaOn9240e5pSydOzT97tVIuL8rRL+6m00cBsxLJcsFjmrGreX3M2T37IifICpFUDaZJYkVcrKvUWXIdgqHECpQgo7YmLlTcC/hP/0= clundin@clundin6.kir.corp.google.com "
      ];
```

##  Flash SD Image

If you need to setup a host runner from scratch, you'll need to flash an SD card with the NixOS image created by this config. You should modify the flake target to the host your are bootstrapping. This example uses "caliptra-hostrunner0".

```bash
$ nix run nixpkgs#nixos-generators -- -f sd-aarch64 --flake path:.#caliptra-hostrunner0 --system aarch64-linux -o ./hostrunner-image
...
$ ls hostrunner-image/sd-image # A new RPI image is created in the hostrunner-image folder. De-compress with zst and then flash the SD card for the Raspberry PI.
nixos-sd-image-24.11.20250421.9684b53-aarch64-linux.img.zst
```

Once the image is flashed the Raspberry PI should be ready to boot, assuming secrets were available when generating the SD image.

## Remotely modify hostrunner

If your hostrunner already is running NixOS, you can manage it over SSH. Below is an example command to cross-compile the caliptra-hostrunner0. After the cross-compiling the configuration, the `switch` command will switch the hostrunner to the new config.

The `--target-host` takes an ssh target as a parameter.

```bash
nix run nixpkgs#nixos-rebuild -- --target-host caliptra-hostrunner0 --use-remote-sudo switch --flake path:.#caliptra-hostrunner0 --impure # --target-host "caliptra-hostrunner0" is an SSH Host and --flake path:.#caliptra-hostrunner0 is the flake target
```

# Udev

Udev rules are used to access USB and SD cards without root permissions. You can see this in `configuration.nix`. 

If you get permission errors, for example you are using a novel SD card, you may need to add the device to the udev rules.

Use the udev tools to figure out the `idVendor` and `idProduct` attributes of the device.

```nix
  services.udev.extraRules = ''
    SUBSYSTEMS=="usb", ATTRS{idVendor}=="0403", ATTRS{idProduct}=="6011", OWNER="${user}", GROUP="users"
    SUBSYSTEMS=="usb", ATTRS{idVendor}=="04e8", ATTRS{idProduct}=="6001", OWNER="${user}", GROUP="users"
    SUBSYSTEMS=="usb", ATTRS{idVendor}=="0424", ATTRS{idProduct}=="2640", OWNER="${user}", GROUP="users"
    SUBSYSTEMS=="usb", ATTRS{idVendor}=="0424", ATTRS{idProduct}=="4050", OWNER="${user}", GROUP="users"
    '';
```

# Download FPGA Image

Download the latest FPGA image from [GitHub](https://github.com/chipsalliance/caliptra-sw/actions/workflows/fpga-image.yml). This job is scheduled to run once a week.

This image should be copied to the host runner and stored at `$HOME/zcu104.img`.

For ZCU-104s this image does not contain a bitstream, the GitHub job is responsible for writing it.

For VCK-190s this image _does_ include the bitstream. This is because it needs to be present on device boot.


# Connect an FPGA to the host runner

For an example, see [hostrunners/kir-0.nix](hostrunners/kir-0.nix) for 3 ZCU-104s managed with systemd. You should use Nix to manage these services so they are re-producible.
