# Introduction

## NixOS system

This is a NixOS installation for Caliptra host runners. This is a Raspberry PI that oversees a cluster of FPGAs running in the Caliptra CI.

Reach out to clundin25@ if you have questions.

## Setting up a NixOS system for cross-compilation

### NixOS

Add the following to your NixOS configuration:

```
boot.binfmt.emulatedSystems = [ "aarch64-linux" ];
```

### non-NixOS

1. Install Nix
1. Install cross-compilation tools
    - E.g. Debian, `sudo apt-get update -q -y && sudo apt-get install -q -y qemu-system-aarch64 binfmt-support qemu-user-static`
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

# Bootstrapping a new Raspberry PI

## Config modifications

It's likely that you will want to make the following modifications to the NixOS configuration.

### Add SSH public key as an Authorized User

See `configuration.nix`.

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
Create a new NixOS image. You should modify the flake target to the host your are bootstrapping. This example uses "caliptra-hostrunner0", which resides in Kirkland.

```bash
$ nix run nixpkgs#nixos-generators -- -f sd-aarch64 --flake path:.#caliptra-hostrunner0 --system aarch64-linux -o ./hostrunner-image
...
$ ls hostrunner-image/sd-image # A new RPI image is created in the hostrunner-image folder. De-compress with zst and then flash the SD card for the Raspberry PI.
nixos-sd-image-24.11.20250421.9684b53-aarch64-linux.img.zst
```

Once the image is flashed the Raspberry PI should be ready to boot, assuming secrets were available when generating the SD image.

## Remotely modify hostrunner

You can cross-compile a NixOS system and copy binaries using SSH. Below is an example command to cross-compile the caliptra-hostrunner0.

Remember, you need to have an SSH config entry to the Raspberry PI for this to work.

```bash
nix run nixpkgs#nixos-rebuild -- --target-host caliptra-hostrunner0 --use-remote-sudo switch --flake path:.#caliptra-hostrunner0 --impure # "caliptra-hostrunner0" is an SSH Host in this example.
```

# Udev

Udev rules are used to access USB and SD cards without root permissions. You can see this in `configuration.nix`. 

If you get permission errors, you most likely need to add the device to the udev rules.

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

# Connect an FPGA to the host runner

For an example, see `hostrunners/kir-0.nix` for 3 ZCU-104s managed with systemd. You should use Nix to manage these services so they are re-producible.

## Generic instructions

### RPI Setup

1. Install Rust
1. Install fpga-boss and cred-tool.
    - `cargo install --git https://github.com/chipsalliance/caliptra-sw.git caliptra-fpga-boss --branch main`
    - `cargo install --git https://github.com/clundin25/cred-tool.git`
1. Download the latest FPGA image from [GitHub](https://github.com/chipsalliance/caliptra-sw/actions/workflows/fpga-image.yml). This job is scheduled to run once a week.
    - In the following examples, the image is stored in `$HOME/zcu-scripts/zcu104.img` for the Raspberry PI user.
1. Get a GitHub Application private key for the CI. This is used to sign JWTs used by the FPGA runners.
    - The template below stores this file at `/etc/secrets/caliptra-gce-ci-github-private-key-pem/prod`.

### UDEV rules

Add UDEV rules for the hardware that is involved to avoid running the CI as root.

Here is an example from my RPI:

```
runner@caliptrarpi:~/zcu104-scripts $ cat /etc/udev/rules.d/99-fpga.rules
SUBSYSTEMS=="usb", ATTRS{idVendor}=="0403", ATTRS{idProduct}=="6011", OWNER="runner", GROUP="runner"
SUBSYSTEMS=="usb", ATTRS{idVendor}=="04e8", ATTRS{idProduct}=="6001", OWNER="runner", GROUP="runner"
SUBSYSTEMS=="usb", ATTRS{idVendor}=="0424", ATTRS{idProduct}=="2640", OWNER="runner", GROUP="runner"
SUBSYSTEMS=="usb", ATTRS{idVendor}=="0424", ATTRS{idProduct}=="4050", OWNER="runner", GROUP="runner"
```

These rules are for the FTDI / SDWIRE USB hosts, as well as the SD Cards that I use. You may have different vendors and products.

## FPGA Bash Script Template

This is a template bash script used to manage each FPGA. 

The following placeholders are populated in subsequent sections:
* `ZCU_FTDI`
* `ZCU_SDWIRE`
* `IDENTIFIER`
* `LOCATION`

```
#!/bin/bash

ZCU_FTDI="" # TODO: Update me!
ZCU_SDWIRE="" # TODO: Update me!
IDENTIFIER="" # TODO: Update me!
LOCATION="" # TODO: Update me!
IMAGE="$HOME/zcu104-scripts/zcu104.img"

$HOME/.cargo/bin/caliptra-fpga-boss --zcu104 $ZCU_FTDI --sdwire $ZCU_SDWIRE serve $IMAGE -- $HOME/.cargo/bin/cred-tool --stage prod --fpga-target zcu104 --fpga-identifier $IDENTIFIER --location $LOCATION --key-path /etc/secrets/caliptra-gce-ci-github-private-key-pem/prod
```

### Populating ZCU_FTDI

This is alternatively documented above in "How do I determine the `--zcu104` parameter for my hardware?". We will use a different method because we will most likely be connecting multiple FPGAs.

First, open a terminal window with `dmesg -w` on the Raspberry PI. I recommend using tmux so we don't have to tab back and forth between the script and dmesg.

Plug in a micro-usb cable to the FPGA serial port and to your Raspberry PI. You should see a log like this:

```
[ 1360.519412] usbserial: USB Serial support registered for FTDI USB Serial Device
[ 1360.519630] ftdi_sio 1-1.1.3:1.0: FTDI USB Serial Device converter detected
[ 1360.519783] usb 1-1.1.3: Detected FT4232H
[ 1360.520694] usb 1-1.1.3: FTDI USB Serial Device converter now attached to ttyUSB0
```

Based on the above log, we would set the `ZCU_FTDI` variable to `1-1.1.3`. This is the USB path to the device.

### Populating ZCU_SDWIRE

This is alternatively documented above in "How do I determine the `--sdwire` parameter for my hardware?". We will use a different method because we will most likely be connecting multiple FPGAs.

First, open a terminal window with `dmesg -w` on the Raspberry PI. I recommend using tmux so we don't have to tab back and forth between the script and dmesg.

Plug in the SDWire. You should see a log like this:

```
[ 1266.724822] usb-storage 1-1.1.4.1:1.0: USB Mass Storage device detected
[ 1266.725524] scsi host0: usb-storage 1-1.1.4.1:1.0
[ 1266.803147] usb 1-1.1.4.2: new full-speed USB device number 6 using xhci_hcd
[ 1266.908861] usb 1-1.1.4.2: New USB device found, idVendor=04e8, idProduct=6001, bcdDevice=10.00
[ 1266.908892] usb 1-1.1.4.2: New USB device strings: Mfr=1, Product=2, SerialNumber=3
[ 1266.908906] usb 1-1.1.4.2: Product: sd-wire
[ 1266.908918] usb 1-1.1.4.2: Manufacturer: SRPOL
[ 1266.908928] usb 1-1.1.4.2: SerialNumber: bdgrd_sdwirec_593
```

Based on the above log, we would set the `ZCU_SDWIRE` variable to `1-1.1.4`. This is the USB path to the device.

### Populating IDENTIFIER

This is a unique string or number to differentiate co-located FPGAs.

In Kirkland, each FPGA is assigned an incrementing number, e.g. 1, 2, 3, 4, etc.

### Populating Location

This identifies where the FPGAs are located. For Kirkland we use "kir", in Sunnyvale we use "svl".
Other companies should also include the company name in this field.

### Saving the bash script

I recommend saving the bash file to `$HOME/zcu104-scripts/zcu-$IDENTIFIER.sh` to help differentiate between FPGAs.

### Testing the script

Run the bash script to see if everything works. A successful run will end with the following output:

```
Apr 21 16:55:26 caliptrarpi bash[2201]: UART: Executing GHA runner
Apr 21 16:55:37 caliptrarpi bash[2201]: UART:
Apr 21 16:55:37 caliptrarpi bash[2201]: UART: √ Connected to GitHub
Apr 21 16:55:37 caliptrarpi bash[2201]: UART:
Apr 21 16:55:38 caliptrarpi bash[2201]: UART: Current runner version: '2.323.0'
Apr 21 16:55:38 caliptrarpi bash[2201]: UART: 2025-04-21 23:55:37Z: Listening for Jobs
```


## Managing the FPGA with systemd

I recommend wrapping the FPGA scripts with systemd for easier management.

Here is a template:

```
[Unit]
Description=ZCU-0 Service
After=network.target sshd.service
Wants=network.target

[Service]
User=runner
Type=simple
Restart=on-failure
RestartSec=15s
StartLimitInterval=60m
StartLimitBurst=3
ExecStart=/usr/bin/bash /home/runner/zcu104-scripts/zcu-0.sh

[Install]
WantedBy=multi-user.target
```

## Starting the FPGA service

```
$ sudo systemctl enable zcu-0 # We want the FPGA service to start when the RPI is rebooted.
$ sudo systemctl start zcu-0
$ journalctl -u zcu-0 -f # Monitor the FPGA to make sure everything is working.
```
