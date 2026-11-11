# Licensed under the Apache-2.0 license
#
# Nix builder for AMD/Xilinx Versal VCK-190 boot firmware (`BOOT.BIN` and `system.dtb`)
# directly from the Vivado `.xsa` hardware handoff archive — completely eliminating PetaLinux.
#
# Components built from Xilinx's official 2024.2 sources:
#   - `bootgen` (host tool): assembles Versal Programmable Device Images (PDI / BOOT.BIN)
#   - `arm-trusted-firmware` (`bl31.elf`): TF-A for Versal (`PLAT=versal`, `pl011` console)
#   - `u-boot-xlnx` (`u-boot.elf`): U-Boot for Versal (`xilinx_versal_virt_defconfig` + Cadence WDT)
#   - `systemDtb` (`system.dtb`): compiled from `nix/system.dts` via `dtc`
#   - `mkBootBin`: extracts the base PDI (`*_boot.pdi`, `plm.elf`, `psm_fw.elf`) from the
#     variant `.xsa` archive and packages `BOOT.BIN` using `bootgen -arch versal`.

{
  buildPkgs,
  targetPkgs,
  lib ? buildPkgs.lib,
}:

let
  # Open-source Xilinx bootgen (v2024.2) built natively on the host
  bootgen = buildPkgs.stdenv.mkDerivation {
    pname = "xilinx-bootgen";
    version = "2024.2";

    src = buildPkgs.fetchFromGitHub {
      owner = "Xilinx";
      repo = "bootgen";
      rev = "6f448fece5d999985128fd454ae047e065a5e45d"; # xilinx_v2024.2
      hash = "sha256-t165nTG4IkI3WrcS3ZryINmAOVzfctxg5zY3oqmNtLw=";
    };

    buildInputs = [ buildPkgs.openssl ];
    enableParallelBuilding = true;

    installPhase = ''
      runHook preInstall
      install -Dm755 bootgen $out/bin/bootgen
      runHook postInstall
    '';
  };

  # Device Tree Blob (`system.dtb`) compiled from `nix/system.dts`
  # Matches PetaLinux `CONFIG_SUBSYSTEM_DEVICETREE_COMPILER_FLAGS="-@"` and `PADDING_SIZE=0x1000`
  systemDtb = buildPkgs.runCommand "vck190-system.dtb" {
    nativeBuildInputs = [ buildPkgs.dtc ];
  } ''
    dtc -@ -p 0x1000 -I dts -O dtb -o $out ${./system.dts}
  '';

  # ARM Trusted Firmware (`bl31.elf`) for Versal (xlnx_rebase_v2.10_2024.2)
  armTrustedFirmware = targetPkgs.stdenv.mkDerivation {
    pname = "arm-trusted-firmware-versal";
    version = "2.10-xilinx-v2024.2";

    src = buildPkgs.fetchFromGitHub {
      owner = "Xilinx";
      repo = "arm-trusted-firmware";
      rev = "14cea4616b6edaceabb607c7c92332436a1699e5"; # xlnx_rebase_v2.10_2024.2
      hash = "sha256-bq9Da3Zc+soEudJxXRejehordtttXJ3vayYZb5IfJFI=";
    };

    depsBuildBuild = [ buildPkgs.stdenv.cc ];
    nativeBuildInputs = [ buildPkgs.openssl ];

    makeFlags = [
      "HOSTCC=${buildPkgs.stdenv.cc.targetPrefix}gcc"
      "CROSS_COMPILE=${targetPkgs.stdenv.cc.targetPrefix}"
      "PLAT=versal"
      "RESET_TO_BL31=1"
      "VERSAL_CONSOLE=pl011"
      "XILINX_OF_BOARD_DTB_ADDR=0x1000"
      "ZYNQMP_WDT_RESTART=1"
      "BUILD_BASE=build"
      "bl31"
    ];

    # Prevent Nix hardening flags from breaking bare-metal EL3 firmware compilation
    hardeningDisable = [ "all" ];
    dontStrip = true;
    enableParallelBuilding = true;

    installPhase = ''
      runHook preInstall
      install -Dm644 build/versal/release/bl31/bl31.elf $out/bl31.elf
      runHook postInstall
    '';
  };

  # U-Boot (`u-boot.elf`) for Versal (xlnx_rebase_v2024.01_2024.2)
  # Matches `xilinx_versal_virt_defconfig` + `meta-user/recipes-bsp/u-boot/files/watchdog.cfg`
  uBootXlnx = targetPkgs.stdenv.mkDerivation {
    pname = "u-boot-xlnx-versal";
    version = "2024.01-xilinx-v2024.2";

    src = buildPkgs.fetchFromGitHub {
      owner = "Xilinx";
      repo = "u-boot-xlnx";
      rev = "7f6ec94aac7eacfec07bd45c83a6d17df4b7d383"; # xlnx_rebase_v2024.01_2024.2
      hash = "sha256-qeyvbpDvgg3Uu9Rr7yQIzIMhbLxGIuSAc/T95GPMDL8=";
    };

    depsBuildBuild = [ buildPkgs.stdenv.cc ];
    nativeBuildInputs = with buildPkgs; [
      bc
      bison
      dtc
      flex
      gnutls
      libuuid
      ncurses
      openssl
      pkg-config
      python3
      swig
      which
    ];

    hardeningDisable = [ "all" ];
    dontStrip = true;
    enableParallelBuilding = true;

    postPatch = ''
      patchShebangs tools scripts
    '';

    configurePhase = ''
      runHook preConfigure
      make CROSS_COMPILE=${targetPkgs.stdenv.cc.targetPrefix} xilinx_versal_virt_defconfig
      cat >> .config << 'EOF'
      CONFIG_WATCHDOG=y
      CONFIG_WDT=y
      CONFIG_CADENCE_WDT=y
      # CONFIG_MULTI_DTB_FIT is not set
      CONFIG_OF_LIST=""
      EOF
      make CROSS_COMPILE=${targetPkgs.stdenv.cc.targetPrefix} olddefconfig
      runHook postConfigure
    '';

    buildPhase = ''
      runHook preBuild
      make -j$NIX_BUILD_CORES \
        HOSTCC=${buildPkgs.stdenv.cc.targetPrefix}gcc \
        CROSS_COMPILE=${targetPkgs.stdenv.cc.targetPrefix} \
        DEVICE_TREE=xilinx-versal-virt \
        u-boot.elf
      runHook postBuild
    '';

    installPhase = ''
      runHook preInstall
      install -Dm644 u-boot.elf $out/u-boot.elf
      runHook postInstall
    '';
  };

  # Default Vivado `.xsa` archives per variant (matching `.github/workflows/fpga-image.yml`)
  defaultXsaSources = {
    core = buildPkgs.fetchurl {
      url = "https://storage.googleapis.com/caliptra-github-ci-bitstreams/v0/20251201/xsa_core2p0_5d069408.xsa";
      sha256 = "e5cf1d375502dc9105becaa16c1c996a65ed1dcf153a688c7f098d51e66ba6ae";
    };
    subsystem = buildPkgs.fetchurl {
      url = "https://storage.googleapis.com/caliptra-github-ci-bitstreams/v0/20251201/xsa_ss2p0_b9f8a767.xsa";
      sha256 = "8fade301b2d2d4864a8586b5fea2cf8a80a76102afc711a940f66d7df79e30b3";
    };
  };

  # Assembles `BOOT.BIN` from a Vivado `.xsa` archive + `system.dtb` + `bl31.elf` + `u-boot.elf`
  mkBootBin =
    {
      variant ? "subsystem",
      xsa ? defaultXsaSources.${variant},
    }:
    buildPkgs.runCommand "vck190-boot-bin-${variant}" {
      nativeBuildInputs = [
        buildPkgs.unzip
        bootgen
      ];
    } ''
      mkdir -p work
      cd work
      unzip -q ${xsa}

      base_pdi=$(ls *_boot.pdi 2>/dev/null | head -n 1)
      if [ -z "$base_pdi" ]; then
        echo "Error: Could not find *_boot.pdi inside ${xsa}" >&2
        exit 1
      fi

      cat > bootgen.bif <<EOF
      the_ROM_image:
      {
        image {
          { type=bootimage, file=$base_pdi }
          { type=bootloader, file=pdi_files/gen_files/plm.elf }
          { core=psm, file=pdi_files/static_files/psm_fw.elf }
        }
        image {
          id = 0x1c000000, name=apu_subsystem
          { type=raw, load=0x00001000, file=${systemDtb} }
          { core=a72-0, exception_level=el-3, trustzone, file=${armTrustedFirmware}/bl31.elf }
          { core=a72-0, exception_level=el-2, file=${uBootXlnx}/u-boot.elf }
        }
      }
      EOF

      bootgen -arch versal -image bootgen.bif -w -o $out
    '';
in
{
  inherit
    bootgen
    systemDtb
    armTrustedFirmware
    uBootXlnx
    defaultXsaSources
    mkBootBin
    ;
  bootBinCore = mkBootBin { variant = "core"; };
  bootBinSubsystem = mkBootBin { variant = "subsystem"; };
}
