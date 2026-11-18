# Licensed under the Apache-2.0 license
#
# Builds the out-of-tree Caliptra FPGA UIO kernel module (io-module.ko)
# for either the `core` or `subsystem` FPGA memory map.

{
  stdenv,
  lib,
  kernel,
  variant ? "core",
}:

assert lib.assertOneOf "variant" variant [
  "core"
  "subsystem"
];

let
  srcFile =
    if variant == "subsystem" then ./io-module/mcu_io_module.c else ./io-module/io_module.c;
in
stdenv.mkDerivation {
  pname = "caliptra-fpga-io-module-${variant}";
  version = "1.0.0-${kernel.version}";

  dontUnpack = true;

  nativeBuildInputs = kernel.moduleBuildDependencies;

  makeFlags = kernel.commonMakeFlags ++ [
    "-C"
    "${kernel.dev}/lib/modules/${kernel.modDirVersion}/build"
  ];

  buildPhase = ''
    runHook preBuild
    cp ${srcFile} io-module.c
    cat > Makefile <<'EOF'
    obj-m := io-module.o
    ccflags-y += -g -DDEBUG
    EOF
    make $makeFlags M=$(pwd) modules
    runHook postBuild
  '';

  installPhase = ''
    runHook preInstall
    make $makeFlags M=$(pwd) INSTALL_MOD_PATH=$out modules_install
    mkdir -p $out/share/caliptra-fpga
    cp io-module.ko $out/share/caliptra-fpga/io-module.ko
    runHook postInstall
  '';

  meta = {
    description = "Caliptra FPGA UIO kernel module (${variant} variant)";
    license = lib.licenses.gpl2Only;
    platforms = [ "aarch64-linux" ];
  };
}
