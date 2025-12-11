{
  pkgs,
  rtool,
  fpga-boss,
  user,
  ...
}:
{
  download-image = pkgs.writeShellScriptBin "download-image" ''
    export GCP_ZONE="us-central1"
    export GITHUB_ORG="chipsalliance"
    export GCP_PROJECT="caliptra-github-ci"
    ${rtool}/bin/rtool download_artifact 379559 40993215 fpga-image.yml "$@"
  '';
  sync-images = pkgs.writeShellScriptBin "sync-images" ''
    export GCP_ZONE="us-central1"
    export GITHUB_ORG="chipsalliance"
    export GCP_PROJECT="caliptra-github-ci"

    cd /home/${user}
    set -eux
    mkdir -p ci-images
    pushd ci-images

    ${rtool}/bin/rtool download_artifact 379559 40993215 fpga-image-1.x.yml caliptra-fpga-image main > caliptra-fpga-image.zip
    ${pkgs.unzip}/bin/unzip caliptra-fpga-image.zip
    DATE_SUFFIX=$(date +%Y%m%d)
    (mv zcu104.img zcu104.img.old."$DATE_SUFFIX" || true)
    mv image.img zcu104.img
    rm caliptra-fpga-image.zip

    for VARIANT in "caliptra-fpga-image-core" "caliptra-fpga-image-subsystem"; do
        ${rtool}/bin/rtool download_artifact 379559 40993215 fpga-image.yml $VARIANT main > $VARIANT.zip
        ${pkgs.unzip}/bin/unzip $VARIANT.zip
        (mv $VARIANT.img $VARIANT.img.old."$DATE_SUFFIX" || true)
        mv image.img $VARIANT.img
        rm $VARIANT.zip
    done

    popd 

    mkdir -p dev-images
    pushd dev-images

    for VARIANT in "caliptra-fpga-image-core-dev" "caliptra-fpga-image-subsystem-dev"; do
        ${rtool}/bin/rtool download_artifact 379559 40993215 fpga-image.yml $VARIANT main > $VARIANT.zip
        ${pkgs.unzip}/bin/unzip $VARIANT.zip
        (mv $VARIANT.img $VARIANT.img.old."$DATE_SUFFIX" || true)
        mv dev-image.img $VARIANT.img
        rm $VARIANT.zip
     done
  '';
  image-cleanup = pkgs.writeShellScriptBin "image-cleanup" ''
    set -eux
    for dir in "/home/${user}/ci-images" "/home/${user}/dev-images"; do
        cd $dir
        ${pkgs.fd}/bin/fd --glob "*.img*.old" --change-older-than "4 weeks" -X rm
    done
  '';
  fpga-boss-script = pkgs.writeShellScriptBin "fpga.sh" ''
    #!${pkgs.bash}/bin/bash
    export GCP_ZONE="us-central1"
    export GITHUB_ORG="chipsalliance"
    export GCP_PROJECT="caliptra-github-ci"

    RAND_POSTFIX=$(${pkgs.python3}/bin/python3 -c 'import random; print("".join(random.choice("0123456789ABCDEF") for i in range(16)))')

    # check if we operate on ZCU_SDWIRE or USBSDMUX
    if [[ -z $USB_SDMUX ]] && [[ -n $ZCU_SDWIRE ]]; then
      SD_MUX="--sdwire $ZCU_SDWIRE"
    elif [[ -n $USB_SDMUX ]] && [[ -z $ZCU_SDWIRE ]]; then
      SD_MUX="--usbsdmux $USB_SDMUX"
    else
      echo "Invalid combination of ZCU_SDWIRE and USB_SDMUX"
      exit 1
    fi

    ${fpga-boss}/bin/caliptra-fpga-boss --zcu104 $ZCU_FTDI $SD_MUX serve $IMAGE -- ${rtool}/bin/rtool jitconfig "$FPGA_TARGET" 379559 40993215 "$IDENTIFIER-$RAND_POSTFIX"
  '';
}
