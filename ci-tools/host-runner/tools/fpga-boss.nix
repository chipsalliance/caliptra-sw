{ lib
, rustPlatform
, fetchFromGitHub
, pkg-config
, libftdi1
}:

rustPlatform.buildRustPackage rec {
  pname = "caliptra-fpga-boss";
  version = "0.1.0";
  src = fetchFromGitHub {
    owner = "chipsalliance";
    repo = "caliptra-sw";
    rev = "b5f9a6bed0e0291a0179df8af250a51a90f29c5b";
    sha256 = "sha256-nzGj4kwvAJy9eULBzp1SUH0+A/MNEXi93BB5MHRO4Pc=";
  };
  sourceRoot = "${src.name}/ci-tools/fpga-boss";
  cargoHash = "sha256-cx+uHWFzeZHnX92G3UzfpAiT0SSWkEPP+5pxmZ/nbfY=";
  nativeBuildInputs = [
    pkg-config
  ];
  buildInputs = [
    libftdi1
  ];
  meta = with lib; {
    description = "A tool for managing caliptra fpgas";
    homepage = "https://github.com/chipsalliance/caliptra-sw";
    license = licenses.mit;
    maintainers = with maintainers; [ "clundin25" ];
    platforms = platforms.linux;
  };
}
