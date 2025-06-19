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
    rev = "a9d7695d";
    sha256 = "sha256-OKMr2xsiEPjHh5/8jG/bl/f9nqIR1Zkhu+Sd+4B/DMQ=";
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
