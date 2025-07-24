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
    rev = "10e4ed31a10b2c6d60642d7894412e2fc8b2b9fb";
    sha256 = "sha256-LIU6GDESwoYTL7KrGYZabopC8QRR8x70qQaU7XAVc5o=";
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
