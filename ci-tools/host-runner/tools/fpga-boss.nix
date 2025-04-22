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
    rev = "ccafea4ccb62d885bca3d668d05cd8a7a5c8cf04";
    sha256 = "sha256-p0e9ezKnplyF8siShHVMj3CHHoDEj2vB+bkbaB2unak=";
  };
  sourceRoot = "${src.name}/ci-tools/fpga-boss";
  cargoHash = "sha256-/iRPkvuVliEi1JbrZdKkWFRNijWCHt6DCtkujEVplHI=";
  nativeBuildInputs = [
    pkg-config
  ];
  buildInputs = [
    libftdi1
  ];
  meta = with lib; {
    description = "A tool for managing caliptra fpgasd";
    homepage = "https://github.com/chipsalliance/caliptra-sw";
    license = licenses.mit;
    maintainers = with maintainers; [ "clundin25" ];
    platforms = platforms.linux;
  };
}
