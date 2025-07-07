{ pkgs }:

pkgs.buildGoModule rec {
  pname = "rtool";
  version = "0.1.0";
  src = pkgs.fetchFromGitHub {
    owner = "chipsalliance";
    repo = "caliptra-sw";
    rev = "a9d7695d";
    hash = "sha256-OKMr2xsiEPjHh5/8jG/bl/f9nqIR1Zkhu+Sd+4B/DMQ=";
  };
  sourceRoot = "${src.name}/ci-tools/github-runner/cmd/rtool";
  proxyVendor = true;
  vendorHash = "sha256-J/WUpXDgugv3v7m/VGlHrW9J1IxuaWB6TQ7v2Us8or0=";
  meta = with pkgs.lib; {
    description = "A tool for working with the Caliptra GitHub CI";
    homepage = "https://github.com/chipsalliance/caliptra-sw";
    license = licenses.mit;
    maintainers = with maintainers; [ "clundin25" ];
  };
}
