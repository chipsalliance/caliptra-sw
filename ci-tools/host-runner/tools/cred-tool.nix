{ lib
, rustPlatform
, fetchFromGitHub
}:

rustPlatform.buildRustPackage rec {
  pname = "cred-tool";
  version = "0.1.0";
  src = fetchFromGitHub {
    owner = "clundin25";
    repo = "cred-tool";
    rev = "7030a25db7f9f6c7b5d879f798630ff136fa7567";
    sha256 = "sha256-tbjZVLaE0w4i7oaDZTUynn2RjeIKA+7d+Om14yNeHdA=";
  };
  cargoHash = "sha256-ncSsUekJ8aXGoLwEMmrIRj5tHYnyn4yGTnfCqoDVzgY=";
  meta = with lib; {
    description = "A command line tool for credential management";
    homepage = "https://github.com/clundin25/cred-tool";
    license = licenses.mit;
    maintainers = with maintainers; [ "clundin25" ];
    platforms = platforms.linux;
  };
}
