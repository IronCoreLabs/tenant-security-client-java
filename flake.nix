{
  description = "Tenant Security Client Java";
  inputs.nixpkgs.url = "nixpkgs/nixos-unstable";
  inputs.flake-utils.url = "github:numtide/flake-utils";

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs { inherit system; };
      in {
        devShell = with pkgs; mkShell {
          buildInputs = [
            maven
            openjdk17
          ];
          # Nix sets SOURCE_DATE_EPOCH to 1980-01-01T00:00:00Z (315532800) for
          # reproducible builds, but maven-javadoc-plugin requires at least
          # 1980-01-01T00:00:02Z. Bump by 2 seconds to satisfy the validation.
          SOURCE_DATE_EPOCH = 315532802;
        };
      }
    );
}
