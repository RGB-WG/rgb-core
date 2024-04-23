{
  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixos-unstable";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
      inputs.flake-utils.follows = "flake-utils";
    };

    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, rust-overlay, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        overlays = [ (import rust-overlay) ];
        pkgs = import nixpkgs {
          inherit system overlays;
        };

        cargoToml = builtins.fromTOML (builtins.readFile ./Cargo.toml);

        nightlyWithWasm = pkgs.rust-bin.nightly.latest.default.override {
          extensions = [ ];
          targets = [ "wasm32-unknown-unknown" ];
        };
      in
      with pkgs;
      {
        devShells = rec {
          default = msrv;

          msrv = mkShell {
            buildInputs = [
              rust-bin.stable."${cargoToml.package."rust-version"}".default
            ];
          };

          stable = mkShell {
            buildInputs = [
              rust-bin.stable.latest.default
            ];
          };

          beta = mkShell {
            buildInputs = [
              rust-bin.beta.latest.default
            ];
          };

          nightly = mkShell {
            buildInputs = [
              rust-bin.nightly.latest.default
            ];
          };

          wasm = mkShell {
            buildInputs = [
              nightlyWithWasm
              chromedriver
              wasm-pack
            ];
          };
        };
      }
    );
}
