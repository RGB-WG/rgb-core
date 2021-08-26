# RGB Core Library

![Build](https://github.com/rgb-org/rgb-core/workflows/Build/badge.svg)
![Tests](https://github.com/rgb-org/rgb-core/workflows/Tests/badge.svg)
![Lints](https://github.com/rgb-org/rgb-core/workflows/Lints/badge.svg)
[![codecov](https://codecov.io/gh/rgb-org/rgb-core/branch/master/graph/badge.svg)](https://codecov.io/gh/rgb-org/rgb-core)

[![crates.io](https://img.shields.io/crates/v/rgb-core)](https://crates.io/crates/rgb-core)
[![Docs](https://docs.rs/rgb-core/badge.svg)](https://docs.rs/rgb-core)
[![unsafe forbidden](https://img.shields.io/badge/unsafe-forbidden-success.svg)](https://github.com/rust-secure-code/safety-dance/)
[![MIT licensed](https://img.shields.io/badge/license-MIT-blue.svg)](./LICENSE)

Rust library implementing confidential & scalable client-validated smart 
contracts for Bitcoin & Lightning.

The current list of the projects based on the library include:
* [RGB Node](https://github.com/LNP-BP/rgb-node): standalone & embeddable node
  for running RGB
* [RGB SDK](https://github.com/LNP-BP/rgb-sdk): SDK for developing mobile, web,
  desktop & server-side wallets and doing other forms of software integration 
  with RGB Node

To learn more about the technologies enabled by the library please check:
* [RGB Technology Internals](https://github.com/LNP-BP/FAQ/blob/master/Presentation%20slides/)
* [LNP/BP Nodes Initiative](https://github.com/LNP-BP/FAQ/blob/master/Presentation%20slides/LNP-BP%20Nodes%20Initiative.pdf)

The development of the library projects is supported by [LNP/BP Standards 
Association](https://github.com/LNP-BP).

Previously the code of the library was part of [LNP/BP Core Library](https://github.com/LNP-BP/rust-lnpbp)
but later was extracted into a separate library in this repository via fork.
The reasons for that were the facts that LNP/BP Core Lib has a lot of usage
outside RGB project scope, and the overall dependencies & feature management
complexity, compile times etc grow significantly. Another reason is the need for
different review policies & security requirements (LNP/BP Core Lib may be more
experimental than RGB).

The library is based on other projects:
* [rust-bitcoin](https://github.com/rust-bitcoin/rust-bitcoin)
* [bitcoin_hashes](https://github.com/rust-bitcoin/bitcoin_hashes)
* [rust-secp256k1](https://github.com/rust-bitcoin/rust-secp256k1)
* [rust-secp256k1-zkp](https://github.com/ElementsProject/rust-secp256k1-zkp) 
  for Pedersen commitments and Bulletproofs used in confidential state inside 
  RGB protocols
* [rust-miniscript](https://github.com/rust-bitcoin/rust-miniscript)
* [rust-lnpbp](https://github.com/LNP-BP/rust-lnpbp) LNP/BP Core Library

## Install

### Get the dependencies

On Debian, run
```shell script
sudo apt-get install cargo libssl-dev libzmq3-dev pkg-config g++ cmake
```

On Mac OS, run
```shell script
brew install rust pkg-config zmq
```

### Clone and compile library

Minimum supported rust compiler version (MSRV): 1.41.1 (if used without tokio)

```shell script
git clone https://github.com/rgb-org/rgb-core
cd rgb-core
cargo build --release --all-features
```

The library can be found in `target/release` directory.

You can run full test suite with:

```
./contrib/test.sh
```

Please refer to the [`cargo` documentation](https://doc.rust-lang.org/stable/cargo/) 
for more detailed instructions. 

### Use library in other projects

Add these lines to your `Cargo.toml` file at the very end of the `[dependecies]`
section:

```toml
rgb-core = "~0.3.0"
```


## Contributing

Contribution guidelines can be found in a separate 
[CONTRIBUTING](CONTRIBUTING.md) file


## More information

### Policy on Altcoins/Altchains

Altcoins and "blockchains" other than Bitcoin blockchain/Bitcoin protocols are 
not supported and not planned to be supported; pull requests targeting them will 
be declined.

### Licensing

See [LICENCE](LICENSE) file.

