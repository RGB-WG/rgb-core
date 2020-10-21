# LNP/BP Core Library

![Build](https://github.com/LNP-BP/rust-lnpbp/workflows/Build/badge.svg)
![Tests](https://github.com/LNP-BP/rust-lnpbp/workflows/Tests/badge.svg)
![Lints](https://github.com/LNP-BP/rust-lnpbp/workflows/Lints/badge.svg)
[![codecov](https://codecov.io/gh/LNP-BP/rust-lnpbp/branch/master/graph/badge.svg)](https://codecov.io/gh/LNP-BP/rust-lnpbp)

[![crates.io](https://meritbadge.herokuapp.com/lnpbp)](https://crates.io/crates/lnpbp)
[![Docs](https://docs.rs/lnpbp/badge.svg)](https://docs.rs/lnpbp)
[![unsafe forbidden](https://img.shields.io/badge/unsafe-forbidden-success.svg)](https://github.com/rust-secure-code/safety-dance/)
[![MIT licensed](https://img.shields.io/badge/license-MIT-blue.svg)](./LICENSE)

This is LNP/BP Core Library: a rust library implementing LNP/BP specifications 
<https://github.com/LNP-BP/LNPBPs>. It can be used to simplify development of
layer 2 & 3 solutions on top of Lightning Network and Bitcoin blockchain. 

The current list of the projects based on the library include:
* [RGB](https://github.com/LNP-BP/rgb-node): Confidential & scalable smart 
  contracts for Bitcoin & Lightning
* [Generalized Lightning Network](https://www.youtube.com/watch?v=YmmNsWS5wiM) 
  and it's reference implementation named 
  [LNP node](https://github.com/LNP-BP/lnp-node) enabling:
  - RGB extensions
  - DLC extensions
  - [Lightspeed payments](https://github.com/LNP-BP/LNPBPs/issues/24)
  - Multi-peer channels
  - Faster lightning experiments (quicker adoption of eltoo, Taproot etc)
* [LNP](https://github.com/LNP-BP/FAQ/blob/master/Presentation%20slides/LNP%20Networking%20%26%20RGB%20Integration_final.pdf): 
  Networking protocol for privacy-keeping and censorship-resistant applications,
  operating in both P2P and RPC modes (currently used as a part of Lightning 
  network, but our effort is to make it more generic and usable even outside of 
  LN). All services, developed by LNP/BP Standards Association (see points
  below) are made with LNP.
* [BP node](https://github.com/LNP-BP/bp-node): Indexing service for bitcoin 
  blockchain; more efficient & universal Electrum server replacement. In 
  perspective - validating Bitcoin network node (using libbitcoinconsus)

The planned projects:
* Decentralized exchange for Lightning Network
* Bifrost Node: P2P LNP/BP network infrastructural node running
  - Decentralized exchange information workflows
  - Watchtowers (RGB-enabled)
  - DLC oracle provider
  - Anonymous intermediate storage for client-validated data (like RGB 
    consignments)
  - Storm storage providers (see below)
* [Storm](https://github.com/storm-org): Incentivised trustless storage and 
  messaging protocol
* [Prometheus](https://github.com/pandoracore/prometheus-spec): Decentralized 
  trustless computing

Potentially, with LNP/BP Core library you can simplify the development of
* Discreet log contracts
* Implement experimental lightning features
* Do complex multi-threaded or elastic/dockerized client-service microservice 
  architectures

To learn more about the technologies enabled by the library please check:
* [RGB Technology Internals](https://github.com/LNP-BP/FAQ/blob/master/Presentation%20slides/)
* [Networking with LNP](https://github.com/LNP-BP/FAQ/blob/master/Presentation%20slides/LNP%20Networking%20%26%20RGB%20Integration_final.pdf)
* [LNP/BP Nodes Initiative](https://github.com/LNP-BP/FAQ/blob/master/Presentation%20slides/LNP-BP%20Nodes%20Initiative.pdf)

The development of the library projects is supported by LNP/BP Standards 
Association.

## Library functionality

The library provides the code for:

* RGB: confidential smart contracts with client-side validation, with Lightning
  network support
* Improvements & utilities for Bitcoin protocol 
* Deterministic commitments that can be embedded into for Bitcoin transactions 
  and public keys (DBC)
* Single-use seals
* Client-side validation
* Lightning networking protocol (LNP)
* Generalized lightning network

This code supports both Bitcoin blockchain and Lightning network.

## Project structure

The library is built as a single Rust crate with the following top-level mods:
* paradigms: generic paradigms (API best practices) which are not bitcoin-specific
* bp: Bitcoin protocol extensions external to [Bitcoin Core](https://github.com/bitcoin/bitcoin) 
  functionality and existing [BIPs](http://github.com/bitcoin/bips). These may
  also cover those of [LNPBP standards](https://github.com/lnp-bp/lnpbps) which 
  are not specific for other layers.
* lnp: Lightning Network protocol extensions: networking, generalized lightning 
  channels and better layerization of
  [BOLT specifications](https://github.com/lightningnetwork/lightning-rfc)
* rgb: smart contracts for Bitcoin and Lightning network based client-side 
  validation, deterministic bitcoin commitments and single-use seals.
* standards: other LNPBPs standard implementation which does not fit into any of
  the categories above

The library is based on other projects:
* [rust-bitcoin](https://github.com/rust-bitcoin/rust-bitcoin)
* [bitcoin_hashes](https://github.com/rust-bitcoin/bitcoin_hashes)
* [rust-secp256k1](https://github.com/rust-bitcoin/rust-secp256k1)
* [rust-secp256k1-zkp](https://github.com/ElementsProject/rust-secp256k1-zkp) 
  for Pedersen commitments and Bulletproofs used in confidential state inside 
  RGB protocols
* [rust-miniscript](https://github.com/rust-bitcoin/rust-miniscript)

## Install

### Get the dependencies

On Debian, run
```shell script
sudo apt-get install cargo libzmq3-dev
```

On Mac OS, run
```shell script
brew cargo
```

### Clone and compile library

Minimum supported rust compiler version (MSRV): 1.41.1

```shell script
git clone https://github.com/lnp-bp/rust-lnpbp
cd rust-lnpbp
cargo build --release --features vendored_openssl
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
lnpbp = "~0.1.0"
lnpbp_derive = "~0.1.0"
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

