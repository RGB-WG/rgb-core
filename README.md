# LNP/BP Core Library

[![TravisCI](https://api.travis-ci.com/LNP-BP/rust-lnpbp.svg?branch=master)](https://api.travis-ci.com/LNP-BP/rust-lnpbp)
[![codecov](https://codecov.io/gh/LNP-BP/rust-lnpbp/branch/master/graph/badge.svg)](https://codecov.io/gh/LNP-BP/rust-lnpbp)

This is Rust library implementing LNP/BP specifications 
<https://github.com/LNP-BP/LNPBPs>. It can be used to simplify development of
layer 2 & 3 solutions on top of Lightning Network and Bitcoin blockchain. 

The current list of such projects include:
* [RGB](https://github.com/LNP-BP/rgb-node): Confidential smart contracts for 
  Bitcoin & Lightning
* [LNP node](https://github.com/LNP-BP/lnp-node): Experimental rust-based 
  modular Lightning network node
* [BP node](https://github.com/LNP-BP/bp-node): Indexing service for bitcoin 
  blockchain; more efficient & universal Electrum server replacement

The planned projects:
* Spectrum: Decentralized exchange for Lightning Network
* [Storm](https://github.com/storm-org): Incentivised trustless storage and 
  messaging
* [Prometheus](https://github.com/pandoracore/prometheus-spec): Decentralized 
  trustless computing

Potentially, with LNP/BP Core library you can simplify the development of
* Discreet log contracts
* Implement experimental lightning features
* Do complex multi-threaded or elastic/dockerized client-service microservice 
  architectures

To learn more about the technologies enabled by the library please check:
* [RGB Technology Guide](https://github.com/LNP-BP/FAQ/blob/master/Presentation%20slides/RGB%20Technology%20Guide%2C%20part%20I.pdf)
* [Networking with LNP](https://github.com/LNP-BP/FAQ/blob/master/Presentation%20slides/LNP%20Networking%20%26%20RGB%20Integration_final.pdf)
* [LNP/BP Nodes Initiative](https://github.com/LNP-BP/FAQ/blob/master/Presentation%20slides/LNP-BP%20Nodes%20Initiative.pdf)

The development of the library projects is supported by LNP/BP Standards 
Association.

## Library functionality

The library provides the code for:

* Improvements & utilities for Bitcoin protocol 
* Deterministic commitments that can be embedded into for Bitcoin transactions 
  and public keys
* Single-use seals
* Client-side validation
* Lightning networking protocol (LNP)
* Generalized lightning network

This code supports both Bitcoin blockchain and Lightning network.

## Project structure

The library is built as a single Rust crate with the following top-level mods:
* common: traits, structures, functions and generics which are used by all parts 
  of the project
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
* lnpbps: other LNPBPs standard implementation which does not fit into any of
  the categories above

The library is based on other projects:
* [rust-bitcoin](https://github.com/rust-bitcoin/rust-bitcoin) and it's dependencies
  * [bitcoin_hashes](https://github.com/rust-bitcoin/bitcoin_hashes)
  * [rust-secp256k1](https://github.com/rust-bitcoin/rust-secp256k1)
  * [rust-secp256k1-zkp](https://github.com/ElementsProject/rust-secp256k1-zkp) 
    for Pedersen commitments and Bulletproofs used in confidential state inside 
    RGB protocols
* [rust-lightning](https://github.com/rust-bitcoin/rust-lightning)

## Install

### Get the dependencies

On Debian, run
```shell script
sudo apt-get install cargo
```

On Mac OS, run
```shell script
brew cargo
```

### Clone and compile library

```shell script
git clone https://github.com/lnp-bp/rust-lnpbp
cd rust-lnpbp
cargo build --release
```

The library can be found in `target/release` directory.

You can run tests with:

```
cargo test
```

Please refer to the [`cargo` documentation](https://doc.rust-lang.org/stable/cargo/) 
for more detailed instructions. 

### Use library in other projects

Include this line into your `Cargo.toml` file:

```toml
lnpbp = { git = "https://github.com/lnp-bp/rust-lnpbp.git", branch = "master" }
```

### Use command-line tool for LNP/BP:

We have developed a command-line tool [`lbx`](https://github.com/lnp-bp/lbx) 
which implements most of this library functionality, so it can be accessed and 
played with. Download it and build according to the instructions in
<https://github.com/lnp-bp/lbx>

## Contributing

Contribution guidelines can be found in a separate 
[CONTRIBUTING](CONTRIBUTING.md) file

### External dependencies

This library depends on a number of external Rust libraries managed by different 
organizations and people within bitcoin community, including Blockstream, 
Chaincode Labs, Pandora Core companies. Some of the functionality required for 
LNP/BP development related to the base Bitcoin protocol and Lightning Network is 
contributed by LNP/BP Association directly into the underlying libraries; 
however sometimes the present library requires changes in them that can't or not 
yet accepted by the community. This brings necessity to maintain our own forks 
of the dependencies. This section presents guidelines for organizing Git 
workflow managing all dependencies, branching, forks etc.

LNP/BP Standards Association maintains a fork of the following external 
libraries:
* bitcoin_hashes
* rust-bitcoin
* rust-miniscript
* rust-lightning
* rust-lightning-invoice
* rust-secp256k1-zkp

Functionality, required for LNP/BP and not yet merged into the upstream `master` 
branches is kept in `staging` branch of each of these forks, which is defined as 
a default branch in GitHub. Parties wanting to contribute to it must fork the 
repo, create a branch per each feature (starting with `feat/` prefix) or bugfix 
(starting with `fix/` prefix) and do a PR to the `staging` branch.

Each commitment within a PR to the `staging` must 
* compile without errors;
* contain all necessary tests for the introduced functional;
* contain all docs.


## More information

### Policy on Altcoins/Altchains

Altcoins and "blockchains" other than Bitcoin blockchain/Bitcoin protocols are 
not supported and not planned to be supported; pull requests targeting them will 
be declined.

### Licensing

See [LICENCE](LICENSE) file.

