# LNP/BP standard library

[![TravisCI](https://api.travis-ci.com/LNP-BP/rust-lnpbp.svg?branch=master)](https://api.travis-ci.com/LNP-BP/rust-lnpbp)

This is Rust library implementing LNP/BP specifications <https://github.com/lnp-bp/lnpbps>. It can be used for building
layer 3 solutions on top of Lightning Network and Bitcoin blockchain. The list of such projects include:
* [RGB](https://github.com/rgb-org): Different forms of assets and asset-managing smart contracts
* [Spectrum](https://github.com/rgb-org): Decentralized exchange for Lightning Network
* [Storm](https://github.com/storm-org): Incentivised trustless storage and messaging
* [Prometheus](https://github.com/pandoracore/prometheus-spec): Decentralized trustless computing

The development of these projects is supported by LNP/BP Standard Association.

## Library functionality

The library provides the code for:
 
* Deterministic commitments that can be embedded into for Bitcoin transactions and public keys
* Single-use seals
* Client-side validated data, including serialization, verification etc
* Client-validated state management

This code supports both Bitcoin blockchain and Lightning network.

## Project structure

The library is built as a single Rust crate with the following top-level mods:
* common: traits, structures, functions and generics which are used by all parts of the project
* seals: Single-use seals in generic form, which is not specific to Bitcoin blockchain and may be applied to any layer
* bp: Bitcoin protocol extensions external to [Bitcoin Core](https://github.com/bitcoin/bitcoin) functionality and 
  existing [BIPs](http://github.com/bitcoin/bips). These may also cover those of 
  [LNPBP standards](https://github.com/lnp-bp/lnpbps) which are not specific for other layers.
* lnp: Lightning Network protocol extensions external to 
  [BOLT specifications](https://github.com/lightningnetwork/lightning-rfc)
* csv: Client-side validation generics for managing all possible off-chain data in standard way.
* cmt: Commitments layer for provable commitments in bitcoin transactions and public keys. 
  Can be used both jointly with single-use seal system or independently from it.
* rgb: More complex client-validated state management based on client-side validation, provable commitments and
  single-use seals, applicable for both Bitcoin blockchain and Lightning Network.

The library is based on other projects:
* [rust-bitcoin](https://github.com/rust-bitcoin/rust-bitcoin) and it's dependencies
  * [bitcoin_hashes](https://github.com/rust-bitcoin/bitcoin_hashes)
  * [rust-secp256k1](https://github.com/rust-bitcoin/rust-secp256k1)
  * [rust-secp256k1-zkp](https://github.com/ElementsProject/rust-secp256k1-zkp) for Pedersen commitments and
    Bulletproofs used in confidential state inside RGB protocols
* [rust-lightning](https://github.com/rust-bitcoin/rust-lightning)

```text
+---------------------------------------------------------------------------------------+
| rgb - client-validated state system                                                   |
+-------------------------------------+-------------------+-----------------------------+
| csv - client-side validation        | cmt - commitments | lnp - LN addons             |
+-------------------------------------+-------------------+--------++==================++
| seals - single-use seals | bp - bitcoin addons                   || crate: lightning ||
+----------------------+--------++=================================++==================++
                       | common || crate: bitcoin                                      ||
                       +--------++===============++==================++================++
                       || crate: hashes || crate: secp256k1 || crate: bitcoinconsensus || 
                       ++===============++==================++=========================++
                                        || C: libsecp256k1  || C: libbitcoinconsensus  ||
                                        ++==================++=========================++
```

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

Please refer to the [`cargo` documentation](https://doc.rust-lang.org/stable/cargo/) for more detailed instructions. 

### Use library in other projects

Include this line into your `Cargo.toml` file:

```toml
lnpbp = { git = "https://github.com/lnp-bp/rust-lnpbp.git", branch = "master" }
```

### Use command-line tool for LNP/BP:

We have developed a command-line tool [`lbx`](https://github.com/lnp-bp/lbx) which implements most of this library 
functionality, so it can be accessed and played with. Download it and build according to the instructions in
<https://github.com/lnp-bp/lbx>

## More information

### Policy on Altcoins/Altchains

Altcoins and "blockchains" other than Bitcoin blockchain/Bitcoin protocols are not supported and not planned to be
supported; pull requests targeting them will be declined.

### Licensing

See [LICENCE](LICENSE) file.

