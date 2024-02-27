# RGB Core Library

![Build](https://github.com/RGB-WG/rgb-core/workflows/Build/badge.svg)
![Tests](https://github.com/RGB-WG/rgb-core/workflows/Tests/badge.svg)
![Lints](https://github.com/RGB-WG/rgb-core/workflows/Lints/badge.svg)
[![codecov](https://codecov.io/gh/RGB-WG/rgb-core/branch/master/graph/badge.svg)](https://codecov.io/gh/RGB-WG/rgb-core)

[![crates.io](https://img.shields.io/crates/v/rgb-core)](https://crates.io/crates/rgb-core)
[![Docs](https://docs.rs/rgb-core/badge.svg)](https://docs.rs/rgb-core)
[![unsafe forbidden](https://img.shields.io/badge/unsafe-forbidden-success.svg)](https://github.com/rust-secure-code/safety-dance/)
[![Apache-2 licensed](https://img.shields.io/crates/l/rgb-core)](./LICENSE)

RGB is confidential & scalable client-validated smart contracts for Bitcoin & 
Lightning. To learn more about RGB please check [RGB website][Site].

RGB Core library provides consensus-critical and validation code for RGB. 
It is a standard implementation, jointly with [LNP/BP Standards][LNPBPs] 
defining RGB consensus and validation rules.

The consensus-critical code library is shared with the following libraries:
1. [Client-side-validation Lib][Foundation]. It is
   non-bitcoin-specific library, covering concepts related to
   client-side-validation (commitments, single-use-seals abstracted from
   bitcoin, consensus-critical data encoding protocols).
2. [BP Core Lib][BP]. This is client-side-validation applied to bitcoin protocol
   with deterministic bitcoin commitments (tapret) and TXO-based
   single-use-seals.
3. [AluVM virtual machine][AluVM] used by RGB for Turing-complete smart contract
   functionality.
4. [Strict types][StrictTypes], defining memory layout and serialization of 
   structured data types used in RGB smart contracts.

The development of the project is supported and managed by [LNP/BP Standards 
Association][Association]. The design of RGB smart contract system and 
implementation of this and underlying consensus libraries was done in 2019-2024 
by [Dr Maxim Orlovsky][Max] basing or earlier ideas of client-side-validation 
and RGB as "assets for bitcoin and LN" by [Peter Todd][Todd] and 
[Giacomo Zucco][Zucco]. Upon the release of RGBv1 the protocol will be immutable
and this library will accept only bugfixes; i.e. it will be ossified by 
requiring consensus ACK for the new changes across the large set of maintainers.

The current list of the projects based on the library include:
* [RGB Standard Lib][RGB Std]: library providing high-level RGB smart contract
  API in rust.
* [RGB Wallet][RGB Wallet]: runtime and command-line tool for working with RGB.

## Contributing

Currently, library functionality is frozen and as a part of ossification only
bugfixes are accepted.

Altcoins and "blockchains" other than Bitcoin blockchain/Bitcoin protocols are 
not supported and not planned to be supported; pull requests targeting them will 
be declined.

## License

See [LICENCE](LICENSE) file.


[LNPBPs]: https://github.com/LNP-BP/LNPBPs
[Association]: https://lnp-bp.org
[Site]: https://rgb.tech
[Foundation]: https://github.com/LNP-BP/client_side_validation
[BP]: https://github.com/BP-WG/bp-core
[AluVM]: https://www.aluvm.org
[StrictTypes]: https://www.strict-types.org
[RGB Std]: https://github.com/RGB-WG/rgb-std
[RGB Wallet]: https://github.com/RGB-WG/rgb
[Max]: https://dr.orlovsky.ch
[Todd]: https://petertodd.org/
[Zucco]: https://giacomozucco.com/
