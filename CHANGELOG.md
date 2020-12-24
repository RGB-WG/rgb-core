Change Log
==========

v0.2.1, v0.2.2
--------------
- Fixing serde to use Bech32 encoding for ContractId and SchemaId types

v0.2.0
------
No changes since RC2

### Changes since v0.1
- Epic: refactoring of LNP protocols and services crate
- Epic: initial implementation of generalized lightning network
- Epic: lightning network specific encodings and derives
- CI covering different mobile & desktop targets

v0.2.0-rc.2
-----------
- New tagged hash implementation defaulting to Bech32 encoding for ContractId
- Using amplify and amplify_derive v2.4

v0.2.0-rc.1
-----------
- Fix for the broken tokio upstream dependency breaking issue
- Fix for zero-balance overflow in case of empty arguments
- Eq implementation for Schema object

v0.2.0-beta.3
-------------
- Multiple BIP-32 improvements on top of rust-bitcoin functionality
- Better CI
- Android/iOS/Windows/MacOs build fixes
- AchorId strict encoding
- Fixed issue with broken `serde_with` macro (pinned older version in Cargo.toml)
- More collection types supporting `AutoConceal`

v0.2.0-beta.2
-------------

### LNP module
- Noise handshake
- Abstract state channels
- Payment channels
- Channel extensibility framework
- BOLT3 transaction structure for payment channels
- Additional LN peer messages supporting RGB

### BP module
- Lexicographic orderings (BIP96) for transactions, PSBTs, inputs and outputs

v0.2.0-beta.1
-------------

### LNP/BP Core Library
- LN messaging & LNPWP: Lightning network peer wire protocol (BOLT-1pt2, BOLT-2)
- BOLT-8 noise encryptor and handshake implementation
- Improvements to LN-specific data types
- LNP socket and node addressing large-scale refactoring
- More serde and strict encoding implementations for data types across the 
  library

### LNP/BP Derivation Library
- Implementation of strict derive macros for enums

### LNP/BP Services Library
- Debugging and display logging improvements with LNP/BP Services library
- ESB functionality improvements in LNP/BP Services libraru

v0.2.0-alpha.3
--------------

- Improvements to the ESB and RPC service architectures
- Improvements to debug logging and displaying of LN messages and service 
  information

v0.2.0-alpha.2
--------------

- Enterprise system bus service type with peer addressing
- Complete set of LN peer messages from BOLT-1 and BOLT-2
- Improved logging and error handling
- Improved LNP node address conversions

v0.2.0-alpha.1
--------------

This is alpha release with some major refactoring in LNP mod adding support for 
LN and Internet2 protocols.

- Refactoring of LNP protocol stack; introduction of Internet2 architacture
- Services crate implementing common client/server and other node architecture 
  patterns
- Basic implementation of core Lightning network data structures

v0.1.0
------

### Library overview
- **Paradigms**: generic APIs for L1/L3 best practices
  * **Client-side validation**
  * **Single-use-seals**
  * **Strict encoding**
- **Bitcoin protocol**: extensions to `bitcoin` crate and L2/L3 APIs
  * **Deterministic bitcoin commitments** (DBC) based on LNPBP1-4 standard
  * **Tagged hashes**: additional procedures for working with Tapproot-style
    tagged hashes
  * **Short bitcoin identifiers** based on LNPBP-4 standard
  * **Resolver API** for requesting transaction graph using providers (like
    Bitcoin Core RPC, Electrum Server API etc)
  * **Chains**, chain parameters and universal asset identifiers
  * **Script types** for differentiating script cycle through different
    transaction parts
  * **Transaction-output-based single-use-seals**: bitcoin-specific 
    implementation of single-use-seals
- **RGB**: confidential smart-contract system for Bitcoin & Lightning Network
  based on client-side validation paradigm (LNPBP11-13 standards)
  * **Schema**: structure defining contract creation and evolution rules and
    restrictions
  * **Contracts**: data types for contract lifecycle
  * **Scripting** with embedded procedures for fungible assets  
  *The library implements RGB Core v1 release candidate set of standards*
- **Lightning networking protocol**: generalized P2P and RPC networking APIs
  based on the original Lightning standard; early preview
  * Universal P2P node ids supporting IPv4, IPv6, Onion v2 and v3 addresses and
    public keys
  * Feature vectors for defining and workinf with set of feature bits
  * LNP networking with ZMQ sockets for RPC interfaces

### Major changes since RC2
- Support for Rust stable and MSRV reduction to 1.41.1
- Custom forks for upstream bitcoin-related dependencies are changed onto the
  latest publicly-released versions

### Breaking changes since RC2
- Updated taproot-based hashed tag system (BIP-340) according to the most
  recent specs.
- RGB `Amount` renamed into `AtomicValue`
- RGB `amount` mod renamed into `value`
- RGB seal definitions and related structures are now `Copy` and returned by 
  value


v0.1.0-rc.2
-----------

### Breaking changes:
- Changed embedded procedure names for RGB VM
- Removed requirement for PSBT to contain fee key in RGB anchor creation (it 
  needs to be a properly constructed PSBT with `witness_utxo`/`non_witness_utxo` 
  data)

### Other changes:
- More embedded procedures for RGB VM
- Schema serde serialization (YAML, JSON etc)
- Serde serialization for all RGB contract structures
- Strict encoding and decoding of Curve25519 public keys and Ed25519 signatures
- Implementation of Curve25519 public keys and Ed25519 signatures as RGB state 
  and metadata
- Bech types for Pedersen commitments, Bulletproofs, Curve25519 data
- Tweaking factor is added into PSBT information during anchor creation
- Added bitcoin protocol resolvers API


v0.1.0-rc.1
-----------

### Breaking changes:
- RGB protocol & schema versioning with feature bits
- Consignment versioning
- Changed Bech32 encodings of RGB data structures; added deflation encoding
- Implemented RGB public state extensions
- Refactored LNP addressing and it's encoding
- Completed Tor v2 and v3 addresses support
- RGB data structures naming refactoring
- Changed bulletproofs commitments which will enable future aggregation
- Introduced Chain and ChainParam types instead of old network versioning

### Other changes:
- Test coverage >70%
- Code docs >50%


v0.1.0-beta.4
-------------

### Breaking changes:
- Updated upstream crates (bitcoin, bitcoin_hashes, secp256k1, 
  grin_secp256k1zpk, miniscript, lightning) with many PRs merged
- EmbedCommitVerify now can mutate container data (used for returning tweaking 
  factors)
- Upgrading `rand` version to the most recent one (blocked previously by 
  grin_secp256k1zpk dependency)
- Changied txout seals to use u32 vouts instead of u16
- Changed txout blinding factor to be u64 instead of u32

### Other changes:
- Test coverage >50% (zero-knowledge functionality & RGB contracts structures)
- Returning tweaking factors
- Minimal support for Tor V2 addresses; improved internet address parsing


v0.1.0-beta.3
-------------

### Breaking changes
- Single-use-seals blinding factor changed from 32-bit to 64-bit of entropy
- Transaction output indexes in single-use-seal definitions are now 32-bit, as 
  in Bitcoin Core / rust-bitcoin (previously were 16-bit)

### New features
- Initial Tor V2 address support
- Test cases for BP mod strict encoding


v0.1.0-beta.2
-------------

### Features overview
- Complete validation workflow with new Validator object
- Virtual machines for RGB contracts (interface + embedded VM)
- `Consignment` now has a version field, so in the future more space-saving 
  variants can be created (like removing txid from anchors and using short 
  universal bitcoin IDs when BP node adoption will increase)
- Anchor contains txid field; so validation can be performed with just Bitcoin 
  Core (no Electrum or BP node is required). This also speeded up validation 
  performance significantly.

### Breaking changes
- Change of `TransitionId` hash tag value (previously-generated transition ids 
  will be invalid)
- Change of `GenesisId`  hash tag value (previously-generated contract/assets 
  ids will be invalid)
- `TransitionId` type is replaced with `NodeId`
- `NodeId` and `ContractId` are now equal by value; `ContractId` is `NodeId` 
  wrapper
- `ancestors()` method moved from `Transition` to `Node` trait; genesis returns 
  an empty array
- Consignment endpoints contain `NodeId` information
