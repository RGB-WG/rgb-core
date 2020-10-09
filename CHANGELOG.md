Change Log
==========

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
- Updated upstream crates (bitcoin, bitcoin_hashes, secp256k1, grin_secp256k1zpk, miniscript, lightning) with many PRs merged
- EmbedCommitVerify now can mutate container data (used for returning tweaking factors)
- Upgrading `rand` version to the most recent one (blocked previously by grin_secp256k1zpk dependency)
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
- Transaction output indexes in single-use-seal definitions are now 32-bit, as in Bitcoin Core / rust-bitcoin (previously were 16-bit)

### New features

- Initial Tor V2 address support
- Test cases for BP mod strict encoding


v0.1.0-beta.2
-------------

### Features overview
- Complete validation workflow with new Validator object
- Virtual machines for RGB contracts (interface + embedded VM)
- `Consignment` now has a version field, so in the future more space-saving variants can be created (like removing txid from anchors and using short universal bitcoin IDs when BP node adoption will increase)
- Anchor contains txid field; so validation can be performed with just Bitcoin Core (no Electrum or BP node is required). This also speeded up validation performance significantly.

### Breaking changes
- Change of `TransitionId` hash tag value (previously-generated transition ids will be invalid)
- Change of `GenesisId`  hash tag value (previously-generated contract/assets ids will be invalid)
- `TransitionId` type is replaced with `NodeId`
- `NodeId` and `ContractId` are now equal by value; `ContractId` is `NodeId` wrapper
- `ancestors()` method moved from `Transition` to `Node` trait; genesis returns an empty array
- Consignment endpoints contain `NodeId` information
