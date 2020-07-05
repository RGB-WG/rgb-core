# Change Log

## v0.1.0-beta.2

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
